//! `/authorize` validation pipeline and error-delivery matrix.
//!
//! Validation order (RFC 6749 §4.1.2.1, RFC 9700 §4.1.3, RFC 9101 §4,
//! RFC 9126 §4): resolve PAR/JAR input, `client_id` → client, the JAR/PAR
//! mandatory rule, `redirect_uri`, `response_type` = `code`, scope, PKCE
//! (`S256`, required), then `state` passthrough. No code is issued here;
//! a [`ValidatedRequest`] only authorizes the login/consent stages to run.
//!
//! Error-delivery matrix: [`AuthorizeFailure::Page`] (HTTP 400, no redirect)
//! only for an absent/unknown `client_id`, an invalid or unregistered
//! `redirect_uri`, or a malformed request (including every PAR/JAR
//! resolution failure, which precedes `redirect_uri` validation and therefore
//! cannot redirect safely). Every later failure redirects to the validated
//! `redirect_uri` with `error` (+ `state`).

use std::collections::HashMap;

use axum::{
  body::Body,
  http::{StatusCode, header},
  response::{Html, IntoResponse, Response},
};
use sqlx::PgPool;

use crate::{
  config::GrantKind,
  crypto::pkce::{CHALLENGE_LEN, S256_METHOD, verify_method},
  db::{client_repo, redirect_repo, scope_repo},
  error::{AppError, OAuthErrorCode},
  jose::jar::{self, JarRequest},
  protocol::{redirect_repo as redirect_match, scope},
  state::RedisConn,
  store::Store,
};

/// Inputs to [`validate`]: live stores plus the raw authorize query.
pub struct AuthorizeInput<'a> {
  /// Postgres pool for the client, redirect, and scope catalog reads.
  pub pool: &'a PgPool,
  /// Versioned PII keys for the encrypted client lookup.
  pub keys: &'a crate::keys::KeyRing,
  /// Redis connection for PAR `request_uri` consumption.
  pub conn: &'a mut RedisConn,
  /// Redis store handle backing the PAR lookup.
  pub store: &'a Store,
  /// Server issuer; the `aud` of JAR request objects.
  pub issuer: &'a str,
  /// Raw authorize query parameters as received.
  pub query: &'a HashMap<String, String>,
}

/// An authorize request that passed every validation step.
///
/// This carries no code and no session: it is the normalized record the
/// pending-auth store (task 24) persists before login/consent runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRequest {
  /// The validated `client_id`.
  pub client_id: String,
  /// The validated `redirect_uri`, exactly as requested.
  pub redirect_uri: String,
  /// The effective scope (explicit request checked; omission defaults to the
  /// client set narrowed by the enabled catalog; user entitlement is enforced
  /// at consent, not here).
  pub scope: scope::ScopeSet,
  /// The S256 `code_challenge` the later code grant is bound to.
  pub code_challenge: String,
  /// The `state` value to echo in the authorization response, if supplied.
  pub state: Option<String>,
  /// The client's single registered post-logout return URI, when it has one.
  /// Resolved during validation so a later logout can return the browser to
  /// the client without accepting any redirect target from a request.
  pub post_logout_uri: Option<String>,
}

/// How an authorize failure reaches the user agent.
///
/// A [`AuthorizeFailure::Page`] renders HTTP 400 with no `Location`; a
/// [`AuthorizeFailure::Redirect`] renders HTTP 302 to the validated
/// `redirect_uri` carrying `error` (+ `error_description`, + `state`).
#[derive(Debug)]
pub enum AuthorizeFailure {
  /// Direct error page: unknown client, bad redirect, or malformed request.
  Page(AppError),
  /// Redirect to the validated `redirect_uri` with an OAuth error.
  Redirect {
    /// The validated `redirect_uri` the user agent returns to.
    target: String,
    /// The OAuth error to encode in the redirect query.
    error: AppError,
    /// The `state` to echo, if the request supplied one.
    state: Option<String>,
  },
}

impl AuthorizeFailure {
  /// The OAuth error code carried by this failure.
  #[must_use]
  pub fn code(&self) -> OAuthErrorCode {
    match self {
      Self::Page(error) | Self::Redirect { error, .. } => error.code(),
    }
  }

  /// Whether this failure carries a stored-value decrypt failure: the
  /// handler audits it as `pii.decrypt_failure` (the repository never emits).
  #[must_use]
  pub fn is_pii_decrypt(&self) -> bool {
    matches!(
      self,
      Self::Page(AppError::PiiDecrypt)
        | Self::Redirect {
          error: AppError::PiiDecrypt,
          ..
        }
    )
  }

  /// Render the failure as an HTTP response (page or redirect).
  #[must_use]
  pub fn into_response(self) -> Response {
    match self {
      Self::Page(error) => error_page(&error),
      Self::Redirect {
        target,
        error,
        state,
      } => error_redirect(&target, &error, state.as_deref()),
    }
  }
}

/// Validate an authorize request following the mandated order.
///
/// Returns the normalized request when every check passes. Returns
/// [`AuthorizeFailure::Page`] before `redirect_uri` is validated and
/// [`AuthorizeFailure::Redirect`] after; no code is issued on any path.
///
/// # Errors
///
/// Returns [`AuthorizeFailure`] as described by the error-delivery matrix.
pub async fn validate(input: AuthorizeInput<'_>) -> Result<ValidatedRequest, AuthorizeFailure> {
  let client_id = present(input.query.get("client_id"))
    .ok_or_else(|| page(AppError::invalid_request("client_id is required")))?;
  let client = client_repo::find_active_by_client_id(input.pool, input.keys, client_id)
    .await
    .map_err(AuthorizeFailure::Page)?
    .ok_or_else(|| page(AppError::invalid_client_non_basic()))?;

  let jar_input = JarRequest {
    client: &client,
    issuer: input.issuer,
    query: input.query,
    request: present(input.query.get("request")).map(String::as_str),
    request_uri: present(input.query.get("request_uri")).map(String::as_str),
  };
  let merged = jar::resolve(input.conn, input.store, &jar_input)
    .await
    .map_err(AuthorizeFailure::Page)?;

  if merged
    .get("client_id")
    .is_some_and(|seen| seen != &client.client_id)
  {
    return Err(page(AppError::invalid_request(
      "client_id binding mismatch",
    )));
  }

  let redirect_uri = present(merged.get("redirect_uri"))
    .ok_or_else(|| page(AppError::invalid_request("redirect_uri is required")))?;
  let effective = redirect_repo::effective_for_client(input.pool, input.keys, &client.client_id)
    .await
    .map_err(AuthorizeFailure::Page)?;
  let registered: Vec<&str> = effective.iter().map(|entry| entry.uri.as_str()).collect();
  match redirect_match::match_redirect_uri(&registered, redirect_uri) {
    redirect_match::RedirectDecision::Exact | redirect_match::RedirectDecision::Loopback => {}
    redirect_match::RedirectDecision::Reject => {
      return Err(page(AppError::invalid_request(
        "redirect_uri is not registered for this client",
      )));
    }
  }
  let redirect = redirect_uri.clone();

  // From here the redirect target is validated: every failure redirects.
  let redirect_err = |error: AppError| AuthorizeFailure::Redirect {
    target: redirect.clone(),
    error,
    state: merged.get("state").cloned(),
  };

  match present(merged.get("response_type")) {
    Some(response_type) if response_type == "code" => {}
    Some(_) => {
      return Err(redirect_err(AppError::unsupported_response_type(
        "only response_type=code is supported",
      )));
    }
    None => {
      return Err(page(AppError::invalid_request("response_type is required")));
    }
  }

  let enabled = scope_repo::list_enabled(input.pool)
    .await
    .map_err(redirect_err)?;
  let enabled_names: Vec<String> = enabled.iter().map(|record| record.name.clone()).collect();
  let enabled_set = scope_set_of(&enabled_names, &redirect, &merged)?;
  let client_registered =
    scope::ScopeSet::parse(&client.scope).map_err(|_| redirect_err(AppError::server_error()))?;
  let scope_input = scope::ScopeInput {
    requested: present(merged.get("scope")).map(String::as_str),
    client_registered: &client_registered,
    user_entitled: &enabled_set,
    enabled: &enabled_set,
    grant: GrantKind::AuthorizationCode,
    exchange_allowlist: &scope::ScopeSet::empty(),
  };
  let effective_scope = scope::effective_scope(&scope_input).map_err(redirect_err)?;

  let challenge = present(merged.get("code_challenge"))
    .ok_or_else(|| redirect_err(AppError::invalid_request("code_challenge is required")))?;
  match present(merged.get("code_challenge_method")) {
    Some(method) if method == S256_METHOD => {}
    Some(_) => {
      return Err(redirect_err(AppError::invalid_request(
        "only code_challenge_method=S256 is accepted",
      )));
    }
    None => {
      return Err(redirect_err(AppError::invalid_request(
        "code_challenge_method=S256 is required",
      )));
    }
  }
  verify_method(S256_METHOD).map_err(|_| redirect_err(AppError::server_error()))?;
  check_challenge_shape(challenge).map_err(redirect_err)?;

  let post_logout_uri =
    redirect_repo::post_logout_for_client(input.pool, input.keys, &client.client_id)
      .await
      .map_err(AuthorizeFailure::Page)?;

  Ok(ValidatedRequest {
    client_id: client.client_id,
    redirect_uri: redirect,
    scope: effective_scope,
    code_challenge: challenge.clone(),
    state: merged.get("state").cloned(),
    post_logout_uri,
  })
}

/// Treat `None` and `""` alike: an absent parameter.
fn present(value: Option<&String>) -> Option<&String> {
  value.filter(|text| !text.is_empty())
}

/// Wrap an [`AppError`] as a direct (no-redirect) failure.
fn page(error: AppError) -> AuthorizeFailure {
  AuthorizeFailure::Page(error)
}

/// Build an enabled-catalog [`scope::ScopeSet`]; a corrupt catalog row is a
/// `server_error` redirect (the target is already validated here).
fn scope_set_of(
  names: &[String],
  redirect: &str,
  merged: &HashMap<String, String>,
) -> Result<scope::ScopeSet, AuthorizeFailure> {
  scope::ScopeSet::from_names(names).map_err(|_| AuthorizeFailure::Redirect {
    target: redirect.to_owned(),
    error: AppError::server_error(),
    state: merged.get("state").cloned(),
  })
}

/// Check the S256 challenge shape (43 base64url characters, no verifier yet).
fn check_challenge_shape(challenge: &str) -> Result<(), AppError> {
  let well_formed = challenge.len() == CHALLENGE_LEN
    && challenge
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
  if well_formed {
    Ok(())
  } else {
    Err(AppError::invalid_request("malformed code_challenge"))
  }
}

/// Render a direct error page: HTTP 400 HTML, no `Location`.
fn error_page(error: &AppError) -> Response {
  let body = format!(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
    <link rel=\"stylesheet\" href=\"/assets/app.css\">\
    <title>{code}</title></head><body><h1>{code}</h1><p>{description}</p></body></html>",
    code = escape_html(error.code().as_str()),
    description = escape_html(error.description()),
  );
  let mut response = Html(body).into_response();
  *response.status_mut() = StatusCode::BAD_REQUEST;
  response
}

/// Render an authorize error redirect: HTTP 302 with `error` (+ `state`).
fn error_redirect(target: &str, error: &AppError, state: Option<&str>) -> Response {
  let separator = if target.contains('?') { '&' } else { '?' };
  let mut location = String::with_capacity(target.len() + 128);
  location.push_str(target);
  location.push(separator);
  location.push_str("error=");
  location.push_str(error.code().as_str());
  location.push_str("&error_description=");
  push_percent_encoded(&mut location, error.description());
  if let Some(state) = state {
    location.push_str("&state=");
    push_percent_encoded(&mut location, state);
  }
  match header::HeaderValue::from_str(&location) {
    Ok(value) => Response::builder()
      .status(StatusCode::FOUND)
      .header(header::LOCATION, value)
      .body(Body::empty())
      .unwrap_or_else(|_| error_page(&AppError::server_error())),
    Err(_) => error_page(&AppError::server_error()),
  }
}

/// Escape the five HTML-significant characters.
fn escape_html(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  for char in text.chars() {
    match char {
      '&' => out.push_str("&amp;"),
      '<' => out.push_str("&lt;"),
      '>' => out.push_str("&gt;"),
      '"' => out.push_str("&quot;"),
      '\'' => out.push_str("&#39;"),
      _ => out.push(char),
    }
  }
  out
}

/// Append `text` percent-encoded (unreserved characters pass through).
fn push_percent_encoded(out: &mut String, text: &str) {
  const HEX: &[u8; 16] = b"0123456789ABCDEF";
  for byte in text.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(byte as char);
    } else {
      out.push('%');
      out.push(HEX[usize::from(byte >> 4)] as char);
      out.push(HEX[usize::from(byte & 0x0F)] as char);
    }
  }
}

#[cfg(test)]
mod tests;

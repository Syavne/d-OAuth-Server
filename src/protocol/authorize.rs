//! `/authorize` validation pipeline and error-delivery matrix.
//!
//! Validation order (RFC 6749 §4.1.2.1, RFC 9700 §4.1.3, RFC 9101 §4,
//! RFC 9126 §4): resolve PAR/JAR input, `client_id` → client, the JAR/PAR
//! mandatory rule, `redirect_uri`, `response_type` = `code`, scope, PKCE
//! (`S256`, required), then `state` passthrough. No code is issued here;
//! a [`ValidatedRequest`] only authorizes the login/consent stages to run.
//!
//! Error-delivery matrix: [`AuthorizeFailure::Page`] (no redirect) only for
//! an absent/unknown `client_id`, an invalid or unregistered `redirect_uri`,
//! or a malformed request (including every PAR/JAR resolution failure, which
//! precedes `redirect_uri` validation and therefore cannot redirect safely).
//! A page renders the error's HTTP status: client errors render 400, a
//! fail-closed outage (`temporarily_unavailable`, Postgres/PII) renders 503
//! with `Retry-After`, and a masked internal failure renders 500. Every later
//! failure redirects to the validated `redirect_uri` with `error` (+ `error_description`, + `state`, + RFC 9207
//! `iss`).

use std::{collections::HashMap, time::Duration};

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
  protocol::{cimd, redirect_repo as redirect_match, scope},
  state::RedisConn,
  store::Store,
};

/// Client ID Metadata Document (CIMD) resolution settings for a request path.
///
/// Present only when `config.cimd_enabled`; a `None` value makes a CIMD URL
/// `client_id` take the existing unknown-client path, so enabling the feature
/// is the sole switch (CIMD draft §3/§4.1).
#[derive(Clone)]
pub struct CimdRequest<'a> {
  /// Token keyspace prefix carrying the `{state}` hash tag, for the
  /// `cimd:<sha256(url)>` document cache.
  pub token_prefix: &'a str,
  /// Maximum accepted document size (`config.cimd_max_bytes`).
  pub max_bytes: usize,
  /// Total fetch budget (`config.cimd_fetch_timeout`).
  pub timeout: Duration,
  /// Document fetcher: the SSRF-guarded production fetch in handlers, an
  /// injected stub in tests. Cloned (never re-fetched) at each use.
  pub fetcher: cimd::CimdFetcher,
}

impl std::fmt::Debug for CimdRequest<'_> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CimdRequest")
      .field("token_prefix", &self.token_prefix)
      .field("max_bytes", &self.max_bytes)
      .field("timeout", &self.timeout)
      .finish_non_exhaustive()
  }
}

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
  /// Config `allow_localhost_redirect`: treat the exact host `localhost` as
  /// an RFC 8252 §7.3 loopback redirect host.
  pub allow_localhost_redirect: bool,
  /// CIMD resolution settings; `None` when `config.cimd_enabled` is off.
  pub cimd: Option<CimdRequest<'a>>,
  /// Raw query parameters as received.
  pub query: &'a HashMap<String, String>,
  /// Repeated `resource` indicators (RFC 8707) in wire order, captured from
  /// the raw query by the `RawQuery` extractor (see `protocol::params`).
  pub resources: Vec<String>,
  /// Config `resource_indicators_enabled`: off + any `resource` present is
  /// `invalid_target` (fail-closed, no silent drop).
  pub resource_indicators_enabled: bool,
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
  /// Validated resource audiences (RFC 8707), sorted and deduped; empty
  /// when unbound. Pinned into the pending record at the route layer.
  pub aud: Vec<String>,
  /// The client's single registered post-logout return URI, when it has one.
  /// Resolved during validation so a later logout can return the browser to
  /// the client without accepting any redirect target from a request.
  pub post_logout_uri: Option<String>,
}

/// How an authorize failure reaches the user agent.
///
/// A [`AuthorizeFailure::Page`] renders the error's HTTP status with no
/// `Location` (400 for client errors, 503 + `Retry-After` for a fail-closed
/// outage, 500 for a masked internal failure); a
/// [`AuthorizeFailure::Redirect`] renders HTTP 302 to the validated
/// `redirect_uri` carrying `error` (+ `error_description`, + `state`, + `iss`
/// per RFC 9207).
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
    /// The server issuer echoed as the RFC 9207 `iss` parameter.
    iss: String,
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
        iss,
      } => error_redirect(&target, &error, state.as_deref(), &iss),
    }
  }
}

/// The resolved authorize client: a registered row, or a registration-free
/// Client ID Metadata Document (CIMD draft §3/§4.1).
///
/// The CIMD arm is purely in-memory: it never writes a row, never attaches a
/// catalog redirect, and never consumes an initial access token.
enum ResolvedClient {
  /// An active `oauth_clients` row.
  Registered(Box<client_repo::Client>),
  /// A validated document fetched from an `https://` `client_id`.
  Cimd(cimd::ValidatedCimd),
}

impl ResolvedClient {
  /// The public `client_id` (the document URL for the CIMD arm).
  fn client_id(&self) -> &str {
    match self {
      Self::Registered(client) => &client.client_id,
      Self::Cimd(validated) => &validated.client_id,
    }
  }

  /// The scope bound used as the client-registered set for the intersect: a
  /// registered client's stored `scope`, or the document's `scope`.
  fn registered_scope(&self) -> &str {
    match self {
      Self::Registered(client) => &client.scope,
      Self::Cimd(validated) => &validated.scope,
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
pub async fn validate(mut input: AuthorizeInput<'_>) -> Result<ValidatedRequest, AuthorizeFailure> {
  let client_id = present(input.query.get("client_id"))
    .ok_or_else(|| page(AppError::invalid_request("client_id is required")))?;

  // A registered row always wins over CIMD; an `https://` `client_id` with no
  // active row is a CIMD client only while the feature is enabled (CIMD
  // draft §3). With `cimd` absent the unknown-client page is unchanged.
  let resolution = match client_repo::find_active_by_client_id(input.pool, input.keys, client_id)
    .await
    .map_err(AuthorizeFailure::Page)?
  {
    Some(client) => ResolvedClient::Registered(Box::new(client)),
    None => {
      // Fail-closed: a registered row that is not active is dead. An
      // inactive `https://` row must never fall through to the CIMD
      // fallback below (zero fetches); the caller keeps unknown-client.
      if client_repo::find_by_client_id_any_state(input.pool, input.keys, client_id)
        .await
        .map_err(AuthorizeFailure::Page)?
        .is_some()
      {
        return Err(page(AppError::invalid_client_non_basic()));
      }
      match resolve_cimd(&mut input, client_id).await? {
        Some(validated) => ResolvedClient::Cimd(validated),
        None => return Err(page(AppError::invalid_client_non_basic())),
      }
    }
  };

  // A registration-free CIMD client resolves through the same JAR entry
  // point as a registered row, but against a synthetic principal
  // materialized from the validated document (CIMD draft §4.1/§5): its
  // inline `jwks` verifies request objects, `require_par_or_jar` keeps the
  // PAR/JAR matrix (a `private_key_jwt` document must use PAR or JAR, a
  // `none` document may use the plain query), and a PAR-issued `request_uri`
  // binds to the document URL exactly as a row id would.
  let synthetic;
  let jar_client: &client_repo::Client = match &resolution {
    ResolvedClient::Registered(client) => client,
    ResolvedClient::Cimd(validated) => {
      synthetic = validated.to_client();
      &synthetic
    }
  };
  let jar_input = JarRequest {
    client: jar_client,
    issuer: input.issuer,
    query: input.query,
    request: present(input.query.get("request")).map(String::as_str),
    request_uri: present(input.query.get("request_uri")).map(String::as_str),
  };
  let merged_claims = jar::resolve(input.conn, input.store, &jar_input)
    .await
    .map_err(AuthorizeFailure::Page)?;
  let merged = &merged_claims.params;

  let expected_client_id = resolution.client_id();
  if merged
    .get("client_id")
    .is_some_and(|seen| seen.as_str() != expected_client_id)
  {
    return Err(page(AppError::invalid_request(
      "client_id binding mismatch",
    )));
  }

  let redirect_uri = present(merged.get("redirect_uri"))
    .ok_or_else(|| page(AppError::invalid_request("redirect_uri is required")))?;
  // A registered client matches against its effective catalog set; a CIMD
  // client against its own document `redirect_uris` only — the catalog is
  // never consulted for a registration-free client (CIMD draft §5).
  let registered_uris: Vec<String> = match &resolution {
    ResolvedClient::Registered(client) => {
      redirect_repo::effective_for_client(input.pool, input.keys, &client.client_id)
        .await
        .map_err(AuthorizeFailure::Page)?
        .into_iter()
        .map(|entry| entry.uri)
        .collect()
    }
    ResolvedClient::Cimd(validated) => validated.redirect_uris.clone(),
  };
  let registered: Vec<&str> = registered_uris.iter().map(String::as_str).collect();
  match redirect_match::match_redirect_uri(
    &registered,
    redirect_uri,
    input.allow_localhost_redirect,
  ) {
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
    iss: input.issuer.to_owned(),
  };

  // JAR/PAR pins the audience in exactly one transport: the PAR record's
  // `aud` or the signed object's `resource` claim. A query `resource` beside
  // either would union into, and widen, that pinned set; a PAR record strips
  // `resource` at push, so the merge cannot see the duplicate. Reject it
  // fail-closed (RFC 9101 §5.2, RFC 8707 §2.1).
  let jar_present =
    input.query.get("request").is_some() || input.query.get("request_uri").is_some();
  if jar_present && !input.resources.is_empty() {
    return Err(redirect_err(AppError::invalid_request_object(
      "resource must be carried in the request object, not the query",
    )));
  }
  let resources = if jar_present {
    merged_claims.resource
  } else {
    let mut resources = input.resources.clone();
    resources.extend(merged_claims.resource);
    resources
  };

  // Resource indicators (RFC 8707) validate after the redirect target, so a
  // bad audience redirects (never a page): unknown, non-https, or flag-off
  // `resource` is `invalid_target`, and the sorted deduped set pins into
  // `ValidatedRequest.aud` for the pending record.
  let aud =
    super::params::validate_resources(input.pool, input.resource_indicators_enabled, &resources)
      .await
      .map_err(redirect_err)?;

  match present(merged.get("response_type")) {
    Some(response_type) if response_type == "code" => {}
    Some(_) => {
      return Err(redirect_err(AppError::unsupported_response_type(
        "only response_type=code is supported",
      )));
    }
    None => {
      return Err(redirect_err(AppError::invalid_request(
        "response_type is required",
      )));
    }
  }

  let enabled = scope_repo::list_enabled(input.pool)
    .await
    .map_err(redirect_err)?;
  let enabled_names: Vec<String> = enabled.iter().map(|record| record.name.clone()).collect();
  let enabled_set = scope_set_of(&enabled_names, &redirect, merged, input.issuer)?;
  let client_registered = scope::ScopeSet::parse(resolution.registered_scope())
    .map_err(|_| redirect_err(AppError::server_error()))?;
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

  // A registration-free client has no catalog post-logout target; only a
  // registered row is consulted.
  let post_logout_uri = match &resolution {
    ResolvedClient::Registered(client) => {
      redirect_repo::post_logout_for_client(input.pool, input.keys, &client.client_id)
        .await
        .map_err(redirect_err)?
    }
    ResolvedClient::Cimd(_) => None,
  };

  Ok(ValidatedRequest {
    client_id: resolution.client_id().to_owned(),
    redirect_uri: redirect,
    scope: effective_scope,
    code_challenge: challenge.clone(),
    state: merged.get("state").cloned(),
    aud,
    post_logout_uri,
  })
}

/// Resolve a Client ID Metadata Document for an `https://` `client_id` when
/// the feature is enabled and no registered row matched.
///
/// Returns `Ok(None)` when CIMD is disabled or `client_id` is not an
/// `https://` URL, so the caller keeps the existing unknown-client behavior.
/// A document that fails validation maps to its client-safe error
/// (`invalid_client_metadata`/`invalid_redirect_uri`; a dependency outage is
/// a fail-closed `503`).
///
/// # Errors
///
/// Returns [`AuthorizeFailure::Page`] for any fetch/validation/backend
/// [`cimd::CimdError`].
async fn resolve_cimd(
  input: &mut AuthorizeInput<'_>,
  client_id: &str,
) -> Result<Option<cimd::ValidatedCimd>, AuthorizeFailure> {
  let Some(settings) = input.cimd.as_ref() else {
    return Ok(None);
  };
  // CIMD draft §3: only an `https://` URL names a metadata document.
  if !client_id.starts_with("https://") {
    return Ok(None);
  }
  let limits = cimd::CimdLimits {
    max_bytes: settings.max_bytes,
    timeout: settings.timeout,
  };
  let validated = cimd::resolve_with_catalog(
    input.conn,
    settings.token_prefix,
    input.pool,
    client_id,
    input.allow_localhost_redirect,
    limits,
    &settings.fetcher,
  )
  .await
  .map_err(|error| page(AppError::from(error)))?;
  Ok(Some(validated))
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
  issuer: &str,
) -> Result<scope::ScopeSet, AuthorizeFailure> {
  scope::ScopeSet::from_names(names).map_err(|_| AuthorizeFailure::Redirect {
    target: redirect.to_owned(),
    error: AppError::server_error(),
    state: merged.get("state").cloned(),
    iss: issuer.to_owned(),
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

/// Render a direct error page: HTML with the error's HTTP status and no
/// `Location`. Client errors render 400; a fail-closed outage
/// (`temporarily_unavailable`) renders 503 with `Retry-After: 1`, and a masked
/// internal failure renders 500 (RFC 6749 §4.1.2.1, RFC 9700 §4.1.3).
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
  *response.status_mut() = error.status();
  if error.code() == OAuthErrorCode::TemporarilyUnavailable {
    response
      .headers_mut()
      .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
  }
  response
}

/// Render an authorize error redirect: HTTP 302 with `error` (+ `state`, + RFC
/// 9207 `iss`).
fn error_redirect(target: &str, error: &AppError, state: Option<&str>, issuer: &str) -> Response {
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
  location.push_str("&iss=");
  push_percent_encoded(&mut location, issuer);
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

//! Pushed Authorization Requests (RFC 9126).
//!
//! `POST /par` authenticates the client (see [`client_auth`]), validates the
//! pushed request rules, stores the parameters under a one-time
//! `request_uri` with the configured PAR TTL (90 s), and returns
//! `{request_uri, expires_in}`. The `/authorize` side never lives here: it
//! consumes the `request_uri` through [`crate::jose::jar::resolve`], which
//! rejects unknown, expired, replayed, or foreign-client ids.

use std::{collections::HashMap, time::Duration};

use axum::{
  extract::{RawForm, State},
  http::{HeaderMap, StatusCode},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::{
  authorize::CimdRequest,
  cimd,
  client_auth::{AuthContext, AuthStores, ClientAuthRequest, authenticate_client},
  redirect_repo::{RedirectDecision, match_redirect_uri},
};
use crate::{
  crypto::tokens::mint_token,
  db::{client_repo, redirect_repo},
  error::AppError,
  jose::jar::PAR_REQUEST_URI_PREFIX,
  middleware::{
    audit::AuditEvent,
    request_id::{REQUEST_ID_HEADER, RequestId},
  },
  state::{AppState, RedisConn},
  store::{Store, par},
};

/// Client-credential form members: authenticated, never stored.
const CREDENTIAL_PARAMS: [&str; 3] = ["client_secret", "client_assertion", "client_assertion_type"];

/// Datastore handles needed by [`push_authorization_request`].
pub struct ParStores<'a> {
  /// Postgres pool for client lookup and redirect-URI matching.
  pub pool: &'a PgPool,
  /// Versioned PII keys for the encrypted client lookup.
  pub keys: &'a crate::keys::KeyRing,
  /// Redis connection for the PAR record store.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs for the PAR store.
  pub store: &'a Store,
}

/// Request-scoped inputs for [`push_authorization_request`].
pub struct ParContext<'a> {
  /// Canonical token endpoint URL (`aud` must equal this exactly).
  pub token_endpoint: &'a str,
  /// Current time for secret-expiry enforcement.
  pub now: OffsetDateTime,
  /// PAR `request_uri` lifetime (90 s per the plan).
  pub par_ttl: Duration,
  /// Config `allow_localhost_redirect`: treat the exact host `localhost` as
  /// an RFC 8252 §7.3 loopback redirect host when matching the pushed
  /// `redirect_uri`.
  pub allow_localhost_redirect: bool,
  /// CIMD resolution settings; `None` when `config.cimd_enabled` is off.
  pub cimd: Option<CimdRequest<'a>>,
  /// Config `resource_indicators_enabled`: off + any `resource` present is
  /// `invalid_target` (fail-closed, no silent drop).
  pub resource_indicators_enabled: bool,
}

/// Successful PAR response body (RFC 9126 §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParResponse {
  /// One-time PAR URN the authorize request references.
  pub request_uri: String,
  /// Lifetime of the `request_uri` in seconds.
  pub expires_in: u64,
}

/// Push an authorization request (RFC 9126 §2).
///
/// Authenticates the client first (unknown clients and missing credentials
/// on confidential clients fail as `invalid_client`), then enforces the
/// request rules: `client_id` must name the authenticated client,
/// `response_type` must be `code`, `redirect_uri` must be present and
/// registered for the client, and neither `request` nor `request_uri` may
/// appear in a pushed body. The surviving parameters (minus credentials)
/// are stored one-time under a fresh `request_uri` for `par_ttl`.
///
/// # Errors
///
/// Returns `invalid_client` when authentication fails, `invalid_request`
/// (or `invalid_scope` for a blank scope) when a request rule is violated,
/// and a masked `server_error` when storage itself fails.
pub async fn push_authorization_request(
  stores: &mut ParStores<'_>,
  ctx: &ParContext<'_>,
  auth: &ClientAuthRequest<'_>,
  params: &HashMap<String, String>,
  resources: &[String],
) -> Result<ParResponse, AppError> {
  let mut auth_stores = AuthStores {
    pool: stores.pool,
    keys: stores.keys,
    conn: stores.conn,
    store: stores.store,
  };
  let auth_ctx = AuthContext {
    token_endpoint: ctx.token_endpoint,
    now: ctx.now,
    cimd: ctx.cimd.as_ref().map(|settings| cimd::CimdSettings {
      token_prefix: settings.token_prefix,
      max_bytes: settings.max_bytes,
      timeout: settings.timeout,
      allow_localhost: ctx.allow_localhost_redirect,
      fetcher: settings.fetcher.clone(),
    }),
  };
  let authenticated = authenticate_client(&mut auth_stores, &auth_ctx, auth).await?;
  let aud = validate_request_rules(
    stores.pool,
    stores.keys,
    stores.conn,
    &authenticated.client.client_id,
    params,
    resources,
    ctx,
  )
  .await?;

  // The pinned audience travels in the record `aud`, never in the stored
  // JSON: a single-valued map cannot hold repeats, and a joined string
  // would collide with comma-bearing URIs.
  let mut stored = params.clone();
  stored.remove("resource");
  for member in CREDENTIAL_PARAMS {
    stored.remove(member);
  }
  let request = serde_json::to_string(&stored).map_err(AppError::internal)?;
  let id = mint_token().map_err(AppError::internal)?;
  let record = par::ParRecord {
    client_id: authenticated.client.client_id.clone(),
    request,
    aud,
  };
  par::put(stores.conn, stores.store, &id, &record, ctx.par_ttl).await?;

  Ok(ParResponse {
    request_uri: format!("{PAR_REQUEST_URI_PREFIX}{id}"),
    expires_in: ctx.par_ttl.as_secs(),
  })
}

/// Enforce the pushed-request rules (RFC 9126 §2), returning the validated
/// resource audience set (RFC 8707) for the PAR record.
async fn validate_request_rules(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  conn: &mut RedisConn,
  client_id: &str,
  params: &HashMap<String, String>,
  resources: &[String],
  ctx: &ParContext<'_>,
) -> Result<Vec<String>, AppError> {
  match params.get("client_id") {
    Some(presented) if presented == client_id => {}
    _ => {
      return Err(AppError::invalid_request(
        "pushed request client_id must name the authenticated client",
      ));
    }
  }
  match params.get("response_type") {
    Some(response_type) if response_type == "code" => {}
    _ => {
      return Err(AppError::invalid_request(
        "pushed request response_type must be code",
      ));
    }
  }
  if params.contains_key("request") || params.contains_key("request_uri") {
    return Err(AppError::invalid_request(
      "pushed request must not contain request or request_uri",
    ));
  }
  if params
    .get("scope")
    .is_some_and(|scope| scope.trim().is_empty())
  {
    return Err(AppError::invalid_scope(
      "pushed request scope must not be blank",
    ));
  }
  let Some(redirect_uri) = params.get("redirect_uri") else {
    return Err(AppError::invalid_request(
      "pushed request redirect_uri is required",
    ));
  };
  let registered_uris: Vec<String> =
    match client_repo::find_active_by_client_id(pool, keys, client_id).await? {
      Some(_) => redirect_repo::effective_for_client(pool, keys, client_id)
        .await?
        .into_iter()
        .map(|entry| entry.uri)
        .collect(),
      // No registered row: a CIMD `client_id` uses its document redirect set
      // (CIMD draft §5); the catalog is never consulted.
      None => match ctx.cimd.as_ref() {
        Some(settings) if client_id.starts_with("https://") => {
          let limits = cimd::CimdLimits {
            max_bytes: settings.max_bytes,
            timeout: settings.timeout,
          };
          cimd::resolve_with_catalog(
            conn,
            settings.token_prefix,
            pool,
            client_id,
            ctx.allow_localhost_redirect,
            limits,
            &settings.fetcher,
          )
          .await
          .map_err(AppError::from)?
          .redirect_uris
        }
        _ => Vec::new(),
      },
    };
  let registered: Vec<&str> = registered_uris.iter().map(String::as_str).collect();
  if match_redirect_uri(&registered, redirect_uri, ctx.allow_localhost_redirect)
    == RedirectDecision::Reject
  {
    return Err(AppError::invalid_request(
      "pushed request redirect_uri is not registered for this client",
    ));
  }
  // Resource indicators (RFC 8707) validate fail-closed: off + present is
  // `invalid_target`, and every value must be an absolute `https` URI with
  // an exact enabled-catalog match. No silent drop, no scope widening.
  super::params::validate_resources(pool, ctx.resource_indicators_enabled, resources).await
}

/// `POST /par` (RFC 9126 §2.1).
///
/// Credentials come from the `Authorization` header and the form body only;
/// a secret observed in the query string is never consulted. Success is
/// `201 Created` with `{request_uri, expires_in}`.
///
/// # Errors
///
/// Returns whatever [`push_authorization_request`] returns; mTLS-bound
/// clients fail closed here until the TLS accept loop injects peer
/// certificates (task 21 owns that seam).
pub async fn par_handler(
  State(state): State<AppState>,
  headers: HeaderMap,
  body: RawForm,
) -> axum::response::Response {
  use axum::response::IntoResponse as _;
  // `RawForm` gates the content type BEFORE `Bytes` buffering, so a wrong
  // content type is rejected 415 without reading the (up to 2 MiB) body.
  // The explicit exact-MIME gate below is the second check: `RawForm` uses a
  // case-sensitive prefix match, so it accepts e.g.
  // `application/x-www-form-urlencodedevil`, which the exact gate rejects.
  let body = body.0;
  // `RawForm` + a manual parse replaces `Form<HashMap>`: the extractor
  // consumed the raw body, hiding repeats — the repeated `resource`
  // indicator (RFC 8707) is captured in order by `params::values_of`
  // while the single-valued map keeps last-wins absorption. A malformed
  // body is the same 400 (deliberately stricter than the old `Form`, which
  // lossily accepted raw non-UTF-8 bytes).
  if let Err(reject) = super::params::require_form_content_type(&headers) {
    return reject.into_response();
  }
  let pairs = match super::params::form_pairs(&body) {
    Ok(pairs) => pairs,
    Err(reject) => return reject.into_response(),
  };
  let form = super::params::single_valued_map(&pairs);
  let resources = super::params::values_of(&pairs, super::params::RESOURCE_PARAM);
  let header_value = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok());
  let body_secret = form
    .get("client_secret")
    .map(|secret| SecretString::from(secret.as_str()));
  let auth = ClientAuthRequest {
    basic_header: header_value,
    client_id: form.get("client_id").map(String::as_str),
    body_secret,
    assertion_type: form.get("client_assertion_type").map(String::as_str),
    assertion: form.get("client_assertion").map(String::as_str),
    peer_certs: None,
  };
  let mut redis = state.redis.clone();
  let mut stores = ParStores {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut redis,
    store: &Store::from_config(&state.config.redis),
  };
  let ctx = ParContext {
    token_endpoint: &super::client_auth::token_endpoint(&state.config.issuer),
    now: state.clock.now(),
    par_ttl: state.config.ttl.par,
    allow_localhost_redirect: state.config.allow_localhost_redirect,
    cimd: state.config.cimd_enabled.then(|| CimdRequest {
      token_prefix: &state.config.redis.token_key_prefix,
      max_bytes: state.config.cimd_max_bytes,
      timeout: state.config.cimd_fetch_timeout,
      fetcher: state.cimd_fetcher.clone(),
    }),
    resource_indicators_enabled: state.config.resource_indicators_enabled,
  };
  let response = match push_authorization_request(&mut stores, &ctx, &auth, &form, &resources).await
  {
    Ok(response) => response,
    Err(error) => {
      emit_pii_decrypt(&headers, &error);
      return error.into_response();
    }
  };
  (StatusCode::CREATED, axum::Json(response)).into_response()
}

fn emit_pii_decrypt(headers: &HeaderMap, error: &AppError) {
  if matches!(error, AppError::PiiDecrypt) {
    let request_id = headers
      .get(REQUEST_ID_HEADER)
      .and_then(|value| value.to_str().ok())
      .and_then(RequestId::parse);
    AuditEvent::PiiDecryptFailure {
      request_id: request_id.as_ref().map(RequestId::as_str),
    }
    .emit();
  }
}

#[cfg(test)]
mod tests;

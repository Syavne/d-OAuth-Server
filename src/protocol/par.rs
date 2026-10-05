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
  Form,
  extract::State,
  http::{HeaderMap, StatusCode},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::{
  client_auth::{AuthContext, AuthStores, ClientAuthRequest, authenticate_client},
  redirect_repo::{RedirectDecision, match_redirect_uri},
};
use crate::{
  crypto::tokens::mint_token,
  db::redirect_repo,
  error::AppError,
  jose::jar::PAR_REQUEST_URI_PREFIX,
  state::{AppState, RedisConn},
  store::{Store, par},
};

/// Client-credential form members: authenticated, never stored.
const CREDENTIAL_PARAMS: [&str; 3] = ["client_secret", "client_assertion", "client_assertion_type"];

/// Datastore handles needed by [`push_authorization_request`].
pub struct ParStores<'a> {
  /// Postgres pool for client lookup and redirect-URI matching.
  pub pool: &'a PgPool,
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
) -> Result<ParResponse, AppError> {
  let mut auth_stores = AuthStores {
    pool: stores.pool,
    conn: stores.conn,
    store: stores.store,
  };
  let auth_ctx = AuthContext {
    token_endpoint: ctx.token_endpoint,
    now: ctx.now,
  };
  let authenticated = authenticate_client(&mut auth_stores, &auth_ctx, auth).await?;
  validate_request_rules(stores.pool, &authenticated.client.client_id, params).await?;

  let mut stored = params.clone();
  for member in CREDENTIAL_PARAMS {
    stored.remove(member);
  }
  let request = serde_json::to_string(&stored).map_err(AppError::internal)?;
  let id = mint_token().map_err(AppError::internal)?;
  let record = par::ParRecord {
    client_id: authenticated.client.client_id.clone(),
    request,
  };
  par::put(stores.conn, stores.store, &id, &record, ctx.par_ttl).await?;

  Ok(ParResponse {
    request_uri: format!("{PAR_REQUEST_URI_PREFIX}{id}"),
    expires_in: ctx.par_ttl.as_secs(),
  })
}

/// Enforce the pushed-request rules (RFC 9126 §2).
async fn validate_request_rules(
  pool: &PgPool,
  client_id: &str,
  params: &HashMap<String, String>,
) -> Result<(), AppError> {
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
  let effective = redirect_repo::effective_for_client(pool, client_id).await?;
  let registered: Vec<&str> = effective.iter().map(|entry| entry.uri.as_str()).collect();
  if match_redirect_uri(&registered, redirect_uri) == RedirectDecision::Reject {
    return Err(AppError::invalid_request(
      "pushed request redirect_uri is not registered for this client",
    ));
  }
  Ok(())
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
  Form(form): Form<HashMap<String, String>>,
) -> Result<(StatusCode, axum::Json<ParResponse>), AppError> {
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
    conn: &mut redis,
    store: &Store::from_config(&state.config.redis),
  };
  let ctx = ParContext {
    token_endpoint: &super::client_auth::token_endpoint(&state.config.issuer),
    now: state.clock.now(),
    par_ttl: state.config.ttl.par,
  };
  let response = push_authorization_request(&mut stores, &ctx, &auth, &form).await?;
  Ok((StatusCode::CREATED, axum::Json(response)))
}

#[cfg(test)]
mod tests;

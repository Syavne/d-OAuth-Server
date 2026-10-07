//! Token revocation (RFC 7009) with family cascade.
//!
//! `POST /revoke` authenticates the caller (see [`super::client_auth`]),
//! accepts an optional `token_type_hint`, and invalidates the presented
//! token. Revoking a refresh token cascades to its grant family, so every
//! token minted from the same authorization grant dies with it.
//!
//! # Ownership and non-oracle semantics
//!
//! A client may revoke only a token it owns. The lookup is performed before
//! the ownership decision, and a token that is unknown, already gone, or
//! **owned by another client** collapses to the same `200` no-op response —
//! the endpoint never reveals whether a token exists and never cross-revokes.
//!
//! Well-formed requests always answer `200 OK` (RFC 7009 §2.2): unknown and
//! invalid tokens are not an error. Client authentication failure is the only
//! failure for an otherwise valid request (`invalid_client`); a token-type
//! hint naming an unsupported type is `unsupported_token_type`.

use std::collections::HashMap;

use axum::{
  Form, Json,
  extract::State,
  http::{HeaderMap, StatusCode, header},
  response::{IntoResponse, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;

use super::{
  client_auth::{AuthContext, AuthStores, ClientAuthRequest, authenticate_client},
  token::TokenService,
};
use crate::{
  error::AppError,
  middleware::{
    audit::AuditEvent,
    request_id::{REQUEST_ID_HEADER, RequestId},
  },
  state::{AppState, RedisConn},
  store::Store,
};

/// Supported `token_type_hint` value for access tokens (RFC 7009 §2.1).
const HINT_ACCESS: &str = "access_token";

/// Supported `token_type_hint` value for refresh tokens (RFC 7009 §2.1).
const HINT_REFRESH: &str = "refresh_token";

/// Client-safe description for `unsupported_token_type`.
const UNSUPPORTED_TOKEN_TYPE: &str =
  "The authorization server does not support the revocation of the presented token type.";

/// Datastore handles needed by [`revoke_tokens`].
pub struct RevokeStores<'a> {
  /// Postgres pool for client authentication.
  pub pool: &'a PgPool,
  /// Versioned PII keys for the encrypted client lookup.
  pub keys: &'a crate::keys::KeyRing,
  /// Redis connection for the token and grant stores.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
  /// Token lookup and revocation primitives.
  pub service: &'a TokenService,
}

/// Request-scoped authentication and audit inputs for [`revoke_tokens`].
pub struct RevokeContext<'a> {
  /// Canonical token endpoint URL used as the `private_key_jwt` audience.
  pub token_endpoint: &'a str,
  /// Current time for client-secret expiry enforcement.
  pub now: OffsetDateTime,
  /// Correlating request id for the audit event, when present.
  pub request_id: Option<&'a str>,
}

/// One revocation request: the token, its optional hint, and credentials.
pub struct RevokeRequest<'a> {
  /// The token the client wants revoked (required, never empty).
  pub token: &'a str,
  /// Optional RFC 7009 `token_type_hint`.
  pub token_type_hint: Option<&'a str>,
  /// Client credentials from the `Authorization` header and the form body.
  pub auth: &'a ClientAuthRequest<'a>,
}

/// Outcome of a well-formed revocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
  /// The caller owned the token; it (and its family for a refresh) is gone.
  Revoked,
  /// Unknown, already revoked, or owned by another client — no-op `200`.
  NoOp,
  /// The `token_type_hint` names no supported token type.
  UnsupportedHint,
}

/// The token to revoke plus the authenticated owner that must match its record.
struct OwnedToken<'a> {
  /// Client that authenticated this request.
  owner_client_id: &'a str,
  /// Presented token value.
  token: &'a str,
  /// Optional type hint (used only to reject unsupported values).
  token_type_hint: Option<&'a str>,
}

/// Authenticate the caller, then revoke the token if (and only if) the caller
/// owns it.
///
/// A completely unauthenticated request (no `Authorization` header, body
/// secret, client assertion, or `client_id`) is `401` + `WWW-Authenticate`,
/// because the endpoint is a protected resource (RFC 7009 §2.1).
///
/// # Errors
///
/// Returns `invalid_request` for a missing token, `invalid_client` for failed
/// authentication, and a masked store failure otherwise.
pub async fn revoke_tokens(
  stores: &mut RevokeStores<'_>,
  ctx: &RevokeContext<'_>,
  request: &RevokeRequest<'_>,
) -> Result<RevokeOutcome, AppError> {
  if request.token.is_empty() {
    return Err(AppError::invalid_request("token is required"));
  }
  if is_unauthenticated(request.auth) {
    return Err(AppError::invalid_client_basic());
  }
  let authenticated = {
    let mut auth_stores = AuthStores {
      pool: stores.pool,
      keys: stores.keys,
      conn: stores.conn,
      store: stores.store,
    };
    let auth_ctx = AuthContext {
      token_endpoint: ctx.token_endpoint,
      now: ctx.now,
    };
    authenticate_client(&mut auth_stores, &auth_ctx, request.auth).await?
  };

  let owned = OwnedToken {
    owner_client_id: &authenticated.client.client_id,
    token: request.token,
    token_type_hint: request.token_type_hint,
  };
  let outcome = revoke_owned(stores.conn, stores.store, stores.service, &owned).await?;
  if matches!(outcome, RevokeOutcome::Revoked) {
    AuditEvent::TokenRevoke {
      request_id: ctx.request_id,
      client_id: &authenticated.client.client_id,
    }
    .emit();
  }
  Ok(outcome)
}

/// Whether no client credential of any style was presented.
fn is_unauthenticated(auth: &ClientAuthRequest<'_>) -> bool {
  auth.basic_header.is_none()
    && auth.body_secret.is_none()
    && auth.assertion.is_none()
    && auth.client_id.is_none()
}

/// Revoke a token owned by `owner_client_id`.
///
/// Both record slots are probed before the ownership decision so the existence
/// lookup is uniform; a foreign owner returns [`RevokeOutcome::NoOp`] without
/// touching the store. A refresh token revokes the whole grant chain; an access
/// token revokes only itself.
async fn revoke_owned(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  owned: &OwnedToken<'_>,
) -> Result<RevokeOutcome, AppError> {
  match owned.token_type_hint.filter(|hint| !hint.is_empty()) {
    None | Some(HINT_ACCESS | HINT_REFRESH) => {}
    Some(_) => return Ok(RevokeOutcome::UnsupportedHint),
  }

  let access = service.find_access(conn, store, owned.token).await?;
  let refresh = service.find_refresh(conn, store, owned.token).await?;

  if let Some(found) = access {
    if found.record.client_id != owned.owner_client_id {
      return Ok(RevokeOutcome::NoOp);
    }
    service.revoke_token(conn, store, owned.token).await?;
    return Ok(RevokeOutcome::Revoked);
  }
  if let Some(found) = refresh {
    if found.record.client_id != owned.owner_client_id {
      return Ok(RevokeOutcome::NoOp);
    }
    service
      .revoke_grant(conn, store, &found.record.grant_id)
      .await?;
    return Ok(RevokeOutcome::Revoked);
  }
  Ok(RevokeOutcome::NoOp)
}

/// Render a revocation outcome: `200 OK` with an empty body for success and
/// no-ops, `400` with `unsupported_token_type` for a rejected hint.
fn outcome_response(outcome: RevokeOutcome) -> Response {
  match outcome {
    RevokeOutcome::Revoked | RevokeOutcome::NoOp => StatusCode::OK.into_response(),
    RevokeOutcome::UnsupportedHint => (
      StatusCode::BAD_REQUEST,
      Json(ErrorBody {
        error: "unsupported_token_type",
        error_description: UNSUPPORTED_TOKEN_TYPE,
      }),
    )
      .into_response(),
  }
}

/// The JSON body for a locally-owned revocation error code.
#[derive(Debug, Serialize)]
struct ErrorBody {
  /// The wire error code.
  error: &'static str,
  /// A client-safe description.
  error_description: &'static str,
}

/// `POST /revoke` (RFC 7009 §2.1).
///
/// Credentials come from the `Authorization` header and the form body only; a
/// secret in the query string is never consulted. All well-formed requests
/// answer `200 OK`, including unknown or foreign tokens.
///
/// # Errors
///
/// Returns the [`revoke_tokens`] failure: `invalid_client` for failed
/// authentication and a masked `server_error` when storage fails. A rejected
/// `token_type_hint` is rendered as `400 unsupported_token_type`.
pub async fn revoke_handler(
  State(state): State<AppState>,
  headers: HeaderMap,
  Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
  let service = TokenService::new(&state.config.ttl, &state.keys)?;
  let auth = ClientAuthRequest {
    basic_header: headers
      .get(header::AUTHORIZATION)
      .and_then(|value| value.to_str().ok()),
    client_id: form.get("client_id").map(String::as_str),
    body_secret: form
      .get("client_secret")
      .map(|secret| SecretString::from(secret.as_str())),
    assertion_type: form.get("client_assertion_type").map(String::as_str),
    assertion: form.get("client_assertion").map(String::as_str),
    peer_certs: None,
  };
  let mut redis = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let mut stores = RevokeStores {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut redis,
    store: &store,
    service: &service,
  };
  let token_endpoint = super::client_auth::token_endpoint(&state.config.issuer);
  let request_id = headers
    .get(REQUEST_ID_HEADER)
    .and_then(|value| value.to_str().ok())
    .and_then(RequestId::parse);
  let ctx = RevokeContext {
    token_endpoint: &token_endpoint,
    now: state.clock.now(),
    request_id: request_id.as_ref().map(RequestId::as_str),
  };
  let request = RevokeRequest {
    token: form.get("token").map(String::as_str).unwrap_or_default(),
    token_type_hint: form.get("token_type_hint").map(String::as_str),
    auth: &auth,
  };
  let outcome = revoke_tokens(&mut stores, &ctx, &request).await?;
  Ok(outcome_response(outcome))
}

#[cfg(test)]
mod tests;

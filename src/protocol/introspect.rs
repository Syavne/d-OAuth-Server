//! Token introspection (RFC 7662).
//!
//! `POST /introspect` requires client authentication; the public `none`
//! method is not offered (see `metadata::INTROSPECTION_AUTH_METHODS`). The
//! presented token is looked up by keyed hash, and unknown, expired, revoked,
//! and rotated tokens all yield the RFC 7662 §2.2 inactive response
//! (`{"active": false}`, HTTP 200) carrying no further claims.
//!
//! Ownership is an indistinguishability rule: a client may introspect only
//! tokens it owns, and a token owned by another client collapses to the same
//! inactive response as an unknown token. Returning `403` would reveal that
//! the token exists, so it is never used.
//!
//! `iat`/`exp` are reconstructed from the record's live Redis TTL and the
//! configured lifetime (task-30 records persist no timestamps). The RFC 8693
//! `act` claim of a token-exchange token rides a sidecar key written through
//! [`record_act`], mirroring the device-binding sidecar pattern.

#[cfg(test)]
mod tests;

use std::time::Duration;

use axum::{Extension, Form, extract::State, http::HeaderMap, response::Json};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::{
  client_auth::{self, AuthContext, AuthStores, ClientAuthRequest},
  token::{Cnf, TokenService, TokenServiceError},
};
use crate::{
  db::{Client, TokenEndpointAuthMethod, user_repo},
  error::{AppError, OAuthErrorCode},
  state::{AppState, RedisConn},
  store::{Store, StoreError},
  tls::PeerCertificates,
};

/// `token_type_hint` value selecting the refresh-token lookup (RFC 7009).
pub const REFRESH_TOKEN_HINT: &str = "refresh_token";
/// `token_type` reported for an active access token (RFC 6749 §5.1).
pub const BEARER: &str = "Bearer";

/// Form fields accepted at `POST /introspect` (RFC 7662 §2.1).
#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
  /// The token to inspect (required).
  ///
  /// Defaulted so a missing field reaches [`introspect`] and renders the
  /// RFC 7662 §2.3 `invalid_request` (400) instead of an extractor rejection.
  #[serde(default)]
  pub token: String,
  /// Optional hint about the token type.
  #[serde(default)]
  pub token_type_hint: Option<String>,
  /// `client_id` for body/`none` authentication.
  #[serde(default)]
  pub client_id: Option<String>,
  /// `client_secret_post` secret (body only, never the query).
  #[serde(default)]
  pub client_secret: Option<String>,
  /// `client_assertion_type` for `private_key_jwt`.
  #[serde(default)]
  pub client_assertion_type: Option<String>,
  /// `client_assertion` for `private_key_jwt`.
  #[serde(default)]
  pub client_assertion: Option<String>,
}

/// RFC 7662 §2.2 introspection response.
///
/// Inactive responses serialize to exactly `{"active": false}`: every other
/// member is skipped, so no token metadata leaks for a miss or a foreign
/// token.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IntrospectionResponse {
  /// Whether the presented token is currently active.
  pub active: bool,
  /// Space-joined scope, when active.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub scope: Option<String>,
  /// Client the token was issued to, when active.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_id: Option<String>,
  /// Token type (`Bearer` for access tokens).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub token_type: Option<String>,
  /// Expiry (Unix seconds), when active.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub exp: Option<i64>,
  /// Issuance (Unix seconds), when active.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub iat: Option<i64>,
  /// Subject, when the token is user-bound.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sub: Option<String>,
  /// Sender-constraint binding, when the token is bound.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub cnf: Option<Cnf>,
  /// RFC 8693 actor claim, for token-exchange tokens.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub act: Option<serde_json::Value>,
}

impl IntrospectionResponse {
  /// The RFC 7662 §2.2 inactive response: `active: false`, nothing else.
  #[must_use]
  pub fn inactive() -> Self {
    Self {
      active: false,
      scope: None,
      client_id: None,
      token_type: None,
      exp: None,
      iat: None,
      sub: None,
      cnf: None,
      act: None,
    }
  }
}

/// Request-scoped inputs, borrowed from the HTTP layer so the core stays
/// callable without a router.
pub struct IntrospectHttpInputs<'a> {
  /// `token` form field (required).
  pub token: &'a str,
  /// `token_type_hint` form field, when present.
  pub token_type_hint: Option<&'a str>,
  /// `client_id` form field, when present.
  pub client_id: Option<&'a str>,
  /// Raw `Authorization` header, when present.
  pub basic_header: Option<&'a str>,
  /// `client_secret` form field (body only), when present.
  pub body_secret: Option<SecretString>,
  /// `client_assertion_type` form field, when present.
  pub assertion_type: Option<&'a str>,
  /// `client_assertion` form field, when present.
  pub assertion: Option<&'a str>,
  /// Verified peer chain injected by the TLS accept loop, when present.
  pub peer_certs: Option<&'a PeerCertificates>,
}

/// Datastore handles needed by [`introspect`].
pub struct IntrospectStores<'a> {
  /// Postgres pool for client lookup and secret verification.
  pub pool: &'a PgPool,
  /// Versioned PII keys for the encrypted client lookup.
  pub keys: &'a crate::keys::KeyRing,
  /// Redis connection for token records and sidecars.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
}

/// Request-scoped context for [`introspect`].
pub struct IntrospectContext<'a> {
  /// Public issuer URL (no trailing slash).
  pub issuer: &'a str,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
  /// Token service: pepper-retried lookup plus configured lifetimes.
  pub service: &'a TokenService,
}

/// Which store record a raw token resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
  /// An access-token record.
  Access,
  /// A refresh-token record.
  Refresh,
}

/// A located token record flattened for response shaping.
struct Located {
  /// Record key hash.
  hash: String,
  /// Owning client.
  client_id: String,
  /// Space-joined scope.
  scope: String,
  /// Subject (empty for client-credentials tokens).
  subject: String,
  /// Stored `cnf` (empty when unbound).
  cnf: String,
  /// Access or refresh record.
  kind: TokenKind,
}

/// Introspect one token: authenticate the caller, look the token up, enforce
/// ownership, and report the RFC 7662 §2.2 shape.
///
/// # Errors
///
/// Returns `invalid_client` (HTTP 401) when the caller is unauthenticated or
/// uses the public `none` method, `invalid_request` for an empty `token`, and
/// a masked `5xx` when a datastore fails. Unknown, expired, revoked, foreign,
/// and inactive tokens are never errors: they return the inactive response.
pub async fn introspect(
  stores: &mut IntrospectStores<'_>,
  ctx: &IntrospectContext<'_>,
  inputs: &IntrospectHttpInputs<'_>,
) -> Result<IntrospectionResponse, AppError> {
  let raw = inputs.token.trim();
  if raw.is_empty() {
    return Err(AppError::invalid_request("token is required"));
  }
  let client = authenticate(stores, ctx, inputs).await?;

  let prefer_refresh = inputs.token_type_hint == Some(REFRESH_TOKEN_HINT);
  let located = locate(ctx.service, stores.conn, stores.store, raw, prefer_refresh)
    .await
    .map_err(AppError::from)?;
  let Some(located) = located else {
    return Ok(IntrospectionResponse::inactive());
  };
  if located.client_id != client.client_id {
    return Ok(IntrospectionResponse::inactive());
  }
  if located.kind == TokenKind::Refresh
    && crate::store::tokens::tombstone_of(stores.conn, stores.store, &located.hash)
      .await
      .map_err(AppError::from)?
      .is_some()
  {
    return Ok(IntrospectionResponse::inactive());
  }
  // Use-time disabled-user re-check: a token whose non-empty subject resolves
  // to a disabled user reports the same inactive shape as an unknown token.
  // Unmapped subjects (client-credentials empties, synthetic principals) stay
  // live; a datastore failure propagates as an error, never as active.
  if !located.subject.trim().is_empty()
    && matches!(
      user_repo::subject_account_status(stores.pool, stores.keys, &located.subject).await?,
      user_repo::SubjectAccountStatus::Disabled
    )
  {
    return Ok(IntrospectionResponse::inactive());
  }
  active_response(stores, ctx, located).await
}

/// Authenticate the introspection caller, rejecting the public `none` method.
///
/// RFC 7662 §2.3 requires HTTP 401 for invalid client credentials, so every
/// `invalid_client` failure is re-mapped to the Basic challenge status.
async fn authenticate(
  stores: &mut IntrospectStores<'_>,
  ctx: &IntrospectContext<'_>,
  inputs: &IntrospectHttpInputs<'_>,
) -> Result<Client, AppError> {
  let endpoint = client_auth::token_endpoint(ctx.issuer);
  let now = OffsetDateTime::from_unix_timestamp(ctx.now_unix).unwrap_or(OffsetDateTime::UNIX_EPOCH);
  let request = ClientAuthRequest {
    basic_header: inputs.basic_header,
    client_id: inputs.client_id,
    body_secret: inputs.body_secret.clone(),
    assertion_type: inputs.assertion_type,
    assertion: inputs.assertion,
    peer_certs: inputs.peer_certs,
  };
  let mut auth_stores = AuthStores {
    pool: stores.pool,
    keys: stores.keys,
    conn: &mut *stores.conn,
    store: stores.store,
  };
  let auth_ctx = AuthContext {
    token_endpoint: &endpoint,
    now,
  };
  let authenticated = client_auth::authenticate_client(&mut auth_stores, &auth_ctx, &request)
    .await
    .map_err(map_auth_error)?;
  if authenticated.method == TokenEndpointAuthMethod::None {
    return Err(AppError::invalid_client_basic());
  }
  Ok(authenticated.client)
}

/// Map a client-authentication failure onto RFC 7662's HTTP 401.
fn map_auth_error(error: AppError) -> AppError {
  if error.code() == OAuthErrorCode::InvalidClient {
    AppError::invalid_client_basic()
  } else {
    error
  }
}

/// Locate a raw token as an access or refresh record, honoring the hint only
/// as an ordering preference (RFC 7662 §2.1: a miss under the hint must fall
/// back to the other type).
async fn locate(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  raw: &str,
  prefer_refresh: bool,
) -> Result<Option<Located>, TokenServiceError> {
  let order = if prefer_refresh {
    [TokenKind::Refresh, TokenKind::Access]
  } else {
    [TokenKind::Access, TokenKind::Refresh]
  };
  for kind in order {
    let found = match kind {
      TokenKind::Access => service
        .find_access(conn, store, raw)
        .await?
        .map(|found| Located {
          hash: found.hash,
          client_id: found.record.client_id,
          scope: found.record.scope,
          subject: found.record.subject,
          cnf: found.record.cnf,
          kind: TokenKind::Access,
        }),
      TokenKind::Refresh => service
        .find_refresh(conn, store, raw)
        .await?
        .map(|found| Located {
          hash: found.hash,
          client_id: found.record.client_id,
          scope: found.record.scope,
          subject: found.record.subject,
          cnf: found.record.cnf,
          kind: TokenKind::Refresh,
        }),
    };
    if let Some(located) = found {
      return Ok(Some(located));
    }
  }
  Ok(None)
}

/// Shape the active response, deriving the validity window and reading any
/// actor claim.
async fn active_response(
  stores: &mut IntrospectStores<'_>,
  ctx: &IntrospectContext<'_>,
  located: Located,
) -> Result<IntrospectionResponse, AppError> {
  let (key, ttl, token_type) = match located.kind {
    TokenKind::Access => (
      stores.store.access_key(&located.hash),
      ctx.service.access_ttl(),
      Some(BEARER.to_owned()),
    ),
    TokenKind::Refresh => (
      stores.store.refresh_key(&located.hash),
      ctx.service.refresh_ttl(),
      None,
    ),
  };
  let (iat, exp) = token_window(stores.conn, &key, ttl, ctx.now_unix).await?;
  let act = if located.kind == TokenKind::Access {
    read_act(stores.conn, stores.store, &located.hash).await?
  } else {
    None
  };
  let cnf = Cnf::parse_storage(&located.cnf).map_err(AppError::from)?;
  Ok(IntrospectionResponse {
    active: true,
    scope: Some(located.scope),
    client_id: Some(located.client_id),
    token_type,
    exp: Some(exp),
    iat: Some(iat),
    sub: (!located.subject.is_empty()).then_some(located.subject),
    cnf: cnf.is_bound().then_some(cnf),
    act,
  })
}

/// Reconstruct `(iat, exp)` from the record's remaining Redis TTL and its
/// configured lifetime.
async fn token_window(
  conn: &mut RedisConn,
  key: &str,
  total: Duration,
  now_unix: i64,
) -> Result<(i64, i64), AppError> {
  let pttl: i64 = redis::cmd("PTTL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  let total_secs = i64::try_from(total.as_secs()).unwrap_or(i64::MAX);
  // -2 (record vanished) and -1 (no expiry) both fall back to the full
  // configured lifetime; the record was already found, so either is a race
  // or a misconfigured key, never a client-visible error.
  let remaining = if pttl < 0 {
    total_secs
  } else {
    pttl.saturating_add(999) / 1000
  };
  let exp = now_unix.saturating_add(remaining);
  Ok((exp.saturating_sub(total_secs), exp))
}

/// Sidecar key holding the RFC 8693 `act` JSON for an access-token hash.
///
/// Derived from the access-record key, so it shares the `{state}` hash slot
/// and is set with the token's lifetime by [`record_act`].
#[must_use]
pub fn act_key(store: &Store, access_hash: &str) -> String {
  format!("{}:act", store.access_key(access_hash))
}

/// Persist the `act` claim for a token-exchange access token.
///
/// The token-exchange grant (RFC 8693) calls this right after minting so
/// [`introspect`] can report the delegation chain. `ttl` should be the access
/// token's remaining lifetime.
///
/// # Errors
///
/// Returns a masked `5xx` when serialization or the Redis write fails.
pub async fn record_act(
  conn: &mut RedisConn,
  store: &Store,
  access_hash: &str,
  act: &serde_json::Value,
  ttl: Duration,
) -> Result<(), AppError> {
  let json = serde_json::to_string(act).map_err(AppError::internal)?;
  redis::cmd("SET")
    .arg(act_key(store, access_hash))
    .arg(json)
    .arg("PX")
    .arg(ttl.as_millis() as u64)
    .query_async::<()>(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

/// Read the `act` claim stored by [`record_act`]; `Ok(None)` when absent.
///
/// A malformed sidecar is a server defect, never a client error.
///
/// # Errors
///
/// Returns a masked `5xx` when Redis fails or the stored JSON is malformed.
pub async fn read_act(
  conn: &mut RedisConn,
  store: &Store,
  access_hash: &str,
) -> Result<Option<serde_json::Value>, AppError> {
  let raw: Option<String> = redis::cmd("GET")
    .arg(act_key(store, access_hash))
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  raw
    .map(|json| serde_json::from_str(&json).map_err(|_| AppError::server_error()))
    .transpose()
}

/// Axum handler for `POST /introspect` (wired by task 40).
///
/// Thin glue: extracts the form, auth headers, and injected peer chain, builds
/// the token service, then delegates to [`introspect`].
pub async fn handler(
  State(state): State<AppState>,
  peer_certs: Option<Extension<PeerCertificates>>,
  headers: HeaderMap,
  Form(form): Form<IntrospectForm>,
) -> Result<Json<IntrospectionResponse>, AppError> {
  let basic_header = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok());
  let service = TokenService::new(&state.config.ttl, &state.keys)?;
  let store = Store::from_config(&state.config.redis);
  let mut conn = state.redis.clone();
  let mut stores = IntrospectStores {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut conn,
    store: &store,
  };
  let ctx = IntrospectContext {
    issuer: &state.config.issuer,
    now_unix: state.clock.now().unix_timestamp(),
    service: &service,
  };
  let inputs = IntrospectHttpInputs {
    token: form.token.as_str(),
    token_type_hint: form.token_type_hint.as_deref(),
    client_id: form.client_id.as_deref(),
    basic_header,
    body_secret: form.client_secret.map(SecretString::from),
    assertion_type: form.client_assertion_type.as_deref(),
    assertion: form.client_assertion.as_deref(),
    peer_certs: peer_certs.as_deref(),
  };
  let response = introspect(&mut stores, &ctx, &inputs).await?;
  Ok(Json(response))
}

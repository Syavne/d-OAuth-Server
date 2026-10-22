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

use axum::{Extension, extract::RawForm, extract::State, http::HeaderMap};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;
use time::OffsetDateTime;

use super::{
  client_auth::{self, AuthContext, AuthStores, ClientAuthRequest},
  token::{Cnf, TokenService, TokenServiceError},
};
use crate::{
  db::{Client, TokenEndpointAuthMethod, user_repo},
  error::{AppError, OAuthErrorCode},
  jose::jwt_access::{JwtAccessSigner, is_jwt_shape, jti_hash, marker_live_strict, subject_active},
  state::{AppState, RedisConn},
  store::{Store, StoreError},
  tls::PeerCertificates,
};

/// `token_type_hint` value selecting the refresh-token lookup (RFC 7009).
pub const REFRESH_TOKEN_HINT: &str = "refresh_token";
/// `token_type` reported for an active access token (RFC 6749 §5.1).
pub const BEARER: &str = "Bearer";
/// `token_type` reported for a DPoP-bound access token (RFC 9449 §6.2).
pub const DPOP: &str = "DPoP";

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

impl IntrospectForm {
  /// Fields the extractor recognizes: a repeat of any of these is the
  /// extractor's 400. Unknown fields (including a repeated `resource`) are
  /// silently absorbed, as `serde_urlencoded` absorbed them.
  const KNOWN_FIELDS: [&str; 6] = [
    "token",
    "token_type_hint",
    "client_id",
    "client_secret",
    "client_assertion_type",
    "client_assertion",
  ];

  /// Build the form from a strict single-valued map (the `Bytes` extractor
  /// replacement for `Form<IntrospectForm>`). A missing `token` defaults to
  /// `""` so the core renders the RFC 7662 §2.3 `invalid_request`, exactly
  /// as the derived `Default` did.
  fn from_map(map: &std::collections::HashMap<String, String>) -> Self {
    Self {
      token: map.get("token").cloned().unwrap_or_default(),
      token_type_hint: map.get("token_type_hint").cloned(),
      client_id: map.get("client_id").cloned(),
      client_secret: map.get("client_secret").cloned(),
      client_assertion_type: map.get("client_assertion_type").cloned(),
      client_assertion: map.get("client_assertion").cloned(),
    }
  }
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
  /// Resource audiences bound to the token (RFC 8707), when non-empty.
  ///
  /// RFC 7662 §2.2 documents `aud` as a string, but this server follows the
  /// RFC 9068 §2.2 array shape: the exact stored set is emitted as a JSON
  /// array, including for a single audience. An empty set omits the member
  /// entirely, and an inactive response never carries it.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub aud: Option<Vec<String>>,
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
      aud: None,
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
  /// Validated, sorted, deduped `resource` values from the repeated form
  /// parameter.
  ///
  /// This is a LOCAL EXTENSION to RFC 7662: the RFC defines no `resource`
  /// parameter for introspection. When non-empty, the located token's `aud`
  /// must include every requested member (see [`audience_includes`]) or the
  /// response collapses to the inactive shape. An empty slice keeps
  /// introspection audience-agnostic, exactly as RFC 7662 specifies.
  pub resource: &'a [String],
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
  /// CIMD resolution settings for a registration-free fallback; `None` when
  /// `config.cimd_enabled` is off. Only `private_key_jwt` documents may
  /// introspect (RFC 7662 §2.3): a `none` principal is still rejected in
  /// [`authenticate`].
  pub cimd: Option<crate::protocol::cimd::CimdSettings<'a>>,
  /// Token service: pepper-retried lookup plus configured lifetimes.
  pub service: &'a TokenService,
  /// AS access-token signer for the JWT path, built per request from the
  /// config (rotation takes effect immediately). `None` covers both the
  /// feature switch off and a missing key: a JWT-shaped token then
  /// introspects inactive, never an error.
  pub jwt_signer: Option<&'a JwtAccessSigner>,
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
  /// Resource audiences bound to the record (RFC 8707).
  aud: Vec<String>,
  /// Access or refresh record.
  kind: TokenKind,
}

/// Introspect one token: authenticate the caller, route by shape, enforce
/// ownership and liveness, and report the RFC 7662 §2.2 shape.
///
/// A JWT-shaped token (`<b64url>.<b64url>.<b64url>`) takes the JWT path
/// ([`introspect_jwt`]: RFC 9068 §4 allowlist verification plus the same
/// request-`resource` filter as the opaque path); anything else takes the
/// opaque record lookup. `token_type_hint` (RFC 7662 §2.1) only reorders the
/// opaque lookup and never changes the JWT verdict.
///
/// # Errors
///
/// Returns `invalid_client` (HTTP 401) when the caller is unauthenticated or
/// uses the public `none` method, `invalid_request` for an empty `token`, and
/// a masked `5xx` when a datastore fails. Unknown, expired, revoked, foreign,
/// and inactive tokens are never errors: they return the inactive response.
/// A backend outage is never masked as `active: false` (that would silently
/// revoke); it propagates as the 503.
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

  if is_jwt_shape(raw) {
    return introspect_jwt(stores, ctx, inputs, &client, raw).await;
  }
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
  // LOCAL EXTENSION to RFC 7662 (which defines no `resource` parameter): a
  // requested audience set asks whether the token is bound to every member.
  // A pinned superset stays active; a missing member is indistinguishable
  // from an unknown token, so it collapses to the §2.2 inactive shape rather
  // than an error.
  if !inputs.resource.is_empty() && !audience_includes(&located.aud, inputs.resource) {
    return Ok(IntrospectionResponse::inactive());
  }
  active_response(stores, ctx, located).await
}

/// Whether `bound` includes every member of `requested`.
///
/// This is set INCLUSION, not equality, so a token pinned to a superset
/// satisfies a narrower request (unlike
/// [`crate::protocol::params::audience_binds`]). Members are SHA-256 hashed
/// and compared through [`subtle::ConstantTimeEq`]; the scan never exits
/// early on the data and accumulates a [`subtle::Choice`] per requested
/// member. Cardinality is public metadata for RFC 8707 audiences, so the
/// empty-set gating is not secret-dependent.
fn audience_includes(bound: &[String], requested: &[String]) -> bool {
  let mut included = subtle::Choice::from(1u8);
  for wanted in requested {
    let wanted = Sha256::digest(wanted.as_bytes());
    let mut found = subtle::Choice::from(0u8);
    for candidate in bound {
      let candidate = Sha256::digest(candidate.as_bytes());
      found |= candidate.as_slice().ct_eq(wanted.as_slice());
    }
    included &= found;
  }
  bool::from(included)
}

/// Introspect a JWT-shaped access token (RFC 9068 §4 allowlist model).
///
/// Checks, in order: the signer is present (the feature switch off or no key
/// configured renders inactive, never an error and never a 4xx); signature
/// plus `iss`/`exp` verify; the verified `client_id` equals the caller
/// (indistinguishable inactive otherwise, as RFC 7662 §2.2 requires);
/// liveness holds under the strict rule (allowlist marker exists AND its
/// `jwt:<jti-hash>` member is still in the marker's own grant set, plus the
/// disabled-subject re-check); the optional request `resource` set is
/// contained in the `aud` claim (the same [`audience_includes`] filter as the
/// opaque path — a LOCAL EXTENSION to RFC 7662, which defines no `resource`
/// parameter).
///
/// The response is shaped from the claims: `token_type: Bearer` (RFC 6749
/// §5.1), `aud` in the RFC 9068 §2.2 array form, `exp`/`iat` straight from the
/// claims. JWTs carry no stored PTTL, so no `token_window` read applies here;
/// likewise there is no `act` sidecar on this path (an exchanged JWT carries
/// its actor inline in the `act` claim). `token_type_hint` (RFC 7009 §2.1
/// names the revocation hints; RFC 7662 §2.1 the introspection hint) is
/// ignored: it only reorders the opaque lookup.
///
/// Every verification or liveness miss collapses to the inactive response. A
/// Redis/Postgres outage propagates as the masked 503, never `active: false`
/// (that would be a silent revocation) and never a 500 or panic.
async fn introspect_jwt(
  stores: &mut IntrospectStores<'_>,
  ctx: &IntrospectContext<'_>,
  inputs: &IntrospectHttpInputs<'_>,
  client: &Client,
  raw: &str,
) -> Result<IntrospectionResponse, AppError> {
  let signer = match ctx.jwt_signer {
    Some(signer) => signer,
    None => return Ok(IntrospectionResponse::inactive()),
  };
  // `verify` is signature plus `iss`/`exp` only (store-free, so it cannot
  // fail with a backend error): `aud` containment runs through
  // `audience_includes` below for exact parity with the opaque path.
  let verified = match signer.verify(raw, None) {
    Ok(verified) => verified,
    Err(_) => return Ok(IntrospectionResponse::inactive()),
  };
  let claims = verified.claims;
  if claims.client_id != client.client_id {
    return Ok(IntrospectionResponse::inactive());
  }
  let live = marker_live_strict(stores.conn, stores.store, &jti_hash(&claims.jti))
    .await
    .map_err(|_| AppError::temporarily_unavailable())?;
  if !live {
    return Ok(IntrospectionResponse::inactive());
  }
  let subject_live = subject_active(stores.pool, stores.keys, &claims.sub)
    .await
    .map_err(|_| AppError::temporarily_unavailable())?;
  if !subject_live {
    return Ok(IntrospectionResponse::inactive());
  }
  if !inputs.resource.is_empty() && !audience_includes(&claims.aud, inputs.resource) {
    return Ok(IntrospectionResponse::inactive());
  }
  let token_type = if claims.cnf.as_ref().is_some_and(|cnf| cnf.jkt.is_some()) {
    DPOP
  } else {
    BEARER
  };
  Ok(IntrospectionResponse {
    active: true,
    scope: Some(claims.scope),
    client_id: Some(claims.client_id),
    token_type: Some(token_type.to_owned()),
    exp: Some(claims.exp),
    iat: Some(claims.iat),
    sub: (!claims.sub.is_empty()).then_some(claims.sub),
    cnf: claims.cnf,
    act: claims.act.map(|act| serde_json::json!({"sub": act.sub})),
    aud: (!claims.aud.is_empty()).then_some(claims.aud),
  })
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
    cimd: ctx.cimd,
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
          aud: found.record.aud,
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
          aud: found.record.aud,
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
  let (key, ttl) = match located.kind {
    TokenKind::Access => (
      stores.store.access_key(&located.hash),
      ctx.service.access_ttl(),
    ),
    TokenKind::Refresh => (
      stores.store.refresh_key(&located.hash),
      ctx.service.refresh_ttl(),
    ),
  };
  let (iat, exp) = token_window(stores.conn, &key, ttl, ctx.now_unix).await?;
  let act = if located.kind == TokenKind::Access {
    read_act(stores.conn, stores.store, &located.hash).await?
  } else {
    None
  };
  let cnf = Cnf::parse_storage(&located.cnf).map_err(AppError::from)?;
  let token_type = match located.kind {
    TokenKind::Access if cnf.jkt.is_some() => Some(DPOP.to_owned()),
    TokenKind::Access => Some(BEARER.to_owned()),
    TokenKind::Refresh => None,
  };
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
    aud: (!located.aud.is_empty()).then_some(located.aud),
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
/// Thin glue: `RawForm` + a manual parse replaces `Form<IntrospectForm>`
/// (the extractor consumed the raw body, hiding repeats), then builds the
/// token service and delegates to [`introspect`]. `RawForm` rejects a wrong
/// content type with 415 before buffering the body; the explicit exact-MIME
/// gate below is the second check for the prefix-match case
/// (`application/x-www-form-urlencodedevil`). A malformed (non-UTF-8) body
/// is 400 plain text (deliberately stricter than the old `Form`, which
/// lossily accepted raw non-UTF-8 bytes); a repeated known field is JSON
/// `invalid_request` (the old `Form` returned 422 `Failed to deserialize
/// form body`, so the new JSON 400 is the intended contract, not parity).
/// A present `resource` indicator (RFC 8707) validates fail-closed
/// (`invalid_target`) before any lookup runs.
///
/// RFC 7662 defines no `resource` parameter. This endpoint accepts it as a
/// LOCAL EXTENSION: the validated set is handed to [`introspect`], which
/// reports a token inactive unless its `aud` includes every requested value.
/// `revoke` and the token-exchange subject-token lookup stay
/// audience-agnostic.
pub async fn handler(
  State(state): State<AppState>,
  peer_certs: Option<Extension<PeerCertificates>>,
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
  if let Err(reject) = crate::protocol::params::require_form_content_type(&headers) {
    return reject.into_response();
  }
  let pairs = match crate::protocol::params::form_pairs(&body) {
    Ok(pairs) => pairs,
    Err(reject) => return reject.into_response(),
  };
  if crate::protocol::params::has_duplicate_field(&pairs, &IntrospectForm::KNOWN_FIELDS) {
    return AppError::invalid_request("the request body includes a parameter more than once")
      .into_response();
  }
  let map = crate::protocol::params::single_valued_map(&pairs);
  let form = IntrospectForm::from_map(&map);
  let resources =
    crate::protocol::params::values_of(&pairs, crate::protocol::params::RESOURCE_PARAM);
  let resources = match crate::protocol::params::validate_resources(
    &state.pool,
    state.config.resource_indicators_enabled,
    &resources,
  )
  .await
  {
    Ok(resources) => resources,
    Err(error) => return error.into_response(),
  };
  let basic_header = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok());
  let service = match TokenService::new(&state.config.ttl, &state.keys) {
    Ok(service) => service,
    Err(error) => return AppError::from(error).into_response(),
  };
  let store = Store::from_config(&state.config.redis);
  let mut conn = state.redis.clone();
  let mut stores = IntrospectStores {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut conn,
    store: &store,
  };
  // The signer is built only for introspection when the operator switch is
  // on; a missing key (or a disabled switch) leaves a JWT-shaped token
  // inactive, never an error.
  let jwt_signer = if state.config.jwt_access_tokens_enabled {
    JwtAccessSigner::from_config(&state.config).ok()
  } else {
    None
  };
  let ctx = IntrospectContext {
    issuer: &state.config.issuer,
    now_unix: state.clock.now().unix_timestamp(),
    cimd: state
      .config
      .cimd_enabled
      .then(|| crate::protocol::cimd::CimdSettings {
        token_prefix: &state.config.redis.token_key_prefix,
        max_bytes: state.config.cimd_max_bytes,
        timeout: state.config.cimd_fetch_timeout,
        allow_localhost: state.config.allow_localhost_redirect,
      }),
    service: &service,
    jwt_signer: jwt_signer.as_ref(),
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
    resource: &resources,
  };
  let response = match introspect(&mut stores, &ctx, &inputs).await {
    Ok(response) => response,
    Err(error) => return error.into_response(),
  };
  axum::Json(response).into_response()
}

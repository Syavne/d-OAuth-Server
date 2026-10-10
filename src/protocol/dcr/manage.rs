//! RFC 7592 client-configuration management.
//!
//! `GET`/`PUT`/`DELETE /register/{client_id}` (mounted by the router in task
//! 40) require the per-client `registration_access_token` as a Bearer
//! credential, verified against the keyed hash stored on the Postgres client
//! row — never Redis, so management survives a Redis loss.
//!
//! Denial semantics: a missing token, an unknown or deactivated client, or a
//! client with no stored registration hash answers `401 invalid_client` (no
//! existence oracle); a presented token that does not match the addressed
//! client's hash answers `403` (the credential belongs to nobody here —
//! notably a token issued for a different client — so it is forbidden, not
//! unauthenticated). A token from client A can therefore never manage
//! client B.
//!
//! `PUT` is full replacement under the exact registration rules
//! ([`super::RegisterRequest`], same defaults): omitted scalars clear to
//! their defaults and `redirect_uris` replaces the attachment set subject to
//! the DCR redirect policy. The body can never set `client_secret`,
//! `client_secret_expires_at`, or `client_id_issued_at`: those have no body
//! field and the metadata update allowlist cannot touch them. Every
//! successful `PUT` rotates the registration token (the response carries the
//! only copy; the previous token immediately reads as `403`), and mints a
//! fresh client secret when the resulting method is secret-based (public,
//! mTLS, and `private_key_jwt` configurations receive none).
//!
//! `DELETE` deactivates the client and revokes its access and refresh tokens
//! (grant-family cascade); later management with the same token answers
//! `401`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret as _;
use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;

use super::RegisterRequest;
use crate::config::Config;
use crate::crypto::tokens as tokens_crypto;
use crate::db::client_repo::{self, Client};
use crate::db::redirect_repo;
use crate::error::AppError;
use crate::state::{AppState, RedisConn};
use crate::store::Store;

pub mod delete;
pub mod revoke;
pub mod update;

#[cfg(test)]
mod support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_delete;
#[cfg(test)]
mod tests_update;

/// Datastore handles needed by the management operations.
pub struct ManageStores<'a> {
  /// Postgres pool for the client row, catalog reads, and attachments.
  pub pool: &'a PgPool,
  /// Redis connection for token revocation on delete.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
}

/// Request-scoped management inputs.
pub struct ManageContext<'a> {
  /// Validated runtime configuration (issuer, policies, peppers).
  pub config: &'a Config,
  /// Current time for response stamps.
  pub now: OffsetDateTime,
}

/// RFC 7592 §2 management response: metadata plus the effective attached
/// redirect list. `client_secret` and `registration_access_token` appear
/// only in the `PUT` response that rotated them, exactly once each.
#[derive(Debug, Clone, Serialize)]
pub struct ManageResponse {
  /// The managed public client identifier.
  pub client_id: String,
  /// Fresh client secret (a `PUT` that configured a secret method only).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_secret: Option<String>,
  /// When the client secret expires, if it does.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_secret_expires_at: Option<i64>,
  /// Fresh registration token (every successful `PUT` rotates it).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub registration_access_token: Option<String>,
  /// The RFC 7592 management URI for this client.
  pub registration_client_uri: String,
  /// Effective (attached + enabled) redirect URIs.
  pub redirect_uris: Vec<String>,
  /// Registered client name.
  pub client_name: String,
  /// Registered token-endpoint authentication method.
  pub token_endpoint_auth_method: String,
  /// Registered grant types.
  pub grant_types: Vec<String>,
  /// Registered response types.
  pub response_types: Vec<String>,
  /// Registered scope string.
  pub scope: String,
  /// Registered inline JWKS, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jwks: Option<serde_json::Value>,
  /// Registered JWKS URI, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jwks_uri: Option<String>,
  /// Registered mTLS subject DN, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tls_client_auth_subject_dn: Option<String>,
  /// Whether the client registered DPoP-bound access tokens.
  pub dpop_bound_access_tokens: bool,
  /// When the client identifier was issued (unix seconds).
  pub client_id_issued_at: i64,
}

/// Management failures: protocol errors render as-is; a mismatched
/// credential on an existing client renders `403`.
#[derive(Debug)]
pub enum ManageError {
  /// A protocol or dependency failure with its own status.
  Protocol(AppError),
  /// The presented token does not match this client's hash.
  Forbidden,
}

impl From<AppError> for ManageError {
  fn from(error: AppError) -> Self {
    Self::Protocol(error)
  }
}

impl IntoResponse for ManageError {
  fn into_response(self) -> Response {
    match self {
      Self::Protocol(error) => error.into_response(),
      Self::Forbidden => (
        StatusCode::FORBIDDEN,
        Json(ForbiddenBody {
          error: "access_denied",
          error_description: "The registration access token is not authorized for this client.",
        }),
      )
        .into_response(),
    }
  }
}

/// The JSON body for the `403` cross-client denial.
#[derive(Debug, Serialize)]
struct ForbiddenBody {
  /// The wire error code.
  error: &'static str,
  /// A client-safe description.
  error_description: &'static str,
}

/// Authorize one management call: the addressed client must be active with a
/// stored registration hash, and the presented token must verify against it
/// under a retained pepper. Absent credentials and unknown clients are
/// `401`; a mismatched credential on an existing client is `403`.
pub async fn authorize_manage(
  pool: &PgPool,
  config: &Config,
  client_id: &str,
  registration_access_token: Option<&str>,
) -> Result<(), ManageError> {
  let Some(presented) = registration_access_token else {
    return Err(AppError::invalid_client_bearer().into());
  };
  let stored = client_repo::registration_token_hash(pool, client_id)
    .await
    .map_err(AppError::from)?;
  let Some(hash) = stored else {
    return Err(AppError::invalid_client_bearer().into());
  };
  if verify_registration_token(config, &hash, presented) {
    Ok(())
  } else {
    Err(ManageError::Forbidden)
  }
}

/// Verify a presented registration token against its stored keyed hash,
/// retrying retained peppers newest-first. A malformed stored hash denies
/// (fail closed) rather than erroring.
fn verify_registration_token(config: &Config, stored: &str, presented: &str) -> bool {
  let parsed = match tokens_crypto::TokenHash::parse_storage_string(stored) {
    Ok(hash) => hash,
    Err(_) => return false,
  };
  let owned: Vec<(tokens_crypto::KeyId, Vec<u8>)> = config
    .keys
    .peppers_newest_first()
    .map(|(id, secret)| {
      (
        tokens_crypto::KeyId::new(id.as_str()),
        secret.expose_secret().as_bytes().to_vec(),
      )
    })
    .collect();
  let candidates: Vec<(tokens_crypto::KeyId, &[u8])> = owned
    .iter()
    .map(|(id, secret)| (id.clone(), secret.as_slice()))
    .collect();
  tokens_crypto::verify_token_hash(&parsed, &candidates, presented)
}

/// Read a managed client's metadata: authorize, then serialize the row with
/// the effective attached redirect list.
pub async fn read_client(
  stores: &mut ManageStores<'_>,
  ctx: &ManageContext<'_>,
  client_id: &str,
  registration_access_token: Option<&str>,
) -> Result<ManageResponse, ManageError> {
  authorize_manage(
    stores.pool,
    ctx.config,
    client_id,
    registration_access_token,
  )
  .await?;
  let row = active_row(stores.pool, &ctx.config.keys, client_id).await?;
  let effective =
    redirect_repo::effective_for_client(stores.pool, &ctx.config.keys, client_id).await?;
  Ok(respond(
    &row,
    effective.into_iter().map(|uri| uri.uri).collect(),
    None,
    None,
    &ctx.config.issuer,
  ))
}

/// Load an active client row; a client that vanished after authorization
/// reads as `401` (fail closed, no oracle).
async fn active_row(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  client_id: &str,
) -> Result<Client, ManageError> {
  let row = client_repo::find_active_by_client_id(pool, keys, client_id).await?;
  row.ok_or_else(|| AppError::invalid_client_bearer().into())
}

/// Shape a management response from a row, the effective redirect list, and
/// any freshly rotated credentials (shown exactly once).
fn respond(
  row: &Client,
  redirect_uris: Vec<String>,
  client_secret: Option<String>,
  registration_access_token: Option<String>,
  issuer: &str,
) -> ManageResponse {
  ManageResponse {
    client_id: row.client_id.clone(),
    client_secret,
    client_secret_expires_at: row
      .client_secret_expires_at
      .map(OffsetDateTime::unix_timestamp),
    registration_access_token,
    registration_client_uri: format!("{issuer}/register/{}", row.client_id),
    redirect_uris,
    client_name: row.client_name.clone(),
    token_endpoint_auth_method: row.token_endpoint_auth_method.clone(),
    grant_types: row.grant_types.clone(),
    response_types: row.response_types.clone(),
    scope: row.scope.clone(),
    jwks: row.jwks.clone(),
    jwks_uri: row.jwks_uri.clone(),
    tls_client_auth_subject_dn: row.tls_client_auth_subject_dn.clone(),
    dpop_bound_access_tokens: row.dpop_bound_access_tokens,
    client_id_issued_at: row.client_id_issued_at.unix_timestamp(),
  }
}

/// Split management datastores and context out of a borrowed [`AppState`].
fn parts_of<'a>(
  state: &'a AppState,
  conn: &'a mut RedisConn,
  store: &'a Store,
) -> (ManageStores<'a>, ManageContext<'a>) {
  let stores = ManageStores {
    pool: &state.pool,
    conn,
    store,
  };
  let ctx = ManageContext {
    config: &state.config,
    now: state.clock.now(),
  };
  (stores, ctx)
}

/// `GET /register/{client_id}` (mounted by the router in task 40).
///
/// # Errors
///
/// Returns the [`read_client`] failure: `401` for a missing token or an
/// unknown client, `403` for a token issued to a different client.
pub async fn read_handler(
  State(state): State<AppState>,
  Path(client_id): Path<String>,
  headers: HeaderMap,
) -> Result<(StatusCode, Json<ManageResponse>), ManageError> {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let (mut stores, ctx) = parts_of(&state, &mut conn, &store);
  let response = read_client(&mut stores, &ctx, &client_id, super::bearer_token(&headers)).await?;
  Ok((StatusCode::OK, Json(response)))
}

/// `PUT /register/{client_id}` (mounted by the router in task 40).
///
/// # Errors
///
/// Returns the [`update::update_client`] failure: `401`/`403` as in
/// [`read_handler`], `invalid_redirect_uri`/`invalid_client_metadata`
/// (`400`) for bad metadata.
pub async fn update_handler(
  State(state): State<AppState>,
  Path(client_id): Path<String>,
  headers: HeaderMap,
  Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<ManageResponse>), ManageError> {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let (mut stores, ctx) = parts_of(&state, &mut conn, &store);
  let response = update::update_client(
    &mut stores,
    &ctx,
    &client_id,
    super::bearer_token(&headers),
    &request,
  )
  .await?;
  Ok((StatusCode::OK, Json(response)))
}

/// `DELETE /register/{client_id}` (mounted by the router in task 40).
///
/// # Errors
///
/// Returns the [`delete::delete_client`] failure: `401` for a missing token
/// or an unknown client, `403` for a token issued to a different client.
pub async fn delete_handler(
  State(state): State<AppState>,
  Path(client_id): Path<String>,
  headers: HeaderMap,
) -> Result<StatusCode, ManageError> {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let (mut stores, ctx) = parts_of(&state, &mut conn, &store);
  delete::delete_client(&mut stores, &ctx, &client_id, super::bearer_token(&headers)).await?;
  Ok(StatusCode::NO_CONTENT)
}

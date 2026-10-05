//! `oauth_clients` repository.
//!
//! CRUD for registered clients; registration-access-token hashes live on the
//! row so management survives Redis loss. Every query is a parameterized
//! `sqlx` macro call, so the schema is checked at compile time and no SQL is
//! ever interpolated.
//!
//! The metadata projection ([`Client`]) deliberately omits
//! `client_secret_hash` and `registration_access_token_hash`: the secret hash
//! is selected only by [`verify_secret`], and the registration hash only by
//! [`registration_token_hash`]. No repository call returns either hash except
//! where verification requires it.

#[cfg(test)]
mod tests;
mod types;

pub use types::{Client, ClientMetadata, ClientRepoError, NewClient, TokenEndpointAuthMethod};

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::secret::verify_secret as verify_argon2;

/// Insert a new client and return its safe projection.
///
/// # Errors
///
/// Returns a database error on a duplicate `client_id`, a duplicate mTLS
/// identity, or any other constraint violation.
pub async fn insert(pool: &PgPool, new: &NewClient) -> Result<Client, sqlx::Error> {
  sqlx::query_as!(
    Client,
    "INSERT INTO oauth_clients (id, client_id, client_secret_hash, client_secret_expires_at, \
       client_id_issued_at, client_name, grant_types, response_types, scope, \
       token_endpoint_auth_method, jwks, jwks_uri, tls_client_auth_subject_dn, \
       tls_client_auth_cert_thumbprint, request_uris, contacts, software_id, \
       registration_access_token_hash, dpop_bound_access_tokens, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, now(), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
       $18, now(), now()) \
     RETURNING id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       grant_types, response_types, scope, token_endpoint_auth_method, jwks, jwks_uri, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, request_uris, contacts, \
       software_id, dpop_bound_access_tokens, active, created_at, updated_at",
    new.id,
    &new.client_id,
    new.client_secret_hash.as_deref(),
    new.client_secret_expires_at,
    &new.client_name,
    &new.grant_types,
    &new.response_types,
    &new.scope,
    &new.token_endpoint_auth_method,
    new.jwks.clone(),
    new.jwks_uri.as_deref(),
    new.tls_client_auth_subject_dn.as_deref(),
    new.tls_client_auth_cert_thumbprint.as_deref(),
    new.request_uris.clone(),
    new.contacts.clone(),
    new.software_id.as_deref(),
    new.registration_access_token_hash.as_deref(),
    new.dpop_bound_access_tokens,
  )
  .fetch_one(pool)
  .await
}

/// Find an active client by its public `client_id`.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn find_active_by_client_id(
  pool: &PgPool,
  client_id: &str,
) -> Result<Option<Client>, sqlx::Error> {
  sqlx::query_as!(
    Client,
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       grant_types, response_types, scope, token_endpoint_auth_method, jwks, jwks_uri, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, request_uris, contacts, \
       software_id, dpop_bound_access_tokens, active, created_at, updated_at \
     FROM oauth_clients WHERE client_id = $1 AND active = true",
    client_id,
  )
  .fetch_optional(pool)
  .await
}

/// Find a client by its surrogate id, active or not.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Client>, sqlx::Error> {
  sqlx::query_as!(
    Client,
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       grant_types, response_types, scope, token_endpoint_auth_method, jwks, jwks_uri, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, request_uris, contacts, \
       software_id, dpop_bound_access_tokens, active, created_at, updated_at \
     FROM oauth_clients WHERE id = $1",
    id,
  )
  .fetch_optional(pool)
  .await
}

/// List clients ordered by issue time, optionally including deactivated ones.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn list(pool: &PgPool, include_inactive: bool) -> Result<Vec<Client>, sqlx::Error> {
  sqlx::query_as!(
    Client,
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       grant_types, response_types, scope, token_endpoint_auth_method, jwks, jwks_uri, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, request_uris, contacts, \
       software_id, dpop_bound_access_tokens, active, created_at, updated_at \
     FROM oauth_clients WHERE ($1 OR active = true) ORDER BY created_at, client_id",
    include_inactive,
  )
  .fetch_all(pool)
  .await
}

/// Full-replace the allowlisted metadata of an active client.
///
/// Never touches identity, secret, issue time, active flag, or registration
/// token. Returns the updated projection, or `None` if no active client has
/// that `client_id`.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn update_metadata(
  pool: &PgPool,
  client_id: &str,
  meta: &ClientMetadata,
) -> Result<Option<Client>, sqlx::Error> {
  sqlx::query_as!(
    Client,
    "UPDATE oauth_clients SET client_name = $2, grant_types = $3, response_types = $4, \
       scope = $5, token_endpoint_auth_method = $6, jwks = $7, jwks_uri = $8, \
       tls_client_auth_subject_dn = $9, tls_client_auth_cert_thumbprint = $10, \
       request_uris = $11, contacts = $12, software_id = $13, dpop_bound_access_tokens = $14, \
       updated_at = now() \
     WHERE client_id = $1 AND active = true \
     RETURNING id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       grant_types, response_types, scope, token_endpoint_auth_method, jwks, jwks_uri, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, request_uris, contacts, \
       software_id, dpop_bound_access_tokens, active, created_at, updated_at",
    client_id,
    &meta.client_name,
    &meta.grant_types,
    &meta.response_types,
    &meta.scope,
    &meta.token_endpoint_auth_method,
    meta.jwks.clone(),
    meta.jwks_uri.as_deref(),
    meta.tls_client_auth_subject_dn.as_deref(),
    meta.tls_client_auth_cert_thumbprint.as_deref(),
    meta.request_uris.clone(),
    meta.contacts.clone(),
    meta.software_id.as_deref(),
    meta.dpop_bound_access_tokens,
  )
  .fetch_optional(pool)
  .await
}

/// Deactivate a client (soft delete). Returns `true` if a live row changed.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn deactivate(pool: &PgPool, client_id: &str) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "UPDATE oauth_clients SET active = false, updated_at = now() \
     WHERE client_id = $1 AND active = true",
    client_id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

/// Replace an active client's secret hash (and optional expiry).
///
/// Returns `true` if a live row changed.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn rotate_secret_hash(
  pool: &PgPool,
  client_id: &str,
  new_hash: &str,
  expires_at: Option<OffsetDateTime>,
) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "UPDATE oauth_clients SET client_secret_hash = $2, client_secret_expires_at = $3, \
       updated_at = now() \
     WHERE client_id = $1 AND active = true",
    client_id,
    new_hash,
    expires_at,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

/// Verify a presented client secret against the stored Argon2id hash.
///
/// Returns `None` when no active client has that `client_id` or the client has
/// no stored secret (a public client cannot be authenticated by secret);
/// otherwise `Some(true)`/`Some(false)` for a match/mismatch.
///
/// # Errors
///
/// Returns [`ClientRepoError::Database`] on a query failure,
/// [`ClientRepoError::Secret`] when the stored PHC string is malformed, and
/// [`ClientRepoError::Task`] if the blocking verifier panics.
pub async fn verify_secret(
  pool: &PgPool,
  client_id: &str,
  secret: &str,
) -> Result<Option<bool>, ClientRepoError> {
  let stored = sqlx::query_scalar!(
    "SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1 AND active = true",
    client_id,
  )
  .fetch_optional(pool)
  .await?
  .flatten();
  let Some(phc) = stored else {
    return Ok(None);
  };
  let secret = secret.to_owned();
  // Argon2id is intentionally CPU-heavy; keep it off the async worker.
  let verified = tokio::task::spawn_blocking(move || verify_argon2(&secret, &phc)).await??;
  Ok(Some(verified))
}

/// Whether `uri` is attached to the client and enabled in the catalog.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn redirect_uri_allowed(
  pool: &PgPool,
  client_id: &str,
  uri: &str,
) -> Result<bool, sqlx::Error> {
  sqlx::query_scalar!(
    "SELECT EXISTS ( \
       SELECT 1 FROM client_redirect_uris AS cru \
       JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
       WHERE cru.client_id = $1 AND ru.enabled = true AND ru.uri = $2) AS \"allowed!\"",
    client_id,
    uri,
  )
  .fetch_one(pool)
  .await
}

/// Whether a single scope token is both registered by the active client and
/// enabled in the catalog.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn scope_allowed(
  pool: &PgPool,
  client_id: &str,
  scope: &str,
) -> Result<bool, sqlx::Error> {
  sqlx::query_scalar!(
    "SELECT EXISTS ( \
       SELECT 1 FROM scopes AS s \
       WHERE s.name = $2 AND s.enabled = true \
         AND EXISTS ( \
           SELECT 1 FROM oauth_clients AS c \
           WHERE c.client_id = $1 AND c.active = true \
             AND $2 = ANY(string_to_array(c.scope, ' ')) \
         ) \
     ) AS \"allowed!\"",
    client_id,
    scope,
  )
  .fetch_one(pool)
  .await
}

/// Fetch the stored RFC 7592 registration-access-token hash for an active
/// client, if one was issued.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn registration_token_hash(
  pool: &PgPool,
  client_id: &str,
) -> Result<Option<String>, sqlx::Error> {
  sqlx::query_scalar!(
    "SELECT registration_access_token_hash FROM oauth_clients \
     WHERE client_id = $1 AND active = true",
    client_id,
  )
  .fetch_optional(pool)
  .await
  .map(Option::flatten)
}

/// Replace an active client's registration-access-token hash (RFC 7592
/// rotation). Returns `true` if a live row changed.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn set_registration_token_hash(
  pool: &PgPool,
  client_id: &str,
  hash: &str,
) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "UPDATE oauth_clients SET registration_access_token_hash = $2, updated_at = now() \
     WHERE client_id = $1 AND active = true",
    client_id,
    hash,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

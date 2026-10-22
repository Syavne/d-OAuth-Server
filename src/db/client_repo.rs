//! `oauth_clients` repository.
//!
//! CRUD for registered clients; registration-access-token hashes live on the
//! row so management survives Redis loss. Every query is a parameterized
//! `sqlx` macro call, so the schema is checked at compile time and no SQL is
//! ever interpolated.
//!
//! PII metadata (`client_name`, `contacts`, `request_uris`, `jwks_uri`,
//! `software_id`, and the two mTLS identities) is sealed into `_enc` bytea
//! columns (AES-256-GCM under the PII key chain) and read back through typed
//! decrypt helpers that fall back to the legacy plaintext only when `_enc`
//! is NULL. Plaintext is written only while `dual_write` holds; the two mTLS
//! identities are always blind-indexed (`_index`, `"{kid}:{hex}"`) for
//! equality checks. Reads never match on decrypted values in SQL.
//!
//! The metadata projection ([`Client`]) deliberately omits
//! `client_secret_hash` and `registration_access_token_hash`: the secret hash
//! is selected only by [`verify_secret`], and the registration hash only by
//! [`registration_token_hash`]. No repository call returns either hash except
//! where verification requires it.

#[cfg(test)]
mod tests;
mod types;

use sqlx::PgPool;
use time::OffsetDateTime;
pub use types::{Client, ClientMetadata, ClientRepoError, NewClient, TokenEndpointAuthMethod};
use uuid::Uuid;

use crate::crypto::field::{
  blind_index_active, blind_index_candidates, open_json, open_text, seal_json, seal_text,
};
use crate::crypto::secret::verify_secret as verify_argon2;
use crate::error::AppError;
use crate::keys::KeyRing;

/// Insert a new client and return its safe projection.
///
/// The seven sealed PII columns are written as ciphertext; their plaintext is
/// written only while `dual_write` holds. Both mTLS identities are checked
/// against the dual predicate before writing because a legacy row with a NULL
/// `_index` would otherwise let a duplicate slip past the partial unique
/// index.
///
/// # Errors
///
/// Returns [`AppError::DuplicateClientIdentity`] on a duplicate subject DN or
/// thumbprint (including a lost INSERT race via `23505`),
/// [`AppError::PiiDecrypt`] when a stored ciphertext fails to open, or a
/// masked error on any other database failure.
pub async fn insert(
  pool: &PgPool,
  keys: &KeyRing,
  dual_write: bool,
  new: &NewClient,
) -> Result<Client, AppError> {
  check_mtls_duplicates(
    pool,
    keys,
    new.tls_client_auth_subject_dn.as_deref(),
    new.tls_client_auth_cert_thumbprint.as_deref(),
    None,
  )
  .await?;
  let sealed = seal_pii(
    keys,
    &SealInput {
      client_name: &new.client_name,
      contacts: new.contacts.as_ref(),
      request_uris: new.request_uris.as_ref(),
      jwks_uri: new.jwks_uri.as_deref(),
      software_id: new.software_id.as_deref(),
      subject_dn: new.tls_client_auth_subject_dn.as_deref(),
      thumbprint: new.tls_client_auth_cert_thumbprint.as_deref(),
    },
  )?;
  let dn_index = new
    .tls_client_auth_subject_dn
    .as_deref()
    .map(|v| blind_index_active(keys, v));
  let thumb_index = new
    .tls_client_auth_cert_thumbprint
    .as_deref()
    .map(|v| blind_index_active(keys, v));
  let name_plain: Option<&str> = if dual_write {
    Some(&new.client_name)
  } else {
    None
  };
  let contacts_plain: Option<serde_json::Value> = if dual_write {
    new.contacts.clone()
  } else {
    None
  };
  let request_uris_plain: Option<serde_json::Value> = if dual_write {
    new.request_uris.clone()
  } else {
    None
  };
  let jwks_uri_plain: Option<&str> = if dual_write {
    new.jwks_uri.as_deref()
  } else {
    None
  };
  let software_plain: Option<&str> = if dual_write {
    new.software_id.as_deref()
  } else {
    None
  };
  let dn_plain: Option<&str> = if dual_write {
    new.tls_client_auth_subject_dn.as_deref()
  } else {
    None
  };
  let thumb_plain: Option<&str> = if dual_write {
    new.tls_client_auth_cert_thumbprint.as_deref()
  } else {
    None
  };
  let row = sqlx::query!(
    "INSERT INTO oauth_clients (id, client_id, client_secret_hash, client_secret_expires_at, \
       client_id_issued_at, client_name, client_name_enc, grant_types, response_types, scope, \
       token_endpoint_auth_method, jwks, jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, \
       tls_client_auth_subject_dn_enc, tls_client_auth_subject_dn_index, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, \
       tls_client_auth_cert_thumbprint_index, request_uris, request_uris_enc, contacts, \
       contacts_enc, software_id, software_id_enc, registration_access_token_hash, \
       dpop_bound_access_tokens, access_token_format, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, now(), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
       $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, now(), now()) \
     RETURNING id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       client_name_enc, grant_types, response_types, scope, token_endpoint_auth_method, jwks, \
       jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, request_uris, \
       request_uris_enc, contacts, contacts_enc, software_id, software_id_enc, \
       dpop_bound_access_tokens, access_token_format, active, created_at, updated_at",
    new.id,
    &new.client_id,
    new.client_secret_hash.as_deref(),
    new.client_secret_expires_at,
    name_plain,
    sealed.name_enc,
    &new.grant_types,
    &new.response_types,
    &new.scope,
    &new.token_endpoint_auth_method,
    new.jwks.clone(),
    jwks_uri_plain,
    sealed.jwks_uri_enc,
    dn_plain,
    sealed.dn_enc,
    dn_index,
    thumb_plain,
    sealed.thumb_enc,
    thumb_index,
    request_uris_plain,
    sealed.request_uris_enc,
    contacts_plain,
    sealed.contacts_enc,
    software_plain,
    sealed.software_enc,
    new.registration_access_token_hash.as_deref(),
    new.dpop_bound_access_tokens,
    &new.access_token_format,
  )
  .fetch_one(pool)
  .await?;
  Ok(Client {
    id: row.id,
    client_id: row.client_id,
    client_secret_expires_at: row.client_secret_expires_at,
    client_id_issued_at: row.client_id_issued_at,
    client_name: decrypt_required_text(keys, row.client_name_enc, row.client_name)?,
    grant_types: row.grant_types,
    response_types: row.response_types,
    scope: row.scope,
    token_endpoint_auth_method: row.token_endpoint_auth_method,
    jwks: row.jwks,
    jwks_uri: decrypt_optional_text(keys, row.jwks_uri_enc, row.jwks_uri)?,
    tls_client_auth_subject_dn: decrypt_optional_text(
      keys,
      row.tls_client_auth_subject_dn_enc,
      row.tls_client_auth_subject_dn,
    )?,
    tls_client_auth_cert_thumbprint: decrypt_optional_text(
      keys,
      row.tls_client_auth_cert_thumbprint_enc,
      row.tls_client_auth_cert_thumbprint,
    )?,
    request_uris: decrypt_optional_json(keys, row.request_uris_enc, row.request_uris)?,
    contacts: decrypt_optional_json(keys, row.contacts_enc, row.contacts)?,
    software_id: decrypt_optional_text(keys, row.software_id_enc, row.software_id)?,
    dpop_bound_access_tokens: row.dpop_bound_access_tokens,
    access_token_format: row.access_token_format,
    active: row.active,
    created_at: row.created_at,
    updated_at: row.updated_at,
  })
}

/// Find an active client by its public `client_id`.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn find_active_by_client_id(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<Option<Client>, AppError> {
  let row = sqlx::query!(
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       client_name_enc, grant_types, response_types, scope, token_endpoint_auth_method, jwks, \
       jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, request_uris, \
       request_uris_enc, contacts, contacts_enc, software_id, software_id_enc, \
       dpop_bound_access_tokens, access_token_format, active, created_at, updated_at \
     FROM oauth_clients WHERE client_id = $1 AND active = true",
    client_id,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      Ok(Client {
        id: row.id,
        client_id: row.client_id,
        client_secret_expires_at: row.client_secret_expires_at,
        client_id_issued_at: row.client_id_issued_at,
        client_name: decrypt_required_text(keys, row.client_name_enc, row.client_name)?,
        grant_types: row.grant_types,
        response_types: row.response_types,
        scope: row.scope,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        jwks: row.jwks,
        jwks_uri: decrypt_optional_text(keys, row.jwks_uri_enc, row.jwks_uri)?,
        tls_client_auth_subject_dn: decrypt_optional_text(
          keys,
          row.tls_client_auth_subject_dn_enc,
          row.tls_client_auth_subject_dn,
        )?,
        tls_client_auth_cert_thumbprint: decrypt_optional_text(
          keys,
          row.tls_client_auth_cert_thumbprint_enc,
          row.tls_client_auth_cert_thumbprint,
        )?,
        request_uris: decrypt_optional_json(keys, row.request_uris_enc, row.request_uris)?,
        contacts: decrypt_optional_json(keys, row.contacts_enc, row.contacts)?,
        software_id: decrypt_optional_text(keys, row.software_id_enc, row.software_id)?,
        dpop_bound_access_tokens: row.dpop_bound_access_tokens,
        access_token_format: row.access_token_format,
        active: row.active,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .transpose()
}

/// Find a client by its surrogate id, active or not.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn find_by_id(
  pool: &PgPool,
  keys: &KeyRing,
  id: Uuid,
) -> Result<Option<Client>, AppError> {
  let row = sqlx::query!(
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       client_name_enc, grant_types, response_types, scope, token_endpoint_auth_method, jwks, \
       jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, request_uris, \
       request_uris_enc, contacts, contacts_enc, software_id, software_id_enc, \
       dpop_bound_access_tokens, access_token_format, active, created_at, updated_at \
     FROM oauth_clients WHERE id = $1",
    id,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      Ok(Client {
        id: row.id,
        client_id: row.client_id,
        client_secret_expires_at: row.client_secret_expires_at,
        client_id_issued_at: row.client_id_issued_at,
        client_name: decrypt_required_text(keys, row.client_name_enc, row.client_name)?,
        grant_types: row.grant_types,
        response_types: row.response_types,
        scope: row.scope,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        jwks: row.jwks,
        jwks_uri: decrypt_optional_text(keys, row.jwks_uri_enc, row.jwks_uri)?,
        tls_client_auth_subject_dn: decrypt_optional_text(
          keys,
          row.tls_client_auth_subject_dn_enc,
          row.tls_client_auth_subject_dn,
        )?,
        tls_client_auth_cert_thumbprint: decrypt_optional_text(
          keys,
          row.tls_client_auth_cert_thumbprint_enc,
          row.tls_client_auth_cert_thumbprint,
        )?,
        request_uris: decrypt_optional_json(keys, row.request_uris_enc, row.request_uris)?,
        contacts: decrypt_optional_json(keys, row.contacts_enc, row.contacts)?,
        software_id: decrypt_optional_text(keys, row.software_id_enc, row.software_id)?,
        dpop_bound_access_tokens: row.dpop_bound_access_tokens,
        access_token_format: row.access_token_format,
        active: row.active,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .transpose()
}

/// List clients ordered by issue time, optionally including deactivated ones.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn list(
  pool: &PgPool,
  keys: &KeyRing,
  include_inactive: bool,
) -> Result<Vec<Client>, AppError> {
  let rows = sqlx::query!(
    "SELECT id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       client_name_enc, grant_types, response_types, scope, token_endpoint_auth_method, jwks, \
       jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, request_uris, \
       request_uris_enc, contacts, contacts_enc, software_id, software_id_enc, \
       dpop_bound_access_tokens, access_token_format, active, created_at, updated_at \
     FROM oauth_clients WHERE ($1 OR active = true) ORDER BY created_at, client_id",
    include_inactive,
  )
  .fetch_all(pool)
  .await?;
  rows
    .into_iter()
    .map(|row| {
      Ok(Client {
        id: row.id,
        client_id: row.client_id,
        client_secret_expires_at: row.client_secret_expires_at,
        client_id_issued_at: row.client_id_issued_at,
        client_name: decrypt_required_text(keys, row.client_name_enc, row.client_name)?,
        grant_types: row.grant_types,
        response_types: row.response_types,
        scope: row.scope,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        jwks: row.jwks,
        jwks_uri: decrypt_optional_text(keys, row.jwks_uri_enc, row.jwks_uri)?,
        tls_client_auth_subject_dn: decrypt_optional_text(
          keys,
          row.tls_client_auth_subject_dn_enc,
          row.tls_client_auth_subject_dn,
        )?,
        tls_client_auth_cert_thumbprint: decrypt_optional_text(
          keys,
          row.tls_client_auth_cert_thumbprint_enc,
          row.tls_client_auth_cert_thumbprint,
        )?,
        request_uris: decrypt_optional_json(keys, row.request_uris_enc, row.request_uris)?,
        contacts: decrypt_optional_json(keys, row.contacts_enc, row.contacts)?,
        software_id: decrypt_optional_text(keys, row.software_id_enc, row.software_id)?,
        dpop_bound_access_tokens: row.dpop_bound_access_tokens,
        access_token_format: row.access_token_format,
        active: row.active,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .collect()
}

/// Full-replace the allowlisted metadata of an active client.
///
/// Never touches identity, secret, issue time, active flag, or registration
/// token. Returns the updated projection, or `None` if no active client has
/// that `client_id`. Both mTLS identity checks exclude the row being updated
/// so a client can rewrite its own unchanged DN/thumbprint.
///
/// # Errors
///
/// Returns [`AppError::DuplicateClientIdentity`] on a duplicate subject DN or
/// thumbprint, [`AppError::PiiDecrypt`] when a stored ciphertext fails to
/// open, or a masked error on any other database failure.
pub async fn update_metadata(
  pool: &PgPool,
  keys: &KeyRing,
  dual_write: bool,
  client_id: &str,
  meta: &ClientMetadata,
) -> Result<Option<Client>, AppError> {
  let current = sqlx::query!(
    "SELECT id FROM oauth_clients WHERE client_id = $1 AND active = true",
    client_id,
  )
  .fetch_optional(pool)
  .await?;
  let Some(current) = current else {
    return Ok(None);
  };
  check_mtls_duplicates(
    pool,
    keys,
    meta.tls_client_auth_subject_dn.as_deref(),
    meta.tls_client_auth_cert_thumbprint.as_deref(),
    Some(current.id),
  )
  .await?;
  let sealed = seal_pii(
    keys,
    &SealInput {
      client_name: &meta.client_name,
      contacts: meta.contacts.as_ref(),
      request_uris: meta.request_uris.as_ref(),
      jwks_uri: meta.jwks_uri.as_deref(),
      software_id: meta.software_id.as_deref(),
      subject_dn: meta.tls_client_auth_subject_dn.as_deref(),
      thumbprint: meta.tls_client_auth_cert_thumbprint.as_deref(),
    },
  )?;
  let dn_index = meta
    .tls_client_auth_subject_dn
    .as_deref()
    .map(|v| blind_index_active(keys, v));
  let thumb_index = meta
    .tls_client_auth_cert_thumbprint
    .as_deref()
    .map(|v| blind_index_active(keys, v));
  let name_plain: Option<&str> = if dual_write {
    Some(&meta.client_name)
  } else {
    None
  };
  let contacts_plain: Option<serde_json::Value> = if dual_write {
    meta.contacts.clone()
  } else {
    None
  };
  let request_uris_plain: Option<serde_json::Value> = if dual_write {
    meta.request_uris.clone()
  } else {
    None
  };
  let jwks_uri_plain: Option<&str> = if dual_write {
    meta.jwks_uri.as_deref()
  } else {
    None
  };
  let software_plain: Option<&str> = if dual_write {
    meta.software_id.as_deref()
  } else {
    None
  };
  let dn_plain: Option<&str> = if dual_write {
    meta.tls_client_auth_subject_dn.as_deref()
  } else {
    None
  };
  let thumb_plain: Option<&str> = if dual_write {
    meta.tls_client_auth_cert_thumbprint.as_deref()
  } else {
    None
  };
  let row = sqlx::query!(
    "UPDATE oauth_clients SET client_name = $2, client_name_enc = $3, grant_types = $4, \
       response_types = $5, scope = $6, token_endpoint_auth_method = $7, jwks = $8, \
       jwks_uri = $9, jwks_uri_enc = $10, tls_client_auth_subject_dn = $11, \
       tls_client_auth_subject_dn_enc = $12, tls_client_auth_subject_dn_index = $13, \
       tls_client_auth_cert_thumbprint = $14, tls_client_auth_cert_thumbprint_enc = $15, \
       tls_client_auth_cert_thumbprint_index = $16, request_uris = $17, request_uris_enc = $18, \
       contacts = $19, contacts_enc = $20, software_id = $21, software_id_enc = $22, \
       dpop_bound_access_tokens = $23, updated_at = now() \
     WHERE id = $1 \
     RETURNING id, client_id, client_secret_expires_at, client_id_issued_at, client_name, \
       client_name_enc, grant_types, response_types, scope, token_endpoint_auth_method, jwks, \
       jwks_uri, jwks_uri_enc, tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_cert_thumbprint, tls_client_auth_cert_thumbprint_enc, request_uris, \
       request_uris_enc, contacts, contacts_enc, software_id, software_id_enc, \
       dpop_bound_access_tokens, access_token_format, active, created_at, updated_at",
    current.id,
    name_plain,
    sealed.name_enc,
    &meta.grant_types,
    &meta.response_types,
    &meta.scope,
    &meta.token_endpoint_auth_method,
    meta.jwks.clone(),
    jwks_uri_plain,
    sealed.jwks_uri_enc,
    dn_plain,
    sealed.dn_enc,
    dn_index,
    thumb_plain,
    sealed.thumb_enc,
    thumb_index,
    request_uris_plain,
    sealed.request_uris_enc,
    contacts_plain,
    sealed.contacts_enc,
    software_plain,
    sealed.software_enc,
    meta.dpop_bound_access_tokens,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      Ok(Client {
        id: row.id,
        client_id: row.client_id,
        client_secret_expires_at: row.client_secret_expires_at,
        client_id_issued_at: row.client_id_issued_at,
        client_name: decrypt_required_text(keys, row.client_name_enc, row.client_name)?,
        grant_types: row.grant_types,
        response_types: row.response_types,
        scope: row.scope,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        jwks: row.jwks,
        jwks_uri: decrypt_optional_text(keys, row.jwks_uri_enc, row.jwks_uri)?,
        tls_client_auth_subject_dn: decrypt_optional_text(
          keys,
          row.tls_client_auth_subject_dn_enc,
          row.tls_client_auth_subject_dn,
        )?,
        tls_client_auth_cert_thumbprint: decrypt_optional_text(
          keys,
          row.tls_client_auth_cert_thumbprint_enc,
          row.tls_client_auth_cert_thumbprint,
        )?,
        request_uris: decrypt_optional_json(keys, row.request_uris_enc, row.request_uris)?,
        contacts: decrypt_optional_json(keys, row.contacts_enc, row.contacts)?,
        software_id: decrypt_optional_text(keys, row.software_id_enc, row.software_id)?,
        dpop_bound_access_tokens: row.dpop_bound_access_tokens,
        access_token_format: row.access_token_format,
        active: row.active,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .transpose()
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

/// Set an active client's access-token format (`opaque` or `jwt`).
///
/// Returns `true` only when the stored value actually changed, so a
/// declarative `config sync` re-run stays a true no-op. The operator CLI is
/// the only caller; dynamic registration always inserts `opaque`.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn set_access_token_format(
  pool: &PgPool,
  client_id: &str,
  format: &str,
) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "UPDATE oauth_clients SET access_token_format = $2, updated_at = now() \
     WHERE client_id = $1 AND active = true AND access_token_format IS DISTINCT FROM $2",
    client_id,
    format,
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
/// The presented URI is matched through its blind-index candidates (one per
/// retained PII key) with a fallback for legacy rows that predate the index:
/// their plaintext `uri` is compared only while `uri_enc` is NULL. Decrypted
/// URIs are never compared in SQL.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn redirect_uri_allowed(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
  uri: &str,
) -> Result<bool, sqlx::Error> {
  let candidates = blind_index_candidates(keys, uri);
  sqlx::query_scalar!(
    "SELECT EXISTS ( \
       SELECT 1 FROM client_redirect_uris AS cru \
       JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
       WHERE cru.client_id = $1 AND ru.enabled = true \
         AND (ru.uri_index = ANY($2) OR (ru.uri_enc IS NULL AND ru.uri = $3))) AS \"allowed!\"",
    client_id,
    &candidates,
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

/// Sealed PII ciphertext for one write.
struct SealedPii {
  name_enc: Vec<u8>,
  contacts_enc: Option<Vec<u8>>,
  request_uris_enc: Option<Vec<u8>>,
  jwks_uri_enc: Option<Vec<u8>>,
  software_enc: Option<Vec<u8>>,
  dn_enc: Option<Vec<u8>>,
  thumb_enc: Option<Vec<u8>>,
}

/// The seven PII plaintext inputs to one seal.
struct SealInput<'a> {
  client_name: &'a str,
  contacts: Option<&'a serde_json::Value>,
  request_uris: Option<&'a serde_json::Value>,
  jwks_uri: Option<&'a str>,
  software_id: Option<&'a str>,
  subject_dn: Option<&'a str>,
  thumbprint: Option<&'a str>,
}

/// Seal the seven PII metadata columns under the active PII key.
fn seal_pii(keys: &KeyRing, input: &SealInput<'_>) -> Result<SealedPii, AppError> {
  Ok(SealedPii {
    name_enc: seal_text(keys, input.client_name).map_err(AppError::from)?,
    contacts_enc: input
      .contacts
      .map(|v| seal_json(keys, v))
      .transpose()
      .map_err(AppError::from)?,
    request_uris_enc: input
      .request_uris
      .map(|v| seal_json(keys, v))
      .transpose()
      .map_err(AppError::from)?,
    jwks_uri_enc: input
      .jwks_uri
      .map(|v| seal_text(keys, v))
      .transpose()
      .map_err(AppError::from)?,
    software_enc: input
      .software_id
      .map(|v| seal_text(keys, v))
      .transpose()
      .map_err(AppError::from)?,
    dn_enc: input
      .subject_dn
      .map(|v| seal_text(keys, v))
      .transpose()
      .map_err(AppError::from)?,
    thumb_enc: input
      .thumbprint
      .map(|v| seal_text(keys, v))
      .transpose()
      .map_err(AppError::from)?,
  })
}

/// Explicit dual-predicate duplicate check for both mTLS identities.
///
/// The partial unique indexes alone cannot catch a duplicate across the
/// encrypt-only pre-backfill window (a legacy row carries a NULL `_index`
/// while a new row carries a non-NULL index), so both predicates run
/// explicitly before every write. `exclude_id` skips the row being updated.
async fn check_mtls_duplicates(
  pool: &PgPool,
  keys: &KeyRing,
  subject_dn: Option<&str>,
  thumbprint: Option<&str>,
  exclude_id: Option<Uuid>,
) -> Result<(), AppError> {
  if let Some(dn) = subject_dn {
    let candidates = blind_index_candidates(keys, dn);
    let exists = match exclude_id {
      Some(id) => {
        sqlx::query_scalar!(
          "SELECT EXISTS(SELECT 1 FROM oauth_clients \
         WHERE (tls_client_auth_subject_dn_index = ANY($1) \
           OR (tls_client_auth_subject_dn IS NOT NULL AND tls_client_auth_subject_dn = $2)) \
           AND id <> $3) AS \"exists!\"",
          &candidates,
          dn,
          id,
        )
        .fetch_one(pool)
        .await?
      }
      None => {
        sqlx::query_scalar!(
          "SELECT EXISTS(SELECT 1 FROM oauth_clients \
         WHERE tls_client_auth_subject_dn_index = ANY($1) \
            OR (tls_client_auth_subject_dn IS NOT NULL AND tls_client_auth_subject_dn = $2)) \
         AS \"exists!\"",
          &candidates,
          dn,
        )
        .fetch_one(pool)
        .await?
      }
    };
    if exists {
      return Err(AppError::DuplicateClientIdentity);
    }
  }
  if let Some(thumb) = thumbprint {
    let candidates = blind_index_candidates(keys, thumb);
    let exists = match exclude_id {
      Some(id) => {
        sqlx::query_scalar!(
          "SELECT EXISTS(SELECT 1 FROM oauth_clients \
         WHERE (tls_client_auth_cert_thumbprint_index = ANY($1) \
           OR (tls_client_auth_cert_thumbprint IS NOT NULL \
             AND tls_client_auth_cert_thumbprint = $2)) \
           AND id <> $3) AS \"exists!\"",
          &candidates,
          thumb,
          id,
        )
        .fetch_one(pool)
        .await?
      }
      None => {
        sqlx::query_scalar!(
          "SELECT EXISTS(SELECT 1 FROM oauth_clients \
         WHERE tls_client_auth_cert_thumbprint_index = ANY($1) \
            OR (tls_client_auth_cert_thumbprint IS NOT NULL \
              AND tls_client_auth_cert_thumbprint = $2)) AS \"exists!\"",
          &candidates,
          thumb,
        )
        .fetch_one(pool)
        .await?
      }
    };
    if exists {
      return Err(AppError::DuplicateClientIdentity);
    }
  }
  Ok(())
}

/// Open a required text field: ciphertext wins, legacy plaintext is the
/// fallback only when `_enc` is NULL, and a row with neither fails closed.
fn decrypt_required_text(
  keys: &KeyRing,
  enc: Option<Vec<u8>>,
  plain: Option<String>,
) -> Result<String, AppError> {
  if let Some(blob) = enc {
    return open_text(keys, &blob).map_err(|_| AppError::PiiDecrypt);
  }
  plain.ok_or(AppError::PiiDecrypt)
}

/// Open an optional text field with the same ciphertext-wins rule.
fn decrypt_optional_text(
  keys: &KeyRing,
  enc: Option<Vec<u8>>,
  plain: Option<String>,
) -> Result<Option<String>, AppError> {
  if let Some(blob) = enc {
    return open_text(keys, &blob)
      .map(Some)
      .map_err(|_| AppError::PiiDecrypt);
  }
  Ok(plain)
}

/// Open an optional JSON field with the same ciphertext-wins rule.
fn decrypt_optional_json(
  keys: &KeyRing,
  enc: Option<Vec<u8>>,
  plain: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, AppError> {
  if let Some(blob) = enc {
    return open_json(keys, &blob)
      .map(Some)
      .map_err(|_| AppError::PiiDecrypt);
  }
  Ok(plain)
}

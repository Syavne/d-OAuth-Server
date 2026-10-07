//! `pii backfill` over `oauth_clients`: seal the seven PII metadata columns.
//!
//! The seven plaintext columns are blanked exactly as listed by the plan:
//! `client_name`, `contacts`, `request_uris`, `jwks_uri`, `software_id`,
//! `tls_client_auth_subject_dn`, and `tls_client_auth_cert_thumbprint`. Only
//! the two mTLS identities carry a blind index, computed over the exact
//! stored string.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::super::context::CliError;
use super::{BackfillReport, malformed, seal_failed};
use crate::crypto::field::{blind_index_active, open_json, open_text, seal_json, seal_text};
use crate::keys::KeyRing;

/// Rows scanned per batch transaction.
const BATCH_SIZE: usize = 100;
/// Advisory-lock key for the `oauth_clients` batches, stable across processes.
const CLIENTS_LOCK: &str = "d_oauth_pii_backfill_clients";

/// Seal every non-null `oauth_clients` PII column, one locked batch at a time
/// (keyset pagination on `id`, never `OFFSET`).
pub(super) async fn backfill_clients(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut BackfillReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(CLIENTS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, client_name, contacts, request_uris, jwks_uri, software_id, \
         tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint, \
         client_name_enc, contacts_enc, request_uris_enc, jwks_uri_enc, software_id_enc, \
         tls_client_auth_subject_dn_enc, tls_client_auth_cert_thumbprint_enc, \
         tls_client_auth_subject_dn_index, tls_client_auth_cert_thumbprint_index \
       FROM oauth_clients \
       WHERE (client_name IS NOT NULL OR contacts IS NOT NULL OR request_uris IS NOT NULL \
         OR jwks_uri IS NOT NULL OR software_id IS NOT NULL \
         OR tls_client_auth_subject_dn IS NOT NULL OR tls_client_auth_cert_thumbprint IS NOT NULL) \
         AND id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(BATCH_SIZE as i64)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
      tx.commit().await?;
      break;
    }
    let fetched = rows.len();
    for row in &rows {
      let id: Uuid = row.try_get("id")?;
      let sealed = seal_client_row(keys, row)?;
      let Some(sealed) = sealed else {
        after = id;
        continue;
      };
      sqlx::query(
        "UPDATE oauth_clients SET client_name_enc = $2, contacts_enc = $3, request_uris_enc = $4, \
           jwks_uri_enc = $5, software_id_enc = $6, tls_client_auth_subject_dn_enc = $7, \
           tls_client_auth_cert_thumbprint_enc = $8, tls_client_auth_subject_dn_index = $9, \
           tls_client_auth_cert_thumbprint_index = $10, client_name = NULL, contacts = NULL, \
           request_uris = NULL, jwks_uri = NULL, software_id = NULL, \
           tls_client_auth_subject_dn = NULL, tls_client_auth_cert_thumbprint = NULL \
         WHERE id = $1",
      )
      .bind(id)
      .bind(sealed.name_enc.as_deref())
      .bind(sealed.contacts_enc.as_deref())
      .bind(sealed.request_uris_enc.as_deref())
      .bind(sealed.jwks_uri_enc.as_deref())
      .bind(sealed.software_enc.as_deref())
      .bind(sealed.dn_enc.as_deref())
      .bind(sealed.thumb_enc.as_deref())
      .bind(sealed.dn_index.as_deref())
      .bind(sealed.thumb_index.as_deref())
      .execute(&mut *tx)
      .await?;
      report.clients_sealed = report.clients_sealed.saturating_add(1);
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// The sealed form of one `oauth_clients` row: fresh ciphertext for every
/// column the row sets (untouched columns keep their stored bytes), plus the
/// two mTLS blind indexes under the exact stored string.
struct SealedClient {
  name_enc: Option<Vec<u8>>,
  contacts_enc: Option<Vec<u8>>,
  request_uris_enc: Option<Vec<u8>>,
  jwks_uri_enc: Option<Vec<u8>>,
  software_enc: Option<Vec<u8>>,
  dn_enc: Option<Vec<u8>>,
  thumb_enc: Option<Vec<u8>>,
  dn_index: Option<String>,
  thumb_index: Option<String>,
}

/// Seal the non-null plaintext columns of one client row, validating any
/// already-stored ciphertext first (`None` when the row sets no plaintext).
fn seal_client_row(
  keys: &KeyRing,
  row: &sqlx::postgres::PgRow,
) -> Result<Option<SealedClient>, CliError> {
  let name: Option<String> = row.try_get("client_name")?;
  let contacts: Option<serde_json::Value> = row.try_get("contacts")?;
  let request_uris: Option<serde_json::Value> = row.try_get("request_uris")?;
  let jwks_uri: Option<String> = row.try_get("jwks_uri")?;
  let software_id: Option<String> = row.try_get("software_id")?;
  let subject_dn: Option<String> = row.try_get("tls_client_auth_subject_dn")?;
  let thumbprint: Option<String> = row.try_get("tls_client_auth_cert_thumbprint")?;
  if name.is_none()
    && contacts.is_none()
    && request_uris.is_none()
    && jwks_uri.is_none()
    && software_id.is_none()
    && subject_dn.is_none()
    && thumbprint.is_none()
  {
    return Ok(None);
  }
  check_text(keys, row, "client_name_enc", name.is_some())?;
  check_json(keys, row, "contacts_enc", contacts.is_some())?;
  check_json(keys, row, "request_uris_enc", request_uris.is_some())?;
  check_text(keys, row, "jwks_uri_enc", jwks_uri.is_some())?;
  check_text(keys, row, "software_id_enc", software_id.is_some())?;
  check_text(
    keys,
    row,
    "tls_client_auth_subject_dn_enc",
    subject_dn.is_some(),
  )?;
  check_text(
    keys,
    row,
    "tls_client_auth_cert_thumbprint_enc",
    thumbprint.is_some(),
  )?;
  let seal_text_value = |value: Option<String>| -> Result<Option<Vec<u8>>, CliError> {
    value
      .map(|plain| seal_text(keys, &plain).map_err(|_| seal_failed()))
      .transpose()
  };
  let seal_json_value = |value: Option<serde_json::Value>| -> Result<Option<Vec<u8>>, CliError> {
    value
      .map(|plain| seal_json(keys, &plain).map_err(|_| seal_failed()))
      .transpose()
  };
  let existing_bytes =
    |column: &str| -> Result<Option<Vec<u8>>, CliError> { Ok(row.try_get(column)?) };
  let existing_index =
    |column: &str| -> Result<Option<String>, CliError> { Ok(row.try_get(column)?) };
  Ok(Some(SealedClient {
    name_enc: or_existing(seal_text_value(name)?, existing_bytes("client_name_enc")?),
    contacts_enc: or_existing(seal_json_value(contacts)?, existing_bytes("contacts_enc")?),
    request_uris_enc: or_existing(
      seal_json_value(request_uris)?,
      existing_bytes("request_uris_enc")?,
    ),
    jwks_uri_enc: or_existing(seal_text_value(jwks_uri)?, existing_bytes("jwks_uri_enc")?),
    software_enc: or_existing(
      seal_text_value(software_id)?,
      existing_bytes("software_id_enc")?,
    ),
    dn_enc: or_existing(
      seal_text_value(subject_dn.clone())?,
      existing_bytes("tls_client_auth_subject_dn_enc")?,
    ),
    thumb_enc: or_existing(
      seal_text_value(thumbprint.clone())?,
      existing_bytes("tls_client_auth_cert_thumbprint_enc")?,
    ),
    dn_index: or_existing(
      subject_dn.map(|value| blind_index_active(keys, &value)),
      existing_index("tls_client_auth_subject_dn_index")?,
    ),
    thumb_index: or_existing(
      thumbprint.map(|value| blind_index_active(keys, &value)),
      existing_index("tls_client_auth_cert_thumbprint_index")?,
    ),
  }))
}

/// When `seal` holds, validate the already-stored text ciphertext still opens.
fn check_text(
  keys: &KeyRing,
  row: &sqlx::postgres::PgRow,
  column: &str,
  seal: bool,
) -> Result<(), CliError> {
  if !seal {
    return Ok(());
  }
  let existing: Option<Vec<u8>> = row.try_get(column)?;
  if let Some(blob) = existing {
    open_text(keys, &blob).map_err(|_| malformed(column))?;
  }
  Ok(())
}

/// When `seal` holds, validate the already-stored JSON ciphertext still opens.
fn check_json(
  keys: &KeyRing,
  row: &sqlx::postgres::PgRow,
  column: &str,
  seal: bool,
) -> Result<(), CliError> {
  if !seal {
    return Ok(());
  }
  let existing: Option<Vec<u8>> = row.try_get(column)?;
  if let Some(blob) = existing {
    open_json::<serde_json::Value>(keys, &blob).map_err(|_| malformed(column))?;
  }
  Ok(())
}

/// Prefer the freshly sealed value, keeping the stored bytes for columns the
/// row leaves untouched.
fn or_existing<T>(sealed: Option<T>, existing: Option<T>) -> Option<T> {
  sealed.or(existing)
}

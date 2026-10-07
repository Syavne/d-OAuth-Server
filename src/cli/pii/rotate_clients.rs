//! `pii rotate` over `oauth_clients`: re-encrypt the seven PII columns.
//!
//! A row is rewritten only when at least one blob names a retired key; both
//! mTLS blind indexes are then recomputed from the opened exact strings under
//! the active key. Plaintext columns are never touched.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::super::context::CliError;
use super::rotate::{BATCH_SIZE, active_kid, blob_kid};
use super::{RotateReport, malformed, seal_failed};
use crate::crypto::field::{blind_index_active, open_json, open_text, seal_json, seal_text};
use crate::keys::KeyRing;

/// Advisory-lock key for the `oauth_clients` batches, stable across processes.
const CLIENTS_LOCK: &str = "d_oauth_pii_rotate_clients";

/// Re-encrypt stale `oauth_clients` PII columns, one locked batch at a time.
pub(super) async fn rotate_clients(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut RotateReport,
) -> Result<(), CliError> {
  let active_kid = active_kid(keys)?;
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(CLIENTS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, client_name_enc, contacts_enc, request_uris_enc, jwks_uri_enc, software_id_enc, \
         tls_client_auth_subject_dn_enc, tls_client_auth_cert_thumbprint_enc \
       FROM oauth_clients \
       WHERE (client_name_enc IS NOT NULL OR contacts_enc IS NOT NULL \
         OR request_uris_enc IS NOT NULL OR jwks_uri_enc IS NOT NULL OR software_id_enc IS NOT NULL \
         OR tls_client_auth_subject_dn_enc IS NOT NULL \
         OR tls_client_auth_cert_thumbprint_enc IS NOT NULL) \
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
      let name = open_text_col(
        keys,
        row.try_get("client_name_enc")?,
        "client_name_enc",
        &active_kid,
      )?;
      let contacts = open_json_col(
        keys,
        row.try_get("contacts_enc")?,
        "contacts_enc",
        &active_kid,
      )?;
      let request_uris = open_json_col(
        keys,
        row.try_get("request_uris_enc")?,
        "request_uris_enc",
        &active_kid,
      )?;
      let jwks = open_text_col(
        keys,
        row.try_get("jwks_uri_enc")?,
        "jwks_uri_enc",
        &active_kid,
      )?;
      let software = open_text_col(
        keys,
        row.try_get("software_id_enc")?,
        "software_id_enc",
        &active_kid,
      )?;
      let subject = open_text_col(
        keys,
        row.try_get("tls_client_auth_subject_dn_enc")?,
        "tls_client_auth_subject_dn_enc",
        &active_kid,
      )?;
      let thumb = open_text_col(
        keys,
        row.try_get("tls_client_auth_cert_thumbprint_enc")?,
        "tls_client_auth_cert_thumbprint_enc",
        &active_kid,
      )?;
      let stale = [name.as_ref(), jwks.as_ref(), software.as_ref()]
        .iter()
        .any(|cell| matches!(cell, Some((_, _, false))))
        || [contacts.as_ref(), request_uris.as_ref()]
          .iter()
          .any(|cell| matches!(cell, Some((_, _, false))))
        || [subject.as_ref(), thumb.as_ref()]
          .iter()
          .any(|cell| matches!(cell, Some((_, _, false))));
      if !stale {
        after = id;
        continue;
      }
      let (name_enc, _) = reseal_text(keys, name)?;
      let contacts_enc = reseal_json(keys, contacts)?;
      let request_uris_enc = reseal_json(keys, request_uris)?;
      let (jwks_enc, _) = reseal_text(keys, jwks)?;
      let (software_enc, _) = reseal_text(keys, software)?;
      let (dn_enc, dn_plain) = reseal_text(keys, subject)?;
      let (thumb_enc, thumb_plain) = reseal_text(keys, thumb)?;
      let dn_index = dn_plain.map(|value| blind_index_active(keys, &value));
      let thumb_index = thumb_plain.map(|value| blind_index_active(keys, &value));
      sqlx::query(
        "UPDATE oauth_clients SET client_name_enc = $2, contacts_enc = $3, request_uris_enc = $4, \
           jwks_uri_enc = $5, software_id_enc = $6, tls_client_auth_subject_dn_enc = $7, \
           tls_client_auth_cert_thumbprint_enc = $8, tls_client_auth_subject_dn_index = $9, \
           tls_client_auth_cert_thumbprint_index = $10 WHERE id = $1",
      )
      .bind(id)
      .bind(name_enc.as_deref())
      .bind(contacts_enc.as_deref())
      .bind(request_uris_enc.as_deref())
      .bind(jwks_enc.as_deref())
      .bind(software_enc.as_deref())
      .bind(dn_enc.as_deref())
      .bind(thumb_enc.as_deref())
      .bind(dn_index.as_deref())
      .bind(thumb_index.as_deref())
      .execute(&mut *tx)
      .await?;
      report.clients_rotated = report.clients_rotated.saturating_add(1);
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// One opened text column: the plaintext plus whether it already names `active`.
fn open_text_col(
  keys: &KeyRing,
  blob: Option<Vec<u8>>,
  column: &'static str,
  active_kid: &str,
) -> Result<Option<(String, Vec<u8>, bool)>, CliError> {
  let Some(blob) = blob else {
    return Ok(None);
  };
  let is_current = blob_kid(&blob).ok_or_else(|| malformed(column))? == active_kid;
  let plain = open_text(keys, &blob).map_err(|_| malformed(column))?;
  Ok(Some((plain, blob, is_current)))
}

/// One opened JSON column: the value plus whether it already names `active`.
fn open_json_col(
  keys: &KeyRing,
  blob: Option<Vec<u8>>,
  column: &'static str,
  active_kid: &str,
) -> Result<Option<(serde_json::Value, Vec<u8>, bool)>, CliError> {
  let Some(blob) = blob else {
    return Ok(None);
  };
  let is_current = blob_kid(&blob).ok_or_else(|| malformed(column))? == active_kid;
  let plain = open_json::<serde_json::Value>(keys, &blob).map_err(|_| malformed(column))?;
  Ok(Some((plain, blob, is_current)))
}

/// Re-seal a text value only when stale, otherwise keep the stored bytes.
fn reseal_text(
  keys: &KeyRing,
  opened: Option<(String, Vec<u8>, bool)>,
) -> Result<(Option<Vec<u8>>, Option<String>), CliError> {
  opened
    .map(|(plain, blob, current)| {
      if current {
        Ok((Some(blob), Some(plain)))
      } else {
        seal_text(keys, &plain)
          .map_err(|_| seal_failed())
          .map(|sealed| (Some(sealed), Some(plain)))
      }
    })
    .transpose()
    .map(|option| option.unwrap_or((None, None)))
}

/// Re-seal a JSON value only when stale, otherwise keep the stored bytes.
fn reseal_json(
  keys: &KeyRing,
  opened: Option<(serde_json::Value, Vec<u8>, bool)>,
) -> Result<Option<Vec<u8>>, CliError> {
  opened
    .map(|(value, blob, current)| {
      if current {
        Ok(Some(blob))
      } else {
        seal_json(keys, &value).map_err(|_| seal_failed()).map(Some)
      }
    })
    .transpose()
    .map(Option::flatten)
}

//! `pii rotate`: re-encrypt sealed PII under the active PII key.
//!
//! The field AEAD key derives from the master PII key, so ciphertext is NOT
//! key-stable: retiring the old key without re-encryption would make reads
//! fail. The blind index is key-dependent too, so every `_index` is recomputed
//! under the active key. Run under a write freeze with the previous key
//! retained; retire it only after this command succeeds everywhere.
//!
//! Each table is scanned in bounded batches. Every batch runs in its own
//! transaction holding `pg_advisory_xact_lock` on the connection that owns
//! that transaction, so a unique-index collision rolls the whole batch back
//! instead of partially overwriting. Rows whose blob already names the active
//! key are skipped, making a re-run a no-op. Plaintext columns are never
//! touched and only counts leave this module.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::super::context::{CliError, audit};
use super::rotate_clients::rotate_clients;
use super::{RotateReport, malformed, seal_failed};
use crate::crypto::field::{blind_index_active, open_text, seal_text};
use crate::db::user_repo::normalize_email;
use crate::keys::KeyRing;

/// Rows scanned per batch transaction.
pub(super) const BATCH_SIZE: usize = 100;
/// Field-blob format version (mirrors the codec; unparseable blobs abort).
const FIELD_BLOB_VERSION: u8 = 1;
/// Advisory-lock key for the `users` batches, stable across processes.
const USERS_LOCK: &str = "d_oauth_pii_rotate_users";
/// Advisory-lock key for the `redirect_uris` batches, stable across processes.
const REDIRECTS_LOCK: &str = "d_oauth_pii_rotate_redirects";

/// Re-encrypt every stale PII blob under the active key, re-indexing as it goes.
///
/// A blob that no longer opens (previous key already retired) aborts the batch
/// fail-closed instead of writing a wrong value; a unique-index collision on
/// the recomputed index rolls the batch back the same way.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active PII key is configured or a
/// stored blob cannot be opened, and [`CliError::Database`] for PostgreSQL
/// failures (including unique-index collisions).
pub(super) async fn rotate_with(pool: &PgPool, keys: &KeyRing) -> Result<RotateReport, CliError> {
  let mut report = RotateReport::default();
  rotate_users(pool, keys, &mut report).await?;
  rotate_clients(pool, keys, &mut report).await?;
  rotate_redirects(pool, keys, &mut report).await?;
  audit("pii.rotate", "pii");
  Ok(report)
}

/// The active PII key id, fail-closed when unconfigured.
pub(super) fn active_kid(keys: &KeyRing) -> Result<String, CliError> {
  keys
    .active_pii_key()
    .map(|(id, _)| id.as_str().to_owned())
    .ok_or_else(|| CliError::Crypto("no active PII encryption key configured".to_owned()))
}

/// The key id named inside a field blob (`None` when the header is corrupt).
pub(super) fn blob_kid(blob: &[u8]) -> Option<&str> {
  if blob.len() < 2 || blob[0] != FIELD_BLOB_VERSION {
    return None;
  }
  let end = 2 + usize::from(blob[1]);
  if blob.len() < end {
    return None;
  }
  core::str::from_utf8(blob.get(2..end)?).ok()
}

/// Re-encrypt stale `users.email_enc` rows, one locked batch at a time.
async fn rotate_users(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut RotateReport,
) -> Result<(), CliError> {
  let active_kid = active_kid(keys)?;
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(USERS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, email_enc FROM users WHERE email_enc IS NOT NULL AND id > $1 \
       ORDER BY id LIMIT $2",
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
      let blob: Vec<u8> = row.try_get("email_enc")?;
      let kid = blob_kid(&blob).ok_or_else(|| malformed("users.email_enc"))?;
      if kid == active_kid {
        after = id;
        continue;
      }
      let opened = open_text(keys, &blob).map_err(|_| malformed("users.email_enc"))?;
      let canonical = normalize_email(&opened);
      let resealed = seal_text(keys, &canonical).map_err(|_| seal_failed())?;
      let index = blind_index_active(keys, &canonical);
      sqlx::query("UPDATE users SET email_enc = $2, email_index = $3 WHERE id = $1")
        .bind(id)
        .bind(&resealed)
        .bind(&index)
        .execute(&mut *tx)
        .await?;
      report.users_rotated = report.users_rotated.saturating_add(1);
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// Re-encrypt stale `redirect_uris.uri_enc` rows, one locked batch at a time.
async fn rotate_redirects(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut RotateReport,
) -> Result<(), CliError> {
  let active_kid = active_kid(keys)?;
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(REDIRECTS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, uri_enc FROM redirect_uris WHERE uri_enc IS NOT NULL AND id > $1 \
       ORDER BY id LIMIT $2",
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
      let blob: Vec<u8> = row.try_get("uri_enc")?;
      let kid = blob_kid(&blob).ok_or_else(|| malformed("redirect_uris.uri_enc"))?;
      if kid == active_kid {
        after = id;
        continue;
      }
      let opened = open_text(keys, &blob).map_err(|_| malformed("redirect_uris.uri_enc"))?;
      let resealed = seal_text(keys, &opened).map_err(|_| seal_failed())?;
      let index = blind_index_active(keys, &opened);
      sqlx::query("UPDATE redirect_uris SET uri_enc = $2, uri_index = $3 WHERE id = $1")
        .bind(id)
        .bind(&resealed)
        .bind(&index)
        .execute(&mut *tx)
        .await?;
      report.redirects_rotated = report.redirects_rotated.saturating_add(1);
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

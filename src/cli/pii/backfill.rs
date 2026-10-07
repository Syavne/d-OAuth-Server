//! `pii backfill`: seal legacy plaintext PII and upgrade TOTP blobs to v3.
//!
//! Every table is scanned in bounded batches. Each batch runs in its own
//! transaction holding `pg_advisory_xact_lock` on the connection that owns
//! that transaction (mirroring `totp rewrap`), so the lock and the batch
//! commit/rollback are atomic. For each row with a non-null plaintext PII
//! value the sealed `_enc` (plus `_index` where the column exists) is written
//! and the plaintext column is nulled; any TOTP blob below v3 is decrypted
//! with the old path and re-encrypted with `envelope = true`. A stored
//! `_enc` that no longer opens aborts the batch (rollback, plaintext intact)
//! instead of being overwritten. The command is idempotent: a re-run finds no
//! plaintext and rewrites nothing.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::super::context::{CliError, audit};
use super::clients::backfill_clients;
use super::{BackfillReport, malformed, seal_failed};
use crate::crypto::field::{blind_index_active, open_text, seal_text};
use crate::crypto::totp::{decrypt_secret, encrypt_secret};
use crate::db::user_repo::normalize_email;
use crate::keys::KeyRing;

/// Rows scanned per batch transaction.
const BATCH_SIZE: usize = 100;
/// Envelope-encrypted TOTP blob version (per-row DEK); anything else is legacy.
const TOTP_BLOB_V3: u8 = 3;
/// Advisory-lock key for the `users` batches, stable across processes.
const USERS_LOCK: &str = "d_oauth_pii_backfill_users";
/// Advisory-lock key for the `redirect_uris` batches, stable across processes.
const REDIRECTS_LOCK: &str = "d_oauth_pii_backfill_redirects";

/// Seal remaining plaintext PII and upgrade TOTP blobs, refusing while
/// dual-write holds.
///
/// # Errors
/// Returns [`CliError::Input`] while `dual_write` holds (refusal),
/// [`CliError::Crypto`] when no active PII key is configured, a stored
/// ciphertext cannot be opened (the batch rolls back, plaintext intact), or a
/// seal fails, and [`CliError::Database`] for PostgreSQL failures.
pub(super) async fn backfill_with(
  pool: &PgPool,
  keys: &KeyRing,
  dual_write: bool,
) -> Result<BackfillReport, CliError> {
  if dual_write {
    return Err(CliError::Input(
      "pii backfill refused while pii_dual_write=true: cutover order is \
       dual-write off, scale-to-zero, backfill, verify"
        .to_owned(),
    ));
  }
  if keys.active_pii_key().is_none() {
    return Err(CliError::Crypto(
      "no active PII encryption key configured".to_owned(),
    ));
  }
  let mut report = BackfillReport::default();
  backfill_users(pool, keys, &mut report).await?;
  backfill_clients(pool, keys, &mut report).await?;
  backfill_redirects(pool, keys, &mut report).await?;
  audit("pii.backfill", "pii");
  Ok(report)
}

/// Seal `users.email` rows and upgrade pre-v3 TOTP blobs, one locked batch at
/// a time (keyset pagination on `id`, never `OFFSET`).
async fn backfill_users(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut BackfillReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(USERS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, email, email_enc, totp_secret_enc FROM users \
       WHERE (email IS NOT NULL OR totp_secret_enc IS NOT NULL) AND id > $1 \
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
      let email: Option<String> = row.try_get("email")?;
      let email_enc: Option<Vec<u8>> = row.try_get("email_enc")?;
      let totp: Option<Vec<u8>> = row.try_get("totp_secret_enc")?;

      let mut sealed_email: Option<Vec<u8>> = None;
      let mut sealed_index: Option<String> = None;
      if let Some(plain) = email {
        if let Some(existing) = email_enc {
          open_text(keys, &existing).map_err(|_| malformed("users.email_enc"))?;
        }
        let canonical = normalize_email(&plain);
        sealed_email = Some(seal_text(keys, &canonical).map_err(|_| seal_failed())?);
        sealed_index = Some(blind_index_active(keys, &canonical));
      }
      let mut upgraded_totp: Option<Vec<u8>> = None;
      if let Some(blob) = totp
        && blob.first().copied() != Some(TOTP_BLOB_V3)
      {
        let plaintext =
          decrypt_secret(keys, &blob).map_err(|_| malformed("users.totp_secret_enc"))?;
        upgraded_totp = Some(encrypt_secret(keys, &plaintext, true).map_err(|_| seal_failed())?);
      }
      if sealed_email.is_some() {
        sqlx::query(
          "UPDATE users SET email_enc = $2, email_index = $3, email = NULL, \
             totp_secret_enc = COALESCE($4, totp_secret_enc) WHERE id = $1",
        )
        .bind(id)
        .bind(sealed_email.as_deref())
        .bind(sealed_index.as_deref())
        .bind(upgraded_totp.as_deref())
        .execute(&mut *tx)
        .await?;
        report.users_sealed = report.users_sealed.saturating_add(1);
      } else if upgraded_totp.is_some() {
        sqlx::query("UPDATE users SET totp_secret_enc = $2 WHERE id = $1")
          .bind(id)
          .bind(upgraded_totp.as_deref())
          .execute(&mut *tx)
          .await?;
      }
      if upgraded_totp.is_some() {
        report.totp_upgraded = report.totp_upgraded.saturating_add(1);
      }
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// Seal `redirect_uris.uri` rows, one locked batch at a time.
async fn backfill_redirects(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut BackfillReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(REDIRECTS_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows = sqlx::query(
      "SELECT id, uri, uri_enc FROM redirect_uris \
       WHERE uri IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
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
      let uri: Option<String> = row.try_get("uri")?;
      let uri_enc: Option<Vec<u8>> = row.try_get("uri_enc")?;
      let Some(plain) = uri else {
        after = id;
        continue;
      };
      if let Some(existing) = uri_enc {
        open_text(keys, &existing).map_err(|_| malformed("redirect_uris.uri_enc"))?;
      }
      let sealed = seal_text(keys, &plain).map_err(|_| seal_failed())?;
      let index = blind_index_active(keys, &plain);
      sqlx::query(
        "UPDATE redirect_uris SET uri_enc = $2, uri_index = $3, uri = NULL WHERE id = $1",
      )
      .bind(id)
      .bind(&sealed)
      .bind(&index)
      .execute(&mut *tx)
      .await?;
      report.redirects_sealed = report.redirects_sealed.saturating_add(1);
      after = id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

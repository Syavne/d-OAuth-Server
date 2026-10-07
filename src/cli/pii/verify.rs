//! `pii verify`: the four cutover checks over sealed PII.
//!
//! The checks are (1) any plaintext PII column still non-NULL, (2) any `_enc`
//! (including `users.totp_secret_enc`) that fails to open under a retained key,
//! (3) any TOTP blob still below v3, and (4) any sealed indexed row with a NULL
//! or mismatched `_index`. Index comparison recomputes the canonical value per
//! column (`normalize_email` for `email_enc`, the exact string for `uri_enc`
//! and the two mTLS identities) and accepts a match against
//! `blind_index_candidates` under any retained key, since during a rotation
//! window a row may legitimately carry an index under the previous key. Only
//! counts are reported, never values or key material.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::super::context::CliError;
use super::VerifyReport;
use crate::crypto::field::{blind_index_candidates, open_json, open_text};
use crate::crypto::totp::decrypt_secret;
use crate::db::user_repo::normalize_email;
use crate::keys::KeyRing;

/// Rows scanned per verification batch.
const BATCH_SIZE: usize = 500;

/// Run the four cutover checks, reporting counts for each.
///
/// A dirty report is still `Ok` here; the caller maps it to a non-zero exit
/// via `ensure_clean`.
///
/// # Errors
/// Returns [`CliError::Database`] for PostgreSQL failures.
pub(super) async fn verify_with(pool: &PgPool, keys: &KeyRing) -> Result<VerifyReport, CliError> {
  let mut report = VerifyReport::default();
  count_plaintext(pool, &mut report).await?;
  count_totp_below_v3(pool, &mut report).await?;
  scan_users(pool, keys, &mut report).await?;
  scan_clients(pool, keys, &mut report).await?;
  scan_redirects(pool, keys, &mut report).await?;
  Ok(report)
}

/// Check (1): rows with any blanked plaintext PII column still non-NULL.
async fn count_plaintext(pool: &PgPool, report: &mut VerifyReport) -> Result<(), CliError> {
  let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email IS NOT NULL")
    .fetch_one(pool)
    .await?;
  let clients: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM oauth_clients \
     WHERE client_name IS NOT NULL OR contacts IS NOT NULL OR request_uris IS NOT NULL \
       OR jwks_uri IS NOT NULL OR software_id IS NOT NULL \
       OR tls_client_auth_subject_dn IS NOT NULL OR tls_client_auth_cert_thumbprint IS NOT NULL",
  )
  .fetch_one(pool)
  .await?;
  let redirects: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM redirect_uris WHERE uri IS NOT NULL")
      .fetch_one(pool)
      .await?;
  report.plaintext = report
    .plaintext
    .saturating_add(count_to_u64(users)?)
    .saturating_add(count_to_u64(clients)?)
    .saturating_add(count_to_u64(redirects)?);
  Ok(())
}

/// Check (3): TOTP blobs still below the v3 envelope format (pure SQL on the
/// version byte; short blobs count as below-v3, fail-closed).
async fn count_totp_below_v3(pool: &PgPool, report: &mut VerifyReport) -> Result<(), CliError> {
  let below: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM users WHERE totp_secret_enc IS NOT NULL \
     AND (length(totp_secret_enc) < 2 OR get_byte(totp_secret_enc, 0) <> 3)",
  )
  .fetch_one(pool)
  .await?;
  report.totp_below_v3 = report.totp_below_v3.saturating_add(count_to_u64(below)?);
  Ok(())
}

/// Checks (2) and (4) over `users`: `email_enc` opens and its `email_index`
/// matches a retained-key candidate for the canonical email; every TOTP blob
/// opens under a retained TOTP key.
async fn scan_users(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut VerifyReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let rows = sqlx::query(
      "SELECT id, email_enc, email_index, totp_secret_enc FROM users \
       WHERE (email_enc IS NOT NULL OR totp_secret_enc IS NOT NULL) AND id > $1 \
       ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(BATCH_SIZE as i64)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
      break;
    }
    let fetched = rows.len();
    for row in &rows {
      let id: Uuid = row.try_get("id")?;
      let email_enc: Option<Vec<u8>> = row.try_get("email_enc")?;
      let email_index: Option<String> = row.try_get("email_index")?;
      let totp: Option<Vec<u8>> = row.try_get("totp_secret_enc")?;
      if let Some(blob) = email_enc {
        match open_text(keys, &blob) {
          Ok(plain) => {
            if !index_matches(keys, &normalize_email(&plain), email_index) {
              report.index_mismatch = report.index_mismatch.saturating_add(1);
            }
          }
          Err(_) => {
            report.undecryptable = report.undecryptable.saturating_add(1);
          }
        }
      }
      if let Some(blob) = totp
        && decrypt_secret(keys, &blob).is_err()
      {
        report.undecryptable = report.undecryptable.saturating_add(1);
      }
      after = id;
    }
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// Checks (2) and (4) over `oauth_clients`: every `_enc` opens (JSON columns
/// via the JSON codec), and both mTLS indexes match a retained-key candidate
/// for the exact stored string.
async fn scan_clients(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut VerifyReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let rows = sqlx::query(
      "SELECT id, client_name_enc, contacts_enc, request_uris_enc, jwks_uri_enc, software_id_enc, \
         tls_client_auth_subject_dn_enc, tls_client_auth_cert_thumbprint_enc, \
         tls_client_auth_subject_dn_index, tls_client_auth_cert_thumbprint_index \
       FROM oauth_clients \
       WHERE (client_name_enc IS NOT NULL OR contacts_enc IS NOT NULL \
         OR request_uris_enc IS NOT NULL OR jwks_uri_enc IS NOT NULL OR software_id_enc IS NOT NULL \
         OR tls_client_auth_subject_dn_enc IS NOT NULL \
         OR tls_client_auth_cert_thumbprint_enc IS NOT NULL) \
         AND id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(BATCH_SIZE as i64)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
      break;
    }
    let fetched = rows.len();
    for row in &rows {
      let id: Uuid = row.try_get("id")?;
      check_optional_text(keys, row, "client_name_enc", None, report)?;
      check_optional_json(keys, row, "contacts_enc", report)?;
      check_optional_json(keys, row, "request_uris_enc", report)?;
      check_optional_text(keys, row, "jwks_uri_enc", None, report)?;
      check_optional_text(keys, row, "software_id_enc", None, report)?;
      for (enc_col, index_col) in [
        (
          "tls_client_auth_subject_dn_enc",
          "tls_client_auth_subject_dn_index",
        ),
        (
          "tls_client_auth_cert_thumbprint_enc",
          "tls_client_auth_cert_thumbprint_index",
        ),
      ] {
        let stored: Option<String> = row.try_get(index_col)?;
        check_optional_text(keys, row, enc_col, Some(stored), report)?;
      }
      after = id;
    }
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// Check one optional text `_enc`: an unopenable blob counts as
/// undecryptable; an opened value counts a NULL or mismatched `_index` when
/// `index` holds the stored index (`None` for columns without one). The caller
/// passes the canonical form implicitly: the opened plaintext is already
/// canonical for these columns (email rows canonicalize via
/// [`normalize_email`] before calling [`index_matches`]).
fn check_optional_text(
  keys: &KeyRing,
  row: &sqlx::postgres::PgRow,
  column: &str,
  index: Option<Option<String>>,
  report: &mut VerifyReport,
) -> Result<(), CliError> {
  let blob: Option<Vec<u8>> = row.try_get(column)?;
  let Some(blob) = blob else {
    return Ok(());
  };
  match open_text(keys, &blob) {
    Ok(plain) => {
      if let Some(stored) = index
        && !index_matches(keys, &plain, stored)
      {
        report.index_mismatch = report.index_mismatch.saturating_add(1);
      }
    }
    Err(_) => {
      report.undecryptable = report.undecryptable.saturating_add(1);
    }
  }
  Ok(())
}

/// Check one optional JSON `_enc`: an unopenable blob counts as undecryptable.
fn check_optional_json(
  keys: &KeyRing,
  row: &sqlx::postgres::PgRow,
  column: &str,
  report: &mut VerifyReport,
) -> Result<(), CliError> {
  let blob: Option<Vec<u8>> = row.try_get(column)?;
  if let Some(blob) = blob
    && open_json::<serde_json::Value>(keys, &blob).is_err()
  {
    report.undecryptable = report.undecryptable.saturating_add(1);
  }
  Ok(())
}

/// Checks (2) and (4) over `redirect_uris`: `uri_enc` opens and `uri_index`
/// matches a retained-key candidate for the exact stored string.
async fn scan_redirects(
  pool: &PgPool,
  keys: &KeyRing,
  report: &mut VerifyReport,
) -> Result<(), CliError> {
  let mut after = Uuid::nil();
  loop {
    let rows = sqlx::query(
      "SELECT id, uri_enc, uri_index FROM redirect_uris \
       WHERE uri_enc IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(BATCH_SIZE as i64)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
      break;
    }
    let fetched = rows.len();
    for row in &rows {
      let id: Uuid = row.try_get("id")?;
      let blob: Option<Vec<u8>> = row.try_get("uri_enc")?;
      let index: Option<String> = row.try_get("uri_index")?;
      if let Some(blob) = blob {
        match open_text(keys, &blob) {
          Ok(plain) => {
            if !index_matches(keys, &plain, index) {
              report.index_mismatch = report.index_mismatch.saturating_add(1);
            }
          }
          Err(_) => {
            report.undecryptable = report.undecryptable.saturating_add(1);
          }
        }
      }
      after = id;
    }
    if fetched < BATCH_SIZE {
      break;
    }
  }
  Ok(())
}

/// Whether `stored` names the canonical value under any retained PII key
/// (rotation-window tolerant). A NULL stored index never matches.
fn index_matches(keys: &KeyRing, canonical: &str, stored: Option<String>) -> bool {
  match stored {
    Some(index) => blind_index_candidates(keys, canonical)
      .iter()
      .any(|candidate| candidate == &index),
    None => false,
  }
}

/// Convert a `COUNT(*)` row to `u64`, failing closed on the impossible
/// negative rather than wrapping or truncating.
fn count_to_u64(count: i64) -> Result<u64, CliError> {
  u64::try_from(count).map_err(|_| CliError::Crypto("row count out of range".to_owned()))
}

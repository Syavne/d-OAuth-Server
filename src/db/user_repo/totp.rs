//! TOTP secret and one-time recovery-code storage for `users`.
//!
//! The TOTP secret is stored only as ciphertext (`totp_secret_enc bytea`);
//! recovery codes are stored only as Argon2id PHC hashes in
//! `totp_recovery_code_hashes jsonb`. Plaintext secrets/codes never reach the
//! database.

use uuid::Uuid;

use crate::{crypto::secret::verify_secret, error::AppError};

/// Set (or replace) the encrypted TOTP secret and enable second-factor.
///
/// `secret_enc` is the ciphertext produced by the KeyRing TOTP key; plaintext
/// secrets are never accepted. Returns whether a user row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn set_totp_secret(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  secret_enc: &[u8],
) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users
          SET totp_secret_enc = $2, totp_enabled = true, updated_at = now()
        WHERE id = $1"#,
    user_id,
    secret_enc,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Read the encrypted TOTP secret blob for a user, if one is stored.
///
/// Genuine gap noted by the login task (25): the repository exposes
/// set/clear/toggle for the secret but no read path, and login must decrypt
/// the secret to verify codes. Uses a runtime `query_as` (not the `query!`
/// macro) so no `.sqlx/` offline-cache entry is needed. Never returns
/// plaintext: the blob still needs a `KeyRing` TOTP key to open.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn totp_secret_blob(
  pool: &sqlx::PgPool,
  user_id: Uuid,
) -> Result<Option<Vec<u8>>, AppError> {
  let row: Option<(Option<Vec<u8>>,)> =
    sqlx::query_as("SELECT totp_secret_enc FROM users WHERE id = $1")
      .bind(user_id)
      .fetch_optional(pool)
      .await?;
  Ok(row.and_then(|(blob,)| blob))
}

/// Clear the TOTP secret and disable second-factor.
///
/// Returns whether a user row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn clear_totp_secret(pool: &sqlx::PgPool, user_id: Uuid) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users
          SET totp_secret_enc = NULL, totp_enabled = false, updated_at = now()
        WHERE id = $1"#,
    user_id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Toggle the TOTP-enabled flag without touching the stored secret.
///
/// Returns whether a user row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn set_totp_enabled(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  enabled: bool,
) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users SET totp_enabled = $2, updated_at = now() WHERE id = $1"#,
    user_id,
    enabled,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Replace the set of TOTP recovery-code hashes.
///
/// Hashes are Argon2id PHC strings; plaintext recovery codes are never stored.
///
/// # Errors
/// Returns an error if serialization or the update fails.
pub async fn set_recovery_codes(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  hashes: &[String],
) -> Result<bool, AppError> {
  let json = serde_json::to_string(hashes).map_err(AppError::internal)?;
  let result = sqlx::query!(
    r#"UPDATE users
          SET totp_recovery_code_hashes = $2::text::jsonb, updated_at = now()
        WHERE id = $1"#,
    user_id,
    json,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Consume one recovery code: verify it against the stored hashes and, on a
/// match, delete exactly that hash so it can never be reused.
///
/// The read/modify/write runs in a single transaction with `SELECT … FOR
/// UPDATE`, so two concurrent attempts cannot both consume the same code.
///
/// # Errors
/// Returns an error when a stored hash is malformed or the transaction fails.
pub async fn consume_recovery_code(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  code: &str,
) -> Result<bool, AppError> {
  let mut tx = pool.begin().await?;
  let row = sqlx::query!(
    r#"SELECT totp_recovery_code_hashes::text AS hashes
         FROM users WHERE id = $1 FOR UPDATE"#,
    user_id,
  )
  .fetch_optional(&mut *tx)
  .await?;
  let Some(row) = row else {
    return Ok(false);
  };
  let hashes: Vec<String> = match row.hashes.as_deref() {
    Some(text) => serde_json::from_str(text).map_err(AppError::internal)?,
    None => return Ok(false),
  };
  let mut remaining = Vec::with_capacity(hashes.len());
  let mut matched = false;
  for stored in hashes {
    if !matched && verify_secret(code, &stored).map_err(AppError::internal)? {
      matched = true;
      continue;
    }
    remaining.push(stored);
  }
  if matched {
    let json = serde_json::to_string(&remaining).map_err(AppError::internal)?;
    sqlx::query!(
      r#"UPDATE users
            SET totp_recovery_code_hashes = $2::text::jsonb, updated_at = now()
          WHERE id = $1"#,
      user_id,
      json,
    )
    .execute(&mut *tx)
    .await?;
  }
  tx.commit().await?;
  Ok(matched)
}

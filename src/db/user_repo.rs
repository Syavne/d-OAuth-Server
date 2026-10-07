//! `users` repository (email-as-username, Argon2id, encrypted TOTP).
//!
//! Admin-provisioned users only; no public sign-up path exists. Email is
//! normalized to lowercase before every insert/lookup so the blind index and
//! the failed-login counters agree on one canonical account label.
//!
//! Email is stored sealed (`email_enc`, AES-256-GCM under the PII key chain)
//! and looked up through a keyed blind index (`email_index`, newest-first
//! candidates so retained keys keep matching after a rotation). Reads use the
//! dual predicate `email_index = ANY($candidates) OR (email_enc IS NULL AND
//! email = $canonical)` so legacy plaintext rows (both new columns NULL)
//! stay readable. Plaintext `email` is written only while `dual_write` holds.
//!
//! The repository never returns [`password_hash`]: [`UserRecord`] omits it and
//! [`verify_password`] reads it only long enough to run the constant-time
//! Argon2id comparison. Failed-login/lockout counters are Redis-only (see the
//! `lockout` section); no lockout state is ever written to Postgres, which is
//! what makes the counters safe under horizontal scaling.

use std::fmt;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
  crypto::{
    field::{blind_index_active, blind_index_candidates, open_text, seal_text},
    secret::{Argon2Params, hash_secret, verify_secret},
  },
  error::AppError,
  keys::KeyRing,
};

/// A user to provision. `password_hash` is an Argon2id PHC string produced by
/// [`crate::crypto::secret::hash_secret`]; the plaintext never reaches here.
pub struct NewUser {
  /// Email address (client-supplied casing; normalized on insert).
  pub email: String,
  /// Pre-computed Argon2id PHC hash of the account password.
  pub password_hash: String,
  /// Whether the account is an administrator.
  pub is_admin: bool,
  /// Whether the account must change its password before normal use.
  pub must_change_password: bool,
}

impl fmt::Debug for NewUser {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("NewUser")
      .field("email", &self.email)
      .field("password_hash", &"[REDACTED]")
      .field("is_admin", &self.is_admin)
      .field("must_change_password", &self.must_change_password)
      .finish()
  }
}

/// A stored user, safe to hand to callers: never carries the password hash or
/// the TOTP secret ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
  /// Primary key.
  pub id: Uuid,
  /// Canonical (lowercase) email.
  pub email: String,
  /// Whether the account is an administrator.
  pub is_admin: bool,
  /// Whether the account must change its password before normal use.
  pub must_change_password: bool,
  /// Whether the account is disabled.
  pub disabled: bool,
  /// Whether TOTP second-factor is enabled.
  pub totp_enabled: bool,
  /// When the password was last set, if ever.
  pub password_changed_at: Option<OffsetDateTime>,
}

/// Outcome of a password verification. Never carries the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerdict {
  /// The password matched.
  Matched,
  /// The password did not match.
  Mismatched,
  /// No account exists for the supplied email.
  Unknown,
  /// The account exists but is disabled (authentication must be refused).
  Disabled,
}

/// Normalize an email-as-username: trim surrounding whitespace, lowercase.
#[must_use]
pub fn normalize_email(email: &str) -> String {
  email.trim().to_lowercase()
}

/// Provision a user, normalizing the email and stamping timestamps.
///
/// The canonical email is sealed into `email_enc` and indexed in
/// `email_index`; plaintext `email` is written only while `dual_write` holds.
/// A dual-predicate existence check runs before INSERT because the partial
/// unique index alone cannot catch a duplicate across the encrypt-only
/// pre-backfill window (legacy rows carry a NULL index).
///
/// `password_changed_at` is set when the account is created ready-to-use and
/// left `NULL` when the account must change its password first.
///
/// # Errors
/// Returns [`AppError::DuplicateEmail`] on a duplicate email (including a
/// race lost at INSERT), `temporarily_unavailable` when PII sealing fails,
/// or a masked error on any other database failure.
pub async fn create_user(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  dual_write: bool,
  new_user: &NewUser,
) -> Result<UserRecord, AppError> {
  let canonical = normalize_email(&new_user.email);
  let candidates = blind_index_candidates(keys, &canonical);
  let exists = sqlx::query_scalar!(
    r#"SELECT EXISTS(
         SELECT 1 FROM users
          WHERE email_index = ANY($1)
             OR (email_enc IS NULL AND email = $2::text::citext)
       ) AS "exists!""#,
    &candidates,
    canonical,
  )
  .fetch_one(pool)
  .await?;
  if exists {
    return Err(AppError::DuplicateEmail);
  }
  let index = blind_index_active(keys, &canonical);
  let enc = seal_text(keys, &canonical).map_err(AppError::from)?;
  let plain: Option<&str> = if dual_write { Some(&canonical) } else { None };
  let row = sqlx::query!(
    r#"INSERT INTO users
         (id, email, email_enc, email_index, password_hash, is_admin,
          must_change_password, password_changed_at, created_at, updated_at)
       VALUES ($1, $2::text::citext, $3, $4, $5, $6, $7,
               CASE WHEN $7 THEN NULL ELSE now() END, now(), now())
       RETURNING id, email::text AS email, email_enc, is_admin,
                 must_change_password, disabled, totp_enabled, password_changed_at"#,
    Uuid::new_v4(),
    plain,
    enc,
    index,
    new_user.password_hash,
    new_user.is_admin,
    new_user.must_change_password,
  )
  .fetch_one(pool)
  .await?;
  Ok(UserRecord {
    id: row.id,
    email: decrypt_stored_email(keys, row.email_enc.as_deref(), row.email.as_deref())?,
    is_admin: row.is_admin,
    must_change_password: row.must_change_password,
    disabled: row.disabled,
    totp_enabled: row.totp_enabled,
    password_changed_at: row.password_changed_at,
  })
}

/// Find a user by email (case-insensitive); `None` when absent.
///
/// Matches the blind-index candidates first and falls back to the legacy
/// plaintext predicate only for rows that carry no ciphertext.
///
/// # Errors
/// Returns [`AppError::PiiDecrypt`] when the matched row's ciphertext fails
/// to open, or a masked error on any database failure.
pub async fn find_by_email(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  email: &str,
) -> Result<Option<UserRecord>, AppError> {
  let canonical = normalize_email(email);
  let candidates = blind_index_candidates(keys, &canonical);
  let row = sqlx::query!(
    r#"SELECT id, email::text AS email, email_enc, is_admin, must_change_password,
              disabled, totp_enabled, password_changed_at
         FROM users
        WHERE email_index = ANY($1)
           OR (email_enc IS NULL AND email = $2::text::citext)"#,
    &candidates,
    canonical,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      decrypt_stored_email(keys, row.email_enc.as_deref(), row.email.as_deref()).map(|email| {
        UserRecord {
          id: row.id,
          email,
          is_admin: row.is_admin,
          must_change_password: row.must_change_password,
          disabled: row.disabled,
          totp_enabled: row.totp_enabled,
          password_changed_at: row.password_changed_at,
        }
      })
    })
    .transpose()
}

/// Verify a password against the stored Argon2id hash.
///
/// Uses the same dual predicate as [`find_by_email`], never the legacy
/// plaintext predicate alone. A tampered `email_enc` on the matched row
/// fails closed with [`AppError::PiiDecrypt`] even though verification only
/// needs the password hash.
///
/// # Errors
/// Returns [`AppError::PiiDecrypt`] on a corrupt row, or a masked error when
/// the stored hash is malformed or the query fails.
pub async fn verify_password(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  email: &str,
  password: &str,
) -> Result<PasswordVerdict, AppError> {
  let canonical = normalize_email(email);
  let candidates = blind_index_candidates(keys, &canonical);
  let row = sqlx::query!(
    r#"SELECT password_hash, disabled, email_enc
         FROM users
        WHERE email_index = ANY($1)
           OR (email_enc IS NULL AND email = $2::text::citext)"#,
    &candidates,
    canonical,
  )
  .fetch_optional(pool)
  .await?;
  let Some(row) = row else {
    return Ok(PasswordVerdict::Unknown);
  };
  if let Some(blob) = row.email_enc.as_deref() {
    open_text(keys, blob).map_err(|_| AppError::PiiDecrypt)?;
  }
  if row.disabled {
    return Ok(PasswordVerdict::Disabled);
  }
  match verify_secret(password, &row.password_hash).map_err(AppError::internal)? {
    true => Ok(PasswordVerdict::Matched),
    false => Ok(PasswordVerdict::Mismatched),
  }
}

/// Resolve the stored email: open the ciphertext when present, else use the
/// legacy plaintext. A non-NULL ciphertext that fails to open never falls
/// back to plaintext; a row with neither representation fails closed.
///
/// # Errors
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open
/// or when the row carries no usable email at all.
fn decrypt_stored_email(
  keys: &KeyRing,
  enc: Option<&[u8]>,
  plain: Option<&str>,
) -> Result<String, AppError> {
  if let Some(blob) = enc {
    return open_text(keys, blob).map_err(|_| AppError::PiiDecrypt);
  }
  plain.map(str::to_owned).ok_or(AppError::PiiDecrypt)
}

mod totp;

pub use totp::{
  clear_totp_secret, consume_recovery_code, set_recovery_codes, set_totp_enabled, set_totp_secret,
  totp_secret_blob,
};

/// Disable a user account. Returns whether a row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn disable_user(pool: &sqlx::PgPool, user_id: Uuid) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users SET disabled = true, updated_at = now() WHERE id = $1"#,
    user_id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Promote (`true`) or demote (`false`) an administrator.
///
/// Returns whether a user row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn set_admin(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  is_admin: bool,
) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users SET is_admin = $2, updated_at = now() WHERE id = $1"#,
    user_id,
    is_admin,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Whether any enabled administrator account exists (bootstrap gate).
///
/// # Errors
/// Returns an error on any database failure.
pub async fn has_any_admin(pool: &sqlx::PgPool) -> Result<bool, AppError> {
  let exists = sqlx::query_scalar!(
    r#"SELECT EXISTS(SELECT 1 FROM users WHERE is_admin AND NOT disabled) AS "exists!""#,
  )
  .fetch_one(pool)
  .await?;
  Ok(exists)
}

/// Set a new password hash, clear `must_change_password`, and stamp
/// `password_changed_at`. Returns whether a user row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn set_password(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  password_hash: &str,
) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE users
          SET password_hash = $2,
              must_change_password = false,
              password_changed_at = now(),
              updated_at = now()
        WHERE id = $1"#,
    user_id,
    password_hash,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Hash a password with the configured Argon2id parameters.
///
/// Convenience for provisioning flows so callers never hand-roll hashing.
///
/// # Errors
/// Returns an error if the parameters are invalid or hashing fails.
pub fn hash_password(password: &str, params: &Argon2Params) -> Result<String, AppError> {
  hash_secret(password, params).map_err(AppError::internal)
}

// ---------------------------------------------------------------------------
// Redis failed-login / lockout counters (used by the login flow)
// ---------------------------------------------------------------------------

mod lockout;

pub use lockout::{
  LockoutPolicy, clear_login_failures, is_locked_out, lockout_remaining, login_failure_count,
  register_login_failure,
};

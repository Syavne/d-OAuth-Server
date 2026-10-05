//! `users` repository (email-as-username, Argon2id, encrypted TOTP).
//!
//! Admin-provisioned users only; no public sign-up path exists. Email is
//! normalized to lowercase before every insert/lookup so `citext` uniqueness
//! and the failed-login counters agree on one canonical account label.
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
  crypto::secret::{Argon2Params, hash_secret, verify_secret},
  error::AppError,
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
/// `password_changed_at` is set when the account is created ready-to-use and
/// left `NULL` when the account must change its password first.
///
/// # Errors
/// Returns an error on a duplicate email or any database failure.
pub async fn create_user(pool: &sqlx::PgPool, new_user: &NewUser) -> Result<UserRecord, AppError> {
  let email = normalize_email(&new_user.email);
  let record = sqlx::query_as!(
    UserRecord,
    r#"INSERT INTO users
         (id, email, password_hash, is_admin, must_change_password,
          password_changed_at, created_at, updated_at)
       VALUES ($1, $2::text::citext, $3, $4, $5,
               CASE WHEN $5 THEN NULL ELSE now() END, now(), now())
       RETURNING id, email::text AS "email!", is_admin, must_change_password,
                 disabled, totp_enabled, password_changed_at"#,
    Uuid::new_v4(),
    email,
    new_user.password_hash,
    new_user.is_admin,
    new_user.must_change_password,
  )
  .fetch_one(pool)
  .await?;
  Ok(record)
}

/// Find a user by email (case-insensitive); `None` when absent.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn find_by_email(
  pool: &sqlx::PgPool,
  email: &str,
) -> Result<Option<UserRecord>, AppError> {
  let email = normalize_email(email);
  let record = sqlx::query_as!(
    UserRecord,
    r#"SELECT id, email::text AS "email!", is_admin, must_change_password,
              disabled, totp_enabled, password_changed_at
         FROM users
        WHERE email = $1::text::citext"#,
    email,
  )
  .fetch_optional(pool)
  .await?;
  Ok(record)
}

/// Verify a password against the stored Argon2id hash.
///
/// # Errors
/// Returns an error when the stored hash is malformed or the query fails.
pub async fn verify_password(
  pool: &sqlx::PgPool,
  email: &str,
  password: &str,
) -> Result<PasswordVerdict, AppError> {
  let email = normalize_email(email);
  let row = sqlx::query!(
    r#"SELECT password_hash, disabled
         FROM users
        WHERE email = $1::text::citext"#,
    email,
  )
  .fetch_optional(pool)
  .await?;
  let Some(row) = row else {
    return Ok(PasswordVerdict::Unknown);
  };
  if row.disabled {
    return Ok(PasswordVerdict::Disabled);
  }
  match verify_secret(password, &row.password_hash).map_err(AppError::internal)? {
    true => Ok(PasswordVerdict::Matched),
    false => Ok(PasswordVerdict::Mismatched),
  }
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

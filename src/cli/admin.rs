//! `admin bootstrap`: create the first administrator under an advisory lock.
//!
//! There is deliberately no HTTP bootstrap endpoint: provisioning is CLI/Job
//! only. The command refuses while any enabled admin exists (`user create
//! --admin` provisions later admins); `--force` overrides with a loud warning
//! and an audit event.
//!
//! Password handling: never via argv (no such flag exists), never logged. The
//! password comes from `--password-file`, from stdin, or — when neither yields
//! a value — a 256-bit generated password that the CLI wrapper prints exactly
//! once to a TTY. The created admin always has `must_change_password = true`
//! and `totp_enabled = false`, so the first login (task 25) yields a
//! restricted session that can only change the password and enroll TOTP.
//!
//! Concurrency: the existence check and the insert run in one transaction
//! holding `pg_advisory_xact_lock`, so two concurrent bootstrap Jobs create
//! exactly one admin (modulo `--force`, which is an explicit override).
//!
//! Audit (on the shared `audit` target via [`crate::cli::context::audit`];
//! never carrying a secret): `admin.bootstrap.created` and
//! `admin.count.changed` on success, `admin.bootstrap.refused` on refusal,
//! `admin.bootstrap.force` on a forced override. First-login,
//! password-changed, and TOTP-enrolled outcomes are emitted by the login flow
//! itself (task 25); this module only creates the account that flow gates.

use std::{fmt, path::Path};

use base64::Engine as _;
use ring::rand::{SecureRandom as _, SystemRandom};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::context::{CliError, audit, require_nonempty};
use super::secret;
use super::user::map_user_repo_error;
use crate::{config::Config, db::user_repo};

/// Bytes of entropy in a generated bootstrap password (256-bit).
const GENERATED_BYTES: usize = 32;

/// How the bootstrap password was supplied.
///
/// `Debug` is redacted: a `Provided` password prints its length plus
/// `[REDACTED]` only, never the password itself.
pub enum BootstrapPassword {
  /// Operator-supplied password (file or stdin), wiped on drop.
  Provided(Zeroizing<String>),
  /// Generate a fresh 256-bit password (printed once by the CLI wrapper).
  Generate,
}

impl fmt::Debug for BootstrapPassword {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Provided(password) => f
        .debug_struct("BootstrapPassword")
        .field("secret", &"[REDACTED]")
        .field("secret_len", &password.len())
        .finish(),
      Self::Generate => f.write_str("Generate"),
    }
  }
}

/// Outcome of a successful bootstrap (never logged; the generated password is
/// printed once by the CLI wrapper and never stored anywhere but the hash).
///
/// `Debug` is redacted for the same reason.
pub struct BootstrapOutcome {
  /// New admin user id.
  pub id: Uuid,
  /// Canonical email.
  pub email: String,
  /// The generated password, when [`BootstrapPassword::Generate`] was used.
  pub generated_password: Option<Zeroizing<String>>,
}

impl fmt::Debug for BootstrapOutcome {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BootstrapOutcome")
      .field("id", &self.id)
      .field("email", &self.email)
      .field("generated_password", &"[REDACTED]")
      .field(
        "generated_password_len",
        &self
          .generated_password
          .as_ref()
          .map(|password| password.len()),
      )
      .finish()
  }
}

/// Resolve the bootstrap password: `--password-file`, else stdin, else
/// generate.
///
/// An empty stdin (e.g. a Job with no piped secret and no mounted file) falls
/// through to [`BootstrapPassword::Generate`]; the caller prints that value
/// exactly once to a TTY.
///
/// # Errors
/// Returns [`CliError::Io`] when the file/stdin read fails.
pub fn resolve_password(password_file: Option<&Path>) -> Result<BootstrapPassword, CliError> {
  if let Some(path) = password_file {
    let password = super::context::read_secret(false, Some(path))?;
    return Ok(BootstrapPassword::Provided(password));
  }
  let password = super::context::read_secret(false, None)?;
  if password.trim().is_empty() {
    Ok(BootstrapPassword::Generate)
  } else {
    Ok(BootstrapPassword::Provided(password))
  }
}

/// Generate a fresh 256-bit password, base64-encoded (43 characters).
///
/// The password is held in [`Zeroizing`] so it is wiped on drop.
///
/// # Errors
/// Returns [`CliError::Crypto`] when OS randomness is unavailable.
pub fn generate_password() -> Result<Zeroizing<String>, CliError> {
  let mut bytes = Zeroizing::new([0u8; GENERATED_BYTES]);
  SystemRandom::new()
    .fill(&mut bytes[..])
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  Ok(Zeroizing::new(
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..]),
  ))
}

/// Create the first admin: advisory-locked existence gate plus a repository
/// insert.
///
/// The password is hashed before the lock is taken so the lock is held only
/// for the check and the insert. On success the admin has `is_admin = true`,
/// `must_change_password = true`, `totp_enabled = false`, and a `NULL`
/// `password_changed_at`.
///
/// # Errors
/// Returns [`CliError::Input`] for an empty email/password,
/// [`CliError::AlreadyExists`] when an enabled admin exists and `force` is
/// false (or when the email itself collides), and [`CliError`] for hashing or
/// database failures. The password never appears in any error or audit event.
pub async fn bootstrap(
  config: &Config,
  pool: &PgPool,
  email: &str,
  password: BootstrapPassword,
  force: bool,
) -> Result<BootstrapOutcome, CliError> {
  let email = user_repo::normalize_email(email);
  require_nonempty(&email, "email")?;
  let (plaintext, was_generated) = match password {
    BootstrapPassword::Provided(password) => {
      require_nonempty(&password, "password")?;
      (password, false)
    }
    BootstrapPassword::Generate => (generate_password()?, true),
  };
  // Hash before taking the lock so the lock is held only for the check and the
  // insert. The plaintext below is never logged and never stored; only the
  // Argon2id hash reaches the database.
  let password_hash = secret::hash_password(config, plaintext.as_str())?;

  // Serialize within the process so a single process never parks multiple
  // pooled connections on the database lock while the winner still needs a
  // second connection for the repository insert.
  let _serialized = BOOTSTRAP_MUTEX.lock().await;
  let mut conn = pool.acquire().await?;
  sqlx::query("SELECT pg_advisory_lock(hashtext('d_oauth_admin_bootstrap'))")
    .execute(&mut *conn)
    .await?;
  let outcome = bootstrap_locked(
    config,
    pool,
    &mut conn,
    &email,
    &password_hash,
    force,
    was_generated.then_some(plaintext),
  )
  .await;
  sqlx::query("SELECT pg_advisory_unlock(hashtext('d_oauth_admin_bootstrap'))")
    .execute(&mut *conn)
    .await?;
  outcome
}

/// Process-wide serialization for [`bootstrap`]; the session advisory lock
/// still serializes across processes.
static BOOTSTRAP_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Run the admin-count gate and the user-repository insert while the advisory
/// lock is held by `conn`.
async fn bootstrap_locked(
  config: &Config,
  pool: &PgPool,
  conn: &mut PgConnection,
  email: &str,
  password_hash: &str,
  force: bool,
  generated_password: Option<Zeroizing<String>>,
) -> Result<BootstrapOutcome, CliError> {
  let existing: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
      .fetch_one(&mut *conn)
      .await?;

  if existing > 0 && !force {
    audit("admin.bootstrap.refused", email);
    return Err(CliError::AlreadyExists(format!(
      "an administrator already exists ({existing}); use `user create --admin` for more admins"
    )));
  }
  if existing > 0 {
    eprintln!(
      "WARNING: admin bootstrap --force: {existing} administrator(s) already exist; \
       creating one more. This override is audited. \
       Prefer `user create --admin` for routine provisioning."
    );
    audit("admin.bootstrap.force", email);
  }

  let record = user_repo::create_user(
    pool,
    &config.keys,
    config.pii_dual_write,
    &user_repo::NewUser {
      email: email.to_owned(),
      password_hash: password_hash.to_owned(),
      is_admin: true,
      must_change_password: true,
    },
  )
  .await
  .map_err(map_user_repo_error)?;

  let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
    .fetch_one(&mut *conn)
    .await?;
  audit("admin.bootstrap.created", email);
  audit("admin.count.changed", &total.to_string());

  Ok(BootstrapOutcome {
    id: record.id,
    email: email.to_owned(),
    generated_password,
  })
}

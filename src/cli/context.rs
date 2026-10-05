//! CLI execution context: configuration, a Postgres pool, audit, and secret
//! input.
//!
//! Commands that only touch Postgres (user/scope/redirect/config sync/migrate)
//! use a short-lived [`Context`] pool. Commands that need Redis
//! (`initial-access-token`, `serve`) build a full [`crate::state::AppState`]
//! so topology selection and durability assertions stay in one place.

use std::{io::Read as _, path::Path, sync::Arc};

use secrecy::ExposeSecret as _;
use sqlx::PgPool;

use crate::config::Config;

/// Failures surfaced by CLI commands.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
  /// Configuration failed to load or validate.
  #[error("configuration error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A migration failed.
  #[error("migration error: {0}")]
  Migrate(#[from] sqlx::migrate::MigrateError),
  /// Application state failed to connect (Redis/Postgres/TLS contract).
  #[error("application state error: {0}")]
  State(#[from] crate::state::StateError),
  /// Password hashing or verification failed.
  #[error("secret hashing error: {0}")]
  Secret(#[from] crate::crypto::secret::SecretHashError),
  /// Token minting failed.
  #[error("token error: {0}")]
  Token(#[from] crate::crypto::tokens::TokenError),
  /// The Redis ephemeral store failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// A raw Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// Local I/O failed (stdin/file write).
  #[error("i/o error: {0}")]
  Io(#[from] std::io::Error),
  /// Operator input was invalid.
  #[error("invalid input: {0}")]
  Input(String),
  /// A referenced record does not exist.
  #[error("not found: {0}")]
  NotFound(String),
  /// A unique record already exists.
  #[error("already exists: {0}")]
  AlreadyExists(String),
  /// A cryptographic operation failed (non-secret detail only).
  #[error("crypto failure: {0}")]
  Crypto(String),
  /// The command's implementation lands in a later task.
  #[error("not yet implemented: {0}")]
  NotImplemented(&'static str),
}

/// A short-lived operator context: validated config plus a Postgres pool.
pub struct Context {
  config: Arc<Config>,
  pool: PgPool,
}

impl Context {
  /// Load configuration from the environment and open a pool.
  ///
  /// # Errors
  /// Returns [`CliError::Config`] for invalid configuration and
  /// [`CliError::Database`] when the pool cannot connect.
  pub async fn from_env() -> Result<Self, CliError> {
    let config = Arc::new(Config::load()?);
    Self::from_config(config).await
  }

  /// Open a pool against an already-validated configuration.
  ///
  /// # Errors
  /// Returns [`CliError::Database`] when the pool cannot connect.
  pub async fn from_config(config: Arc<Config>) -> Result<Self, CliError> {
    let pool = open_pool(&config).await?;
    Ok(Self { config, pool })
  }

  /// Validated runtime configuration.
  #[must_use]
  pub fn config(&self) -> &Arc<Config> {
    &self.config
  }

  /// The Postgres pool.
  #[must_use]
  pub fn pool(&self) -> &PgPool {
    &self.pool
  }
}

/// Open a short-lived Postgres pool from validated configuration.
///
/// CLI commands are one-shot, so the pool is capped at the configured maximum
/// with no minimum kept alive.
///
/// # Errors
/// Returns [`CliError::Database`] when the pool cannot connect.
pub async fn open_pool(config: &Config) -> Result<PgPool, CliError> {
  let db = &config.database;
  let pool = sqlx::postgres::PgPoolOptions::new()
    .max_connections(db.max_connections)
    .min_connections(0)
    .acquire_timeout(db.acquire_timeout)
    .connect(db.url.expose_secret())
    .await?;
  Ok(pool)
}

/// Emit one structured audit event for an operator mutation.
///
/// Events go to the dedicated `audit` tracing target with a stable
/// `event = "cli.mutation"` name and a non-secret operation/subject pair. The
/// shared [`crate::middleware::audit::AuditEvent`] enum models HTTP outcomes
/// only; CLI mutations use this stable target so every mutation is auditable
/// without widening a peer-owned enum.
pub fn audit(operation: &str, subject: &str) {
  tracing::info!(
    target: "audit",
    event = "cli.mutation",
    operation = %operation,
    subject = %subject,
    "cli mutation"
  );
}

/// Read a password/secret from stdin or a file, never argv.
///
/// `from_stdin` and `file` are mutually exclusive. Trailing CR/LF is trimmed so
/// `echo secret | ...` and a file with a trailing newline behave identically.
///
/// # Errors
/// Returns [`CliError::Input`] when both sources are given and
/// [`CliError::Io`] when reading fails.
pub fn read_secret(from_stdin: bool, file: Option<&Path>) -> Result<String, CliError> {
  match (from_stdin, file) {
    (true, Some(_)) => Err(CliError::Input(
      "--password-stdin and --password-file are mutually exclusive".to_owned(),
    )),
    (_, Some(path)) => {
      let raw = std::fs::read_to_string(path)?;
      Ok(trim_newline(&raw))
    }
    (_, None) => {
      let mut raw = String::new();
      std::io::stdin().read_to_string(&mut raw)?;
      Ok(trim_newline(&raw))
    }
  }
}

/// Reject an empty secret early with a clear message.
///
/// # Errors
/// Returns [`CliError::Input`] when `secret` is empty after trimming.
pub fn require_nonempty(secret: &str, what: &str) -> Result<(), CliError> {
  if secret.trim().is_empty() {
    return Err(CliError::Input(format!("{what} must not be empty")));
  }
  Ok(())
}

fn trim_newline(raw: &str) -> String {
  raw.trim_end_matches(['\r', '\n']).to_owned()
}

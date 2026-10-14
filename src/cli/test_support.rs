//! Compose-services harness for the `test(cli)` suite.
//!
//! Tests connect to the shared Postgres and Redis from `compose.test.yaml`
//! through the crate-wide helpers. Each harness build creates a fresh database
//! on the shared server (migrated once) and mints a Redis prefix pair that is
//! per-process under `cargo test` (shared `static HARNESS`) and per-test under
//! `cargo nextest`; handler-side `Store::from_config` resolves the same
//! keyspace because the prefixes live in the config.

use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt as _;

use super::context::{CliError, Context};
use crate::{
  config::Config,
  state::MIGRATOR,
  test_guard::{Lease, Shared},
};

/// Errors raised by the CLI test scaffolding.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// Crate configuration failed to load.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// The layered config source failed.
  #[error("config source error: {0}")]
  Source(#[from] ::config::ConfigError),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A migration failed.
  #[error("migration error: {0}")]
  Migrate(#[from] sqlx::migrate::MigrateError),
  /// Application state failed to connect.
  #[error("state error: {0}")]
  State(#[from] crate::state::StateError),
  /// A CLI operation failed.
  #[error("cli error: {0}")]
  Cli(#[from] CliError),
  /// An application-core operation failed (login flow in bootstrap tests).
  #[error("app error: {0}")]
  App(#[from] crate::error::AppError),
  /// A TOTP operation failed.
  #[error("totp error: {0}")]
  Totp(#[from] crate::crypto::totp::TotpError),
  /// JSON (de)serialization failed.
  #[error("json error: {0}")]
  Json(#[from] serde_json::Error),
  /// A Redis operation failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A lockout-counter operation failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// A required value was unexpectedly absent.
  #[error("missing value: {0}")]
  Missing(&'static str),
  /// An I/O operation failed.
  #[error("i/o error: {0}")]
  Io(#[from] std::io::Error),
  /// A test-harness operation failed (boxed peer-harness error).
  #[error("harness error: {0}")]
  Harness(String),
}

/// Validated configuration pointing at the shared services.
///
/// Under `cargo test` the shared `static HARNESS` means one harness build per
/// process owns a fresh database plus a per-process Redis prefix pair; under
/// `cargo nextest` each test runs in its own process, so the pair is per-test.
pub struct Harness {
  /// Validated configuration pointing at the fresh database and shared Redis.
  pub config: Arc<Config>,
}

static HARNESS: Shared<Harness> = Shared::new();

/// Start (once per process) and return a lease on the harness.
///
/// The lease dereferences to the harness; hold it for the duration of the
/// test alongside the context.
///
/// # Errors
/// Returns [`TestError`] when the database, config load, or migration fails.
pub async fn harness() -> Result<Lease<Harness>, TestError> {
  HARNESS.lease(build()).await
}

/// Build an operator context over the shared harness.
///
/// The lease keeps the harness alive; bind it (usually as
/// `_harness`) for the duration of the test alongside the context.
///
/// # Errors
/// Returns [`TestError`] when the pool cannot connect.
pub async fn context() -> Result<(Lease<Harness>, Context), TestError> {
  let harness = harness().await?;
  let context = Context::from_config(harness.config.clone()).await?;
  Ok((harness, context))
}

/// A unique email under the reserved `.test` TLD.
#[must_use]
pub fn unique_email(prefix: &str) -> String {
  format!("{prefix}-{}@example.test", uuid::Uuid::new_v4())
}

/// A unique scope/catalog name.
#[must_use]
pub fn unique_name(prefix: &str) -> String {
  format!("{prefix}:{}", uuid::Uuid::new_v4())
}

/// A scoped audit capture: the buffer plus the subscriber guard to keep alive.
pub struct AuditCapture {
  /// Captured JSON log bytes.
  pub buffer: Arc<Mutex<Vec<u8>>>,
  /// Scoped default-subscriber guard; drop when the audited call returns.
  pub guard: tracing::subscriber::DefaultGuard,
}

/// Install a thread-local JSON tracing subscriber and return its buffer.
///
/// The returned guard must stay alive while the audited operation runs.
///
/// # Errors
/// Returns [`TestError`] when the mutex is poisoned.
pub fn install_capture() -> Result<AuditCapture, TestError> {
  let buffer = Arc::new(Mutex::new(Vec::new()));
  let writer = buffer.clone();
  let subscriber = tracing_subscriber::registry().with(
    tracing_subscriber::fmt::layer()
      .json()
      .with_writer(move || Capture(writer.clone())),
  );
  let guard = tracing::subscriber::set_default(subscriber);
  Ok(AuditCapture { buffer, guard })
}

/// Read captured JSON log bytes as a lossy string.
#[must_use]
pub fn captured(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
  buffer
    .lock()
    .map(|guard| String::from_utf8_lossy(&guard).into_owned())
    .unwrap_or_default()
}

async fn build() -> Result<Harness, TestError> {
  let (pg_url, pool) = crate::test_support::fresh_database_pool()
    .await
    .map_err(|error| TestError::Harness(format!("shared postgres: {error}")))?;
  MIGRATOR.run(&pool).await?;
  pool.close().await;
  let redis_url = crate::test_support::test_redis_url();
  let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
  let config = Arc::new(test_config(&pg_url, &redis_url, &state_prefix, &rl_prefix)?);
  Ok(Harness { config })
}

fn test_config(
  pg_url: &str,
  redis_url: &str,
  state_prefix: &str,
  rl_prefix: &str,
) -> Result<Config, TestError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/cli-test-cert.pem", "key_path": "/tmp/cli-test-key.pem"},
    "database": {"url": pg_url},
    "redis": {
      "url": redis_url,
      "durability": "waitaof",
      "token_key_prefix": state_prefix,
      "ratelimit_key_prefix": rl_prefix,
    },
    "token_pepper": "cli-test-pepper-0123456789abcdef",
    "totp_encryption_key": "cli-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "cli-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  Ok(Config::from_source(source)?)
}

struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    let mut guard = self
      .0
      .lock()
      .map_err(|_| std::io::Error::other("audit capture poisoned"))?;
    guard.extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

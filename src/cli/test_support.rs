//! Shared testcontainers harness for the `test(cli)` suite.
//!
//! One Postgres (migrated once) and one Redis (AOF on, satisfying the
//! durability contract) are shared across the suite; tests use unique emails
//! and scope names so parallel execution stays isolated.

use std::sync::{Arc, Mutex};

use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use tracing_subscriber::layer::SubscriberExt as _;

use super::context::{self, CliError, Context};
use crate::{
  config::Config,
  state::MIGRATOR,
  test_guard::{ContainerGuard, Lease, Shared},
};

const PG_PASSWORD: &str = "cli-test-secret";

/// Errors raised by the CLI test scaffolding.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
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

/// Shared Postgres + Redis containers plus the validated config.
///
/// The containers are [`ContainerGuard`]s, so the last test releasing the
/// shared slot removes them synchronously instead of orphaning them.
pub struct Harness {
  /// Validated configuration pointing at the containers.
  pub config: Arc<Config>,
  _postgres: ContainerGuard,
  _redis: ContainerGuard,
}

static HARNESS: Shared<Harness> = Shared::new();

/// Start (once) and return a lease on the shared harness.
///
/// The lease dereferences to the harness; hold it for the duration of the
/// test so the shared containers stay alive, and dropping the last lease
/// removes them deterministically.
///
/// # Errors
/// Returns [`TestError`] when a container, config load, or migration fails.
pub async fn harness() -> Result<Lease<Harness>, TestError> {
  HARNESS.lease(build()).await
}

/// Build an operator context over the shared harness.
///
/// The lease keeps the shared containers alive; bind it (usually as
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
  let (postgres, pg_url) = postgres_container().await?;
  let (redis, redis_url) = redis_container().await?;
  let config = Arc::new(test_config(&pg_url, &redis_url)?);
  let pool = context::open_pool(&config).await?;
  MIGRATOR.run(&pool).await?;
  drop(pool);
  Ok(Harness {
    config,
    _postgres: postgres,
    _redis: redis,
  })
}

async fn postgres_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("postgres", "latest")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_wait_for(WaitFor::message_on_stdout(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  Ok((guarded, url))
}

async fn redis_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(vec!["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

fn test_config(pg_url: &str, redis_url: &str) -> Result<Config, TestError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/cli-test-cert.pem", "key_path": "/tmp/cli-test-key.pem"},
    "database": {"url": pg_url},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "cli-test-pepper-0123456789abcdef",
    "totp_encryption_key": "cli-test-totp-key-0123456789abcdef",
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

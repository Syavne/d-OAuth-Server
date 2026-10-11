//! Shared testcontainers scaffolding for the `test(health)` suite.
//!
//! Postgres and Redis run from locally cached images (`postgres:18-alpine`,
//! `redis:8-alpine`); no pulls, no `redis-server` binary needed.
//! Sentinel and Cluster topologies talk over container bridge IPs, which are
//! directly routable from the Linux host, so Sentinel-advertised and
//! cluster-gossiped addresses stay valid without port-mapping tricks.

use std::time::Duration;

use serde_json::Value;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

use super::{AppState, MIGRATOR};
use crate::{
  config::{Config, ConfigError},
  test_guard::ContainerGuard,
};

/// Test Postgres superuser password.
const PG_PASSWORD: &str = "health-test-secret";

/// Test body result (no `unwrap`/`expect` under the deny lints).
pub type TestResult = Result<(), TestError>;

/// Start Postgres and return the container plus a plaintext URL with an
/// explicit `sslmode=disable` (honored verbatim by the pool builder).
///
/// The guard removes the container synchronously when the test drops it.
pub async fn postgres_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("postgres", "18-alpine")
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

/// Start a single-node Redis with AOF on; `requirepass` enables AUTH.
///
/// The guard removes the container synchronously when the test drops it.
pub async fn redis_single_container(
  requirepass: Option<&str>,
) -> Result<(ContainerGuard, String), TestError> {
  let args: Vec<&str> = match requirepass {
    Some(secret) => vec![
      "redis-server",
      "--appendonly",
      "yes",
      "--requirepass",
      secret,
    ],
    None => vec!["redis-server", "--appendonly", "yes"],
  };
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(args)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Build a full [`Config`] over the given Postgres URL and Redis block.
pub fn test_config(pg_url: &str, redis: Value) -> Result<Config, ConfigError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/health-test-cert.pem", "key_path": "/tmp/health-test-key.pem"},
    "database": {"url": pg_url},
    "redis": redis,
    "token_pepper": "health-test-pepper-0123456789abcdef",
    "totp_encryption_key": "health-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "health-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// Default single-node Redis block for tests (AOF is on in these containers).
pub fn single_redis_block(url: &str) -> Value {
  serde_json::json!({"url": url, "durability": "waitaof"})
}

/// Simulate the `migrate` subcommand having run: applies [`MIGRATOR`]
/// (currently zero migrations, but still creates `_sqlx_migrations`, which
/// is exactly what readiness checks for).
pub async fn mark_migrated(state: &AppState) -> Result<(), TestError> {
  MIGRATOR.run(&state.pool).await?;
  Ok(())
}

/// Drive `GET <path>` at the health-only router without binding a socket.
pub async fn get_health(state: &AppState, path: &str) -> Result<(u16, Value), TestError> {
  use tower::ServiceExt as _;
  let router = super::health_router(state.clone());
  let request = axum::http::Request::builder()
    .uri(path)
    .body(axum::body::Body::empty())?;
  let response = router.oneshot(request).await?;
  let status = response.status().as_u16();
  let bytes = http_body_util::BodyExt::collect(response.into_body())
    .await
    .map_err(|_| TestError::Body("body collection failed".to_owned()))?
    .to_bytes();
  // Plaintext-listener 404s carry no body; normalize empties to null.
  let body = if bytes.is_empty() {
    Value::Null
  } else {
    serde_json::from_slice::<Value>(&bytes)?
  };
  Ok((status, body))
}

/// Drive `GET <path>` at the health-only router and return its headers.
///
/// The health listener is built without the public router's security-header
/// layer, so this probe verifies the header set the health router inserts on
/// its own responses (`Cache-Control`, `X-Content-Type-Options`).
pub async fn get_health_headers(
  state: &AppState,
  path: &str,
) -> Result<axum::http::HeaderMap, TestError> {
  use tower::ServiceExt as _;
  let router = super::health_router(state.clone());
  let request = axum::http::Request::builder()
    .uri(path)
    .body(axum::body::Body::empty())?;
  let response = router.oneshot(request).await?;
  Ok(response.headers().clone())
}

/// Freeze (`pause`) or resume (`unpause`) a container via the Docker CLI.
pub async fn docker_pause(id: &str, pause: bool) -> Result<(), TestError> {
  let action = if pause { "pause" } else { "unpause" };
  let output = tokio::process::Command::new("docker")
    .args([action, id])
    .output()
    .await
    .map_err(|_| TestError::Docker(action.to_owned()))?;
  if !output.status.success() {
    return Err(TestError::Docker(action.to_owned()));
  }
  // Give the kernel a beat to stop scheduling the container's processes.
  tokio::time::sleep(Duration::from_millis(500)).await;
  Ok(())
}

/// Errors raised by the health test scaffolding itself.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// The crate configuration failed to load.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// Application state failed to connect.
  #[error("state error: {0}")]
  State(#[from] super::StateError),
  /// The layered config source or validation failed.
  #[error("config source error: {0}")]
  Source(#[from] ::config::ConfigError),
  /// A `docker pause/unpause` call failed.
  #[error("docker {0} failed")]
  Docker(String),
  /// An HTTP builder error while driving the router.
  #[error("http error: {0}")]
  Http(#[from] axum::http::Error),
  /// The in-process router returned its (uninhabited) error type.
  #[error("router error")]
  Router(#[from] std::convert::Infallible),
  /// A body/JSON error while reading a probe response.
  #[error("body error: {0}")]
  Body(String),
  /// A JSON error while reading a probe response.
  #[error("json error: {0}")]
  Json(#[from] serde_json::Error),
  /// A sqlx failure inside the test body.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A migration failure inside the test body.
  #[error("migration error: {0}")]
  Migrate(#[from] sqlx::migrate::MigrateError),
  /// A Redis failure inside the test body.
  #[error("redis error: {0}")]
  Redis(#[from] ::redis::RedisError),
}

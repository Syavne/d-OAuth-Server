//! `test(grant_device)` harness: live Postgres + Redis plus builders.
//!
//! Child suites share these helpers through `super::*`. Every acceptance
//! test drives the public [`super::super::poll_device`] API; DPoP proofs are
//! minted per call because each `jti` is single-use.

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use sqlx::PgPool;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

use crate::{config::Config, state::RedisConn, store::Store, test_guard::ContainerGuard};

mod backoff;
mod expired;
mod flows;
mod keys;
mod matrix;
mod poll;
mod race;
mod scope;
mod setup;

/// Test body result (no `unwrap`/`expect` under the deny lints).
pub(super) type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// Configuration was rejected.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// A JWT operation failed.
  #[error("jwt error: {0}")]
  Jwt(#[from] jsonwebtoken::errors::Error),
  /// A JWK helper failed.
  #[error("jwk error: {0}")]
  Jwk(#[from] crate::jose::jwk::JwkError),
  /// An application error escaped where success was required.
  #[error("app error: {0}")]
  App(#[from] crate::error::AppError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// The token service was rejected.
  #[error("token service error: {0}")]
  Service(#[from] crate::protocol::token::TokenServiceError),
  /// Test key generation was rejected.
  #[error("test key generation failed: {0}")]
  KeyGen(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

pub(super) static NONCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn unique(label: &str) -> String {
  let n = NONCE.fetch_add(1, Ordering::Relaxed);
  format!("grant-device-test-{n}-{label}")
}

/// Live handles for one test: pool, Redis, store, and validated config.
pub(super) struct Harness {
  _db: crate::test_guard::Lease<crate::db::test_support::Db>,
  pub(super) pool: PgPool,
  pub(super) conn: RedisConn,
  pub(super) store: Store,
  pub(super) config: Config,
}

pub(super) async fn harness() -> Result<(ContainerGuard, Harness), TestError> {
  let (db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg: {error}")))?;
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let redis_url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(redis_url.as_str())?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    crate::config::DurabilityMode::WaitAof,
  );
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/grant-device-test-cert.pem", "key_path": "/tmp/grant-device-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/grant_device"},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "grant-device-test-pepper-0123456789abcdef",
    "totp_encryption_key": "grant-device-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "grant-device-test-pii-key-0123456789abcdef",
    "rate_limit": {"enabled": true, "window_secs": 60, "per_ip": 120,
      "per_client": 300, "login_per_ip": 20, "token_per_client": 60},
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config source: {error}")))?;
  let config = Config::from_source(source)?;
  Ok((
    guarded,
    Harness {
      _db: db,
      pool,
      conn: RedisConn::Single(manager),
      store,
      config,
    },
  ))
}

//! `test(revoke)` suite: ownership-scoped revocation and grant cascade.
//!
//! A shared Redis 7.2 container (AOF on) backs the token/grant stores; unique
//! grant/client labels keep the keyspace collision-free. Authentication-scoped
//! behaviour that needs no database is exercised against a lazy Postgres pool
//! that is never dialed.

mod auth;
mod cascade;

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use secrecy::SecretString;
use testcontainers::{
  GenericImage, ImageExt as _,
  core::{IntoContainerPort as _, WaitFor},
  runners::AsyncRunner as _,
};

use crate::{
  config::{DurabilityMode, TtlConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    client_auth::ClientAuthRequest,
    token::{ClientKind, MintRequest, SenderProof, TokenService, TokenServiceError},
  },
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the revocation test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error")]
  Redis(#[from] redis::RedisError),
  /// A Postgres setup operation failed.
  #[error("postgres error")]
  Sqlx(#[from] sqlx::Error),
  /// A store operation failed.
  #[error("store error")]
  Store(#[from] StoreError),
  /// The token service failed.
  #[error("service error")]
  Service(#[from] TokenServiceError),
  /// The revocation handler returned an RFC error.
  #[error("app error")]
  App(#[from] crate::error::AppError),
  /// Reading a response body failed.
  #[error("body error")]
  Body(#[from] axum::Error),
  /// The key ring was rejected.
  #[error("key ring error")]
  Keys(#[from] KeyRingError),
  /// Response body was not JSON.
  #[error("json error")]
  Json(#[from] serde_json::Error),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// One shared Redis 7.2 container for the whole suite.
static REDIS: Shared<ContainerGuard> = Shared::new();

/// Fresh connection plus store handle against the shared container.
async fn test_redis() -> Result<(Lease<ContainerGuard>, RedisConn, Store), TestError> {
  let container = REDIS
    .lease::<TestError>(async {
      let started = GenericImage::new("redis", "7.2-alpine")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_cmd(["redis-server", "--appendonly", "yes"])
        .start()
        .await?;
      Ok(ContainerGuard::new(started))
    })
    .await?;
  let port = container.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(url.as_str())?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  Ok((container, RedisConn::Single(manager), store()))
}

/// A store handle with the canonical test key prefixes.
fn store() -> Store {
  Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  )
}

/// A lazy Redis connection that is never actually dialed.
fn lazy_redis() -> Result<RedisConn, TestError> {
  let client = redis::Client::open("redis://127.0.0.1:1")?;
  let manager = redis::aio::ConnectionManager::new_lazy_with_config(
    client,
    redis::aio::ConnectionManagerConfig::new()
      .set_number_of_retries(0)
      .set_response_timeout(Some(Duration::from_millis(200)))
      .set_connection_timeout(Some(Duration::from_millis(200))),
  )?;
  Ok(RedisConn::Single(manager))
}

/// A lazy Postgres pool that is never actually dialed.
fn lazy_pool() -> Result<sqlx::PgPool, TestError> {
  Ok(
    sqlx::postgres::PgPoolOptions::new()
      .acquire_timeout(Duration::from_millis(200))
      .connect_lazy("postgres://postgres:secret@127.0.0.1:1/postgres")?,
  )
}

static TEST_NONCE: AtomicU64 = AtomicU64::new(70_000);

/// A label no other test uses, so grants/clients never collide.
fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("revoke-test-{n}-{label}")
}

/// A token service over the default TTLs.
fn service() -> Result<TokenService, TestError> {
  let ring = KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("revoke-test-pepper-one"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("revoke-test-totp"))],
  )?;
  TokenService::new(&TtlConfig::default(), &ring).map_err(TestError::from)
}

/// A confidential-client mint request with fixed subject/scope.
fn mint_request(client: &str, grant: &str) -> MintRequest {
  MintRequest {
    client_id: client.to_owned(),
    client_kind: ClientKind::Confidential,
    subject: "user-1".to_owned(),
    scope: "orders:read".to_owned(),
    grant_id: grant.to_owned(),
    proof: SenderProof::none(),
  }
}

/// Current time as seconds since the Unix epoch.
fn now_unix() -> i64 {
  time::OffsetDateTime::now_utc().unix_timestamp()
}

/// An empty credential set: no header, secret, assertion, or `client_id`.
fn no_credentials() -> ClientAuthRequest<'static> {
  ClientAuthRequest {
    basic_header: None,
    client_id: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

//! `test(token_service)` suite: mint, hash-store, sender-constraint matrix.
//!
//! Shared Redis 7.2 container (AOF on) plus per-test connections; unique
//! grant/client labels keep the shared keyspace collision-free.

mod matrix;
mod mint_find;
mod peppers;
mod rotate;
mod shape;

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

use super::{ClientKind, Cnf, MintRequest, SenderProof, TokenService, TokenServiceError};
use crate::{
  config::{DurabilityMode, TtlConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the token-service test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error")]
  Store(#[from] StoreError),
  /// The token service failed.
  #[error("service error")]
  Service(#[from] TokenServiceError),
  /// The key ring was rejected.
  #[error("key ring error")]
  Keys(#[from] KeyRingError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// One shared Redis 7.2 container for the whole suite.
static REDIS: Shared<ContainerGuard> = Shared::new();

/// Fresh connection plus store handle against the shared container.
///
/// The returned lease keeps the container alive; bind it for the test.
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
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((container, RedisConn::Single(manager), store))
}

static TEST_NONCE: AtomicU64 = AtomicU64::new(50_000);

/// A label no other test uses, so grants/clients never collide.
fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("token-service-test-{n}-{label}")
}

/// A key ring from newest-first `(id, pepper)` pairs plus a dummy TOTP key.
fn ring(pairs: &[(&str, &str)]) -> Result<KeyRing, TestError> {
  let peppers = pairs
    .iter()
    .map(|(id, value)| (KeyId::new(*id), SecretString::from(*value)))
    .collect();
  KeyRing::from_parts(
    peppers,
    vec![(KeyId::new("v1"), SecretString::from("totp-test-secret"))],
    vec![(KeyId::new("v1"), SecretString::from("pii-test-secret"))],
  )
  .map_err(TestError::from)
}

/// A service over the default TTLs (access 300 s, refresh 30 d).
fn service(pairs: &[(&str, &str)]) -> Result<TokenService, TestError> {
  TokenService::new(&TtlConfig::default(), &ring(pairs)?).map_err(TestError::from)
}

/// A mint request with fixed subject/scope.
fn mint_request(client: &str, kind: ClientKind, grant: &str, proof: SenderProof) -> MintRequest {
  MintRequest {
    client_id: client.to_owned(),
    client_kind: kind,
    subject: "user-1".to_owned(),
    scope: "orders:read".to_owned(),
    grant_id: grant.to_owned(),
    proof,
  }
}

/// Current time as seconds since the Unix epoch.
fn now_unix() -> i64 {
  time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `cnf` storage shape round-trips per the matrix vocabulary.
#[test]
fn token_service_cnf_storage_round_trip() -> TestResult {
  let unbound = Cnf::default();
  if unbound.is_bound() || !unbound.to_storage()?.is_empty() {
    return Err(TestError::Unexpected(
      "unconstrained cnf must store as empty".to_owned(),
    ));
  }
  if Cnf::parse_storage("")? != unbound {
    return Err(TestError::Unexpected(
      "empty storage must parse as unbound".to_owned(),
    ));
  }
  let bound = Cnf {
    jkt: Some("jkt-value".to_owned()),
    x5t_s256: Some("x5t-value".to_owned()),
  };
  if !bound.is_bound() {
    return Err(TestError::Unexpected(
      "cnf with members must be bound".to_owned(),
    ));
  }
  let stored = bound.to_storage()?;
  if !stored.contains("jkt-value") || !stored.contains("x5t#S256") {
    return Err(TestError::Unexpected(
      "stored cnf must carry jkt and x5t#S256".to_owned(),
    ));
  }
  if Cnf::parse_storage(&stored)? != bound {
    return Err(TestError::Unexpected(
      "stored cnf must parse back identically".to_owned(),
    ));
  }
  if Cnf::parse_storage("{not json").is_ok() {
    return Err(TestError::Unexpected(
      "malformed cnf must be rejected".to_owned(),
    ));
  }
  Ok(())
}

//! `test(grant_refresh)` harness: shared Redis plus builders.
//!
//! Child suites drive the public [`super::super::refresh`] API. Every test
//! uses unique client/grant labels so the shared keyspace never collides.

mod concurrent;
mod disabled_subject;
mod entitlements;
mod failover;
mod proofs;
mod recovery;
mod reuse;
mod rotation;
mod scope;

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

use super::RefreshInput;
use crate::{
  config::{DurabilityMode, TtlConfig},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, MintedTokens, SenderProof, TokenService, TokenServiceError},
  },
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the refresh-grant test scaffolding itself.
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
  /// The grant (or scope parsing) failed.
  #[error("app error")]
  App(#[from] AppError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// One shared Redis 7.2 container for the whole suite.
static REDIS: Shared<ContainerGuard> = Shared::new();

/// Fresh connection plus store handle against the shared container, with the
/// container URL for opening extra connections (concurrency tests).
async fn test_redis() -> Result<(Lease<ContainerGuard>, RedisConn, Store, String), TestError> {
  let container = REDIS
    .lease::<TestError>(async {
      let started = GenericImage::new("redis", "7.2-alpine")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_cmd([
          "redis-server",
          "--appendonly",
          "yes",
          "--appendfsync",
          "always",
        ])
        .start()
        .await?;
      Ok(ContainerGuard::new(started))
    })
    .await?;
  let port = container.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let conn = connect(&url).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((container, conn, store, url))
}

/// A second connection against the same container URL.
async fn connect(url: &str) -> Result<RedisConn, TestError> {
  let client = redis::Client::open(url)?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  Ok(RedisConn::Single(manager))
}

static TEST_NONCE: AtomicU64 = AtomicU64::new(50_000);

/// A label no other test uses, so grants/clients never collide.
fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("grant-refresh-test-{n}-{label}")
}

/// A key ring with one pepper plus a dummy TOTP key.
fn ring() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("refresh-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("totp-test-secret"))],
    vec![(KeyId::new("v1"), SecretString::from("pii-test-secret"))],
  )
  .map_err(TestError::from)
}

/// A service over the default TTLs (access 300 s, refresh 30 d).
fn service() -> Result<TokenService, TestError> {
  TokenService::new(&TtlConfig::default(), &ring()?).map_err(TestError::from)
}

/// Current time as seconds since the Unix epoch.
fn now_unix() -> i64 {
  time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A DPoP-only proof for `jkt`.
fn dpop_proof(jkt: &str) -> SenderProof {
  SenderProof {
    dpop_jkt: Some(jkt.to_owned()),
    mtls_x5t_s256: None,
  }
}

/// An mTLS-only proof for `x5t`.
fn mtls_proof(x5t: &str) -> SenderProof {
  SenderProof {
    dpop_jkt: None,
    mtls_x5t_s256: Some(x5t.to_owned()),
  }
}

/// Mint an initial grant the tests can rotate; returns the minted pair.
async fn mint_grant(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  kind: ClientKind,
  scope: &str,
  proof: SenderProof,
) -> Result<MintedTokens, TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: client.to_owned(),
        client_kind: kind,
        subject: unique("subject"),
        scope: scope.to_owned(),
        grant_id: unique("grant"),
        proof,
      },
      now_unix(),
    )
    .await?;
  Ok(minted)
}

/// Baseline refresh inputs; tests override what they probe.
///
/// Redis-only suites carry no Postgres user, so the client registration and
/// the user entitlement both default to the enabled catalog (fully entitled):
/// scope assertions there probe narrowing/widening only. Suites with a real
/// user build [`RefreshInput`] literally with the current sets instead.
fn input<'a>(
  client: &'a str,
  kind: ClientKind,
  token: &'a str,
  scope: Option<&'a str>,
  proof: &'a SenderProof,
  enabled: &'a ScopeSet,
) -> RefreshInput<'a> {
  RefreshInput {
    client_id: client,
    client_kind: kind,
    refresh_token: token,
    requested_scope: scope,
    proof,
    enabled,
    client_registered: enabled,
    user_entitled: enabled,
    now_unix: now_unix(),
  }
}

/// Whether the rejection is `invalid_grant`.
fn is_invalid_grant(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidGrant
}

/// Whether the rejection is `invalid_scope`.
fn is_invalid_scope(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidScope
}

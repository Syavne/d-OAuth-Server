//! `test(grant_client_credentials)` suite: confidential-only, scope, bindings.
//!
//! Shared Redis 7.2 container plus per-test connections; unique client
//! labels keep the shared keyspace collision-free.

mod binding;
mod issue;

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

use super::{ClientCredentialsInput, ClientCredentialsTokens};
use crate::{
  config::{DurabilityMode, TtlConfig},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, SenderProof, TokenService, TokenServiceError},
  },
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the client-credentials test scaffolding itself.
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
  /// The issuance (or scope parsing) failed.
  #[error("app error")]
  App(#[from] AppError),
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
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((container, RedisConn::Single(manager), store))
}

static TEST_NONCE: AtomicU64 = AtomicU64::new(400_000);

/// A label no other test uses, so grants/clients never collide.
fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("client-credentials-test-{n}-{label}")
}

/// A key ring with one pepper plus a dummy TOTP key.
fn ring() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("cc-test-pepper"))],
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

/// An empty proof: no DPoP, no mTLS.
fn no_proof() -> SenderProof {
  SenderProof::none()
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

/// Shared issuance context for one client-credentials test.
struct Ctx<'a> {
  kind: ClientKind,
  registered: &'a ScopeSet,
  enabled: &'a ScopeSet,
  dpop_bound: Option<&'a str>,
  mtls_bound: Option<&'a str>,
  proof: &'a SenderProof,
}

/// Baseline issuance inputs; tests override what they probe.
fn input<'a>(
  client: &'a str,
  requested_scope: Option<&'a str>,
  ctx: &Ctx<'a>,
) -> ClientCredentialsInput<'a> {
  ClientCredentialsInput {
    client_id: client,
    client_kind: ctx.kind,
    client_registered: ctx.registered,
    enabled: ctx.enabled,
    requested_scope,
    dpop_bound_jkt: ctx.dpop_bound,
    mtls_bound_x5t_s256: ctx.mtls_bound,
    proof: ctx.proof,
    now_unix: now_unix(),
  }
}

/// Whether the error renders as `invalid_client`.
fn is_invalid_client(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidClient
}

/// Whether the error renders as `invalid_grant`.
fn is_invalid_grant(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidGrant
}

/// Whether the error renders as `invalid_scope`.
fn is_invalid_scope(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidScope
}

//! `test(grant_token_exchange)` suite: policy, proofs, scope pinning.
//!
//! Shared Redis 7.2 container plus per-test connections; unique client
//! labels keep the shared keyspace collision-free.

mod exchange_ok;
mod policy;
mod proof;

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

use super::{ExchangeInput, TOKEN_TYPE_ACCESS_TOKEN};
use crate::{
  config::{DurabilityMode, TokenExchangeRule, TtlConfig},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, SenderProof, TokenService, TokenServiceError},
  },
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the token-exchange test scaffolding itself.
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
  /// The exchange (or scope parsing) failed.
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

static TEST_NONCE: AtomicU64 = AtomicU64::new(90_000);

/// A label no other test uses, so grants/clients never collide.
fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("token-exchange-test-{n}-{label}")
}

/// A key ring with one pepper plus a dummy TOTP key.
fn ring() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("exchange-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("totp-test-secret"))],
    vec![(KeyId::new("v1"), SecretString::from("pii-test-secret"))],
  )
  .map_err(TestError::from)
}

/// A service over the default TTLs (access 300 s, refresh 30 d).
fn service() -> Result<TokenService, TestError> {
  TokenService::new(&TtlConfig::default(), &ring()?).map_err(TestError::from)
}

/// Mint a subject access token; returns its raw value.
async fn mint_subject(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  subject: &str,
  scope: &str,
  proof: SenderProof,
) -> Result<String, TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: client.to_owned(),
        client_kind: ClientKind::Confidential,
        subject: subject.to_owned(),
        scope: scope.to_owned(),
        grant_id: unique("subject-grant"),
        proof,
      },
      now_unix(),
    )
    .await?;
  Ok(minted.access_token)
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

/// Shared scope/policy context for one exchange test.
struct Ctx<'a> {
  caller_registered: &'a ScopeSet,
  entitled: &'a ScopeSet,
  enabled: &'a ScopeSet,
  allowlist: &'a [TokenExchangeRule],
  proof: &'a SenderProof,
}

/// Baseline exchange inputs; tests override what they probe.
fn input<'a>(
  caller: &'a str,
  subject_token: &'a str,
  requested_scope: Option<&'a str>,
  ctx: &Ctx<'a>,
) -> ExchangeInput<'a> {
  ExchangeInput {
    caller_client_id: caller,
    caller_kind: ClientKind::Confidential,
    caller_registered: ctx.caller_registered,
    subject_token,
    subject_token_type: TOKEN_TYPE_ACCESS_TOKEN,
    actor_token: None,
    actor_token_type: None,
    requested_token_type: None,
    requested_scope,
    subject_user_entitled: ctx.entitled,
    enabled: ctx.enabled,
    allow_exchange: true,
    allowlist: ctx.allowlist,
    proof: ctx.proof,
    now_unix: now_unix(),
  }
}

/// The allowlist code of an `invalid_grant` rejection.
fn is_invalid_grant(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidGrant
}

/// The allowlist code of an `invalid_scope` rejection.
fn is_invalid_scope(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidScope
}

/// The allowlist code of an `invalid_request` rejection.
fn is_invalid_request(error: &AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidRequest
}

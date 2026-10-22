//! `test(grant_token_exchange)` suite: policy, proofs, scope pinning.
//!
//! Connects to the shared compose Redis with a per-test unique key prefix
//! pair; unique client labels keep the keyspace collision-free.

mod exchange_ok;
mod policy;
mod proof;

use std::sync::atomic::{AtomicU64, Ordering};

use secrecy::SecretString;

use super::{ExchangeInput, TOKEN_TYPE_ACCESS_TOKEN};
use crate::{
  config::{DurabilityMode, TokenExchangeRule, TtlConfig},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService, TokenServiceError},
  },
  state::RedisConn,
  store::{Store, StoreError},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the token-exchange test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
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

/// Fresh connection plus store handle against the shared compose Redis.
async fn test_redis() -> Result<(RedisConn, Store), TestError> {
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, rl_prefix, DurabilityMode::WaitAof);
  Ok((RedisConn::Single(manager), store))
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
        dpop_required: false,
        subject: subject.to_owned(),
        scope: scope.to_owned(),
        grant_id: unique("subject-grant"),
        proof,
        aud: Vec::new(),
        refresh_aud: Vec::new(),
        format: TokenFormat::Opaque,
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
    caller_dpop_required: false,
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

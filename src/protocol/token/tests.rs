//! `test(token_service)` suite: mint, hash-store, sender-constraint matrix.
//!
//! The shared compose Redis (`compose.test.yaml`) backs the token store; a
//! per-test unique `{state}`/`{rl}` prefix pair keeps the keyspace
//! collision-free, and unique grant/client labels keep lookups distinct.

mod jwt;
mod matrix;
mod mint_find;
mod peppers;
mod rotate;
mod shape;

use std::sync::atomic::{AtomicU64, Ordering};

use secrecy::SecretString;

use super::{
  ClientKind, Cnf, MintRequest, SenderProof, TokenFormat, TokenService, TokenServiceError,
};
use crate::{
  config::{DurabilityMode, TtlConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  state::RedisConn,
  store::{Store, StoreError},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the token-service test scaffolding itself.
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
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Fresh connection plus a scoped store handle against the shared compose
/// Redis. The `{state}`/`{rl}` prefixes are unique per test, so parallel tests
/// never observe each other's keys.
async fn test_redis() -> Result<(RedisConn, Store), TestError> {
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  Ok((RedisConn::Single(manager), store))
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
    dpop_required: kind == ClientKind::Public,
    subject: "user-1".to_owned(),
    scope: "orders:read".to_owned(),
    access_scope: "orders:read".to_owned(),
    grant_id: grant.to_owned(),
    proof,
    aud: Vec::new(),
    refresh_aud: Vec::new(),
    format: TokenFormat::Opaque,
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

/// An unbound public client mints a `Bearer` token with no DPoP proof.
#[tokio::test]
async fn public_unbound_gets_bearer() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "public-unbound-pepper")])?;
  let minted = service
    .mint(
      &mut conn,
      &store,
      &MintRequest {
        client_id: unique("public-unbound"),
        client_kind: ClientKind::Public,
        dpop_required: false,
        subject: "user-1".to_owned(),
        scope: "orders:read".to_owned(),
        access_scope: "orders:read".to_owned(),
        grant_id: unique("grant"),
        proof: SenderProof::none(),
        aud: Vec::new(),
        refresh_aud: Vec::new(),
        format: TokenFormat::Opaque,
      },
      now_unix(),
    )
    .await?;
  if minted.cnf.is_bound() {
    return Err(TestError::Unexpected(
      "unbound public mint must carry no sender constraint".to_owned(),
    ));
  }
  Ok(())
}

/// A DPoP-bound public client still requires a proof at mint time.
#[tokio::test]
async fn public_bound_requires_dpop() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "public-bound-pepper")])?;
  match service
    .mint(
      &mut conn,
      &store,
      &MintRequest {
        client_id: unique("public-bound"),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: "user-1".to_owned(),
        scope: "orders:read".to_owned(),
        access_scope: "orders:read".to_owned(),
        grant_id: unique("grant"),
        proof: SenderProof::none(),
        aud: Vec::new(),
        refresh_aud: Vec::new(),
        format: TokenFormat::Opaque,
      },
      now_unix(),
    )
    .await
  {
    Err(TokenServiceError::MissingDpopBinding) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "bound public mint without proof must be MissingDpopBinding, got {other}"
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a bound public client must never mint proof-free".to_owned(),
    )),
  }
}

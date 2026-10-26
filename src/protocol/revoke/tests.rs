//! `test(revoke)` suite: ownership-scoped revocation and grant cascade.
//!
//! The shared compose Redis (`compose.test.yaml`) backs the token/grant stores;
//! a per-test unique `{state}`/`{rl}` prefix pair keeps the keyspace
//! collision-free, and unique grant/client labels keep lookups distinct.
//! Authentication-scoped behaviour that needs no database is exercised against
//! a lazy Postgres pool that is never dialed.

mod auth;
mod cascade;
mod jwt;
mod mtls;

use std::{
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};

use secrecy::SecretString;

use crate::{
  config::{DurabilityMode, TtlConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::{
    client_auth::ClientAuthRequest,
    token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService, TokenServiceError},
  },
  state::{AppState, Clock, RedisConn},
  store::{Store, StoreError},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the revocation test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
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

/// Fresh connection plus a scoped store handle against the shared compose
/// Redis, paired with the exact `{state}`/`{rl}` prefixes that scope the store.
async fn test_redis() -> Result<(RedisConn, Store, (String, String)), TestError> {
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(
    state_prefix.clone(),
    ratelimit_prefix.clone(),
    DurabilityMode::WaitAof,
  );
  Ok((
    RedisConn::Single(manager),
    store,
    (state_prefix, ratelimit_prefix),
  ))
}

/// A store handle with a fresh per-test unique key-prefix pair.
fn store() -> Store {
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  Store::from_parts(state_prefix, ratelimit_prefix, DurabilityMode::WaitAof)
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

/// An [`AppState`] for handler-level tests whose Postgres and Redis handles are
/// lazy and never dialed: the missing-`token` path is rejected before any
/// datastore call.
fn handler_state() -> Result<AppState, TestError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/revoke-test-cert.pem", "key_path": "/tmp/revoke-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/revoke"},
    "redis": {"url": "redis://127.0.0.1:1", "durability": "waitaof"},
    "token_pepper": "revoke-test-pepper-0123456789abcdef",
    "totp_encryption_key": "revoke-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "revoke-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  let config = crate::config::Config::from_source(source)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  Ok(AppState {
    pool: lazy_pool()?,
    redis: lazy_redis()?,
    config: Arc::new(config),
    keys: Arc::new(test_keys()?),
    transition_unsafe: Arc::new(AtomicBool::new(false)),
    clock: Clock::system(),
    cimd_fetcher: crate::protocol::cimd::ssrf_fetcher(),
  })
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
    vec![(KeyId::new("v1"), SecretString::from("revoke-test-pii"))],
  )?;
  TokenService::new(&TtlConfig::default(), &ring).map_err(TestError::from)
}

/// A PII key ring for the encrypted client lookup.
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("revoke-test-pepper-one"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("revoke-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("revoke-test-pii"))],
  )?)
}

/// A confidential-client mint request with fixed subject/scope.
fn mint_request(client: &str, grant: &str) -> MintRequest {
  MintRequest {
    client_id: client.to_owned(),
    client_kind: ClientKind::Confidential,
    dpop_required: false,
    subject: "user-1".to_owned(),
    scope: "orders:read".to_owned(),
    access_scope: "orders:read".to_owned(),
    grant_id: grant.to_owned(),
    proof: SenderProof::none(),
    aud: Vec::new(),
    refresh_aud: Vec::new(),
    format: TokenFormat::Opaque,
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

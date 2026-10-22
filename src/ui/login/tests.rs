//! `test(login)` harness: live Postgres + Redis, user provisioning, presessions.
//!
//! Child suites (`auth`, `enroll`) drive the public [`super`] API through
//! these helpers; every test owns a fresh database and a unique Redis prefix
//! pair on the shared compose Redis.

use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  time::Duration,
};

use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{LoginAttempt, LoginDeps, ensure_presession, login_csrf_token, session_cookie};
use crate::{
  config::Config,
  crypto::{
    secret::{Argon2Params, hash_secret},
    totp,
  },
  db::user_repo::{self, NewUser},
  state::RedisConn,
  store::Store,
  store::pending::{self, PendingAuth},
};

pub(super) mod auth;
pub(super) mod enroll;

/// Default source IP for harness login attempts: the composite lockout path
/// keys on the peer, so attempts without an explicit IP share this one.
pub(super) const TEST_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
/// Socket form of [`TEST_PEER_IP`] for handler-level `ConnectInfo` values.
pub(super) const TEST_PEER_SOCK: SocketAddr = SocketAddr::new(TEST_PEER_IP, 5000);

/// Test body result (no `unwrap`/`expect` under the deny lints).
pub(super) type TestResult = Result<(), TestError>;

/// Scaffolding failures for the login suites.
#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// Configuration was rejected.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// An application error escaped where success was required.
  #[error("app error: {0}")]
  App(#[from] crate::error::AppError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// A TOTP operation failed.
  #[error("totp error: {0}")]
  Totp(#[from] totp::TotpError),
  /// A secret-hash operation failed.
  #[error("secret hash error: {0}")]
  Secret(#[from] crate::crypto::secret::SecretHashError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Live handles for one test: pool, Redis, store, and validated config.
pub(super) struct Harness {
  /// Lease on the shared Postgres server (keeps the container alive).
  pub(super) _db: crate::test_guard::Lease<crate::db::test_support::Db>,
  /// Fresh migrated database for this test.
  pub(super) pool: PgPool,
  /// Live Redis connection.
  pub(super) conn: RedisConn,
  /// Store handle over the test keyspaces.
  pub(super) store: Store,
  /// Validated config (weak Argon2 for speed, test keys).
  pub(super) config: std::sync::Arc<Config>,
  /// Fixed clock midpoint of a TOTP step (deterministic codes).
  pub(super) now: OffsetDateTime,
  /// The step counter `now` sits in.
  pub(super) counter: u64,
}

/// Start Postgres (fresh DB) + Redis and validate a test config.
pub(super) async fn harness() -> Result<Harness, TestError> {
  let (db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg: {error}")))?;
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(
    state_prefix.clone(),
    rl_prefix.clone(),
    crate::config::DurabilityMode::WaitAof,
  );
  let fixture = json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/login-test-cert.pem", "key_path": "/tmp/login-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/login"},
    "redis": {
      "url": crate::test_support::test_redis_url(),
      "durability": "waitaof",
      "token_key_prefix": state_prefix,
      "ratelimit_key_prefix": rl_prefix,
    },
    "token_pepper": "login-test-pepper-0123456789abcdef",
    "totp_encryption_key": "login-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "login-test-pii-key-0123456789abcdef",
    "argon2": {"memory_kib": 8192, "iterations": 1, "parallelism": 1},
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config source: {error}")))?;
  let config = Config::from_source(source)?;
  // Pin the clock mid-step so generated codes never straddle a boundary.
  let wall = OffsetDateTime::now_utc().unix_timestamp().max(0);
  let wall = u64::try_from(wall).map_err(|_| TestError::Unexpected("clock".to_owned()))?;
  let counter = wall / totp::TOTP_STEP_SECS;
  let now = OffsetDateTime::from_unix_timestamp(
    counter
      .saturating_mul(totp::TOTP_STEP_SECS)
      .saturating_add(totp::TOTP_STEP_SECS / 2) as i64,
  )
  .map_err(|_| TestError::Unexpected("clock".to_owned()))?;
  Ok(Harness {
    _db: db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    config: std::sync::Arc::new(config),
    now,
    counter,
  })
}

/// Build HTTP handler state over the harness backends, so suites can drive
/// the public handlers (`get_login`, ...) directly instead of only the core.
pub(super) fn app_state(harness: &Harness) -> crate::state::AppState {
  crate::state::AppState {
    pool: harness.pool.clone(),
    redis: harness.conn.clone(),
    config: harness.config.clone(),
    keys: std::sync::Arc::new(harness.config.keys.clone()),
    transition_unsafe: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    clock: crate::state::Clock::fixed(harness.now),
  }
}

/// Borrow the harness into core dependencies.
pub(super) fn deps_of(harness: &mut Harness) -> LoginDeps<'_> {
  LoginDeps {
    pool: &harness.pool,
    conn: &mut harness.conn,
    store: &harness.store,
    keys: &harness.config.keys,
    config: &harness.config,
    now: harness.now,
  }
}

/// Argon2 parameters matching the test config (fast, still Argon2id).
fn test_params(harness: &Harness) -> Result<Argon2Params, TestError> {
  let raw = &harness.config.argon2;
  Ok(Argon2Params::new(
    raw.memory_kib,
    raw.iterations,
    raw.parallelism,
    32,
  )?)
}

/// A provisioned user plus its live second-factor material.
pub(super) struct TestUser {
  /// Primary key.
  pub(super) id: Uuid,
  /// Canonical email.
  pub(super) email: String,
  /// Plaintext password (for login attempts).
  pub(super) password: String,
  /// Plaintext TOTP secret, when enrolled.
  pub(super) totp_secret: Option<String>,
  /// Plaintext recovery codes, when enrolled.
  pub(super) recovery_codes: Vec<String>,
}

/// Provision a user; enroll TOTP (+ recovery codes) when asked.
pub(super) async fn create_user(
  harness: &mut Harness,
  email: &str,
  password: &str,
  must_change: bool,
  with_totp: bool,
) -> Result<TestUser, TestError> {
  let params = test_params(harness)?;
  let record = user_repo::create_user(
    &harness.pool,
    &harness.config.keys,
    harness.config.pii_dual_write,
    &NewUser {
      email: email.to_owned(),
      password_hash: hash_secret(password, &params)?,
      is_admin: false,
      must_change_password: must_change,
    },
  )
  .await?;
  let mut user = TestUser {
    id: record.id,
    email: record.email,
    password: password.to_owned(),
    totp_secret: None,
    recovery_codes: Vec::new(),
  };
  if with_totp {
    let secret = totp::generate_secret()?;
    let blob = totp::encrypt_secret(
      &harness.config.keys,
      &secret,
      !harness.config.pii_dual_write,
    )?;
    if !user_repo::set_totp_secret(&harness.pool, user.id, &blob).await? {
      return Err(TestError::Unexpected("totp enroll failed".to_owned()));
    }
    let codes = totp::generate_recovery_codes()?;
    let mut hashes = Vec::with_capacity(codes.len());
    for code in &codes {
      hashes.push(hash_secret(code, &params)?);
    }
    if !user_repo::set_recovery_codes(&harness.pool, user.id, &hashes).await? {
      return Err(TestError::Unexpected("recovery store failed".to_owned()));
    }
    user.totp_secret = Some(secret);
    user.recovery_codes = codes;
  }
  Ok(user)
}

/// Current TOTP code for a user at the harness clock.
pub(super) fn current_code(user: &TestUser, harness: &Harness) -> Result<String, TestError> {
  let secret = user
    .totp_secret
    .as_deref()
    .ok_or_else(|| TestError::Unexpected("no totp secret".to_owned()))?;
  let verifier = totp::build_totp(secret)?;
  Ok(
    verifier
      .generate(harness.counter * totp::TOTP_STEP_SECS)
      .to_string(),
  )
}

/// A code guaranteed to differ from the current one (flip the first digit).
pub(super) fn wrong_code(user: &TestUser, harness: &Harness) -> Result<String, TestError> {
  let current = current_code(user, harness)?;
  let mut bytes = current.into_bytes();
  bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
  String::from_utf8(bytes).map_err(|_| TestError::Unexpected("code".to_owned()))
}

/// Fresh pre-session plus its login-CSRF token.
pub(super) async fn presession(harness: &mut Harness) -> Result<(String, String), TestError> {
  let mut deps = deps_of(harness);
  let (id, fresh) = ensure_presession(&mut deps, None).await?;
  if !fresh {
    return Err(TestError::Unexpected("presession must be fresh".to_owned()));
  }
  let csrf = login_csrf_token(&harness.config.keys, &id)?;
  Ok((id, csrf))
}

/// Build a login attempt for a user with an explicit code.
pub(super) fn attempt(
  presession_id: &str,
  csrf: &str,
  user: &TestUser,
  code: &str,
) -> LoginAttempt {
  LoginAttempt {
    presession_id: presession_id.to_owned(),
    email: user.email.clone(),
    password: user.password.clone(),
    code: code.to_owned(),
    csrf: csrf.to_owned(),
    peer_ip: Some(TEST_PEER_IP),
  }
}

/// Stash a pending-auth record and return its id.
pub(super) async fn pending_request(harness: &mut Harness) -> Result<String, TestError> {
  let request_id =
    pending::new_request_id().map_err(|_| TestError::Unexpected("rng".to_owned()))?;
  let record = PendingAuth {
    client_id: "login-test-client".to_owned(),
    redirect_uri: "https://client.example.test/cb".to_owned(),
    scope: "orders:read".to_owned(),
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    state: Some("state-xyz".to_owned()),
    dpop_jkt: None,
    iss: "https://auth.example.test".to_owned(),
    post_logout_uri: None,
    aud: Vec::new(),
  };
  pending::put(
    &mut harness.conn,
    &harness.store,
    &request_id,
    &record,
    Duration::from_secs(300),
  )
  .await?;
  Ok(request_id)
}

/// Render the session cookie as a `Set-Cookie` value for attribute asserts.
pub(super) fn cookie_header(harness: &Harness, session_id: &str) -> String {
  session_cookie(&harness.config, session_id).to_string()
}

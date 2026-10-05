//! `test(user_repo)` — shared-services Postgres + Redis coverage for
//! `db/{user_repo,scope_repo,user_scope_repo}` and the Redis lockout counters.
//!
//! Postgres backs the user/scope/entitlement assertions; the shared Redis
//! backs the failed-login/lockout assertions. Both come from
//! `compose.test.yaml` (`docker compose -f compose.test.yaml up -d`); each
//! test migrates a freshly created database and uses unique Redis key
//! prefixes, so parallel tests never share state (and never FLUSH shared
//! state). Test bodies use `Result` + `?` (`unwrap`/`expect`/`panic` are
//! denied workspace-wide).

use std::{error::Error, time::Duration};

use d_oauth::{
  config::DurabilityMode,
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    scope_repo,
    user_repo::{self, LockoutPolicy, NewUser, PasswordVerdict},
    user_scope_repo,
  },
  state::RedisConn,
  store::Store,
};
use sqlx::PgPool;

mod common;

use common::{fresh_migrated_db, redis_url, unique_prefixes};

/// Boxed test error.
type TestError = Box<dyn Error + Send + Sync>;

/// Fallible test body.
type TestResult = Result<(), TestError>;

/// Fast Argon2id parameters keep the hashing-dependent tests quick.
fn fast_params() -> Result<Argon2Params, TestError> {
  Ok(Argon2Params::new(8, 1, 1, 32)?)
}
/// Build a `NewUser` with a freshly hashed password.
fn new_user(
  email: &str,
  password: &str,
  is_admin: bool,
  must_change_password: bool,
) -> Result<NewUser, TestError> {
  Ok(NewUser {
    email: email.to_owned(),
    password_hash: hash_secret(password, &fast_params()?)?,
    is_admin,
    must_change_password,
  })
}

/// A pool on a freshly created, fully migrated database on the shared
/// test Postgres (see `tests/common/mod.rs`).
async fn postgres_pool() -> Result<PgPool, TestError> {
  Ok(fresh_migrated_db().await?)
}

/// A [`RedisConn`] plus [`Store`] on the shared test Redis with unique key
/// prefixes, so parallel tests never share state.
async fn redis_store() -> Result<(RedisConn, Store), TestError> {
  let url = redis_url();
  let client = redis::Client::open(url.as_str()).map_err(|error| {
    format!("cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`")
  })?;
  let manager = redis::aio::ConnectionManager::new(client).await.map_err(|error| {
    format!("cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`")
  })?;
  let (token_prefix, ratelimit_prefix) = unique_prefixes();
  let store = Store::from_parts(token_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  Ok((RedisConn::Single(manager), store))
}

/// Create/find normalizes the email and rejects a case-variant duplicate.
#[tokio::test]
async fn user_repo_create_and_find_is_case_insensitive() -> TestResult {
  let pool = postgres_pool().await?;

  let created = user_repo::create_user(
    &pool,
    &new_user("  Alice@Example.COM ", "pw-one", false, false)?,
  )
  .await?;
  assert_eq!(created.email, "alice@example.com");
  assert!(created.password_changed_at.is_some());
  assert!(!created.must_change_password);

  let found = user_repo::find_by_email(&pool, "ALICE@example.com")
    .await?
    .ok_or("user not found by case-variant email")?;
  assert_eq!(found.id, created.id);

  let duplicate = user_repo::create_user(
    &pool,
    &new_user("alice@example.com", "pw-two", false, false)?,
  )
  .await;
  assert!(
    duplicate.is_err(),
    "case-variant duplicate must be rejected"
  );

  assert!(
    user_repo::find_by_email(&pool, "missing@example.com")
      .await?
      .is_none()
  );
  Ok(())
}

/// Password verification matches/mismatches and refuses disabled accounts.
#[tokio::test]
async fn user_repo_verify_password() -> TestResult {
  let pool = postgres_pool().await?;
  let user = user_repo::create_user(
    &pool,
    &new_user("carol@example.com", "s3cret", false, true)?,
  )
  .await?;
  assert!(user.must_change_password);

  assert_eq!(
    user_repo::verify_password(&pool, "CAROL@example.com", "s3cret").await?,
    PasswordVerdict::Matched
  );
  assert_eq!(
    user_repo::verify_password(&pool, "carol@example.com", "wrong").await?,
    PasswordVerdict::Mismatched
  );
  assert_eq!(
    user_repo::verify_password(&pool, "nobody@example.com", "s3cret").await?,
    PasswordVerdict::Unknown
  );

  assert!(user_repo::disable_user(&pool, user.id).await?);
  assert_eq!(
    user_repo::verify_password(&pool, "carol@example.com", "s3cret").await?,
    PasswordVerdict::Disabled
  );
  Ok(())
}

/// TOTP secret set/clear/toggle plus one-time recovery-code consumption.
#[tokio::test]
async fn user_repo_totp_and_recovery_codes() -> TestResult {
  let pool = postgres_pool().await?;
  let user =
    user_repo::create_user(&pool, &new_user("dave@example.com", "pw", false, false)?).await?;

  assert!(user_repo::set_totp_secret(&pool, user.id, &[1, 2, 3, 4]).await?);
  assert!(user_repo::set_totp_enabled(&pool, user.id, true).await?);
  assert!(user_repo::clear_totp_secret(&pool, user.id).await?);

  let code = "RECOVERY-CODE-ONE";
  let hash = hash_secret(code, &fast_params()?)?;
  assert!(user_repo::set_recovery_codes(&pool, user.id, std::slice::from_ref(&hash)).await?);

  assert!(user_repo::consume_recovery_code(&pool, user.id, code).await?);
  assert!(
    !user_repo::consume_recovery_code(&pool, user.id, code).await?,
    "a recovery code is single-use"
  );
  assert!(!user_repo::consume_recovery_code(&pool, user.id, "WRONG").await?);
  Ok(())
}

/// Admin counting/promote/demote and password rotation semantics.
#[tokio::test]
async fn user_repo_admin_and_password_rotation() -> TestResult {
  let pool = postgres_pool().await?;
  assert!(!user_repo::has_any_admin(&pool).await?);

  let user =
    user_repo::create_user(&pool, &new_user("erin@example.com", "first", false, true)?).await?;
  assert!(!user_repo::has_any_admin(&pool).await?);
  assert!(user_repo::set_admin(&pool, user.id, true).await?);
  assert!(user_repo::has_any_admin(&pool).await?);

  // A disabled admin does not count toward the bootstrap gate.
  assert!(user_repo::disable_user(&pool, user.id).await?);
  assert!(!user_repo::has_any_admin(&pool).await?);

  // set_password clears must_change_password and stamps password_changed_at.
  let rotated = hash_secret("second", &fast_params()?)?;
  assert!(user_repo::set_password(&pool, user.id, &rotated).await?);
  let refreshed = user_repo::find_by_email(&pool, "erin@example.com")
    .await?
    .ok_or("user missing after password rotation")?;
  assert!(!refreshed.must_change_password);
  assert!(refreshed.password_changed_at.is_some());
  assert_eq!(
    user_repo::verify_password(&pool, "erin@example.com", "second").await?,
    PasswordVerdict::Disabled,
    "the account is still disabled until re-enabled"
  );
  Ok(())
}

/// Scope catalog: upsert idempotency, enable/disable, guarded delete, and
/// entitlement round-trips.
#[tokio::test]
async fn user_repo_scope_and_entitlement_round_trip() -> TestResult {
  let pool = postgres_pool().await?;

  let created = scope_repo::upsert(&pool, "api:read", "Read API").await?;
  assert!(created.enabled);
  let updated = scope_repo::upsert(&pool, "api:read", "Read API v2").await?;
  assert_eq!(updated.description, "Read API v2");

  assert_eq!(scope_repo::list_enabled(&pool).await?.len(), 1);
  assert!(scope_repo::set_enabled(&pool, "api:read", false).await?);
  assert!(scope_repo::list_enabled(&pool).await?.is_empty());

  let user =
    user_repo::create_user(&pool, &new_user("frank@example.com", "pw", false, false)?).await?;
  user_scope_repo::entitle(&pool, user.id, "api:read", None).await?;
  user_scope_repo::entitle(&pool, user.id, "api:read", None).await?;
  assert_eq!(
    user_scope_repo::list_for_user(&pool, user.id).await?,
    vec!["api:read".to_owned()]
  );
  assert!(user_scope_repo::is_entitled(&pool, user.id, "api:read").await?);

  // A referenced scope cannot be deleted; revoking the entitlement frees it.
  assert!(!scope_repo::delete_if_unreferenced(&pool, "api:read").await?);
  assert!(user_scope_repo::revoke(&pool, user.id, "api:read").await?);
  assert!(!user_scope_repo::is_entitled(&pool, user.id, "api:read").await?);
  assert!(scope_repo::delete_if_unreferenced(&pool, "api:read").await?);
  assert!(scope_repo::get(&pool, "api:read").await?.is_none());
  Ok(())
}

/// Redis lockout: threshold locks, label is case-insensitive, clear-on-success
/// and TTL expiry both unlock; a correct password while locked is still gated.
#[tokio::test]
async fn user_repo_lockout_locks_after_threshold_and_clears() -> TestResult {
  let (mut conn, store) = redis_store().await?;
  let policy = LockoutPolicy::new(3, Duration::from_millis(600)).ok_or("invalid policy")?;
  let label = "Locked@Example.com";

  for _ in 0..3 {
    user_repo::register_login_failure(&mut conn, &store, policy, label).await?;
  }
  assert!(user_repo::is_locked_out(&mut conn, &store, policy, label).await?);
  assert_eq!(
    user_repo::login_failure_count(&mut conn, &store, "locked@example.com").await?,
    3,
    "counter is keyed by the normalized label"
  );
  assert!(
    user_repo::lockout_remaining(&mut conn, &store, label)
      .await?
      .is_some()
  );

  // Clear-on-success unlocks immediately.
  user_repo::clear_login_failures(&mut conn, &store, label).await?;
  assert_eq!(
    user_repo::login_failure_count(&mut conn, &store, label).await?,
    0
  );
  assert!(!user_repo::is_locked_out(&mut conn, &store, policy, label).await?);

  // TTL expiry (unlock policy) also releases the lock.
  for _ in 0..3 {
    user_repo::register_login_failure(&mut conn, &store, policy, label).await?;
  }
  assert!(user_repo::is_locked_out(&mut conn, &store, policy, label).await?);
  tokio::time::sleep(Duration::from_millis(800)).await;
  assert_eq!(
    user_repo::login_failure_count(&mut conn, &store, label).await?,
    0
  );
  assert!(!user_repo::is_locked_out(&mut conn, &store, policy, label).await?);
  Ok(())
}

/// A correct password is still rejected by the gate while the account is
/// locked: the repo verifies the secret but `is_locked_out` must deny login.
#[tokio::test]
async fn user_repo_lockout_gate_rejects_correct_password() -> TestResult {
  let pool = postgres_pool().await?;
  let (mut conn, store) = redis_store().await?;
  user_repo::create_user(
    &pool,
    &new_user("gina@example.com", "correct", false, false)?,
  )
  .await?;
  let policy = LockoutPolicy::new(2, Duration::from_secs(60)).ok_or("invalid policy")?;

  for _ in 0..2 {
    user_repo::register_login_failure(&mut conn, &store, policy, "gina@example.com").await?;
  }

  let locked = user_repo::is_locked_out(&mut conn, &store, policy, "gina@example.com").await?;
  let verdict = user_repo::verify_password(&pool, "gina@example.com", "correct").await?;
  assert_eq!(
    verdict,
    PasswordVerdict::Matched,
    "password itself is valid"
  );
  assert!(locked, "login must refuse despite the valid password");
  Ok(())
}

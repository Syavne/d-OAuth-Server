//! `test(user_repo)` — real `testcontainers` Postgres + Redis coverage for
//! `db/{user_repo,scope_repo,user_scope_repo}` and the Redis lockout counters.
//!
//! Postgres backs the user/scope/entitlement assertions; a single-node Redis
//! backs the failed-login/lockout assertions. Test bodies use `Result` + `?`
//! (`unwrap`/`expect`/`panic` are denied workspace-wide).

use std::{error::Error, time::Duration};

use d_oauth::{
  config::DurabilityMode,
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    scope_repo,
    user_repo::{self, LockoutPolicy, NewUser, PasswordVerdict},
    user_scope_repo,
  },
  state::{MIGRATOR, RedisConn},
  store::Store,
};
use sqlx::PgPool;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use test_guard::ContainerGuard;

/// Boxed test error.
type TestError = Box<dyn Error + Send + Sync>;

/// Fallible test body.
type TestResult = Result<(), TestError>;

/// Throwaway Postgres superuser password.
const PG_PASSWORD: &str = "user-repo-test-secret";

/// Fast Argon2id parameters keep container-backed tests quick.
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

/// Start Postgres, apply every migration, and return the pool.
///
/// The guard removes the container synchronously when the test drops it.
async fn postgres_pool() -> Result<(ContainerGuard, PgPool), TestError> {
  let container = GenericImage::new("postgres", "latest")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_wait_for(WaitFor::message_on_stdout(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  let pool = PgPool::connect(&url).await?;
  MIGRATOR.run(&pool).await?;
  Ok((guarded, pool))
}

/// Start a single-node Redis and return a [`RedisConn`] plus [`Store`].
///
/// The guard removes the container synchronously when the test drops it.
async fn redis_store() -> Result<(ContainerGuard, RedisConn, Store), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(vec!["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(url.as_str())?;
  let manager = redis::aio::ConnectionManager::new(client).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((guarded, RedisConn::Single(manager), store))
}

/// Create/find normalizes the email and rejects a case-variant duplicate.
#[tokio::test]
async fn user_repo_create_and_find_is_case_insensitive() -> TestResult {
  let (_pg, pool) = postgres_pool().await?;

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
  let (_pg, pool) = postgres_pool().await?;
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
  let (_pg, pool) = postgres_pool().await?;
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
  let (_pg, pool) = postgres_pool().await?;
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
  let (_pg, pool) = postgres_pool().await?;

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
  let (_redis, mut conn, store) = redis_store().await?;
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
  let (_pg, pool) = postgres_pool().await?;
  let (_redis, mut conn, store) = redis_store().await?;
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

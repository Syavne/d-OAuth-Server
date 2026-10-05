//! Redis failed-login / lockout counters (used by the login flow).
//!
//! Counters live entirely in Redis, keyed by a hash of the normalized account
//! label, so the policy is shared across replicas and horizontal-scaling safe.
//! No lockout state is ever written to Postgres. The low-level counter
//! primitive is [`crate::store::sessions`]; this module owns the policy
//! (threshold, lock duration, unlock-on-success/expiry) on top of it.

use std::time::Duration;

use crate::{
  state::RedisConn,
  store::{self, Store, StoreError, sessions},
};

use super::normalize_email;

/// Login lockout policy: after `threshold` failures within `lock_duration`,
/// the account is locked until the counter's TTL expires or a successful login
/// clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
  /// Failures within the window that trigger a lock.
  pub threshold: u64,
  /// Fixed window that doubles as the lock duration.
  pub lock_duration: Duration,
}

impl LockoutPolicy {
  /// Validate a policy; `None` when the threshold is zero or the window empty.
  #[must_use]
  pub fn new(threshold: u64, lock_duration: Duration) -> Option<Self> {
    (threshold > 0 && !lock_duration.is_zero()).then_some(Self {
      threshold,
      lock_duration,
    })
  }

  /// Whether `count` failures meet or exceed the lock threshold.
  #[must_use]
  pub fn is_locked(&self, count: u64) -> bool {
    count >= self.threshold
  }
}

/// Record a failed login and return the in-window failure count.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn register_login_failure(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  account_label: &str,
) -> Result<u64, StoreError> {
  sessions::record_failed_login(
    conn,
    store,
    &normalize_email(account_label),
    policy.lock_duration,
  )
  .await
}

/// Current in-window failure count for an account label.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn login_failure_count(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<u64, StoreError> {
  sessions::failed_login_count(conn, store, &normalize_email(account_label)).await
}

/// Whether the account is currently locked out.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn is_locked_out(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  account_label: &str,
) -> Result<bool, StoreError> {
  let count = login_failure_count(conn, store, account_label).await?;
  Ok(policy.is_locked(count))
}

/// Clear the failed-login counter after a successful login.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn clear_login_failures(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<(), StoreError> {
  sessions::clear_failed_logins(conn, store, &normalize_email(account_label)).await
}

/// Remaining lockout time, or `None` when the account is not locked (the
/// counter is absent or has expired).
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn lockout_remaining(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<Option<Duration>, StoreError> {
  let key = store.login_fail_key(&store::sha256_hex(
    normalize_email(account_label).as_bytes(),
  ));
  let pttl: i64 = redis::cmd("PTTL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok((pttl > 0).then(|| Duration::from_millis(u64::try_from(pttl).unwrap_or(0))))
}

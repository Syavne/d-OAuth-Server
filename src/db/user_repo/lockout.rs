//! Redis failed-login / lockout counters (used by the login flow).
//!
//! Counters live entirely in Redis, keyed by a hash of the normalized account
//! label, so the policy is shared across replicas and horizontal-scaling safe.
//! No lockout state is ever written to Postgres. The low-level counter
//! primitive is [`crate::store::sessions`]; this module owns the policy
//! (threshold, lock duration, unlock-on-success/expiry) on top of it.
//!
//! T3-C1 composite policy: every failure increments both the per-account
//! counter (a global abuse cap) and the per-(IP, account) composite counter.
//! An account is locked for a source IP when either bucket reaches its
//! threshold, so failures from one IP never lock the account for another IP
//! while a distributed burst still trips the global cap. Failures for absent
//! labels never mint per-label keys; they share the source IP's single
//! unknown bucket, so label enumeration cannot spray the keyspace.

use std::{net::IpAddr, time::Duration};

use crate::{
  state::RedisConn,
  store::{self, Store, StoreError, sessions},
};

use super::normalize_email;

/// Login lockout policy: after `threshold` failures from one IP for one
/// account within `lock_duration`, that IP is locked out for the account;
/// after `account_threshold` failures from any IPs in the window, the account
/// is locked globally. The window doubles as the lock duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
  /// Failures from one IP for one account within the window that lock it.
  pub threshold: u64,
  /// Failures from any IPs within the window that lock the account globally.
  pub account_threshold: u64,
  /// Fixed window that doubles as the lock duration.
  pub lock_duration: Duration,
}

impl LockoutPolicy {
  /// Validate a policy; `None` when either threshold is zero or the window
  /// is empty.
  #[must_use]
  pub fn new(threshold: u64, account_threshold: u64, lock_duration: Duration) -> Option<Self> {
    (threshold > 0 && account_threshold > 0 && !lock_duration.is_zero()).then_some(Self {
      threshold,
      account_threshold,
      lock_duration,
    })
  }

  /// Whether `count` failures meet or exceed the per-IP lock threshold.
  #[must_use]
  pub fn is_locked(&self, count: u64) -> bool {
    count >= self.threshold
  }

  /// Whether `count` failures meet or exceed the global account cap.
  #[must_use]
  pub fn is_account_locked(&self, count: u64) -> bool {
    count >= self.account_threshold
  }
}

/// Source-IP identity for composite keying: the peer address, or the fixed
/// `unknown-peer` bucket when the peer is absent (one bounded key shared by
/// all peer-less attempts, never a raw value in Redis).
fn ip_label(peer_ip: Option<IpAddr>) -> String {
  peer_ip.map_or_else(|| "unknown-peer".to_owned(), |ip| ip.to_string())
}

/// Record a failed login and return the in-window failure count for this
/// source.
///
/// Both the per-account counter and, when the peer is known, the composite
/// per-(IP, account) counter advance. The returned count is the composite one
/// for a known peer and the account one otherwise.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn register_login_failure(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  account_label: &str,
  peer_ip: Option<IpAddr>,
) -> Result<u64, StoreError> {
  let canonical = normalize_email(account_label);
  let account =
    sessions::record_failed_login(conn, store, &canonical, policy.lock_duration).await?;
  let Some(peer) = peer_ip else {
    return Ok(account);
  };
  sessions::record_ip_failure(
    conn,
    store,
    &ip_label(Some(peer)),
    &canonical,
    policy.lock_duration,
  )
  .await
}

/// Record a failed login for an absent account label and return the
/// in-window unknown count for this source.
///
/// No per-label key is created: the attempt counts toward the source IP's
/// single shared bucket, keeping the keyspace bounded under enumeration.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn register_unknown_failure(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  peer_ip: Option<IpAddr>,
) -> Result<u64, StoreError> {
  sessions::record_unknown_failure(conn, store, &ip_label(peer_ip), policy.lock_duration).await
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

/// Current in-window composite count for one source IP and account label
/// (`0` when the peer is absent: peer-less attempts track the account
/// counter only).
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn ip_failure_count(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
  peer_ip: Option<IpAddr>,
) -> Result<u64, StoreError> {
  let Some(peer) = peer_ip else {
    return Ok(0);
  };
  sessions::ip_failure_count(
    conn,
    store,
    &ip_label(Some(peer)),
    &normalize_email(account_label),
  )
  .await
}

/// Current in-window unknown-label count for one source.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn unknown_failure_count(
  conn: &mut RedisConn,
  store: &Store,
  peer_ip: Option<IpAddr>,
) -> Result<u64, StoreError> {
  sessions::unknown_failure_count(conn, store, &ip_label(peer_ip)).await
}

/// Whether the account is currently locked out for this source: the
/// composite per-(IP, account) bucket reached `threshold`, or the global
/// per-account counter reached `account_threshold`.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn is_locked_out(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  account_label: &str,
  peer_ip: Option<IpAddr>,
) -> Result<bool, StoreError> {
  let canonical = normalize_email(account_label);
  let account = sessions::failed_login_count(conn, store, &canonical).await?;
  if policy.is_account_locked(account) {
    return Ok(true);
  }
  let Some(peer) = peer_ip else {
    return Ok(false);
  };
  let composite =
    sessions::ip_failure_count(conn, store, &ip_label(Some(peer)), &canonical).await?;
  Ok(policy.is_locked(composite))
}

/// Whether unknown labels are currently locked out for this source: the
/// source IP's shared unknown bucket reached `threshold`.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn is_unknown_locked_out(
  conn: &mut RedisConn,
  store: &Store,
  policy: LockoutPolicy,
  peer_ip: Option<IpAddr>,
) -> Result<bool, StoreError> {
  let count = sessions::unknown_failure_count(conn, store, &ip_label(peer_ip)).await?;
  Ok(policy.is_locked(count))
}

/// Clear the failed-login counters after a successful login: the per-account
/// counter and this source's composite bucket. Other sources' buckets keep
/// their TTL, so a successful login does not release an attacker's IP.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn clear_login_failures(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
  peer_ip: Option<IpAddr>,
) -> Result<(), StoreError> {
  let canonical = normalize_email(account_label);
  sessions::clear_failed_logins(conn, store, &canonical).await?;
  if let Some(peer) = peer_ip {
    sessions::clear_ip_failures(conn, store, &ip_label(Some(peer)), &canonical).await?;
  }
  Ok(())
}

/// Clear every lockout counter for an account label: the per-account counter
/// and all per-IP composite buckets. Backs the `user unlock` admin command.
///
/// Returns the number of keys removed. The unknown buckets carry no label
/// and are never touched.
///
/// # Errors
/// Returns a [`StoreError`] when Redis is unavailable.
pub async fn unlock_login(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<u64, StoreError> {
  let account_hash = store::sha256_hex(normalize_email(account_label).as_bytes());
  let account_key = store.login_fail_key(&account_hash);
  let mut removed = 0;
  let deleted: i64 = redis::cmd("DEL")
    .arg(&account_key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  removed += u64::try_from(deleted).unwrap_or(0);
  let pattern = format!("{}*:{account_hash}", store.login_fail_ip_prefix());
  let mut cursor = "0".to_owned();
  loop {
    let (next, batch): (String, Vec<String>) = redis::cmd("SCAN")
      .arg(&cursor)
      .arg("MATCH")
      .arg(&pattern)
      .arg("COUNT")
      .arg(100)
      .query_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    for key in &batch {
      let deleted: i64 = redis::cmd("DEL")
        .arg(key)
        .query_async(conn)
        .await
        .map_err(StoreError::Redis)?;
      removed += u64::try_from(deleted).unwrap_or(0);
    }
    if next == "0" {
      break;
    }
    cursor = next;
  }
  Ok(removed)
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

#[cfg(test)]
mod tests {
  use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
  };

  use super::{
    LockoutPolicy, clear_login_failures, ip_failure_count, is_locked_out, is_unknown_locked_out,
    login_failure_count, register_login_failure, register_unknown_failure, unknown_failure_count,
    unlock_login,
  };
  use crate::{config::DurabilityMode, state::RedisConn, store::Store};

  fn attacker_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
  }

  fn victim_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))
  }

  fn policy() -> Result<LockoutPolicy, Box<dyn std::error::Error + Send + Sync>> {
    LockoutPolicy::new(5, 20, Duration::from_secs(900)).ok_or("invalid policy".into())
  }

  async fn harness() -> Result<(RedisConn, Store), TestError> {
    let manager = crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
    let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
    let store = Store::from_parts(state_prefix, rl_prefix, DurabilityMode::WaitAof);
    Ok((RedisConn::Single(manager), store))
  }

  #[derive(Debug, thiserror::Error)]
  enum TestError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  type TestResult = Result<(), TestError>;

  async fn scan_login_fail(conn: &mut RedisConn, store: &Store) -> Result<Vec<String>, TestError> {
    let pattern = format!("{}*", store.login_fail_prefix());
    let mut cursor = "0".to_owned();
    let mut out = Vec::new();
    loop {
      let (next, batch): (String, Vec<String>) = redis::cmd("SCAN")
        .arg(&cursor)
        .arg("MATCH")
        .arg(&pattern)
        .arg("COUNT")
        .arg(100)
        .query_async(conn)
        .await?;
      out.extend(batch);
      if next == "0" {
        break;
      }
      cursor = next;
    }
    Ok(out)
  }

  /// T3-C1 (a): five failures from an attacker IP lock that IP's composite
  /// bucket only; the same account from a different IP is not locked.
  #[tokio::test]
  async fn lockout_attacker_ip_burst_does_not_lock_victim_ip() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = policy().map_err(|_| TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "victim@example.test";
    for _ in 0..5 {
      register_login_failure(&mut conn, &store, policy, label, Some(attacker_ip())).await?;
    }
    if !is_locked_out(&mut conn, &store, policy, label, Some(attacker_ip())).await? {
      return Err(TestError::Unexpected(
        "the attacker IP bucket must lock after the threshold".to_owned(),
      ));
    }
    if is_locked_out(&mut conn, &store, policy, label, Some(victim_ip())).await? {
      return Err(TestError::Unexpected(
        "the victim IP must not inherit the attacker IP lockout".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 (b): unknown labels never mint per-label keys; every unknown
  /// attempt from one IP lands in that IP's single bounded bucket.
  #[tokio::test]
  async fn lockout_unknown_labels_share_one_bounded_bucket() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = policy().map_err(|_| TestError::Unexpected("invalid policy".to_owned()))?;
    for _ in 0..25 {
      register_unknown_failure(&mut conn, &store, policy, Some(attacker_ip())).await?;
    }
    if !is_unknown_locked_out(&mut conn, &store, policy, Some(attacker_ip())).await? {
      return Err(TestError::Unexpected(
        "the unknown bucket must lock after the threshold".to_owned(),
      ));
    }
    if is_unknown_locked_out(&mut conn, &store, policy, Some(victim_ip())).await? {
      return Err(TestError::Unexpected(
        "the unknown lockout must not leak across IPs".to_owned(),
      ));
    }
    if unknown_failure_count(&mut conn, &store, Some(attacker_ip())).await? != 25 {
      return Err(TestError::Unexpected(
        "the unknown bucket must count every attempt".to_owned(),
      ));
    }
    let keys = scan_login_fail(&mut conn, &store).await?;
    if keys.len() != 1 {
      return Err(TestError::Unexpected(format!(
        "25 unknown labels must leave exactly one key, found {}",
        keys.len()
      )));
    }
    Ok(())
  }

  /// T3-C1 (c): the admin unlock clears the account counter and every
  /// per-IP composite bucket for the label.
  #[tokio::test]
  async fn lockout_unlock_clears_composite_and_account() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(2, 4, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "locked@example.test";
    for _ in 0..2 {
      register_login_failure(&mut conn, &store, policy, label, Some(attacker_ip())).await?;
      register_login_failure(&mut conn, &store, policy, label, Some(victim_ip())).await?;
    }
    if !is_locked_out(&mut conn, &store, policy, label, Some(attacker_ip())).await?
      || !is_locked_out(&mut conn, &store, policy, label, Some(victim_ip())).await?
    {
      return Err(TestError::Unexpected(
        "both IP buckets must lock before unlock".to_owned(),
      ));
    }
    let removed = unlock_login(&mut conn, &store, label).await?;
    if removed < 3 {
      return Err(TestError::Unexpected(format!(
        "unlock must remove the account and both composite keys, removed {removed}"
      )));
    }
    if is_locked_out(&mut conn, &store, policy, label, Some(attacker_ip())).await?
      || is_locked_out(&mut conn, &store, policy, label, Some(victim_ip())).await?
    {
      return Err(TestError::Unexpected(
        "unlock must release every IP bucket".to_owned(),
      ));
    }
    if ip_failure_count(&mut conn, &store, label, Some(attacker_ip())).await? != 0 {
      return Err(TestError::Unexpected(
        "unlock must clear the composite counter".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 (a-ii): the global account cap locks even a never-seen IP while
  /// every source stays below the per-IP threshold (distributed burst).
  #[tokio::test]
  async fn lockout_global_cap_locks_fresh_ip_while_each_ip_below_threshold() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(5, 8, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "global-cap@example.test";
    let sources = [
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)),
    ];
    for source in sources {
      for _ in 0..2 {
        register_login_failure(&mut conn, &store, policy, label, Some(source)).await?;
      }
    }
    for source in sources {
      if ip_failure_count(&mut conn, &store, label, Some(source)).await? != 2 {
        return Err(TestError::Unexpected(
          "each source must stay below the per-IP threshold".to_owned(),
        ));
      }
    }
    // Four sources times two failures meets the global cap of eight, so an
    // IP that never failed is locked too.
    let fresh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
    if !is_locked_out(&mut conn, &store, policy, label, Some(fresh)).await? {
      return Err(TestError::Unexpected(
        "the global cap must lock an IP that never failed".to_owned(),
      ));
    }
    if !is_locked_out(&mut conn, &store, policy, label, None).await? {
      return Err(TestError::Unexpected(
        "the global cap must lock the peer-less path too".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 peer-less path: without a source IP only the per-account counter
  /// advances; no composite bucket is minted and the clear removes just it.
  #[tokio::test]
  async fn lockout_peerless_attempts_track_account_counter_only() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(5, 20, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "peerless@example.test";
    for want in 1..=2u64 {
      let count = register_login_failure(&mut conn, &store, policy, label, None).await?;
      if count != want {
        return Err(TestError::Unexpected(format!(
          "peer-less attempts must return the account count, want {want}, got {count}"
        )));
      }
    }
    if ip_failure_count(&mut conn, &store, label, None).await? != 0 {
      return Err(TestError::Unexpected(
        "peer-less attempts must not mint a composite bucket".to_owned(),
      ));
    }
    if is_locked_out(&mut conn, &store, policy, label, None).await? {
      return Err(TestError::Unexpected(
        "two peer-less failures must not lock under a 5/20 policy".to_owned(),
      ));
    }
    let keys = scan_login_fail(&mut conn, &store).await?;
    if keys.len() != 1 {
      return Err(TestError::Unexpected(format!(
        "peer-less attempts must leave exactly one key, found {}",
        keys.len()
      )));
    }
    clear_login_failures(&mut conn, &store, label, None).await?;
    if login_failure_count(&mut conn, &store, label).await? != 0 {
      return Err(TestError::Unexpected(
        "a peer-less clear must reset the account counter".to_owned(),
      ));
    }
    if !scan_login_fail(&mut conn, &store).await?.is_empty() {
      return Err(TestError::Unexpected(
        "a peer-less clear must leave no lockout keys".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 (c-ii): a successful login clears the account counter and only
  /// the calling IP's composite bucket; another IP's locked bucket survives.
  #[tokio::test]
  async fn lockout_clear_success_releases_only_calling_ip() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(5, 100, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "scoped-clear@example.test";
    for _ in 0..5 {
      register_login_failure(&mut conn, &store, policy, label, Some(attacker_ip())).await?;
      register_login_failure(&mut conn, &store, policy, label, Some(victim_ip())).await?;
    }
    clear_login_failures(&mut conn, &store, label, Some(attacker_ip())).await?;
    if login_failure_count(&mut conn, &store, label).await? != 0 {
      return Err(TestError::Unexpected(
        "success must reset the per-account counter".to_owned(),
      ));
    }
    if ip_failure_count(&mut conn, &store, label, Some(attacker_ip())).await? != 0 {
      return Err(TestError::Unexpected(
        "success must clear the calling IP bucket".to_owned(),
      ));
    }
    if ip_failure_count(&mut conn, &store, label, Some(victim_ip())).await? != 5 {
      return Err(TestError::Unexpected(
        "success must leave the other IP bucket locked".to_owned(),
      ));
    }
    if is_locked_out(&mut conn, &store, policy, label, Some(attacker_ip())).await? {
      return Err(TestError::Unexpected(
        "the calling IP must be released".to_owned(),
      ));
    }
    if !is_locked_out(&mut conn, &store, policy, label, Some(victim_ip())).await? {
      return Err(TestError::Unexpected(
        "the other IP must stay locked".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 addressing: composite buckets key on the IP's string form, so an
  /// IPv4 address and its IPv4-mapped IPv6 twin are deliberately distinct
  /// buckets (no cross-family normalization; each family locks alone).
  #[tokio::test]
  async fn lockout_ipv4_and_mapped_ipv6_use_distinct_buckets() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(5, 100, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "family-split@example.test";
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mapped: IpAddr = "::ffff:192.0.2.7"
      .parse()
      .map_err(|_| TestError::Unexpected("the mapped address must parse".to_owned()))?;
    if v4.to_string() == mapped.to_string() {
      return Err(TestError::Unexpected(
        "the test needs two string-distinct addresses".to_owned(),
      ));
    }
    for _ in 0..5 {
      register_login_failure(&mut conn, &store, policy, label, Some(v4)).await?;
    }
    if ip_failure_count(&mut conn, &store, label, Some(mapped)).await? != 0 {
      return Err(TestError::Unexpected(
        "the mapped twin must not share the IPv4 bucket".to_owned(),
      ));
    }
    if !is_locked_out(&mut conn, &store, policy, label, Some(v4)).await? {
      return Err(TestError::Unexpected(
        "the IPv4 bucket must lock".to_owned(),
      ));
    }
    if is_locked_out(&mut conn, &store, policy, label, Some(mapped)).await? {
      return Err(TestError::Unexpected(
        "the mapped twin must stay unlocked".to_owned(),
      ));
    }
    Ok(())
  }

  /// T3-C1 admin sweep: `unlock_login` pages past one `SCAN` batch (`COUNT`
  /// 100), removes the account key plus every composite bucket, and never
  /// touches the label-less unknown buckets.
  #[tokio::test]
  async fn lockout_unlock_sweeps_more_than_scan_page() -> TestResult {
    let (mut conn, store) = harness().await?;
    let policy = LockoutPolicy::new(5, 1_000_000, Duration::from_secs(900))
      .ok_or(TestError::Unexpected("invalid policy".to_owned()))?;
    let label = "paged-sweep@example.test";
    const SOURCES: usize = 150;
    for index in 0..SOURCES {
      let source = IpAddr::V4(Ipv4Addr::new(
        10,
        9,
        (index >> 8) as u8,
        (index & 0xff) as u8,
      ));
      register_login_failure(&mut conn, &store, policy, label, Some(source)).await?;
    }
    let before = scan_login_fail(&mut conn, &store).await?;
    if before.len() != SOURCES + 1 {
      return Err(TestError::Unexpected(format!(
        "150 sources plus the account key must mint 151 keys, found {}",
        before.len()
      )));
    }
    register_unknown_failure(&mut conn, &store, policy, Some(attacker_ip())).await?;
    let removed = unlock_login(&mut conn, &store, label).await?;
    if removed != (SOURCES as u64) + 1 {
      return Err(TestError::Unexpected(format!(
        "the sweep must remove all 151 keys, removed {removed}"
      )));
    }
    let after = scan_login_fail(&mut conn, &store).await?;
    if after.len() != 1 {
      return Err(TestError::Unexpected(format!(
        "only the unknown bucket must survive the sweep, found {}",
        after.len()
      )));
    }
    if unknown_failure_count(&mut conn, &store, Some(attacker_ip())).await? != 1 {
      return Err(TestError::Unexpected(
        "the sweep must leave the unknown bucket untouched".to_owned(),
      ));
    }
    let sample = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 3));
    if is_locked_out(&mut conn, &store, policy, label, Some(sample)).await? {
      return Err(TestError::Unexpected(
        "the sweep must release every bucket".to_owned(),
      ));
    }
    Ok(())
  }
}

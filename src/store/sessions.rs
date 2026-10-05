//! Server-side login sessions (opaque id cookie, rotated on login).
//!
//! Includes failed-login/lockout counters: security-ephemeral, Redis-only.
//! Counter keys hash the account label (never a raw email) and live under the
//! token-state prefix; the lockout policy itself belongs to the login flow.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{Store, StoreError, hset_record, retry_op, sha256_hex};
use crate::state::RedisConn;

/// A server-side login session record, keyed by its opaque id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
  /// Authenticated subject, empty while the login is still in progress.
  pub subject: String,
  /// Whether the session passed its second factor.
  pub mfa_verified: bool,
  /// Whether this is a restricted bootstrap session (must change password).
  pub restricted: bool,
}

impl SessionRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("subject".to_owned(), self.subject.clone()),
      ("mfa_verified".to_owned(), self.mfa_verified.to_string()),
      ("restricted".to_owned(), self.restricted.to_string()),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    let flag = |field: &str| match map.get(field).map(String::as_str) {
      Some("true") => Ok(true),
      Some("false") => Ok(false),
      _ => Err(StoreError::InvalidData),
    };
    Ok(Self {
      subject: get("subject")?,
      mfa_verified: flag("mfa_verified")?,
      restricted: flag("restricted")?,
    })
  }
}

/// Store a session record (idempotent rewrite).
pub async fn put(
  conn: &mut RedisConn,
  store: &Store,
  session_id: &str,
  record: &SessionRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.session_key(session_id);
  let pairs = record.to_pairs();
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(sessions_redis)
  })
  .map_err(StoreError::Redis)
}

/// Read a session record; `Ok(None)` when absent or expired.
pub async fn get(
  conn: &mut RedisConn,
  store: &Store,
  session_id: &str,
) -> Result<Option<SessionRecord>, StoreError> {
  let key = store.session_key(session_id);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(sessions_redis)
  })
  .map_err(StoreError::Redis)?;
  map
    .map(|fields| SessionRecord::from_map(&fields))
    .transpose()
}

/// Rotate a session on login: store the new record first, then delete the old
/// one, so a crash never loses the session.
pub async fn rotate(
  conn: &mut RedisConn,
  store: &Store,
  old_session_id: &str,
  new_session_id: &str,
  record: &SessionRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  put(conn, store, new_session_id, record, ttl).await?;
  let old_key = store.session_key(old_session_id);
  let _: () = redis::cmd("DEL")
    .arg(&old_key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

/// Destroy a session (logout); missing sessions destroy to success.
pub async fn destroy(
  conn: &mut RedisConn,
  store: &Store,
  session_id: &str,
) -> Result<(), StoreError> {
  let key = store.session_key(session_id);
  let _: () = redis::cmd("DEL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

/// Record a failed login for an account label and return the in-window count.
///
/// The label is hashed before keying so no raw email ever becomes a key.
pub async fn record_failed_login(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
  window: Duration,
) -> Result<u64, StoreError> {
  let key = store.login_fail_key(&sha256_hex(account_label.as_bytes()));
  // `INCR` is not idempotent: a single attempt, never retried. Over-counting
  // would lock accounts early, under-counting would weaken lockout.
  let mut invocation = super::SCRIPT_RATELIMIT_INCR.prepare_invoke();
  invocation.key(key.as_str());
  invocation.arg(window.as_millis() as u64);
  let count: u64 = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(count)
}

/// Read the in-window failed-login count for an account label.
pub async fn failed_login_count(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<u64, StoreError> {
  let key = store.login_fail_key(&sha256_hex(account_label.as_bytes()));
  let budget = store.retry_budget();
  retry_op!(conn, budget, async {
    redis::cmd("GET")
      .arg(&key)
      .query_async::<Option<u64>>(conn)
      .await
  })
  .map(|count| count.unwrap_or(0))
  .map_err(StoreError::Redis)
}

/// Clear the failed-login counter (successful login or lockout expiry).
pub async fn clear_failed_logins(
  conn: &mut RedisConn,
  store: &Store,
  account_label: &str,
) -> Result<(), StoreError> {
  let key = store.login_fail_key(&sha256_hex(account_label.as_bytes()));
  let _: () = redis::cmd("DEL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

fn sessions_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store session write failed")),
  }
}

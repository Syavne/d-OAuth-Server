//! Rate-limit counters (own keyspace: never evict token state).
//!
//! Low-level fixed-window counter primitive consumed by the rate-limit
//! middleware (task 13): atomic Lua `INCR` + `PEXPIRE`-on-first under the
//! `{rl}`-tagged prefix, so counters distribute across cluster shards and can
//! never share a slot with — or evict — token state. Buckets are SHA-256
//! hashed before keying (no raw IPs or client ids as keys). Counters are
//! `NonIdempotent`: a failed increment is never retried, and any store outage
//! propagates so the caller fails closed.

use std::time::Duration;

use super::{SCRIPT_RATELIMIT_INCR, Store, StoreError, sha256_hex};
use crate::state::RedisConn;

/// Outcome of one fixed-window counter check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
  /// Whether the request is within budget.
  pub allowed: bool,
  /// In-window count AFTER this increment.
  pub count: u64,
  /// Seconds until the window resets (for `Retry-After`).
  pub retry_after_secs: u64,
}

/// Hash a bucket label (IP, client id, endpoint) into a key suffix.
#[must_use]
pub fn hash_bucket(label: &str) -> String {
  sha256_hex(label.as_bytes())
}

/// Atomically increment the fixed-window counter for `bucket` and report
/// whether the call is within `limit`. Never retried: `INCR` is not
/// idempotent, and any error propagates for fail-closed handling.
pub async fn check_and_incr(
  conn: &mut RedisConn,
  store: &Store,
  bucket: &str,
  window: Duration,
  limit: u64,
) -> Result<RateLimitDecision, StoreError> {
  let key = store.ratelimit_key(&hash_bucket(bucket));
  let window_ms = window.as_millis() as u64;
  let mut invocation = SCRIPT_RATELIMIT_INCR.prepare_invoke();
  invocation.key(key.as_str());
  invocation.arg(window_ms);
  let count: u64 = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  let ttl_ms: i64 = redis::cmd("PTTL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(RateLimitDecision {
    allowed: count <= limit,
    count,
    retry_after_secs: retry_after_secs(ttl_ms, window),
  })
}

fn retry_after_secs(ttl_ms: i64, window: Duration) -> u64 {
  if ttl_ms > 0 {
    let secs = (ttl_ms as u64).div_ceil(1000);
    secs.max(1)
  } else {
    window.as_secs().max(1)
  }
}

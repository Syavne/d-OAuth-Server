//! Polling-interval enforcement (RFC 8628 §3.5 `slow_down`).
//!
//! The last attempt time rides a sidecar key derived from the device record
//! key, so it shares the `{state}` hash slot and expires with the record.

use super::{DevicePollError, PollState};
use crate::{
  error::AppError,
  store::{self, Store},
};

/// Polling-attempt sidecar: last poll time (Unix seconds) for a device hash.
///
/// It carries the device TTL so it can never outlive its record by more than
/// one issuance lifetime.
pub(super) fn poll_key(store: &Store, device_hash: &str) -> String {
  format!("{}:poll", store.device_key(device_hash))
}

/// Enforce the polling interval, counting this attempt.
///
/// A poll sooner than one interval after the previous attempt fails with
/// `slow_down`; the attempt still refreshes the marker so repeated fast
/// polls keep backing off instead of racing the window edge.
pub(super) async fn check_interval(
  state: &mut PollState<'_>,
  device_hash: &str,
) -> Result<(), DevicePollError> {
  let key = poll_key(state.store, device_hash);
  let last: Option<String> = redis::cmd("GET")
    .arg(&key)
    .query_async(state.conn)
    .await
    .map_err(store::StoreError::Redis)
    .map_err(AppError::from)?;
  if let Some(raw) = last {
    let last_secs = raw.parse::<i64>().map_err(|_| AppError::server_error())?;
    let elapsed = state.now_unix.saturating_sub(last_secs);
    let interval_secs = state.interval.as_secs() as i64;
    if elapsed < interval_secs {
      stamp_poll(state, &key).await?;
      let wait = interval_secs.saturating_sub(elapsed).max(1) as u64;
      return Err(DevicePollError::SlowDown {
        retry_after_secs: wait,
      });
    }
  }
  stamp_poll(state, &key).await?;
  Ok(())
}

/// Record this poll attempt under the device TTL.
async fn stamp_poll(state: &mut PollState<'_>, key: &str) -> Result<(), DevicePollError> {
  redis::cmd("SET")
    .arg(key)
    .arg(state.now_unix)
    .arg("PX")
    .arg(state.device_ttl.as_millis() as u64)
    .query_async::<()>(state.conn)
    .await
    .map_err(store::StoreError::Redis)
    .map_err(AppError::from)?;
  Ok(())
}

//! Polling-interval enforcement (RFC 8628 §3.5 `slow_down`).

use super::{DevicePollError, PollState};
use crate::{error::AppError, store::device as device_store};

/// Enforce the polling interval, counting this attempt.
///
/// A poll sooner than one interval after the previous attempt fails with
/// `slow_down`; the attempt still refreshes the marker so repeated fast
/// polls keep backing off instead of racing the window edge.
///
/// The read-compare-write runs as one Lua compare-and-set
/// ([`device_store::claim_poll_slot`]), so concurrent polls cannot both pass
/// the gate.
pub(super) async fn check_interval(
  state: &mut PollState<'_>,
  device_hash: &str,
) -> Result<(), DevicePollError> {
  let slot = device_store::claim_poll_slot(
    state.conn,
    state.store,
    device_hash,
    state.now_unix,
    state.interval,
    state.device_ttl,
  )
  .await
  .map_err(AppError::from)?;
  match slot {
    device_store::PollSlot::Allowed => Ok(()),
    device_store::PollSlot::SlowDown { retry_after_secs } => {
      Err(DevicePollError::SlowDown { retry_after_secs })
    }
  }
}

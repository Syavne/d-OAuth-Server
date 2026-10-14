//! `test(grant_device)` races: concurrent polls admit exactly one attempt.

use std::time::Duration;

use super::super::DevicePollError;
use super::super::PollState;
use super::super::interval::check_interval;
use super::flows::now_unix;
use super::{TestError, TestResult, harness, unique};
use crate::protocol::device::DEVICE_INTERVAL_SECS;
use crate::store::device::poll_key;

/// T3-B2: two polls racing at the same instant must not both pass the
/// interval gate. A GET-then-SET gate admits every concurrent reader; the
/// Lua compare-and-set admits exactly one and answers `slow_down` to the
/// loser while still advancing the stamp.
#[tokio::test]
async fn test_grant_device_concurrent_interval_admits_only_one() -> TestResult {
  let mut h = harness().await?;
  let device_hash = unique("device-race");
  let now = now_unix();
  let interval = Duration::from_secs(DEVICE_INTERVAL_SECS);
  for round in 0..50u32 {
    let sidecar = poll_key(&h.store, &device_hash);
    let _: () = redis::cmd("DEL")
      .arg(&sidecar)
      .query_async(&mut h.conn)
      .await?;
    let mut left_conn = h.conn.clone();
    let mut right_conn = h.conn.clone();
    let mut left = PollState {
      pool: &h.pool,
      conn: &mut left_conn,
      store: &h.store,
      keys: &h.config.keys,
      issuer: &h.config.issuer,
      device_ttl: h.config.ttl.device,
      interval,
      ttl: &h.config.ttl,
      now_unix: now,
    };
    let mut right = PollState {
      pool: &h.pool,
      conn: &mut right_conn,
      store: &h.store,
      keys: &h.config.keys,
      issuer: &h.config.issuer,
      device_ttl: h.config.ttl.device,
      interval,
      ttl: &h.config.ttl,
      now_unix: now,
    };
    let (left_outcome, right_outcome) = tokio::join!(
      check_interval(&mut left, device_hash.as_str()),
      check_interval(&mut right, device_hash.as_str())
    );
    let admitted = u8::from(left_outcome.is_ok()) + u8::from(right_outcome.is_ok());
    if admitted != 1 {
      return Err(TestError::Unexpected(format!(
        "round {round}: racing polls admitted {admitted}, want exactly one"
      )));
    }
    let loser = if left_outcome.is_ok() {
      right_outcome
    } else {
      left_outcome
    };
    if !matches!(loser, Err(DevicePollError::SlowDown { .. })) {
      return Err(TestError::Unexpected(format!(
        "round {round}: losing poll must be slow_down"
      )));
    }
  }
  Ok(())
}

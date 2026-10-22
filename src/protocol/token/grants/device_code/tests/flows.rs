//! Poll/authorize/decide drivers for `test(grant_device)` at pinned times.

use std::time::Duration;

use secrecy::SecretString;
use time::OffsetDateTime;

use super::super::{
  DevicePollError, DevicePollInputs, DeviceTokenResponse, PollState, poll_device,
};
use super::{Harness, TestError};
use crate::{
  error::AppError,
  protocol::{
    device::{
      DEVICE_INTERVAL_SECS, DeviceAuthorizationResponse, DeviceContext, DeviceHttpInputs,
      DeviceStores, authorize_device, hash_token,
    },
    token::TokenFormat,
  },
};

/// Pin "now" for one test; proofs and contexts share it, so no wall-clock
/// second flip can flake a freshness or interval assertion.
pub(super) fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// Issue through the device authorization endpoint at a pinned time.
pub(super) async fn authorize(
  h: &mut Harness,
  inputs: &DeviceHttpInputs<'_>,
  now: i64,
) -> Result<DeviceAuthorizationResponse, AppError> {
  authorize_with_resources(h, inputs, now, false).await
}

/// Issue with an explicit `resource_indicators_enabled` flag.
pub(super) async fn authorize_with_resources(
  h: &mut Harness,
  inputs: &DeviceHttpInputs<'_>,
  now: i64,
  resource_indicators_enabled: bool,
) -> Result<DeviceAuthorizationResponse, AppError> {
  let mut stores = DeviceStores {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.config.keys,
  };
  let ctx = DeviceContext {
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    now_unix: now,
    resource_indicators_enabled,
  };
  authorize_device(&mut stores, &ctx, inputs).await
}

/// Poll through the device-code grant at a pinned time.
pub(super) async fn poll_once(
  h: &mut Harness,
  inputs: &DevicePollInputs<'_>,
  now: i64,
) -> Result<DeviceTokenResponse, DevicePollError> {
  poll_once_with_flag(h, inputs, now, true).await
}

/// Poll with an explicit `resource_indicators_enabled` flag, for the stale
/// catalog and flag-off negatives.
pub(super) async fn poll_once_with_flag(
  h: &mut Harness,
  inputs: &DevicePollInputs<'_>,
  now: i64,
  resource_indicators_enabled: bool,
) -> Result<DeviceTokenResponse, DevicePollError> {
  let mut state = PollState {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.config.keys,
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    interval: Duration::from_secs(DEVICE_INTERVAL_SECS),
    ttl: &h.config.ttl,
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: None,
    resource_indicators_enabled,
    now_unix: now,
  };
  poll_device(&mut state, inputs).await
}

/// Record the user's verdict on an issued device code.
pub(super) async fn decide(
  h: &mut Harness,
  device_code: &str,
  approve: bool,
  subject: &str,
) -> Result<bool, TestError> {
  let device_hash = hash_token(&h.config.keys, device_code)?;
  Ok(crate::ui::device::decide_device(&mut h.conn, &h.store, &device_hash, approve, subject).await?)
}

/// Public-client poll inputs with a fresh DPoP proof.
pub(super) fn public_inputs<'a>(
  client_id: &'a str,
  device_code: &'a str,
  proof: Option<&'a str>,
) -> DevicePollInputs<'a> {
  DevicePollInputs {
    client_id,
    device_code,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: proof,
    peer_certs: None,
    aud: &[],
  }
}

/// Build a SecretString without touching the deny lints.
pub(super) fn secret(value: &str) -> SecretString {
  SecretString::from(value.to_owned())
}

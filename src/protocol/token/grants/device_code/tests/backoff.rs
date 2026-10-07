//! `test(grant_device)` pacing: `slow_down` inside the interval, denial.

use super::super::DevicePollError;
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod,
  protocol::device::{DEVICE_INTERVAL_SECS, DeviceHttpInputs},
};

#[tokio::test]
async fn test_grant_device_fast_poll_is_slow_down() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  setup::insert_client(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  let t0 = now_unix();
  let key = keys::fresh_key()?;
  let authorize_htu = keys::device_htu(&h.config);
  let poll_htu = keys::token_htu(&h.config);

  let authorize_proof = keys::mint_proof(&key, &authorize_htu, &unique("jti"), t0)?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(authorize_proof.as_str()),
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;

  let first_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&first_proof)),
    t0,
  )
  .await
  {
    Err(DevicePollError::AuthorizationPending) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "first poll must pend, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "tokens must never issue before approval".to_owned(),
      ));
    }
  }

  let fast_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&fast_proof)),
    t0,
  )
  .await
  {
    Err(DevicePollError::SlowDown { retry_after_secs })
      if retry_after_secs == DEVICE_INTERVAL_SECS => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "fast poll must be slow_down, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "tokens must never issue before approval".to_owned(),
      ));
    }
  }

  let slow_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0 + 6)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&slow_proof)),
    t0 + 6,
  )
  .await
  {
    Err(DevicePollError::AuthorizationPending) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "paced poll must pend, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "tokens must never issue before approval".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_grant_device_denied_is_access_denied() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  setup::insert_client(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  let t0 = now_unix();
  let key = keys::fresh_key()?;
  let authorize_htu = keys::device_htu(&h.config);
  let poll_htu = keys::token_htu(&h.config);

  let authorize_proof = keys::mint_proof(&key, &authorize_htu, &unique("jti"), t0)?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(authorize_proof.as_str()),
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;

  if !decide(&mut h, &issued.device_code, false, &unique("subject")).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let denied_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0 + 6)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&denied_proof)),
    t0 + 6,
  )
  .await
  {
    Err(DevicePollError::AccessDenied) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "denied poll must be access_denied, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a denied request must never mint tokens".to_owned(),
    )),
  }
}

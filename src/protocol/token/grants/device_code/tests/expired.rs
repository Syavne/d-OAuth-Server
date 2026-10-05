//! `test(grant_device)` expiry: unknown and lapsed codes.

use super::super::DevicePollError;
use super::flows::{authorize, now_unix, poll_once, public_inputs};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod,
  protocol::device::{DeviceHttpInputs, normalize_user_code},
};

#[tokio::test]
async fn test_grant_device_expired_token_after_ttl() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  setup::insert_client(
    &h.pool,
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

  let unknown_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, "AAAA-BBBB-CCCC-DDDD", Some(&unknown_proof)),
    t0,
  )
  .await
  {
    Err(DevicePollError::ExpiredToken) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "unknown code must be expired_token, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "an unknown code must never mint tokens".to_owned(),
      ));
    }
  }

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
  let device_hash = crate::protocol::device::hash_token(&h.config.keys, &issued.device_code)?;
  let user_hash =
    crate::protocol::device::hash_token(&h.config.keys, &normalize_user_code(&issued.user_code))?;
  redis::cmd("DEL")
    .arg(h.store.device_key(&device_hash))
    .arg(h.store.user_code_key(&user_hash))
    .query_async::<()>(&mut h.conn)
    .await?;
  let lapsed_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&lapsed_proof)),
    t0,
  )
  .await
  {
    Err(DevicePollError::ExpiredToken) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "lapsed code must be expired_token, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a lapsed code must never mint tokens".to_owned(),
    )),
  }
}

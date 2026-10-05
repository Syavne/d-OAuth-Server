//! `test(grant_device)` scope enforcement at redemption time.

use super::super::DevicePollError;
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod, error::OAuthErrorCode, protocol::device::DeviceHttpInputs,
};

#[tokio::test]
async fn test_grant_device_unentitled_scope_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  setup::insert_client(
    &h.pool,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read orders:admin",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:admin", "orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &["orders:read"]).await?;
  let t0 = now_unix();
  let key = keys::fresh_key()?;
  let authorize_htu = keys::device_htu(&h.config);
  let poll_htu = keys::token_htu(&h.config);

  let authorize_proof = keys::mint_proof(&key, &authorize_htu, &unique("jti"), t0)?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read orders:admin"),
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

  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let redeem_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0 + 6)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&redeem_proof)),
    t0 + 6,
  )
  .await
  {
    Err(DevicePollError::Protocol(error)) if error.code() == OAuthErrorCode::InvalidScope => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "unentitled scope must be invalid_scope, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "an unentitled scope must never be minted".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_grant_device_scope_reduced_to_user_entitlement() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  setup::insert_client(
    &h.pool,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read orders:admin",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:admin", "orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &["orders:read"]).await?;
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

  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let redeem_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0 + 6)?;
  let tokens = poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&redeem_proof)),
    t0 + 6,
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("approved poll rejected: {}", error.code())))?;
  if tokens.scope != "orders:read" {
    return Err(TestError::Unexpected(format!(
      "scope must reduce to the user entitlement, got {}",
      tokens.scope
    )));
  }
  Ok(())
}

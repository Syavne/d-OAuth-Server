//! `test(grant_device)` sender-constraint matrix at redemption time.

use std::time::Duration;

use super::super::{DevicePollError, DevicePollInputs, PollState, poll_device};
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs, secret};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod, error::OAuthErrorCode, protocol::device::DeviceHttpInputs,
};

#[tokio::test]
async fn test_grant_device_public_without_dpop_rejected() -> TestResult {
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

  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, None),
    t0,
  )
  .await
  {
    Err(DevicePollError::Protocol(error)) if error.code() == OAuthErrorCode::InvalidDpopProof => {
      Ok(())
    }
    Err(other) => Err(TestError::Unexpected(format!(
      "proofless public poll must be invalid_dpop_proof, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a public client must never receive an unbound token".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_grant_device_confidential_secret_redeems_bearer() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("conf");
  setup::insert_client(
    &h.pool,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("poll-secret"),
    "orders:read",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &["orders:read"]).await?;
  let t0 = now_unix();

  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: Some(secret("poll-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;

  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let poll_inputs = DevicePollInputs {
    client_id: client_id.as_str(),
    device_code: issued.device_code.as_str(),
    basic_header: None,
    body_secret: Some(secret("poll-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  let mut state = PollState {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.config.keys,
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    interval: Duration::from_secs(crate::protocol::device::DEVICE_INTERVAL_SECS),
    ttl: &h.config.ttl,
    now_unix: t0 + 6,
  };
  let tokens = poll_device(&mut state, &poll_inputs)
    .await
    .map_err(|error| {
      TestError::Unexpected(format!("confidential poll rejected: {}", error.code()))
    })?;
  if tokens.token_type != "Bearer" || tokens.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "unconstrained confidential redemption must be a Bearer token".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn test_grant_device_dpop_bound_confidential_requires_fresh_proof() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("bound-conf");
  setup::insert_client_bound(
    &h.pool,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("bound-secret"),
    "orders:read",
    true,
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &["orders:read"]).await?;
  let t0 = now_unix();

  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: Some(secret("bound-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;
  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }

  let poll_inputs = DevicePollInputs {
    client_id: client_id.as_str(),
    device_code: issued.device_code.as_str(),
    basic_header: None,
    body_secret: Some(secret("bound-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  let mut state = PollState {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.config.keys,
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    interval: Duration::from_secs(crate::protocol::device::DEVICE_INTERVAL_SECS),
    ttl: &h.config.ttl,
    now_unix: t0 + 6,
  };
  match poll_device(&mut state, &poll_inputs).await {
    Err(DevicePollError::Protocol(error)) if error.code() == OAuthErrorCode::InvalidGrant => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "proofless bound poll must be invalid_grant, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a DPoP-bound client must never receive an unbound token".to_owned(),
      ));
    }
  }

  let key = keys::fresh_key()?;
  let token_htu = keys::token_htu(&h.config);
  let proof = keys::mint_proof(&key, &token_htu, &unique("jti"), t0 + 6)?;
  let proof_inputs = DevicePollInputs {
    dpop_proof: Some(proof.as_str()),
    ..poll_inputs
  };
  let tokens = poll_device(&mut state, &proof_inputs)
    .await
    .map_err(|error| {
      TestError::Unexpected(format!("bound fresh-proof poll rejected: {}", error.code()))
    })?;
  if tokens.token_type != "DPoP" || tokens.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "a fresh proof must mint a DPoP token for the bound client".to_owned(),
    ));
  }
  Ok(())
}

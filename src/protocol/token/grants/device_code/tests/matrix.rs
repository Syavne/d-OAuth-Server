//! `test(grant_device)` sender-constraint matrix at redemption time.

use std::time::Duration;

use axum::http::StatusCode;

use super::super::{DevicePollError, DevicePollInputs, PollState, poll_device};
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs, secret};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod,
  error::OAuthErrorCode,
  protocol::{device::DeviceHttpInputs, token::TokenFormat},
};

#[tokio::test]
async fn test_grant_device_public_without_dpop_rejected() -> TestResult {
  let mut h = harness().await?;
  let client_id = unique("public");
  setup::insert_client_bound(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
    true,
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
    resource: &[],
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

/// An unbound public client completes the device flow with no DPoP proof:
/// authorization, approval, and poll all succeed with a `Bearer` token.
#[tokio::test]
async fn public_unbound_device_authorization_and_poll_succeeds() -> TestResult {
  let mut h = harness().await?;
  let client_id = unique("public-unbound");
  setup::insert_client(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &h.config, &["orders:read"]).await?;
  let t0 = now_unix();

  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    resource: &[],
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("unbound authorize rejected: {error}")))?;
  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let tokens = poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, None),
    t0 + 6,
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("unbound poll rejected: {}", error.code())))?;
  if tokens.token_type != "Bearer" || tokens.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "unbound device redemption must be a Bearer token".to_owned(),
    ));
  }
  Ok(())
}

/// A DPoP-bound public client cannot start the device flow without a proof:
/// authorization itself is `invalid_dpop_proof` before any state is written.
#[tokio::test]
async fn public_bound_device_poll_requires_dpop() -> TestResult {
  let mut h = harness().await?;
  let client_id = unique("public-bound");
  setup::insert_client_bound(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
    true,
  )
  .await?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    resource: &[],
    peer_certs: None,
  };
  match authorize(&mut h, &authorize_inputs, now_unix()).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidDpopProof => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "bound authorize without proof must be invalid_dpop_proof, got {other}"
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a bound client must never start a proof-free device flow".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_grant_device_confidential_secret_redeems_bearer() -> TestResult {
  let mut h = harness().await?;
  let client_id = unique("conf");
  setup::insert_client(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("poll-secret"),
    "orders:read",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &h.config, &["orders:read"]).await?;
  let t0 = now_unix();

  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: Some(secret("poll-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    resource: &[],
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
    aud: &[],
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
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: None,
    resource_indicators_enabled: false,
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
  let mut h = harness().await?;
  let client_id = unique("bound-conf");
  setup::insert_client_bound(
    &h.pool,
    &h.config,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("bound-secret"),
    "orders:read",
    true,
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &h.config, &["orders:read"]).await?;
  let t0 = now_unix();

  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: Some(secret("bound-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    resource: &[],
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
    aud: &[],
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
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: None,
    resource_indicators_enabled: false,
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

/// RFC 6749 §5.2 and the error table in docs/OAUTH.md: a grant issued to
/// another client is `invalid_grant`. The foreign poll must not consume the
/// code, so the legitimate client still redeems it.
#[tokio::test]
async fn test_grant_device_cross_client_poll_is_invalid_grant() -> TestResult {
  let mut h = harness().await?;
  let owner_id = unique("owner");
  let intruder_id = unique("intruder");
  setup::insert_client(
    &h.pool,
    &h.config,
    &owner_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  setup::insert_client(
    &h.pool,
    &h.config,
    &intruder_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &h.config, &["orders:read"]).await?;
  let t0 = now_unix();
  let owner_key = keys::fresh_key()?;
  let authorize_htu = keys::device_htu(&h.config);
  let poll_htu = keys::token_htu(&h.config);

  let authorize_proof = keys::mint_proof(&owner_key, &authorize_htu, &unique("jti"), t0)?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: owner_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(authorize_proof.as_str()),
    resource: &[],
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;
  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }

  let t1 = t0 + 6;
  let intruder_key = keys::fresh_key()?;
  let intruder_proof = keys::mint_proof(&intruder_key, &poll_htu, &unique("jti"), t1)?;
  match poll_once(
    &mut h,
    &public_inputs(&intruder_id, &issued.device_code, Some(&intruder_proof)),
    t1,
  )
  .await
  {
    Err(DevicePollError::Protocol(error))
      if error.code() == OAuthErrorCode::InvalidGrant
        && error.status() == StatusCode::BAD_REQUEST => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "cross-client poll must be invalid_grant 400, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a foreign client must never mint a token".to_owned(),
      ));
    }
  }

  // The rejected poll left the grant untouched: the owner still redeems it.
  let owner_proof = keys::mint_proof(&owner_key, &poll_htu, &unique("jti"), t1)?;
  let tokens = poll_once(
    &mut h,
    &public_inputs(&owner_id, &issued.device_code, Some(&owner_proof)),
    t1,
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("owner redemption rejected: {}", error.code())))?;
  if tokens.token_type != "DPoP"
    || tokens.access_token.is_empty()
    || tokens.refresh_token.is_empty()
    || tokens.scope != "orders:read"
  {
    return Err(TestError::Unexpected(
      "the owner must still redeem the untouched grant".to_owned(),
    ));
  }
  Ok(())
}

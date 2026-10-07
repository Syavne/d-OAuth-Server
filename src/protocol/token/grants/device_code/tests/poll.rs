//! `test(grant_device)` approval path: pending, then bound tokens once.

use super::super::DevicePollError;
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod,
  jose::jwk::thumbprint,
  protocol::{
    device::{DEVICE_INTERVAL_SECS, DeviceHttpInputs},
    token::{Cnf, TokenService},
  },
};

#[tokio::test]
async fn test_grant_device_pending_then_approved_issues_bound_tokens() -> TestResult {
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
  setup::enable_scopes(&h.pool, &["orders:read"]).await?;
  let user_id = setup::entitled_user(&h.pool, &h.config, &["orders:read"]).await?;
  let t0 = now_unix();
  let key = keys::fresh_key()?;
  let authorize_htu = keys::device_htu(&h.config);
  let poll_htu = keys::token_htu(&h.config);

  let authorize_proof = keys::mint_proof(&key, &authorize_htu, &unique("jti"), t0)?;
  let authorize_inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
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

  let pending_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t0)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&pending_proof)),
    t0,
  )
  .await
  {
    Err(DevicePollError::AuthorizationPending) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "pending poll must be authorization_pending, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "tokens must never issue before approval".to_owned(),
      ));
    }
  }

  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let t1 = t0 + DEVICE_INTERVAL_SECS as i64 + 1;
  let redeem_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t1)?;
  let tokens = poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&redeem_proof)),
    t1,
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("approved poll rejected: {}", error.code())))?;
  if tokens.token_type != "DPoP"
    || tokens.scope != "orders:read"
    || tokens.expires_in != 300
    || tokens.access_token.is_empty()
    || tokens.refresh_token.is_empty()
    || tokens.access_token == tokens.refresh_token
  {
    return Err(TestError::Unexpected(
      "redemption must return a DPoP token pair with the granted scope".to_owned(),
    ));
  }

  let service = TokenService::new(&h.config.ttl, &h.config.keys)?;
  let found = service
    .find_access(&mut h.conn, &h.store, &tokens.access_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("access token must resolve".to_owned()))?;
  let stored = Cnf::parse_storage(&found.record.cnf)?;
  let expected_jkt = thumbprint(&key.jwk)?;
  if stored.jkt.as_deref() != Some(expected_jkt.as_str()) {
    return Err(TestError::Unexpected(
      "public token must carry the proven jkt".to_owned(),
    ));
  }
  if found.record.subject != user_id.to_string()
    || found.record.grant_id.is_empty()
    || found.record.scope != "orders:read"
  {
    return Err(TestError::Unexpected(
      "access record must bind subject, grant, and scope".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut h.conn, &h.store, &tokens.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "refresh token must resolve".to_owned(),
    ));
  }

  let replay_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t1 + 6)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&replay_proof)),
    t1 + 6,
  )
  .await
  {
    Err(DevicePollError::ExpiredToken) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "consumed code must be expired_token, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a device code must redeem exactly once".to_owned(),
    )),
  }
}

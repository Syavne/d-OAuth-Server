//! `test(grant_device)` approval path: pending, then bound tokens once.

use std::time::Duration;

use axum::http::StatusCode;

use super::super::{DevicePollError, PollState, poll_device};
use super::flows::{authorize, decide, now_unix, poll_once, public_inputs};
use super::{TestError, TestResult, harness, unique};
use super::{keys, setup};
use crate::{
  db::TokenEndpointAuthMethod,
  error::OAuthErrorCode,
  jose::jwk::thumbprint,
  protocol::{
    device::{DEVICE_INTERVAL_SECS, DeviceHttpInputs},
    token::{Cnf, TokenFormat, TokenService},
  },
};

#[tokio::test]
async fn test_grant_device_pending_then_approved_issues_bound_tokens() -> TestResult {
  let mut h = harness().await?;
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
    resource: &[],
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

/// RFC 8628 §3.5: an approved device code redeems exactly once. Two polls
/// issued concurrently must mint exactly one token pair; the loser observes
/// the terminal `expired_token` (or `invalid_grant`), never a second pair.
///
/// The interval is zeroed so the test isolates the atomic consume from
/// §3.5 pacing, which the boundary suite pins separately.
#[tokio::test]
async fn test_grant_device_concurrent_poll_mints_once() -> TestResult {
  let mut h = harness().await?;
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
    resource: &[],
    peer_certs: None,
  };
  let issued = authorize(&mut h, &authorize_inputs, t0)
    .await
    .map_err(|error| TestError::Unexpected(format!("authorize rejected: {error}")))?;
  if !decide(&mut h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }

  let t1 = t0 + DEVICE_INTERVAL_SECS as i64 + 1;
  let left_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t1)?;
  let right_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), t1)?;
  let left_inputs = public_inputs(&client_id, &issued.device_code, Some(&left_proof));
  let right_inputs = public_inputs(&client_id, &issued.device_code, Some(&right_proof));

  // Separate handles to the same multiplexed connection so both polls run to
  // completion concurrently.
  let mut left_conn = h.conn.clone();
  let mut right_conn = h.conn.clone();
  let mut left_state = PollState {
    pool: &h.pool,
    conn: &mut left_conn,
    store: &h.store,
    keys: &h.config.keys,
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    interval: Duration::ZERO,
    ttl: &h.config.ttl,
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: None,
    now_unix: t1,
  };
  let mut right_state = PollState {
    pool: &h.pool,
    conn: &mut right_conn,
    store: &h.store,
    keys: &h.config.keys,
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    interval: Duration::ZERO,
    ttl: &h.config.ttl,
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: None,
    now_unix: t1,
  };
  let (left, right) = tokio::join!(
    poll_device(&mut left_state, &left_inputs),
    poll_device(&mut right_state, &right_inputs)
  );

  let (winner, loser) = match (left, right) {
    (Ok(tokens), Err(error)) | (Err(error), Ok(tokens)) => (tokens, error),
    (Ok(_), Ok(_)) => {
      return Err(TestError::Unexpected(
        "two racing polls must not both mint".to_owned(),
      ));
    }
    (Err(left_error), Err(right_error)) => {
      return Err(TestError::Unexpected(format!(
        "racing polls must mint exactly one pair: {} / {}",
        left_error.code(),
        right_error.code()
      )));
    }
  };
  match &loser {
    DevicePollError::ExpiredToken => {}
    DevicePollError::Protocol(error) if error.code() == OAuthErrorCode::InvalidGrant => {}
    other => {
      return Err(TestError::Unexpected(format!(
        "losing poll must be expired_token or invalid_grant, got {}",
        other.code()
      )));
    }
  }
  if loser.status() != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(
      "losing poll must answer 400".to_owned(),
    ));
  }

  // Exactly the winner's pair resolves; nothing else was minted.
  let service = TokenService::new(&h.config.ttl, &h.config.keys)?;
  if service
    .find_access(&mut h.conn, &h.store, &winner.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "winner access token must resolve".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut h.conn, &h.store, &winner.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "winner refresh token must resolve".to_owned(),
    ));
  }
  if winner.token_type != "DPoP" || winner.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "winner pair must be DPoP-bound in the granted scope".to_owned(),
    ));
  }

  // The code is consumed: a follow-up poll is terminal, never a re-mint.
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
      "a consumed code must never mint again".to_owned(),
    )),
  }
}

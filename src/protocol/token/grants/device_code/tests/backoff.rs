//! `test(grant_device)` pacing: `slow_down` inside the interval, denial.

use axum::http::StatusCode;

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

/// RFC 8628 §3.5: polling exactly `interval` seconds after the previous
/// attempt — and just past that boundary — is `authorization_pending`, never
/// a spurious `slow_down`; `slow_down` resumes only inside the window.
#[tokio::test]
async fn test_grant_device_interval_boundary_not_slow_down() -> TestResult {
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
  let interval = DEVICE_INTERVAL_SECS as i64;

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

  // Exactly one interval after the stamped attempt: allowed (>= interval).
  let boundary = t0 + interval;
  let boundary_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), boundary)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&boundary_proof)),
    boundary,
  )
  .await
  {
    Err(DevicePollError::AuthorizationPending) => {}
    Err(DevicePollError::SlowDown { .. }) => {
      return Err(TestError::Unexpected(
        "a poll exactly at the interval boundary must not be slow_down".to_owned(),
      ));
    }
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "boundary poll must pend, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "tokens must never issue before approval".to_owned(),
      ));
    }
  }

  // Just past that boundary: still inside the contract.
  let just_after = t0 + 2 * interval + 1;
  let just_after_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), just_after)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&just_after_proof)),
    just_after,
  )
  .await
  {
    Err(DevicePollError::AuthorizationPending) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "just-after-boundary poll must pend, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "tokens must never issue before approval".to_owned(),
      ));
    }
  }

  // One second later the pacing bites again: the marker advanced, so the
  // boundary polls were really counted.
  let too_soon = just_after + 1;
  let too_soon_proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), too_soon)?;
  match poll_once(
    &mut h,
    &public_inputs(&client_id, &issued.device_code, Some(&too_soon_proof)),
    too_soon,
  )
  .await
  {
    Err(DevicePollError::SlowDown { retry_after_secs }) => {
      if retry_after_secs != (interval - 1) as u64 {
        return Err(TestError::Unexpected(format!(
          "slow_down must advertise the remaining window, got {retry_after_secs}"
        )));
      }
      Ok(())
    }
    Err(other) => Err(TestError::Unexpected(format!(
      "inside-window poll must be slow_down, got {}",
      other.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "tokens must never issue before approval".to_owned(),
    )),
  }
}

/// RFC 8628 §3.5: after `access_denied` the code is terminal. A later poll
/// stays `access_denied`, never `authorization_pending` and never a mint.
#[tokio::test]
async fn test_grant_device_denied_then_poll_stays_access_denied() -> TestResult {
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
  let subject = unique("subject");

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
  if !decide(&mut h, &issued.device_code, false, &subject).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }

  for now in [t0 + 6, t0 + 12] {
    let proof = keys::mint_proof(&key, &poll_htu, &unique("jti"), now)?;
    match poll_once(
      &mut h,
      &public_inputs(&client_id, &issued.device_code, Some(&proof)),
      now,
    )
    .await
    {
      Err(error)
        if error.code() == "access_denied" && error.status() == StatusCode::BAD_REQUEST => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!(
          "repeated denied poll must stay access_denied 400, got {}",
          other.code()
        )));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(
          "a denied request must never mint tokens".to_owned(),
        ));
      }
    }
  }

  let device_hash = crate::protocol::device::hash_token(&h.config.keys, &issued.device_code)?;
  let record = crate::store::device::poll(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("denied record must persist".to_owned()))?;
  if record.status != crate::store::device::DeviceStatus::Denied
    || record.subject != subject
    || !record.grant_id.is_empty()
  {
    return Err(TestError::Unexpected(
      "denial must stay terminal with no grant bound".to_owned(),
    ));
  }
  Ok(())
}

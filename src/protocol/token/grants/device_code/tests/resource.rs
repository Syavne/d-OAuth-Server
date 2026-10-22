//! `test(device_pins_resource)`: RFC 8707 audience pinning for the device
//! flow (device authorization pins, polling enforces or inherits).
//!
//! Every scenario drives the real issuers: the catalog is seeded through
//! `resource_repo::upsert`, authorization through `authorize_device`, and
//! redemption through `poll_device`, so the stored `DeviceRecord.aud` is read
//! back from Redis rather than reconstructed.

use uuid::Uuid;

use super::super::{DevicePollError, DevicePollInputs};
use super::flows::{authorize_with_resources, decide, now_unix, poll_once, public_inputs};
use super::setup;
use super::{TestError, TestResult, harness, unique};
use crate::{
  db::{TokenEndpointAuthMethod, resource_repo},
  error::OAuthErrorCode,
  protocol::{
    device::{DeviceAuthorizationResponse, DeviceHttpInputs, hash_token},
    token::TokenService,
  },
  store::device as device_store,
};

const RES_A: &str = "https://api.example.test/";
const RES_B: &str = "https://other.example.test/";
const RES_C: &str = "https://ghost.example.test/";

async fn seed_catalog(h: &mut super::Harness, values: &[&str]) -> TestResult {
  for value in values {
    resource_repo::upsert(&h.pool, value, "device resource test").await?;
  }
  Ok(())
}

/// An unbound public client plus an entitled user (no DPoP proof needed).
async fn public_client(h: &super::Harness) -> Result<(String, Uuid), TestError> {
  let client_id = unique("public-resource");
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
  Ok((client_id, user_id))
}

/// Authorize with resource indicators enabled, then approve the request.
async fn issue_approved(
  h: &mut super::Harness,
  client_id: &str,
  user_id: &Uuid,
  resources: &[String],
  now: i64,
) -> Result<DeviceAuthorizationResponse, TestError> {
  let inputs = DeviceHttpInputs {
    client_id,
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    resource: resources,
    peer_certs: None,
  };
  let issued = authorize_with_resources(h, &inputs, now, true).await?;
  if !decide(h, &issued.device_code, true, &user_id.to_string()).await? {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  Ok(issued)
}

fn inputs<'a>(client_id: &'a str, device_code: &'a str, aud: &'a [String]) -> DevicePollInputs<'a> {
  DevicePollInputs {
    aud,
    ..public_inputs(client_id, device_code, None)
  }
}

/// Access/refresh key counts: a failed poll must not add either.
async fn minted_counts(h: &mut super::Harness) -> Result<(usize, usize), TestError> {
  let access = format!("{}*", h.store.access_key(""));
  let refresh = format!("{}*", h.store.refresh_key(""));
  let access_keys: Vec<String> = redis::cmd("KEYS")
    .arg(&access)
    .query_async(&mut h.conn)
    .await?;
  let refresh_keys: Vec<String> = redis::cmd("KEYS")
    .arg(&refresh)
    .query_async(&mut h.conn)
    .await?;
  Ok((access_keys.len(), refresh_keys.len()))
}

async fn device_keys(h: &mut super::Harness) -> Result<usize, TestError> {
  let pattern = format!("{}*", h.store.device_key_prefix());
  let keys: Vec<String> = redis::cmd("KEYS")
    .arg(&pattern)
    .query_async(&mut h.conn)
    .await?;
  Ok(keys.len())
}

fn sorted(values: &[&str]) -> Vec<String> {
  let mut set = values
    .iter()
    .map(|value| (*value).to_owned())
    .collect::<Vec<_>>();
  set.sort();
  set
}

fn is_invalid_target(error: &crate::error::AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidTarget
}

fn is_invalid_grant(error: &DevicePollError) -> bool {
  matches!(
    error,
    DevicePollError::Protocol(error) if error.code() == OAuthErrorCode::InvalidGrant
  )
}

/// RFC 8707 §2: the device authorization pins the requested resource set and
/// the poll must present exactly that set (in any order); a partial set is a
/// grant-binding mismatch (`invalid_grant`), never a request-level error.
#[tokio::test]
async fn device_pins_resource() -> TestResult {
  let mut h = harness().await?;
  seed_catalog(&mut h, &[RES_A, RES_B]).await?;
  let (client_id, user_id) = public_client(&h).await?;
  let t0 = now_unix();

  let requested = vec![RES_B.to_owned(), RES_A.to_owned()];
  let issued = issue_approved(&mut h, &client_id, &user_id, &requested, t0).await?;

  let body = serde_json::to_value(&issued)
    .map_err(|error| TestError::Unexpected(format!("response body: {error}")))?;
  for field in ["aud", "resource", "resource_indicators", "target"] {
    if body.get(field).is_some() {
      return Err(TestError::Unexpected(format!(
        "device authorization response must not echo `{field}`"
      )));
    }
  }

  let device_hash = hash_token(&h.config.keys, &issued.device_code)?;
  let record = device_store::poll(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("device record must exist".to_owned()))?;
  if record.aud != sorted(&[RES_A, RES_B]) {
    return Err(TestError::Unexpected(format!(
      "pinned audience must be the sorted requested set, got {:?}",
      record.aud
    )));
  }

  let t1 = t0 + crate::protocol::device::DEVICE_INTERVAL_SECS as i64 + 1;
  let presented = vec![RES_A.to_owned(), RES_B.to_owned()];
  let tokens = poll_once(
    &mut h,
    &inputs(&client_id, &issued.device_code, &presented),
    t1,
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("matching poll rejected: {}", error.code())))?;
  if tokens.access_token.is_empty() || tokens.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "matching poll must mint the approved scope".to_owned(),
    ));
  }
  let service = TokenService::new(&h.config.ttl, &h.config.keys)?;
  if service
    .find_access(&mut h.conn, &h.store, &tokens.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "matching poll access token must resolve".to_owned(),
    ));
  }

  let (access_before, refresh_before) = minted_counts(&mut h).await?;
  let t2 = t1 + crate::protocol::device::DEVICE_INTERVAL_SECS as i64 + 1;
  let second = issue_approved(&mut h, &client_id, &user_id, &requested, t2).await?;
  let partial = vec![RES_A.to_owned()];
  match poll_once(
    &mut h,
    &inputs(&client_id, &second.device_code, &partial),
    t2 + crate::protocol::device::DEVICE_INTERVAL_SECS as i64 + 1,
  )
  .await
  {
    Err(error) if is_invalid_grant(&error) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "partial audience must be invalid_grant, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a partial audience must never mint".to_owned(),
      ));
    }
  }
  let (access_after, refresh_after) = minted_counts(&mut h).await?;
  if (access_after, refresh_after) != (access_before, refresh_before) {
    return Err(TestError::Unexpected(
      "a mismatched poll must not mint any token".to_owned(),
    ));
  }
  Ok(())
}

/// RFC 8707 §2.2: a device client never re-sends `resource` on the poll, so an
/// empty presented set inherits the pinned one.
#[tokio::test]
async fn device_poll_inherits_pinned_resource() -> TestResult {
  let mut h = harness().await?;
  seed_catalog(&mut h, &[RES_A, RES_B]).await?;
  let (client_id, user_id) = public_client(&h).await?;
  let t0 = now_unix();

  let requested = vec![RES_A.to_owned(), RES_B.to_owned()];
  let issued = issue_approved(&mut h, &client_id, &user_id, &requested, t0).await?;
  let t1 = t0 + crate::protocol::device::DEVICE_INTERVAL_SECS as i64 + 1;
  let tokens = poll_once(&mut h, &inputs(&client_id, &issued.device_code, &[]), t1)
    .await
    .map_err(|error| {
      TestError::Unexpected(format!("inheriting poll rejected: {}", error.code()))
    })?;
  if tokens.access_token.is_empty() {
    return Err(TestError::Unexpected(
      "inheriting poll must mint an access token".to_owned(),
    ));
  }
  Ok(())
}

/// Superset and differing-member presentations are mismatches too, never a
/// silent widening or narrowing of the pinned grant.
#[tokio::test]
async fn device_poll_rejects_different_resource() -> TestResult {
  let mut h = harness().await?;
  seed_catalog(&mut h, &[RES_A, RES_B, RES_C]).await?;
  let (client_id, user_id) = public_client(&h).await?;
  let t0 = now_unix();
  let requested = vec![RES_A.to_owned(), RES_B.to_owned()];

  for (index, presented) in [
    vec![RES_A.to_owned(), RES_B.to_owned(), RES_C.to_owned()],
    vec![RES_A.to_owned(), RES_C.to_owned()],
    vec![RES_C.to_owned()],
  ]
  .into_iter()
  .enumerate()
  {
    let issued = issue_approved(&mut h, &client_id, &user_id, &requested, t0).await?;
    let poll_at = t0 + crate::protocol::device::DEVICE_INTERVAL_SECS as i64 + 1;
    match poll_once(
      &mut h,
      &inputs(&client_id, &issued.device_code, &presented),
      poll_at,
    )
    .await
    {
      Err(error) if is_invalid_grant(&error) => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!(
          "case {index}: differing audience must be invalid_grant, got {}",
          other.code()
        )));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(format!(
          "case {index}: a differing audience must never mint"
        )));
      }
    }
  }
  Ok(())
}

/// Authorization-side negatives: the flag gate and the catalog/scheme checks
/// fail closed with `invalid_target` before any device record is written.
#[tokio::test]
async fn device_authorization_rejects_resource_without_catalog() -> TestResult {
  let mut h = harness().await?;
  seed_catalog(&mut h, &[RES_A]).await?;

  let valid = vec![RES_A.to_owned()];
  let unknown = vec![RES_C.to_owned()];
  let insecure = vec!["http://api.example.test/".to_owned()];

  for (label, resources, enabled) in [
    ("flag disabled", valid.as_slice(), false),
    ("unknown identifier", unknown.as_slice(), true),
    ("non-https identifier", insecure.as_slice(), true),
  ] {
    let inputs = DeviceHttpInputs {
      client_id: "resource-negatives",
      scope: None,
      basic_header: None,
      body_secret: None,
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      resource: resources,
      peer_certs: None,
    };
    match authorize_with_resources(&mut h, &inputs, now_unix(), enabled).await {
      Err(error) if is_invalid_target(&error) => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!(
          "{label} must be invalid_target, got {other}"
        )));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(format!(
          "{label} must never issue a device code"
        )));
      }
    }
    if device_keys(&mut h).await? != 0 {
      return Err(TestError::Unexpected(format!(
        "{label} must not write a device record"
      )));
    }
  }
  Ok(())
}

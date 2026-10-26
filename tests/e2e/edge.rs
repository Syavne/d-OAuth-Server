//! Request mechanics for the `tests/e2e_edge_matrix.rs` rejection matrix.
//!
//! Each function owns one row's wire setup against the live router; the
//! suite owns the table and the row-level assertions. Device rows reuse the
//! shared `e2e/device.rs` driver so `/device` and `/token` are exercised
//! exactly as the RFC 8628 flow does.

use std::time::Duration;

use d_oauth::{
  crypto::tokens::{KeyId as TokenKeyId, mint_token, token_hash},
  db::TokenEndpointAuthMethod,
  store::dcr::{self, InitialAccessRecord},
};
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use serde_json::Value;

use super::{
  browser, device,
  device::{
    Client, DEVICE_GRANT, Decision, PUBLIC_CLIENT, Poll, SCOPE, decide, issue, poll,
    seed_public_client,
  },
  dpop::DpopKey,
  harness::{TestError, World, ensure, fail, json_body, open_rate_limit, seed_client},
};

/// User provisioned for the device approval flow.
const DEVICE_EMAIL: &str = "edge-device@example.test";
/// Password for [`DEVICE_EMAIL`].
const DEVICE_PASSWORD: &str = "e2e-edge-device-password-1a2b3c";

/// Seed an IAT exactly as `protocol::dcr::tests::issue_iat` does: the storage
/// key is the active pepper's keyed hash, not a plain `sha256_hex`.
async fn seed_iat(world: &World) -> Result<String, TestError> {
  let raw = mint_token().map_err(|error| fail(format!("mint IAT failed: {error}")))?;
  let (key_id, pepper) = world
    .state
    .config
    .keys
    .active_pepper()
    .ok_or_else(|| fail("config has no active token pepper"))?;
  let hash = token_hash(
    &TokenKeyId::new(key_id.as_str()),
    pepper.expose_secret().as_bytes(),
    &raw,
  )
  .to_storage_string();
  let mut conn = world.state.redis.clone();
  dcr::issue(
    &mut conn,
    &world.store,
    &hash,
    &InitialAccessRecord {
      uses_remaining: 1,
      label: "edge".to_owned(),
    },
    Duration::from_secs(600),
  )
  .await
  .map_err(|error| fail(format!("seed IAT failed: {error}")))?;
  Ok(raw)
}

/// One DCR rejection: exact code, no client in the body, no client row.
pub async fn dcr_rejects(body: Value, expected: &str) -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let iat = seed_iat(&world).await?;
  let response = world
    .client
    .post(format!("{}/register", world.base))
    .bearer_auth(&iat)
    .json(&body)
    .send()
    .await?;
  let status = response.status();
  let text = response.text().await?;
  ensure_error(status, &text, StatusCode::BAD_REQUEST, expected)?;
  ensure(
    json_body(&text)?.get("client_id").is_none(),
    format!("a rejected registration must mint no client: {text}"),
  )?;
  let clients: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
    .fetch_one(&world.pool)
    .await?;
  ensure(
    clients == 0,
    format!("a rejected registration must persist no client row, found {clients}"),
  )
}

/// Assert an exact OAuth error response that minted nothing.
pub fn ensure_error(
  status: StatusCode,
  body: &str,
  expected_status: StatusCode,
  expected: &str,
) -> Result<(), TestError> {
  ensure(
    status == expected_status,
    format!("expected {expected_status} {expected}, got {status}: {body}"),
  )?;
  let parsed = json_body(body)?;
  ensure(
    parsed["error"].as_str() == Some(expected),
    format!("expected {expected}, got {body}"),
  )?;
  ensure(
    parsed.get("access_token").is_none() && parsed.get("refresh_token").is_none(),
    format!("a rejection must mint no token: {body}"),
  )
}

/// A device authorization wider than the client registration is `invalid_scope`.
pub async fn device_over_registered_scope() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    PUBLIC_CLIENT,
    None,
    &[DEVICE_GRANT],
    SCOPE,
    TokenEndpointAuthMethod::None,
  )
  .await?;
  let (status, _, body) = world
    .post_form(
      "/device_authorization",
      &[("client_id", PUBLIC_CLIENT), ("scope", "read write")],
      None,
      &[],
    )
    .await?;
  ensure_error(status, &body, StatusCode::BAD_REQUEST, "invalid_scope")?;
  ensure(
    json_body(&body)?.get("device_code").is_none(),
    format!("an over-scope request must mint no device code: {body}"),
  )
}

/// An approved device interaction both consumed-code rows observe.
struct ApprovedDevice {
  /// Live world owned by the flow.
  world: World,
  /// Authenticated session id.
  session: String,
  /// Opaque device code.
  device_code: String,
  /// Display user code.
  user_code: String,
  /// Polling proof key.
  key: DpopKey,
  /// Polling client.
  client: Client<'static>,
}

/// Issue a device code, approve it through the real UI, and return the state
/// both consumed-code rows observe.
async fn approve_device() -> Result<ApprovedDevice, TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_public_client(&world).await?;
  let browser = browser::login_session(world, DEVICE_EMAIL, DEVICE_PASSWORD).await?;
  let session = browser
    .session
    .clone()
    .ok_or_else(|| fail("login_session must authenticate"))?;
  let key = DpopKey::generate()?;
  let client = Client {
    id: PUBLIC_CLIENT,
    secret: None,
    scope: SCOPE,
  };
  let (device_code, user_code) = issue(&browser.world, client, &key).await?;
  let page = device::review(&browser.world, &session, &user_code).await?;
  let csrf = browser::hidden_input(&page, "csrf")?;
  decide(
    &browser.world,
    Decision {
      session: &session,
      user_code: &user_code,
      csrf: &csrf,
      action: "approve",
    },
  )
  .await?;
  Ok(ApprovedDevice {
    world: browser.world,
    session,
    device_code,
    user_code,
    key,
    client,
  })
}

/// A consumed user code at `/device` is the generic 200 miss, never
/// `expired_token`.
pub async fn device_user_code_consumed() -> Result<(), TestError> {
  let approved = approve_device().await?;
  let cookie = device::session_cookie(&approved.session);
  let (status, _, body) = approved
    .world
    .post_form(
      "/device",
      &[("user_code", approved.user_code.as_str())],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("a consumed user_code must be a 200 miss, got {status}: {body}"),
  )?;
  ensure(
    !body.contains("expired_token")
      && !body.contains(PUBLIC_CLIENT)
      && !body.contains("access_token"),
    format!("the /device miss must be generic: {body}"),
  )
}

/// A consumed device code at `/token` is `400 expired_token` and mints nothing.
pub async fn device_code_consumed_at_token() -> Result<(), TestError> {
  let approved = approve_device().await?;
  let request = Poll {
    client: approved.client,
    device_code: &approved.device_code,
  };
  let (status, body) = poll(&approved.world, request, &approved.key).await?;
  ensure(
    status == StatusCode::OK,
    format!("the approved poll must mint: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["access_token"].as_str().is_some(),
    "the first poll must mint an access token",
  )?;
  let (status, body) = poll(&approved.world, request, &approved.key).await?;
  ensure_error(status, &body, StatusCode::BAD_REQUEST, "expired_token")
}

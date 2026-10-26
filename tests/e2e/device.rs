//! Device-grant wire mechanics shared by `tests/e2e_device.rs`.
//!
//! The suite owns the scenario assertions; this module owns the RFC 8628
//! request shapes (authorization issue, review page + CSRF, decision, poll)
//! and the fixture client definitions.

use d_oauth::db::TokenEndpointAuthMethod;
use reqwest::StatusCode;

use super::{
  browser,
  dpop::DpopKey,
  harness::{SeedClientOpts, TestError, World, ensure, fail, json_body, seed_client_bound},
};

/// Grant-type URN for the device-code grant (RFC 8628 §3.4).
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Catalog scope the device requests and the user is entitled to.
pub const SCOPE: &str = "read";
/// DPoP-bound confidential client used for the approve/poll/introspect case.
pub const DEVICE_CLIENT: &str = "e2e-device-owner";
/// Owner secret (also the leak probe).
pub const DEVICE_SECRET: &str = "e2e-device-secret-1a2b3c4d5e6f708192a0";
/// Public DPoP-bound client used for the deny and normalization cases.
pub const PUBLIC_CLIENT: &str = "e2e-device-public";

/// A client that may request a device authorization.
#[derive(Clone, Copy)]
pub struct Client<'a> {
  /// Registered client id.
  pub id: &'a str,
  /// Owner secret; `None` for a public client.
  pub secret: Option<&'a str>,
  /// Requested/registered scope.
  pub scope: &'a str,
}

impl Client<'_> {
  /// Basic-auth pair for a confidential client, `None` for a public one.
  fn basic(&self) -> Option<(&str, &str)> {
    self.secret.map(|secret| (self.id, secret))
  }
}

/// One `/token` device-code poll.
#[derive(Clone, Copy)]
pub struct Poll<'a> {
  /// Polling client.
  pub client: Client<'a>,
  /// Opaque device code returned by `/device_authorization`.
  pub device_code: &'a str,
}

/// One approve/deny submission from the review page.
#[derive(Clone, Copy)]
pub struct Decision<'a> {
  /// Authenticated session id.
  pub session: &'a str,
  /// User code echoed by the review form.
  pub user_code: &'a str,
  /// Stateless CSRF token minted for this decision.
  pub csrf: &'a str,
  /// `approve` or `deny`.
  pub action: &'a str,
}

/// Seed the public DPoP-bound client used by the deny and normalization rows.
pub async fn seed_public_client(world: &World) -> Result<(), TestError> {
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    PUBLIC_CLIENT,
    None,
    &SeedClientOpts {
      grants: &[DEVICE_GRANT],
      scope: SCOPE,
      method: TokenEndpointAuthMethod::None,
      dpop_bound: true,
    },
  )
  .await
}

/// `POST /device_authorization` with a fresh proof; returns
/// `(device_code, user_code)`.
pub async fn issue(
  world: &World,
  client: Client<'_>,
  key: &DpopKey,
) -> Result<(String, String), TestError> {
  let htu = format!("{}/device_authorization", world.state.config.issuer);
  let proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/device_authorization",
      &[("client_id", client.id), ("scope", client.scope)],
      client.basic(),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("device authorization must 200: {status} {body}"),
  )?;
  let payload = json_body(&body)?;
  let device_code = payload["device_code"]
    .as_str()
    .ok_or_else(|| fail("device authorization must return device_code"))?
    .to_owned();
  let user_code = payload["user_code"]
    .as_str()
    .ok_or_else(|| fail("device authorization must return user_code"))?
    .to_owned();
  Ok((device_code, user_code))
}

/// `POST /token` for the device grant with a fresh proof per attempt.
pub async fn poll(
  world: &World,
  request: Poll<'_>,
  key: &DpopKey,
) -> Result<(StatusCode, String), TestError> {
  let htu = format!("{}/token", world.state.config.issuer);
  let proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", DEVICE_GRANT),
        ("device_code", request.device_code),
        ("client_id", request.client.id),
      ],
      request.client.basic(),
      &[("dpop", proof.as_str())],
    )
    .await?;
  Ok((status, body))
}

/// Session cookie header for the device UI.
pub fn session_cookie(session: &str) -> String {
  format!("{}={session}", browser::SESSION_COOKIE)
}

/// `POST /device` with a code and no `action`: the review page (with CSRF).
pub async fn review(world: &World, session: &str, user_code: &str) -> Result<String, TestError> {
  let cookie = session_cookie(session);
  let (status, _, body) = world
    .post_form(
      "/device",
      &[("user_code", user_code)],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("device review page must render: {status} {body}"),
  )?;
  Ok(body)
}

/// Approve or deny the pending device request through the real form.
pub async fn decide(world: &World, decision: Decision<'_>) -> Result<(), TestError> {
  let cookie = session_cookie(decision.session);
  let (status, _, body) = world
    .post_form(
      "/device",
      &[
        ("user_code", decision.user_code),
        ("action", decision.action),
        ("csrf", decision.csrf),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!(
      "device {} must render the outcome page: {status} {body}",
      decision.action
    ),
  )?;
  Ok(())
}

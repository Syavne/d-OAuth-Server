//! `binary(e2e_device)` device-grant flow over the live router (RFC 8628).
//!
//! Every request goes through the production router over a loopback socket
//! against the real shared Postgres + Redis. The tests drive the real user
//! half (`POST /device` entry form, review form, CSRF) through the shared
//! browser helper, then poll `/token` with a fresh DPoP proof, exactly as a
//! device would.
//!
//! The minted token is introspected with the owner client: introspection is
//! client-scoped (`src/protocol/introspect.rs`, a foreign token collapses to
//! `active:false`) and RFC 7662 authentication rejects the public `none`
//! method, so the DPoP-bound device client here holds a secret for the
//! introspection leg. Public-client device issuance and denial are covered by
//! the other two cases.

#[path = "e2e/harness.rs"]
#[allow(dead_code)]
mod harness;

#[path = "e2e/browser.rs"]
#[allow(dead_code)]
mod browser;

#[path = "e2e/dpop.rs"]
mod dpop;

#[path = "e2e/device.rs"]
mod device;

use d_oauth::db::TokenEndpointAuthMethod;
use device::{
  Client, DEVICE_CLIENT, DEVICE_GRANT, DEVICE_SECRET, Decision, PUBLIC_CLIENT, Poll, SCOPE, decide,
  issue, poll, review, seed_public_client,
};
use dpop::DpopKey;
use harness::{
  SeedClientOpts, TestError, World, ensure, fail, json_body, open_rate_limit, seed_client_bound,
  seed_scope,
};
use reqwest::StatusCode;

/// Provisioned user in the approve/poll case.
const OWNER_EMAIL: &str = "device-owner@example.test";
/// Provisioned password in the approve/poll case.
const OWNER_PASSWORD: &str = "e2e-device-owner-password-1a2b";
/// Provisioned user in the deny case.
const DENY_EMAIL: &str = "device-deny@example.test";
/// Provisioned password in the deny case.
const DENY_PASSWORD: &str = "e2e-device-deny-password-1a2b";
/// Provisioned user in the normalization case.
const NORMALIZE_EMAIL: &str = "device-normalize@example.test";
/// Provisioned password in the normalization case.
const NORMALIZE_PASSWORD: &str = "e2e-device-normalize-password-1a2b";
/// Provisioned user in the guess-budget case.
const BUDGET_EMAIL: &str = "device-budget@example.test";
/// Provisioned password in the guess-budget case.
const BUDGET_PASSWORD: &str = "e2e-device-budget-password-1a2b";

/// Approve through the UI, then redeem exactly once and introspect the token.
#[tokio::test]
async fn e2e_device_grant_approve_poll_mint() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let client = Client {
    id: DEVICE_CLIENT,
    secret: Some(DEVICE_SECRET),
    scope: SCOPE,
  };
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    client.id,
    client.secret,
    &SeedClientOpts {
      grants: &[DEVICE_GRANT],
      scope: SCOPE,
      method: TokenEndpointAuthMethod::ClientSecretBasic,
      dpop_bound: true,
    },
  )
  .await?;
  seed_scope(&world.pool, SCOPE).await?;
  let key = DpopKey::generate()?;
  let (device_code, user_code) = issue(&world, client, &key).await?;

  // The anonymous GET /device only renders the entry form; the review page
  // comes from POST /device without an `action`, on an authenticated session.
  let browser = browser::login_session(world, OWNER_EMAIL, OWNER_PASSWORD).await?;
  let session = browser
    .session
    .as_deref()
    .ok_or_else(|| fail("login_session must return an authenticated session"))?;
  let page = review(&browser.world, session, &user_code).await?;
  let csrf = browser::hidden_input(&page, "csrf")?;
  decide(
    &browser.world,
    Decision {
      session,
      user_code: &user_code,
      csrf: &csrf,
      action: "approve",
    },
  )
  .await?;

  let request = Poll {
    client,
    device_code: &device_code,
  };
  let (status, body) = poll(&browser.world, request, &key).await?;
  ensure(
    status == StatusCode::OK,
    format!("approved device poll must mint: {status} {body}"),
  )?;
  let tokens = json_body(&body)?;
  ensure(tokens["token_type"] == "DPoP", "token must be DPoP-bound")?;
  ensure(
    tokens["scope"] == SCOPE,
    "token must carry the granted scope",
  )?;
  let access_token = tokens["access_token"]
    .as_str()
    .filter(|token| !token.is_empty())
    .ok_or_else(|| fail("redemption must return a non-empty access token"))?;
  ensure(
    tokens["refresh_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "redemption must return a non-empty refresh token",
  )?;

  let basic = Some((DEVICE_CLIENT, DEVICE_SECRET));
  let (status, _, body) = browser
    .world
    .post_form("/introspect", &[("token", access_token)], basic, &[])
    .await?;
  ensure(status == StatusCode::OK, "introspection must answer 200")?;
  let introspection = json_body(&body)?;
  ensure(
    introspection["active"] == true,
    "minted token must be active",
  )?;
  ensure(
    introspection["client_id"] == DEVICE_CLIENT,
    "introspection must report the owning client",
  )?;

  // The code is single-use: the next poll is terminal `expired_token`, never a
  // second pair and never `invalid_grant`.
  let (status, body) = poll(&browser.world, request, &key).await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("second poll must be 400: {status} {body}"),
  )?;
  let error = json_body(&body)?;
  ensure(
    error["error"] == "expired_token",
    format!("consumed code must be expired_token: {error}"),
  )?;
  ensure(!body.contains("access_token"), "replay must mint nothing")?;
  Ok(())
}

/// Denying the request makes every later poll `access_denied` with no token.
#[tokio::test]
async fn e2e_device_grant_deny_is_access_denied() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let client = Client {
    id: PUBLIC_CLIENT,
    secret: None,
    scope: SCOPE,
  };
  seed_public_client(&world).await?;
  let key = DpopKey::generate()?;
  let (device_code, user_code) = issue(&world, client, &key).await?;

  let browser = browser::login_session(world, DENY_EMAIL, DENY_PASSWORD).await?;
  let session = browser
    .session
    .as_deref()
    .ok_or_else(|| fail("login_session must return an authenticated session"))?;
  let page = review(&browser.world, session, &user_code).await?;
  let csrf = browser::hidden_input(&page, "csrf")?;
  decide(
    &browser.world,
    Decision {
      session,
      user_code: &user_code,
      csrf: &csrf,
      action: "deny",
    },
  )
  .await?;

  let request = Poll {
    client,
    device_code: &device_code,
  };
  let (status, body) = poll(&browser.world, request, &key).await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("denied poll must be 400: {status} {body}"),
  )?;
  let error = json_body(&body)?;
  ensure(
    error["error"] == "access_denied",
    format!("denied poll must be access_denied: {error}"),
  )?;
  ensure(!body.contains("access_token"), "denial must mint nothing")?;
  Ok(())
}

/// A lowercase, hyphenated code resolves, and the 11th lookup from one IP is
/// rate-limited with a positive `Retry-After`.
#[tokio::test]
async fn e2e_device_user_code_normalization_and_guess_limit() -> Result<(), TestError> {
  // Normalization: a real code typed as `abcd-efgh` must reach the review
  // page. Separate worlds give the guess-budget half a fresh per-IP counter
  // (each world has its own Redis key prefix).
  let world = World::start(open_rate_limit()).await?;
  let client = Client {
    id: PUBLIC_CLIENT,
    secret: None,
    scope: SCOPE,
  };
  seed_public_client(&world).await?;
  let key = DpopKey::generate()?;
  let (_device_code, user_code) = issue(&world, client, &key).await?;
  let browser = browser::login_session(world, NORMALIZE_EMAIL, NORMALIZE_PASSWORD).await?;
  let session = browser
    .session
    .as_deref()
    .ok_or_else(|| fail("login_session must return an authenticated session"))?;
  let normalized = user_code.to_ascii_lowercase();
  ensure(
    normalized.contains('-'),
    "the issued user code must have the display hyphen",
  )?;
  let page = review(&browser.world, session, &normalized).await?;
  ensure(
    page.contains(PUBLIC_CLIENT),
    "the normalized code must resolve to the pending client",
  )?;
  // The review form is the observable proof the code was accepted.
  let _csrf = browser::hidden_input(&page, "csrf")?;

  // Guess budget: 10 lookups pass, the 11th from the same IP is `429` with a
  // positive `Retry-After` (RFC 8628 §3.3 brute-force protection).
  let world = World::start(open_rate_limit()).await?;
  let browser = browser::login_session(world, BUDGET_EMAIL, BUDGET_PASSWORD).await?;
  let session = browser
    .session
    .as_deref()
    .ok_or_else(|| fail("login_session must return an authenticated session"))?;
  let cookie = device::session_cookie(session);
  for attempt in 1..=10 {
    let code = format!("ZZZZ-{attempt:04}");
    let (status, _, body) = browser
      .world
      .post_form(
        "/device",
        &[("user_code", code.as_str())],
        None,
        &[("cookie", cookie.as_str())],
      )
      .await?;
    ensure(
      status == StatusCode::OK,
      format!("bad guess {attempt} must be allowed: {status} {body}"),
    )?;
  }
  let (status, headers, body) = browser
    .world
    .post_form(
      "/device",
      &[("user_code", "ZZZZ-9999")],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::TOO_MANY_REQUESTS,
    format!("the 11th bad guess must be 429: {status} {body}"),
  )?;
  let retry_after = headers
    .get(reqwest::header::RETRY_AFTER)
    .and_then(|value| value.to_str().ok())
    .ok_or_else(|| fail("429 must carry Retry-After"))?;
  let seconds: u64 = retry_after
    .parse()
    .map_err(|_| fail("Retry-After must be whole seconds"))?;
  ensure(seconds >= 1, "Retry-After must be positive")?;
  Ok(())
}

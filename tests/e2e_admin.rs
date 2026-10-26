//! `binary(e2e_admin)` disabled-user cascade over the live router.
//!
//! `user disable` purges the subject's Redis state BEFORE flipping the
//! Postgres flag (`src/cli/user.rs:105-137`), so this suite drives both halves
//! in that order. The purge removes the session, the unredeemed code, and the
//! approved device record; the flag kills introspection and refresh at their
//! use-time re-checks. A flag-only disable would still fail the token checks
//! but leave the code, the device record, and the session alive — exactly the
//! three records whose assertions here fail without the purge.
//!
//! The browser flow and device wire mechanics come from the shared
//! [`browser`]/[`device`] helpers. User-token subjects are the canonical
//! EMAIL, which is what `purge_subject` and the use-time re-checks resolve.
//! The approved device record must carry that subject too: a merely pending
//! record stores `subject: ""` and the purge never sees it
//! (`src/store/device.rs:49-50`, `src/protocol/purge.rs:131-145`).

// allow: SIZE_OK — the plan fixes both cascade scenarios in this one suite
// file, and the browser/device/harness modules are owned by sibling todos.
// The extra length is assertion messages, not duplicated driver logic.

#[path = "e2e/harness.rs"]
#[allow(dead_code)]
mod harness;

#[path = "e2e/browser.rs"]
#[allow(dead_code)]
mod browser;

#[path = "e2e/dpop.rs"]
#[allow(dead_code)]
mod dpop;

#[path = "e2e/device.rs"]
#[allow(dead_code)]
mod device;

use browser::{
  CLIENT_ID, INVALID_CREDENTIALS, REDIRECT_URI, SESSION_COOKIE, begin_browser, cookie_value,
  encoded, get_consent, hidden_input, location_of, oauth2_pkce, post_consent, post_login,
  query_value, totp_now,
};
use d_oauth::{
  db::{TokenEndpointAuthMethod, user_repo},
  protocol::{
    purge::{PurgedSubject, purge_subject},
    token::ClientKind,
  },
};
use device::{
  Client as DeviceClient, Decision, Poll, decide, issue, poll, review, seed_public_client,
};
use dpop::DpopKey;
use harness::{TestError, World, ensure, fail, json_body, open_rate_limit, seed_client};
use reqwest::StatusCode;

/// Provisioned user in the cascade case.
const CASCADE_EMAIL: &str = "e2e-admin-cascade@example.test";
/// Provisioned password in the cascade case.
const CASCADE_PASSWORD: &str = "e2e-admin-cascade-password-1a2b";
/// Confidential client used to introspect the minted tokens.
const INTROSPECT_CLIENT: &str = "e2e-admin-introspect";
/// Secret for [`INTROSPECT_CLIENT`].
const INTROSPECT_SECRET: &str = "e2e-admin-introspect-secret-1a2b3c4d5e6f";
/// Provisioned user in the re-login case.
const RELOGIN_EMAIL: &str = "e2e-admin-relogin@example.test";
/// Provisioned password in the re-login case.
const RELOGIN_PASSWORD: &str = "e2e-admin-relogin-password-1a2b";

/// Flip the flag exactly like the CLI: purge the subject's Redis state first,
/// then set `users.disabled`. Returns the purge summary.
async fn disable_like_cli(world: &World, email: &str) -> Result<PurgedSubject, TestError> {
  let record = user_repo::find_by_email(&world.pool, &world.state.keys, email)
    .await?
    .ok_or_else(|| fail("seeded user must resolve by email"))?;
  let mut conn = world.state.redis.clone();
  let summary = purge_subject(
    &mut conn,
    &world.store,
    &record.email,
    &record.id.to_string(),
  )
  .await?;
  ensure(
    user_repo::disable_user(&world.pool, record.id).await?,
    "disable_user must update the user row",
  )?;
  Ok(summary)
}

/// Introspect `token` as the confidential fixture client.
async fn introspect(world: &World, token: &str) -> Result<serde_json::Value, TestError> {
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", token)],
      Some((INTROSPECT_CLIENT, INTROSPECT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("introspection must answer 200: {status} {body}"),
  )?;
  json_body(&body)
}

/// Drive one more `/authorize` → `/consent` leg on an authenticated session
/// and return the fresh (unredeemed) code with its PKCE verifier.
async fn consent_for_new_code(
  browser: &browser::Browser,
  session: &str,
) -> Result<(String, String), TestError> {
  let (challenge, verifier) = oauth2_pkce();
  let issuer = &browser.world.state.config.issuer;
  let proof = browser.dpop.proof("GET", &format!("{issuer}/authorize"))?;
  let cookie = format!("{SESSION_COOKIE}={session}");
  let path = format!(
    "/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}\
     &code_challenge={challenge}&code_challenge_method=S256",
    encoded(CLIENT_ID),
    encoded(REDIRECT_URI),
    encoded(browser::SCOPE),
    encoded(browser::STATE),
  );
  let (status, headers, body) = browser
    .world
    .get(
      &path,
      &[("dpop", proof.as_str()), ("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("second authorize must 303 to login: {status} {body}"),
  )?;
  let request_id = query_value(&location_of(&headers)?, "request_id")?;
  let (status, headers, body) = browser
    .world
    .get(
      &format!("/login?request_id={request_id}"),
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("an authenticated login must 303 onward: {status} {body}"),
  )?;
  ensure(
    location_of(&headers)? == "/consent",
    "an authenticated session must land on consent",
  )?;

  let (status, _, body) = get_consent(browser, session).await?;
  ensure(
    status == StatusCode::OK,
    format!("second consent must render: {status} {body}"),
  )?;
  let bound = hidden_input(&body, "request_id")?;
  let csrf = hidden_input(&body, "csrf")?;
  let (status, headers, body) = post_consent(browser, session, &bound, &csrf, "approve").await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("second consent must 303 to the redirect: {status} {body}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location.starts_with(REDIRECT_URI),
    format!("the new code must return to the registered redirect: {location}"),
  )?;
  Ok((query_value(&location, "code")?, verifier))
}

/// Disabling a real user purges the session, the unredeemed code, and the
/// approved device record, and every use of the old material fails closed.
#[tokio::test]
async fn e2e_user_disable_kills_tokens_refresh_and_code() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(world, CASCADE_EMAIL, CASCADE_PASSWORD).await?;
  let two_factor = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) =
    post_login(&browser, &browser.password.clone(), &two_factor).await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status} {body}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;

  let (status, _, body) = get_consent(&browser, &session).await?;
  ensure(
    status == StatusCode::OK,
    format!("consent must render: {status} {body}"),
  )?;
  let request_id = hidden_input(&body, "request_id")?;
  let csrf = hidden_input(&body, "csrf")?;
  let (status, headers, body) =
    post_consent(&browser, &session, &request_id, &csrf, "approve").await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("consent approval must 303: {status} {body}"),
  )?;
  let code = query_value(&location_of(&headers)?, "code")?;

  // Redeem the first code for the real access/refresh pair.
  let proof = browser.dpop.proof(
    "POST",
    &format!("{}/token", browser.world.state.config.issuer),
  )?;
  let (status, _, body) = browser
    .world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", browser.verifier.as_str()),
      ],
      None,
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("code redemption must mint: {status} {body}"),
  )?;
  let tokens = json_body(&body)?;
  let access_token = tokens["access_token"]
    .as_str()
    .filter(|value| !value.is_empty())
    .ok_or_else(|| fail("redemption must return an access token"))?
    .to_owned();
  let refresh_token = tokens["refresh_token"]
    .as_str()
    .filter(|value| !value.is_empty())
    .ok_or_else(|| fail("redemption must return a refresh token"))?
    .to_owned();

  // A second, unredeemed code for the post-purge redemption check.
  let (fresh_code, fresh_verifier) = consent_for_new_code(&browser, &session).await?;

  // Approve a device code through the real UI so its record carries the
  // subject the purge will match. A pending record's empty subject is
  // invisible to `purge_subject`.
  seed_public_client(&browser.world).await?;
  let device_key = DpopKey::generate()?;
  let device_client = DeviceClient {
    id: device::PUBLIC_CLIENT,
    secret: None,
    scope: device::SCOPE,
  };
  let (device_code, user_code) = issue(&browser.world, device_client, &device_key).await?;
  let page = review(&browser.world, &session, &user_code).await?;
  let device_csrf = hidden_input(&page, "csrf")?;
  decide(
    &browser.world,
    Decision {
      session: session.as_str(),
      user_code: user_code.as_str(),
      csrf: device_csrf.as_str(),
      action: "approve",
    },
  )
  .await?;

  // A confidential fixture token proves introspection reads the live subject
  // before the cascade and the dead one after it.
  seed_client(
    &browser.world.pool,
    &browser.world.state.keys,
    INTROSPECT_CLIENT,
    Some(INTROSPECT_SECRET),
    &["authorization_code"],
    browser::SCOPE,
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  let fixture = browser
    .world
    .mint_for_subject(
      INTROSPECT_CLIENT,
      CASCADE_EMAIL,
      browser::SCOPE,
      ClientKind::Confidential,
      None,
    )
    .await?;
  ensure(
    introspect(&browser.world, &fixture.access_token).await?["active"] == true,
    "the fixture access token must start active",
  )?;

  // CLI order: purge the Redis state, then flip the flag.
  let summary = disable_like_cli(&browser.world, CASCADE_EMAIL).await?;
  ensure(
    summary.sessions >= 1,
    format!("the purge must delete the login session, got {summary:?}"),
  )?;
  ensure(
    summary.codes >= 1,
    format!("the purge must delete the unredeemed code, got {summary:?}"),
  )?;
  ensure(
    summary.devices == 1,
    format!("the purge must delete the approved device record, got {summary:?}"),
  )?;

  // 1. Introspection: both the fixture token and the browser token are dead.
  ensure(
    introspect(&browser.world, &fixture.access_token).await?["active"] == false,
    "the fixture access token must introspect inactive after disable",
  )?;
  ensure(
    introspect(&browser.world, &access_token).await?["active"] == false,
    "the browser access token must introspect inactive after disable",
  )?;

  // 2. Refresh: the record is gone, so the grant is invalid.
  let proof = browser.dpop.proof(
    "POST",
    &format!("{}/token", browser.world.state.config.issuer),
  )?;
  let (status, _, body) = browser
    .world
    .post_form(
      "/token",
      &[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", CLIENT_ID),
      ],
      None,
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("refresh must be 400: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_grant",
    "refresh must be invalid_grant",
  )?;

  // 3. Authorization code: the unredeemed record is gone.
  let proof = browser.dpop.proof(
    "POST",
    &format!("{}/token", browser.world.state.config.issuer),
  )?;
  let (status, _, body) = browser
    .world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", fresh_code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", fresh_verifier.as_str()),
      ],
      None,
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("code redemption must be 400: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_grant",
    "code redemption must be invalid_grant",
  )?;

  // 4. Device: the approved record is gone, so polling is terminal
  //    `expired_token` (never a mint, never `invalid_grant`).
  let (status, body) = poll(
    &browser.world,
    Poll {
      client: device_client,
      device_code: device_code.as_str(),
    },
    &device_key,
  )
  .await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("the purged device poll must be 400: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "expired_token",
    "the purged device code must be expired_token",
  )?;

  // 5. Session: the old cookie no longer authenticates a consent page.
  let (status, headers, _) = get_consent(&browser, &session).await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("a purged session must bounce from consent: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the purged session must bounce to /login",
  )?;
  Ok(())
}

/// A disabled account's correct password + TOTP is still the uniform 401 and
/// never upgrades the pre-session.
#[tokio::test]
async fn e2e_disabled_user_cannot_relogin() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(world, RELOGIN_EMAIL, RELOGIN_PASSWORD).await?;
  disable_like_cli(&browser.world, RELOGIN_EMAIL).await?;

  let two_factor = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) =
    post_login(&browser, &browser.password.clone(), &two_factor).await?;
  ensure(
    status == StatusCode::UNAUTHORIZED,
    format!("a disabled account must be 401: {status} {body}"),
  )?;
  ensure(
    body.contains(INVALID_CREDENTIALS),
    "the rejection must render the uniform credential message",
  )?;
  ensure(
    cookie_value(&headers, SESSION_COOKIE).is_err(),
    "a disabled account must not upgrade the pre-session",
  )?;
  let (status, headers, _) = get_consent(&browser, &browser.presession).await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("without a session consent must bounce to login: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the bounce target must be /login",
  )?;
  Ok(())
}

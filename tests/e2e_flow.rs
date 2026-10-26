//! `test(e2e_flow)` full-browser authorization-code flow over the live router.
//!
//! The existing e2e suites stop at `303 /login?request_id=` (or mint codes
//! directly through [`d_oauth::protocol::code::CodeIssuer`]); no test drives
//! the complete browser flow. These tests do: `GET /authorize` (RFC 6749
//! §4.1.1 + OAuth 2.1 draft §4.1.3) → `GET /login` → `POST /login` (password +
//! TOTP) → `GET /consent` → `POST /consent` → code on the registered redirect
//! (RFC 9700 §4.5.3, `code` + `state` + RFC 9207 `iss`) → `POST /token` with
//! the PKCE verifier (RFC 7636 §4.5) → tokens.
//!
//! A public client is used so the flow needs no PAR/JAR (a confidential
//! client with only plain query params is rejected with `invalid_request`).
//! Public clients are DPoP-bound end to end: the SAME [`browser::DpopKey`]
//! proves `GET /authorize` (its `jkt` is stashed in the pending-auth record)
//! and `POST /token` (the redemption checks the proof `jkt` against the code's
//! `cnf` binding), so one key spans the whole flow.
//!
//! The driver itself lives in [`browser`] so the CIMD, device, logout, and
//! disabled-user suites reuse one implementation instead of copying it.

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

#[allow(dead_code)]
#[path = "e2e/browser.rs"]
mod browser;

use browser::{
  CLIENT_ID, INVALID_CREDENTIALS, REDIRECT_URI, SCOPE, SESSION_COOKIE, STATE, begin_browser,
  cookie_value, get_consent, has_query_key, hidden_input, location_of, post_consent, post_login,
  query_value, totp_now,
};
use harness::{TestError, World, ensure, json_body, open_rate_limit};

/// Happy path: the full browser flow issues a code and redeems it for
/// DPoP-bound tokens; the code is single-use (RFC 6749 §4.1.2: a second
/// redemption is `invalid_grant`).
#[tokio::test]
async fn e2e_flow_browser_authorize_login_consent_token() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "flow-happy@example.test",
    "correct-horse-28-happy-path",
  )
  .await?;
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let (status, headers, _) = post_login(&browser, &browser.password.clone(), &code_2fa).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location == "/consent",
    format!("login must land on consent, got {location}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;
  ensure(
    session != browser.presession,
    "login must rotate the session id",
  )?;

  let (status, _, body) = get_consent(&browser, &session).await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("consent must render: {status} {body}"),
  )?;
  let bound = hidden_input(&body, "request_id")?;
  ensure(
    bound == browser.request_id,
    "consent must serve the bound authorization request",
  )?;
  let consent_csrf = hidden_input(&body, "csrf")?;

  let (status, headers, _) =
    post_consent(&browser, &session, &bound, &consent_csrf, "approve").await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("consent approval must 303 to the redirect: {status}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location.starts_with(REDIRECT_URI),
    format!("code must return to the registered redirect, got {location}"),
  )?;
  let code = query_value(&location, "code")?;
  ensure(
    query_value(&location, "state")? == STATE,
    "code redirect must echo state",
  )?;
  ensure(
    has_query_key(&location, "iss"),
    "code redirect must carry iss (RFC 9207)",
  )?;

  // Authorization-code redemption (RFC 7636 §4.5): the same DPoP key that
  // proved `/authorize` proves `/token`, binding the minted token.
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
    status == reqwest::StatusCode::OK,
    format!("code redemption must mint: {status} {body}"),
  )?;
  let tokens = json_body(&body)?;
  ensure(
    tokens["token_type"] == "DPoP",
    format!("public issuance must be DPoP-bound, got {tokens}"),
  )?;
  ensure(
    tokens["access_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "redemption must return an access token",
  )?;
  ensure(
    tokens["refresh_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "a registered refresh_token grant must return a refresh token",
  )?;
  ensure(
    tokens["scope"] == SCOPE,
    format!("tokens must carry the scope, got {tokens}"),
  )?;

  // The code is single-use: a second redemption fails closed.
  let replay = browser.dpop.proof(
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
      &[("dpop", replay.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("code replay must be 400, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_grant",
    "code replay must be invalid_grant",
  )?;
  Ok(())
}

/// A wrong password is rejected uniformly (401, no session upgrade): the
/// presession never becomes an authenticated session, so `/consent` bounces
/// back to `/login` and no code can ever issue for the flow.
#[tokio::test]
async fn e2e_flow_login_wrong_password_rejected() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "flow-badpw@example.test",
    "correct-horse-28-right-one",
  )
  .await?;
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) = post_login(&browser, "wrong-password-00000000", &code_2fa).await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    format!("wrong password must be 401, got {status}: {body}"),
  )?;
  ensure(
    body.contains(INVALID_CREDENTIALS),
    "rejection must render the uniform message",
  )?;
  ensure(
    cookie_value(&headers, SESSION_COOKIE).is_err(),
    "rejection must not upgrade the session",
  )?;
  let (status, headers, _) = get_consent(&browser, &browser.presession).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("without a session consent must bounce to login: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the bounce target must be the login page",
  )?;
  Ok(())
}

/// A correct password with a wrong TOTP code is rejected uniformly (401, no
/// session upgrade): the presession never becomes an authenticated session,
/// so `/consent` bounces back to `/login`. A follow-up attempt with the live
/// code still succeeds, proving the rejection was code-specific.
#[tokio::test]
async fn e2e_flow_login_wrong_totp_rejected() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "flow-badcode@example.test",
    "correct-horse-28-right-one",
  )
  .await?;
  // A valid-format but incorrect 6-digit code: flip the first digit of the
  // live code (the unit-suite `wrong_code` idiom).
  let live = totp_now(&browser.totp_secret).await?;
  let mut digits: Vec<u8> = live.bytes().collect();
  digits[0] = if digits[0] == b'0' { b'1' } else { b'0' };
  let wrong: String = digits.into_iter().map(|byte| byte as char).collect();
  let (status, headers, body) = post_login(&browser, &browser.password.clone(), &wrong).await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    format!("wrong TOTP must be 401, got {status}: {body}"),
  )?;
  ensure(
    body.contains(INVALID_CREDENTIALS),
    "rejection must render the uniform message",
  )?;
  ensure(
    cookie_value(&headers, SESSION_COOKIE).is_err(),
    "rejection must not upgrade the session",
  )?;
  let (status, headers, _) = get_consent(&browser, &browser.presession).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("without a session consent must bounce to login: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the bounce target must be the login page",
  )?;
  // The live code still authenticates afterwards: the rejection was
  // code-specific, not an account or session defect.
  let live = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) = post_login(&browser, &browser.password.clone(), &live).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("live code must 303 to consent: {status} {body}"),
  )?;
  ensure(
    location_of(&headers)? == "/consent",
    "live code must land on consent",
  )?;
  Ok(())
}

/// A mismatched login CSRF is rejected fail-closed (400 `invalid_request`,
/// no session upgrade): the presession never becomes an authenticated
/// session, so `/consent` bounces back to `/login`.
#[tokio::test]
async fn e2e_flow_login_csrf_mismatch_rejected() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "flow-badcsrf@example.test",
    "correct-horse-28-right-one",
  )
  .await?;
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let cookie = format!("{SESSION_COOKIE}={}", browser.presession);
  let (status, headers, body) = browser
    .world
    .post_form(
      "/login",
      &[
        ("email", browser.email.as_str()),
        ("password", browser.password.as_str()),
        ("code", code_2fa.as_str()),
        ("csrf", "tampered-token"),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("CSRF mismatch must be 400, got {status}: {body}"),
  )?;
  ensure(
    body.contains("invalid_request"),
    "CSRF mismatch must be invalid_request",
  )?;
  ensure(
    cookie_value(&headers, SESSION_COOKIE).is_err(),
    "rejection must not upgrade the session",
  )?;
  let (status, headers, _) = get_consent(&browser, &browser.presession).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("without a session consent must bounce to login: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the bounce target must be the login page",
  )?;
  Ok(())
}

/// Denying consent redirects to the registered redirect with
/// `error=access_denied` + echoed `state` (RFC 6749 §4.1.2.1) and issues no
/// code.
#[tokio::test]
async fn e2e_flow_consent_deny_redirects_access_denied() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "flow-deny@example.test",
    "correct-horse-28-deny-case",
  )
  .await?;
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) = post_login(&browser, &browser.password.clone(), &code_2fa).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status} {body}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;
  let (status, _, body) = get_consent(&browser, &session).await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("consent must render: {status}"),
  )?;
  let bound = hidden_input(&body, "request_id")?;
  let consent_csrf = hidden_input(&body, "csrf")?;

  let (status, headers, _) =
    post_consent(&browser, &session, &bound, &consent_csrf, "deny").await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("consent denial must 303 to the redirect: {status}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location.starts_with(REDIRECT_URI),
    format!("denial must return to the registered redirect, got {location}"),
  )?;
  ensure(
    query_value(&location, "error")? == "access_denied",
    "denial must carry error=access_denied",
  )?;
  ensure(
    query_value(&location, "state")? == STATE,
    "denial must echo state",
  )?;
  ensure(
    !has_query_key(&location, "code"),
    "denial must issue zero codes",
  )?;
  Ok(())
}

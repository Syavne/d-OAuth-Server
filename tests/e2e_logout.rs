//! `test(e2e_logout)` RP-initiated logout over the live router.
//!
//! `GET /logout` is a read-only confirmation, and only `POST /logout` with the
//! session-bound form token destroys the session. The return target is never
//! caller-supplied: `/authorize` freezes the client's registered post-logout
//! URI in session meta, and `POST /logout` honors it only while the client and
//! that exact URI are still registered.

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

#[allow(dead_code)]
#[path = "e2e/browser.rs"]
mod browser;

use browser::{
  SESSION_COOKIE, begin_browser, begin_browser_with_post_logout, cookie_value, get_consent,
  hidden_input, location_of, post_login, totp_now,
};
use harness::{TestError, World, ensure, open_rate_limit};

/// Registered client the logout flow drives.
const CLIENT_ID: &str = "e2e-logout-app";
/// Registered authorize redirect (RFC 8252 loopback exception applies).
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// Registered post-logout return target.
const POST_LOGOUT_URI: &str = "https://client.example.test/signed-out";
/// Catalog scope the client and the user share.
const SCOPE: &str = "read";

/// A valid `POST /logout` destroys the session server-side, clears the cookie,
/// and redirects to the exact post-logout URI the authorization flow froze.
#[tokio::test]
async fn e2e_logout_post_destroys_session_and_redirects() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser_with_post_logout(
    world,
    CLIENT_ID,
    REDIRECT_URI,
    SCOPE,
    "logout-post@example.test",
    "correct-horse-28-logout-post",
    POST_LOGOUT_URI,
  )
  .await?;
  let (session, cookie) = login(&browser).await?;

  let (status, _, body) = browser
    .world
    .get("/logout", &[("cookie", cookie.as_str())])
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("GET /logout must render the confirmation: {status} {body}"),
  )?;
  let logout_csrf = hidden_input(&body, "csrf")?;

  let (status, headers, body) = browser
    .world
    .post_form(
      "/logout",
      &[("csrf", logout_csrf.as_str())],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("POST /logout must 303 to the bound target: {status} {body}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location == POST_LOGOUT_URI,
    format!("logout must return to the registered post-logout URI, got {location}"),
  )?;
  let prefix = format!("{SESSION_COOKIE}=");
  let cleared = headers.get_all("set-cookie").iter().any(|value| {
    value
      .to_str()
      .ok()
      .is_some_and(|text| text.starts_with(prefix.as_str()) && text.contains("Max-Age=0"))
  });
  ensure(cleared, "POST /logout must expire the session cookie")?;

  let (status, headers, _) = get_consent(&browser, &session).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("the destroyed session must not reach consent: {status}"),
  )?;
  ensure(
    location_of(&headers)? == "/login",
    "the destroyed session must bounce consent to login",
  )?;
  Ok(())
}

/// `GET /logout` only renders the confirmation form; the session survives and
/// still serves the bound consent page.
#[tokio::test]
async fn e2e_logout_get_is_read_only() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "logout-get@example.test",
    "correct-horse-28-logout-get",
  )
  .await?;
  let (session, cookie) = login(&browser).await?;

  let (status, _, body) = browser
    .world
    .get("/logout", &[("cookie", cookie.as_str())])
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("GET /logout must render the confirmation: {status} {body}"),
  )?;
  ensure(
    body.contains("Sign out"),
    "GET /logout must offer the sign-out form",
  )?;
  let logout_csrf = hidden_input(&body, "csrf")?;
  ensure(
    !logout_csrf.is_empty(),
    "the confirmation form must carry a session-bound token",
  )?;

  let (status, _, body) = get_consent(&browser, &session).await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("a read-only GET must leave the session usable: {status} {body}"),
  )?;
  Ok(())
}

/// A POST without a valid session-bound token is rejected with
/// `invalid_request`, touches no cookie, and leaves the session usable.
#[tokio::test]
async fn e2e_logout_csrf_mismatch_keeps_session() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let browser = begin_browser(
    world,
    "logout-csrf@example.test",
    "correct-horse-28-logout-csrf",
  )
  .await?;
  let (session, cookie) = login(&browser).await?;

  for presented in [None, Some("forged-token")] {
    let params: Vec<(&str, &str)> = presented.map_or_else(Vec::new, |csrf| vec![("csrf", csrf)]);
    let (status, headers, body) = browser
      .world
      .post_form("/logout", &params, None, &[("cookie", cookie.as_str())])
      .await?;
    ensure(
      status == reqwest::StatusCode::BAD_REQUEST,
      format!("a bad logout token must be 400: {status} {body}"),
    )?;
    ensure(
      body.contains("invalid_request"),
      "a bad logout token must be invalid_request",
    )?;
    ensure(
      !headers.contains_key("set-cookie"),
      "a rejected logout must not touch cookies",
    )?;
  }

  let (status, _, body) = get_consent(&browser, &session).await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("a rejected logout must leave the session usable: {status} {body}"),
  )?;
  Ok(())
}

/// Log in through the driver and return the authenticated session id plus its
/// cookie header value.
async fn login(browser: &browser::Browser) -> Result<(String, String), TestError> {
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) = post_login(browser, &browser.password.clone(), &code_2fa).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status} {body}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;
  let cookie = format!("{SESSION_COOKIE}={session}");
  Ok((session, cookie))
}

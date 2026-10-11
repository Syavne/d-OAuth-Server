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
//! Public clients are DPoP-bound end to end: the SAME [`DpopKey`] proves
//! `GET /authorize` (its `jkt` is stashed in the pending-auth record) and
//! `POST /token` (the redemption checks the proof `jkt` against the code's
//! `cnf` binding), so one key spans the whole flow.

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

use std::time::Duration;

use d_oauth::db::{
  TokenEndpointAuthMethod,
  user_repo::{self, NewUser},
  user_scope_repo,
};
use dpop::DpopKey;
use harness::{
  TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_scope,
};

/// Fixture public client (no secret: DPoP is its sender constraint).
const CLIENT_ID: &str = "e2e-flow-public";
/// Registered loopback redirect (RFC 8252 loopback exception applies).
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// Catalog scope exercised by the flow.
const SCOPE: &str = "read";
/// `state` echoed from authorize to the code redirect (unreserved chars only).
const STATE: &str = "e2e-flow-state";
/// Session cookie name (production `src/ui/login.rs`: `SESSION_COOKIE`).
const SESSION_COOKIE: &str = "__Host-session_id";
/// Uniform credential-rejection page text (`INVALID_CREDENTIALS`).
const INVALID_CREDENTIALS: &str = "Invalid email, password, or code.";

/// One browser driving the flow: live world, PKCE pair, DPoP key, login
/// session material, and the provisioned user's credentials.
struct Browser {
  world: World,
  dpop: DpopKey,
  verifier: String,
  request_id: String,
  presession: String,
  login_csrf: String,
  email: String,
  password: String,
  totp_secret: String,
}

/// Seed the world (public client + scope + redirect) and one TOTP-enrolled
/// user entitled to the scope; drive `GET /authorize` → `GET /login`.
async fn begin_browser(email: &str, password: &str) -> Result<Browser, TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    CLIENT_ID,
    None,
    &["authorization_code", "refresh_token"],
    SCOPE,
    TokenEndpointAuthMethod::None,
  )
  .await?;
  seed_scope(&world.pool, SCOPE).await?;
  attach_redirect(&world.pool, &world.state.keys, CLIENT_ID, REDIRECT_URI).await?;
  let totp_secret = seed_user(&world, email, password).await?;

  let (challenge, verifier) = oauth2_pkce();
  let dpop = DpopKey::generate()?;
  let proof = dpop.proof("GET", &format!("{}/authorize", world.state.config.issuer))?;
  let (status, headers, body) = world
    .get(
      &format!(
        "/authorize?client_id={CLIENT_ID}&redirect_uri={}&response_type=code&scope={SCOPE}\
         &state={STATE}&code_challenge={challenge}&code_challenge_method=S256",
        encoded(REDIRECT_URI)
      ),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("authorize must 303 to login: {status} {body}"),
  )?;
  let request_id = query_value(&location_of(&headers)?, "request_id")?;
  // The authorize layer stashes the verified DPoP thumbprint in the
  // pending-auth record the later code issuance binds (RFC 9700 §4.5.3).
  let mut conn = world.state.redis.clone();
  let record = d_oauth::store::pending::get(&mut conn, &world.store, &request_id)
    .await
    .map_err(|error| fail(format!("pending read failed: {error}")))?
    .ok_or_else(|| fail("pending record must exist"))?;
  let expected = d_oauth::jose::jwk::thumbprint(&dpop.jwk())
    .map_err(|error| fail(format!("jwk thumbprint: {error}")))?;
  ensure(
    record.dpop_jkt.as_deref() == Some(expected.as_str()),
    "pending record must carry the verified DPoP thumbprint",
  )?;

  let (status, headers, body) = world
    .get(&format!("/login?request_id={request_id}"), &[])
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("login page must render: {status} {body}"),
  )?;
  let presession = cookie_value(&headers, SESSION_COOKIE)?;
  let login_csrf = hidden_input(&body, "csrf")?;
  Ok(Browser {
    world,
    dpop,
    verifier,
    request_id,
    presession,
    login_csrf,
    email: email.to_owned(),
    password: password.to_owned(),
    totp_secret,
  })
}

/// Provision one enabled user (known password + TOTP secret, entitled to
/// `SCOPE`) through the REAL repository path, using the server's own Argon2
/// parameters so verification matches production exactly.
async fn seed_user(world: &World, email: &str, password: &str) -> Result<String, TestError> {
  let raw = &world.state.config.argon2;
  let params =
    d_oauth::crypto::secret::Argon2Params::new(raw.memory_kib, raw.iterations, raw.parallelism, 32)
      .map_err(|error| fail(format!("argon2 params: {error}")))?;
  let hash = d_oauth::crypto::secret::hash_secret(password, &params)
    .map_err(|error| fail(format!("hash password: {error}")))?;
  let created = user_repo::create_user(
    &world.pool,
    &world.state.keys,
    world.state.config.pii_dual_write,
    &NewUser {
      email: email.to_owned(),
      password_hash: hash,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  let secret = d_oauth::crypto::totp::generate_secret()
    .map_err(|error| fail(format!("totp secret: {error}")))?;
  let blob = d_oauth::crypto::totp::encrypt_secret(
    &world.state.keys,
    &secret,
    !world.state.config.pii_dual_write,
  )
  .map_err(|error| fail(format!("totp seal: {error}")))?;
  ensure(
    user_repo::set_totp_secret(&world.pool, created.id, &blob).await?,
    "totp enroll must update the user row",
  )?;
  user_scope_repo::entitle(&world.pool, created.id, SCOPE, None).await?;
  Ok(secret)
}

/// Current TOTP code from the wall clock, computed the way the server
/// verifies it (RFC 6238, ±1-step window). Steps back from the step edge so
/// the code cannot roll over between generation and the `POST /login`.
async fn totp_now(secret: &str) -> Result<String, TestError> {
  let step = d_oauth::crypto::totp::TOTP_STEP_SECS;
  let now = time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
  if now % step >= step - 2 {
    tokio::time::sleep(Duration::from_secs(3)).await;
  }
  let now = time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
  let verifier = d_oauth::crypto::totp::build_totp(secret)
    .map_err(|error| fail(format!("totp verifier: {error}")))?;
  let counter = now / step;
  Ok(format!("{:06}", verifier.generate(counter * step)))
}

/// `POST /login` as the browser: presession cookie + form credentials.
async fn post_login(
  browser: &Browser,
  password: &str,
  code: &str,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String), TestError> {
  let cookie = format!("{SESSION_COOKIE}={}", browser.presession);
  browser
    .world
    .post_form(
      "/login",
      &[
        ("email", browser.email.as_str()),
        ("password", password),
        ("code", code),
        ("csrf", browser.login_csrf.as_str()),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await
}

/// `GET /consent` as the browser holding `session`.
async fn get_consent(
  browser: &Browser,
  session: &str,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String), TestError> {
  let cookie = format!("{SESSION_COOKIE}={session}");
  browser
    .world
    .get("/consent", &[("cookie", cookie.as_str())])
    .await
}

/// `POST /consent` with the bound `request_id` and the session form token.
async fn post_consent(
  browser: &Browser,
  session: &str,
  request_id: &str,
  csrf: &str,
  decision: &str,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String), TestError> {
  let cookie = format!("{SESSION_COOKIE}={session}");
  browser
    .world
    .post_form(
      "/consent",
      &[
        ("request_id", request_id),
        ("csrf", csrf),
        ("decision", decision),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await
}

/// Happy path: the full browser flow issues a code and redeems it for
/// DPoP-bound tokens; the code is single-use (RFC 6749 §4.1.2: a second
/// redemption is `invalid_grant`).
#[tokio::test]
async fn e2e_flow_browser_authorize_login_consent_token() -> Result<(), TestError> {
  let browser = begin_browser("flow-happy@example.test", "correct-horse-28-happy-path").await?;
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
  let browser = begin_browser("flow-badpw@example.test", "correct-horse-28-right-one").await?;
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

/// Denying consent redirects to the registered redirect with
/// `error=access_denied` + echoed `state` (RFC 6749 §4.1.2.1) and issues no
/// code.
#[tokio::test]
async fn e2e_flow_consent_deny_redirects_access_denied() -> Result<(), TestError> {
  let browser = begin_browser("flow-deny@example.test", "correct-horse-28-deny-case").await?;
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

/// PKCE pair from the `oauth2` crate (baseline-flow material only).
fn oauth2_pkce() -> (String, String) {
  let (challenge, verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
  (challenge.as_str().to_owned(), verifier.secret().to_owned())
}

/// Percent-encode a value for query embedding.
fn encoded(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
      out.push(byte as char);
    } else {
      out.push_str(&format!("%{byte:02X}"));
    }
  }
  out
}

/// Read the `location` header or fail the test.
fn location_of(headers: &reqwest::header::HeaderMap) -> Result<String, TestError> {
  headers
    .get("location")
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
    .ok_or_else(|| fail("response lacks location header"))
}

/// Read a cookie value from the `set-cookie` headers or fail the test.
fn cookie_value(headers: &reqwest::header::HeaderMap, name: &str) -> Result<String, TestError> {
  let prefix = format!("{name}=");
  let mut found = None;
  for value in headers.get_all("set-cookie").iter() {
    let text = value
      .to_str()
      .map_err(|_| fail("set-cookie is not visible ascii"))?;
    if let Some(rest) = text.strip_prefix(prefix.as_str()) {
      let end = rest.find(';').unwrap_or(rest.len());
      found = Some(rest[..end].to_owned());
    }
  }
  found.ok_or_else(|| fail(format!("response lacks {name} cookie")))
}

/// Read a hidden form field (`name=".." value=".."`) from a page or fail.
fn hidden_input(body: &str, name: &str) -> Result<String, TestError> {
  let needle = format!("name=\"{name}\" value=\"");
  let start = body
    .find(needle.as_str())
    .ok_or_else(|| fail(format!("page lacks hidden {name}")))?;
  let rest = &body[start + needle.len()..];
  let end = rest
    .find('"')
    .ok_or_else(|| fail(format!("hidden {name} is unterminated")))?;
  Ok(rest[..end].to_owned())
}

/// Read one query value from a redirect location or fail the test.
fn query_value(location: &str, key: &str) -> Result<String, TestError> {
  let query = location
    .split_once('?')
    .map(|pair| pair.1)
    .ok_or_else(|| fail(format!("location carries no query: {location}")))?;
  let prefix = format!("{key}=");
  for pair in query.split('&') {
    if let Some(value) = pair.strip_prefix(prefix.as_str()) {
      return Ok(value.to_owned());
    }
  }
  Err(fail(format!("location lacks {key}: {location}")))
}

/// Whether a redirect location carries a query key.
fn has_query_key(location: &str, key: &str) -> bool {
  let Some(query) = location.split_once('?').map(|pair| pair.1) else {
    return false;
  };
  let prefix = format!("{key}=");
  query
    .split('&')
    .any(|pair| pair.strip_prefix(prefix.as_str()).is_some())
}

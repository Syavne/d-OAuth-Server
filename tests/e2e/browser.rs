//! Shared browser-flow driver for the end-to-end suites.
//!
//! One [`Browser`] walks the real authorization-code UI over the live router:
//! `GET /authorize` (RFC 6749 §4.1.1 + OAuth 2.1 draft §4.1.3) → `GET /login` →
//! `POST /login` (password + TOTP) → `GET /consent` → `POST /consent` → code on
//! the registered redirect (RFC 9700 §4.5.3, `code` + `state` + RFC 9207
//! `iss`), and the caller redeems it with [`Browser::verifier`].
//!
//! Suites include this file with `#[path = "e2e/browser.rs"] mod browser;` and
//! must also include `e2e/harness.rs` and `e2e/dpop.rs` as siblings: the driver
//! borrows their [`World`] and [`DpopKey`]. The world is supplied by the caller
//! so a suite can pin its own config (CIMD fetcher, rate budgets, feature
//! gates) before the driver touches it.
//!
//! A public client is used so the flow needs no PAR/JAR (a confidential client
//! with only plain query params is rejected with `invalid_request`). Public
//! clients are DPoP-bound end to end: the SAME [`DpopKey`] proves
//! `GET /authorize` (its `jkt` is stashed in the pending-auth record) and
//! `POST /token` (the redemption checks the proof `jkt` against the code's
//! `cnf` binding), so one key spans the whole flow.

// allow: SIZE_OK — the plan fixes one shared driver surface (four constructors
// plus the exported HTTP helpers) at this single path; splitting it would
// scatter the contract the suite modules import.

use std::time::Duration;

use d_oauth::db::{
  TokenEndpointAuthMethod,
  user_repo::{self, NewUser},
  user_scope_repo,
};

pub use super::dpop::DpopKey;
use super::harness::{
  TestError, World, attach_post_logout, attach_redirect, ensure, fail, seed_client, seed_scope,
};

/// Fixture public client used by [`begin_browser`] (no secret: DPoP is its
/// sender constraint).
pub const CLIENT_ID: &str = "e2e-flow-public";
/// Registered loopback redirect for [`begin_browser`] (RFC 8252 loopback
/// exception applies).
pub const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// Catalog scope exercised by [`begin_browser`].
pub const SCOPE: &str = "read";
/// `state` echoed from authorize to the code redirect (unreserved chars only).
pub const STATE: &str = "e2e-flow-state";
/// Session cookie name (production `src/ui/login.rs`: `SESSION_COOKIE`).
pub const SESSION_COOKIE: &str = "__Host-session_id";
/// Uniform credential-rejection page text (`INVALID_CREDENTIALS`).
pub const INVALID_CREDENTIALS: &str = "Invalid email, password, or code.";

/// One browser driving the flow: live world, PKCE pair, DPoP key, login
/// session material, and the provisioned user's credentials.
pub struct Browser {
  /// Live router world the flow runs against.
  pub world: World,
  /// Sender-constraint key proving both `/authorize` and `/token`.
  pub dpop: DpopKey,
  /// PKCE `code_verifier` matching the challenge sent to `/authorize`.
  pub verifier: String,
  /// Pending-auth id the authorize redirect handed to `/login`.
  pub request_id: String,
  /// Pre-login session id (`GET /login`).
  pub presession: String,
  /// Authenticated session id, when a constructor logged in already.
  pub session: Option<String>,
  /// Login-form CSRF token (`GET /login`).
  pub login_csrf: String,
  /// Provisioned user's email.
  pub email: String,
  /// Provisioned user's password.
  pub password: String,
  /// Provisioned user's TOTP secret.
  pub totp_secret: String,
}

/// Client metadata a browser run drives authorize for.
struct Flow<'a> {
  /// Client id the authorize request presents.
  client_id: &'a str,
  /// Callback the authorize request presents.
  redirect_uri: &'a str,
  /// Requested scope.
  scope: &'a str,
  /// Provisioned user's email.
  email: &'a str,
  /// Provisioned user's password.
  password: &'a str,
}

/// Seed the fixed e2e-flow client (public, code + refresh) and one
/// TOTP-enrolled user entitled to [`SCOPE`]; drive `GET /authorize` →
/// `GET /login` against the caller's world.
///
/// # Errors
///
/// Returns any seeding, routing, or assertion failure of the first two legs.
pub async fn begin_browser(
  world: World,
  email: &str,
  password: &str,
) -> Result<Browser, TestError> {
  begin_registered(
    world,
    Flow {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      email,
      password,
    },
  )
  .await
}

/// Drive the first two legs for a client the world resolves another way
/// (a CIMD document), so no client row or redirect is seeded: only the scope
/// catalog entry and the entitled user. `GET /authorize` performs the fetch.
///
/// # Errors
///
/// Returns any seeding, routing, or assertion failure of the first two legs.
pub async fn begin_browser_for(
  world: World,
  client_id: &str,
  redirect_uri: &str,
  scope: &str,
  email: &str,
  password: &str,
) -> Result<Browser, TestError> {
  let flow = Flow {
    client_id,
    redirect_uri,
    scope,
    email,
    password,
  };
  seed_scope(&world.pool, flow.scope).await?;
  let totp_secret = seed_user(&world, flow.email, flow.password, flow.scope).await?;
  authorize_login(world, &flow, totp_secret).await
}

/// Seed a registered public client with both an authorize and a post-logout
/// redirect, then drive the first two legs; `/authorize` freezes the logout
/// binding in the session meta.
///
/// # Errors
///
/// Returns any seeding, routing, or assertion failure of the first two legs.
pub async fn begin_browser_with_post_logout(
  world: World,
  client_id: &str,
  redirect_uri: &str,
  scope: &str,
  email: &str,
  password: &str,
  post_logout_uri: &str,
) -> Result<Browser, TestError> {
  let flow = Flow {
    client_id,
    redirect_uri,
    scope,
    email,
    password,
  };
  let totp_secret = seed_registered(&world, &flow, Some(post_logout_uri)).await?;
  authorize_login(world, &flow, totp_secret).await
}

/// Seed one entitled user and sign in through `GET /login` → `POST /login`
/// with no pending authorization request (the device-approval entry point).
/// The returned [`Browser::session`] is the authenticated session id.
///
/// # Errors
///
/// Returns any seeding, routing, or assertion failure of the login legs.
pub async fn login_session(
  world: World,
  email: &str,
  password: &str,
) -> Result<Browser, TestError> {
  seed_scope(&world.pool, SCOPE).await?;
  let totp_secret = seed_user(&world, email, password, SCOPE).await?;
  let (status, headers, body) = world.get("/login", &[]).await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("standalone login page must render: {status} {body}"),
  )?;
  let presession = cookie_value(&headers, SESSION_COOKIE)?;
  let login_csrf = hidden_input(&body, "csrf")?;
  let code_2fa = totp_now(&totp_secret).await?;
  let cookie = format!("{SESSION_COOKIE}={presession}");
  let (status, headers, body) = world
    .post_form(
      "/login",
      &[
        ("email", email),
        ("password", password),
        ("code", code_2fa.as_str()),
        ("csrf", login_csrf.as_str()),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("standalone login must 303: {status} {body}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;
  Ok(Browser {
    world,
    dpop: DpopKey::generate()?,
    verifier: String::new(),
    request_id: String::new(),
    presession,
    session: Some(session),
    login_csrf,
    email: email.to_owned(),
    password: password.to_owned(),
    totp_secret,
  })
}

/// Seed a fixed-client flow and drive the first two legs.
async fn begin_registered(world: World, flow: Flow<'_>) -> Result<Browser, TestError> {
  let totp_secret = seed_registered(&world, &flow, None).await?;
  authorize_login(world, &flow, totp_secret).await
}

/// Seed the client row, its catalog scope, its authorize redirect (plus an
/// optional post-logout redirect), and one entitled user.
async fn seed_registered(
  world: &World,
  flow: &Flow<'_>,
  post_logout_uri: Option<&str>,
) -> Result<String, TestError> {
  seed_client(
    &world.pool,
    &world.state.keys,
    flow.client_id,
    None,
    &["authorization_code", "refresh_token"],
    flow.scope,
    TokenEndpointAuthMethod::None,
  )
  .await?;
  seed_scope(&world.pool, flow.scope).await?;
  attach_redirect(
    &world.pool,
    &world.state.keys,
    flow.client_id,
    flow.redirect_uri,
  )
  .await?;
  if let Some(uri) = post_logout_uri {
    attach_post_logout(&world.pool, &world.state.keys, flow.client_id, uri).await?;
  }
  seed_user(world, flow.email, flow.password, flow.scope).await
}

/// Drive `GET /authorize` → pending-record binding check → `GET /login`.
async fn authorize_login(
  world: World,
  flow: &Flow<'_>,
  totp_secret: String,
) -> Result<Browser, TestError> {
  let (challenge, verifier) = oauth2_pkce();
  let dpop = DpopKey::generate()?;
  let proof = dpop.proof("GET", &format!("{}/authorize", world.state.config.issuer))?;
  let (status, headers, body) = world
    .get(
      &format!(
        "/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}\
         &code_challenge={challenge}&code_challenge_method=S256",
        encoded(flow.client_id),
        encoded(flow.redirect_uri),
        encoded(flow.scope),
        encoded(STATE)
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
    session: None,
    login_csrf,
    email: flow.email.to_owned(),
    password: flow.password.to_owned(),
    totp_secret,
  })
}

/// Provision one enabled user (known password + TOTP secret, entitled to
/// `scope`) through the REAL repository path, using the server's own Argon2
/// parameters so verification matches production exactly.
///
/// # Errors
///
/// Returns a hashing, repository, or TOTP-sealing failure.
pub async fn seed_user(
  world: &World,
  email: &str,
  password: &str,
  scope: &str,
) -> Result<String, TestError> {
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
  user_scope_repo::entitle(&world.pool, created.id, scope, None).await?;
  Ok(secret)
}

/// Current TOTP code from the wall clock, computed the way the server
/// verifies it (RFC 6238, ±1-step window). Steps back from the step edge so
/// the code cannot roll over between generation and the `POST /login`.
///
/// # Errors
///
/// Returns a TOTP-constructor failure.
pub async fn totp_now(secret: &str) -> Result<String, TestError> {
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
///
/// # Errors
///
/// Returns the HTTP transport failure.
pub async fn post_login(
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
///
/// # Errors
///
/// Returns the HTTP transport failure.
pub async fn get_consent(
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
///
/// # Errors
///
/// Returns the HTTP transport failure.
pub async fn post_consent(
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

/// PKCE pair from the `oauth2` crate.
#[must_use]
pub fn oauth2_pkce() -> (String, String) {
  let (challenge, verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
  (challenge.as_str().to_owned(), verifier.secret().to_owned())
}

/// Percent-encode a value for query embedding.
#[must_use]
pub fn encoded(value: &str) -> String {
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
///
/// # Errors
///
/// Returns [`TestError::Failed`] when the header is absent or not ASCII.
pub fn location_of(headers: &reqwest::header::HeaderMap) -> Result<String, TestError> {
  headers
    .get("location")
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
    .ok_or_else(|| fail("response lacks location header"))
}

/// Read a cookie value from the `set-cookie` headers or fail the test.
///
/// # Errors
///
/// Returns [`TestError::Failed`] when the cookie is absent or not ASCII.
pub fn cookie_value(headers: &reqwest::header::HeaderMap, name: &str) -> Result<String, TestError> {
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
///
/// # Errors
///
/// Returns [`TestError::Failed`] when the field is absent or unterminated.
pub fn hidden_input(body: &str, name: &str) -> Result<String, TestError> {
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
///
/// # Errors
///
/// Returns [`TestError::Failed`] when the query or key is absent.
pub fn query_value(location: &str, key: &str) -> Result<String, TestError> {
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
#[must_use]
pub fn has_query_key(location: &str, key: &str) -> bool {
  let Some(query) = location.split_once('?').map(|pair| pair.1) else {
    return false;
  };
  let prefix = format!("{key}=");
  query
    .split('&')
    .any(|pair| pair.strip_prefix(prefix.as_str()).is_some())
}

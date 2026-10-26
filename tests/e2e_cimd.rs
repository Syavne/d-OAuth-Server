//! `test(e2e_cimd)` end-to-end coverage of Client ID Metadata Documents
//! (CIMD draft §3/§4.1/§5) through the real router and the injected fetcher
//! seam (`AppState::cimd_fetcher`).
//!
//! Every world installs its own counting fetcher, so the cache behavior is
//! observed rather than assumed: one fetch for the first resolution, zero for
//! every cached/registered/inactive resolution within the TTL. Each invalid
//! document row gets its own world (and its own URL) so the short-lived
//! `cimd:invalid:` marker cannot replay across rows.
//!
//! The fetcher is the ONLY document source: no test performs a real network
//! call.

use std::{
  future::Future,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
};

use base64::Engine as _;
use d_oauth::{
  db::{TokenEndpointAuthMethod, client_repo},
  protocol::cimd::{CimdDocument, CimdError, CimdFetchFuture, CimdFetcher, CimdLimits},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};
use time::OffsetDateTime;

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

#[allow(dead_code)]
#[path = "e2e/browser.rs"]
mod browser;

use browser::{
  Browser, SESSION_COOKIE, cookie_value, get_consent, hidden_input, location_of, oauth2_pkce,
  post_consent, post_login, query_value, seed_user, totp_now,
};
use harness::{
  TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_scope,
};

/// Registration-free client identifier: an `https://` document URL.
const CLIENT_URL: &str = "https://cimd.example.test/client.json";
/// Loopback redirect declared by the fixture documents (RFC 8252 §7.3).
const REDIRECT: &str = "http://127.0.0.1:9/cb";
/// Catalog scope the fixture documents and users are entitled to.
const SCOPE: &str = "read";
/// `state` echoed from authorize to the code redirect.
const STATE: &str = "cimd-e2e-state";

/// Start a world with a counting fetcher and the CIMD feature gate.
async fn cimd_world(fetcher: CimdFetcher, cimd_enabled: bool) -> Result<World, TestError> {
  World::start_with_cimd_fetcher(
    open_rate_limit(),
    json!({"cimd_enabled": cimd_enabled, "allow_localhost_redirect": true}),
    fetcher,
  )
  .await
}

/// Box one fetch so the higher-ranked [`CimdFetcher`] alias accepts the
/// closure (mirrors the module-private helper production uses).
fn boxed<'a>(
  future: impl Future<Output = Result<CimdDocument, CimdError>> + Send + 'a,
) -> CimdFetchFuture<'a> {
  Box::pin(future)
}

/// A document fetcher that counts every call and returns `document`.
fn document_fetcher(document: CimdDocument) -> (CimdFetcher, Arc<AtomicUsize>) {
  let calls = Arc::new(AtomicUsize::new(0));
  let counter = Arc::clone(&calls);
  let fetcher: CimdFetcher = Arc::new(move |_url: &str, _limits: CimdLimits| {
    let document = document.clone();
    let counter = Arc::clone(&counter);
    boxed(async move {
      counter.fetch_add(1, Ordering::SeqCst);
      Ok(document)
    })
  });
  (fetcher, calls)
}

/// A fetcher that counts every call and always fails. Used to prove that a
/// path never reaches the fetch at all.
fn failing_fetcher() -> (CimdFetcher, Arc<AtomicUsize>) {
  let calls = Arc::new(AtomicUsize::new(0));
  let counter = Arc::clone(&calls);
  let fetcher: CimdFetcher = Arc::new(move |_url: &str, _limits: CimdLimits| {
    let counter = Arc::clone(&counter);
    boxed(async move {
      counter.fetch_add(1, Ordering::SeqCst);
      Err(CimdError::Fetch)
    })
  });
  (fetcher, calls)
}

/// A valid `none` metadata document.
fn none_document(url: &str, dpop_bound: bool) -> CimdDocument {
  CimdDocument {
    client_id: url.to_owned(),
    redirect_uris: vec![REDIRECT.to_owned()],
    token_endpoint_auth_method: Some("none".to_owned()),
    grant_types: Some(vec![
      "authorization_code".to_owned(),
      "refresh_token".to_owned(),
    ]),
    scope: Some(SCOPE.to_owned()),
    jwks: None,
    jwks_uri: None,
    client_name: None,
    dpop_bound_access_tokens: Some(dpop_bound),
  }
}

/// A valid `private_key_jwt` metadata document carrying an inline JWKS.
fn private_key_document(url: &str, jwks: Value) -> CimdDocument {
  CimdDocument {
    client_id: url.to_owned(),
    redirect_uris: vec![REDIRECT.to_owned()],
    token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
    grant_types: Some(vec![
      "authorization_code".to_owned(),
      "refresh_token".to_owned(),
    ]),
    scope: Some(SCOPE.to_owned()),
    jwks: Some(jwks),
    jwks_uri: None,
    client_name: None,
    dpop_bound_access_tokens: Some(false),
  }
}

/// An Ed25519 signer plus the matching inline JWKS for one document.
struct DocKey {
  /// Signing key for request objects and client assertions.
  encoding: EncodingKey,
  /// Public JWKS the document publishes.
  jwks: Value,
}

impl DocKey {
  /// Generate a fresh Ed25519 key pair and its JWKS.
  fn generate(kid: &str) -> Result<Self, TestError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|error| fail(format!("ed25519 keygen failed: {error}")))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
      .map_err(|error| fail(format!("ed25519 reload failed: {error}")))?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    Ok(Self {
      encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
      jwks: json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid }]
      }),
    })
  }

  /// Sign one EdDSA JWT with `kid`.
  fn sign(&self, kid: &str, claims: &Value) -> Result<String, TestError> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    encode(&header, claims, &self.encoding).map_err(|error| fail(format!("jwt encode: {error}")))
  }

  /// A signed RFC 9101 request object bound to `client_id`/`issuer`.
  fn request_object(
    &self,
    kid: &str,
    client_id: &str,
    issuer: &str,
    extra: Value,
  ) -> Result<String, TestError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = json!({
      "iss": client_id,
      "aud": issuer,
      "exp": now + 300,
      "iat": now,
    });
    let object = claims
      .as_object_mut()
      .ok_or_else(|| fail("request claims must be an object"))?;
    let extra_object = extra
      .as_object()
      .ok_or_else(|| fail("request extras must be an object"))?;
    for (key, value) in extra_object {
      object.insert(key.clone(), value.clone());
    }
    self.sign(kid, &claims)
  }

  /// A `private_key_jwt` client assertion (RFC 7523 §3).
  fn assertion(
    &self,
    kid: &str,
    client_id: &str,
    audience: &str,
    jti: &str,
  ) -> Result<String, TestError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    self.sign(
      kid,
      &json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti,
        "exp": now + 300,
        "iat": now,
      }),
    )
  }
}

/// Build a plain-query `/authorize` path (public `none` clients).
fn authorize_path(client_id: &str, challenge: &str) -> String {
  format!(
    "/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}\
     &code_challenge={}&code_challenge_method=S256",
    browser::encoded(client_id),
    browser::encoded(REDIRECT),
    browser::encoded(SCOPE),
    browser::encoded(STATE),
    browser::encoded(challenge),
  )
}

/// Assert an authorize error page renders `expected`.
fn ensure_error_page(
  status: reqwest::StatusCode,
  body: &str,
  expected: &str,
) -> Result<(), TestError> {
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("{expected} must render 400, got {status}: {body}"),
  )?;
  ensure(
    body.contains(&format!("<h1>{expected}</h1>")),
    format!("page must name {expected}: {body}"),
  )
}

/// Drive login → consent approval for a [`Browser`] already parked on the
/// login page and return the issued authorization code.
async fn approve(browser: &Browser, expected_state: &str) -> Result<String, TestError> {
  let code_2fa = totp_now(&browser.totp_secret).await?;
  let (status, headers, body) = post_login(browser, &browser.password, &code_2fa).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status} {body}"),
  )?;
  let session = cookie_value(&headers, SESSION_COOKIE)?;
  let (status, _, body) = get_consent(browser, &session).await?;
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
    post_consent(browser, &session, &bound, &consent_csrf, "approve").await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("consent approval must 303 to the redirect: {status}"),
  )?;
  let location = location_of(&headers)?;
  ensure(
    location.starts_with(REDIRECT),
    format!("code must return to the document redirect, got {location}"),
  )?;
  ensure(
    query_value(&location, "state")? == expected_state,
    "code redirect must echo state",
  )?;
  query_value(&location, "code")
}

/// Happy path: a `none` CIMD document carries the full browser flow through
/// authorization-code redemption, and a second authorize inside the cache TTL
/// performs no second fetch.
#[tokio::test]
async fn e2e_cimd_authorize_login_consent_token() -> Result<(), TestError> {
  let (fetcher, calls) = document_fetcher(none_document(CLIENT_URL, true));
  let world = cimd_world(fetcher, true).await?;
  let browser = browser::begin_browser_for(
    world,
    CLIENT_URL,
    REDIRECT,
    SCOPE,
    "cimd-happy@example.test",
    "correct-horse-28-cimd-happy",
  )
  .await?;
  ensure(
    calls.load(Ordering::SeqCst) == 1,
    format!(
      "first authorize must fetch once, got {}",
      calls.load(Ordering::SeqCst)
    ),
  )?;

  let code = approve(&browser, browser::STATE).await?;

  // CIMD draft §4.1: a DPoP-bound document binds both the code and the token.
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
        ("redirect_uri", REDIRECT),
        ("client_id", CLIENT_URL),
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
    format!("a DPoP-bound document must mint DPoP tokens, got {tokens}"),
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
    "the document grants refresh_token, so one must be returned",
  )?;
  ensure(
    tokens["scope"] == SCOPE,
    format!("tokens must carry the document scope, got {tokens}"),
  )?;

  // A second authorize inside the 15-minute TTL is a cache hit: zero fetches.
  let (challenge, _) = oauth2_pkce();
  let proof = browser.dpop.proof(
    "GET",
    &format!("{}/authorize", browser.world.state.config.issuer),
  )?;
  let (status, headers, body) = browser
    .world
    .get(
      &authorize_path(CLIENT_URL, &challenge),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("cached second authorize must 303: {status} {body}"),
  )?;
  ensure(
    location_of(&headers)?.starts_with("/login?request_id="),
    "cached second authorize must reach login",
  )?;
  let count = calls.load(Ordering::SeqCst);
  ensure(
    count == 1,
    format!("second authorize within the TTL must add zero fetches, got {count}"),
  )?;
  Ok(())
}

/// A `private_key_jwt` document is confidential: a plain query authorize is
/// rejected with `invalid_request`, exactly like a registered confidential
/// client (RFC 9101 §4, `tests/jar.rs:229-251`).
#[tokio::test]
async fn e2e_cimd_private_key_jwt_requires_par_or_jar() -> Result<(), TestError> {
  let key = DocKey::generate("cimd-doc-key-plain")?;
  let (fetcher, calls) = document_fetcher(private_key_document(CLIENT_URL, key.jwks.clone()));
  let world = cimd_world(fetcher, true).await?;
  seed_scope(&world.pool, SCOPE).await?;

  let (challenge, _) = oauth2_pkce();
  let (status, _, body) = world
    .get(&authorize_path(CLIENT_URL, &challenge), &[])
    .await?;
  ensure_error_page(status, &body, "invalid_request")?;
  let count = calls.load(Ordering::SeqCst);
  ensure(
    count == 1,
    format!("the rejected authorize must fetch exactly once, got {count}"),
  )?;
  Ok(())
}

/// The same `private_key_jwt` document authorizes, logs in, consents, and
/// redeems when the request object is signed with the document key; the token
/// request authenticates with a document-key assertion. One fetch total.
#[tokio::test]
async fn e2e_cimd_private_key_jwt_par_jar_positive() -> Result<(), TestError> {
  const KID: &str = "cimd-doc-key-jar";
  const URL: &str = "https://cimd.example.test/private-key-jar.json";
  let key = DocKey::generate(KID)?;
  let (fetcher, calls) = document_fetcher(private_key_document(URL, key.jwks.clone()));
  let world = cimd_world(fetcher, true).await?;
  seed_scope(&world.pool, SCOPE).await?;
  let email = "cimd-jar@example.test";
  let password = "correct-horse-28-cimd-jar";
  let totp_secret = seed_user(&world, email, password, SCOPE).await?;

  let (challenge, verifier) = oauth2_pkce();
  let issuer = world.state.config.issuer.clone();
  let request = key.request_object(
    KID,
    URL,
    &issuer,
    json!({
      "client_id": URL,
      "response_type": "code",
      "redirect_uri": REDIRECT,
      "scope": SCOPE,
      "state": STATE,
      "code_challenge": challenge,
      "code_challenge_method": "S256",
    }),
  )?;
  let path = format!(
    "/authorize?client_id={}&request={}",
    browser::encoded(URL),
    browser::encoded(&request)
  );
  let (status, headers, body) = world.get(&path, &[]).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("signed request object must authorize: {status} {body}"),
  )?;
  let request_id = query_value(&location_of(&headers)?, "request_id")?;
  let (status, headers, body) = world
    .get(&format!("/login?request_id={request_id}"), &[])
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("login page must render: {status} {body}"),
  )?;
  let presession = cookie_value(&headers, SESSION_COOKIE)?;
  let login_csrf = hidden_input(&body, "csrf")?;
  let browser = Browser {
    world,
    dpop: browser::DpopKey::generate()?,
    verifier,
    request_id,
    presession,
    session: None,
    login_csrf,
    email: email.to_owned(),
    password: password.to_owned(),
    totp_secret,
  };

  let code = approve(&browser, STATE).await?;
  let assertion = key.assertion(KID, URL, &format!("{issuer}/token"), "cimd-jar-jti-1")?;
  let (status, _, body) = browser
    .world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("client_id", URL),
        ("code_verifier", browser.verifier.as_str()),
        (
          "client_assertion_type",
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
      ],
      None,
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("JAR + assertion redemption must mint: {status} {body}"),
  )?;
  let tokens = json_body(&body)?;
  ensure(
    tokens["access_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "redemption must return an access token",
  )?;
  let count = calls.load(Ordering::SeqCst);
  ensure(
    count == 1,
    format!("the whole JAR flow must fetch exactly once, got {count}"),
  )?;
  Ok(())
}

/// Every invalid document fails closed with its typed error, exactly one
/// fetch per row. One world per row: a shared Redis prefix would let the
/// two-second `cimd:invalid:` marker replay the first row's verdict.
#[tokio::test]
async fn e2e_cimd_invalid_documents_fail_closed() -> Result<(), TestError> {
  let mut jwks_uri = none_document("https://cimd.example.test/jwks-uri.json", false);
  jwks_uri.jwks_uri = Some("https://keys.example.test/jwks.json".to_owned());

  let mut unsupported = none_document("https://cimd.example.test/unsupported-method.json", false);
  unsupported.token_endpoint_auth_method = Some("client_secret_basic".to_owned());

  let mut wildcard = none_document("https://cimd.example.test/wildcard.json", false);
  wildcard.redirect_uris = vec!["https://app.example.test/*".to_owned()];

  let mut mismatch = none_document("https://cimd.example.test/mismatch.json", false);
  mismatch.client_id = "https://cimd.example.test/different.json".to_owned();

  let rows = [
    (
      "https://cimd.example.test/jwks-uri.json",
      jwks_uri,
      "invalid_client_metadata",
    ),
    (
      "https://cimd.example.test/unsupported-method.json",
      unsupported,
      "invalid_client_metadata",
    ),
    (
      "https://cimd.example.test/wildcard.json",
      wildcard,
      "invalid_redirect_uri",
    ),
    (
      "https://cimd.example.test/mismatch.json",
      mismatch,
      "invalid_client_metadata",
    ),
  ];

  for (url, document, expected) in rows {
    let (fetcher, calls) = document_fetcher(document);
    let world = cimd_world(fetcher, true).await?;
    let (challenge, _) = oauth2_pkce();
    let (status, _, body) = world.get(&authorize_path(url, &challenge), &[]).await?;
    ensure_error_page(status, &body, expected)?;
    let count = calls.load(Ordering::SeqCst);
    ensure(
      count == 1,
      format!("{url} must fetch exactly once, got {count}"),
    )?;
  }
  Ok(())
}

/// Registered rows always win over CIMD: an active row never fetches, an
/// inactive row is dead with zero fetches (todo 5 fail-closed), and a disabled
/// feature keeps the normal unknown-client error with zero fetches.
#[tokio::test]
async fn e2e_cimd_registered_row_wins_and_inactive_is_dead() -> Result<(), TestError> {
  // Active registered row with an `https://` id: zero fetches.
  const ACTIVE_URL: &str = "https://cimd.example.test/registered.json";
  let (fetcher, active_calls) = document_fetcher(none_document(ACTIVE_URL, true));
  let world = cimd_world(fetcher, true).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    ACTIVE_URL,
    None,
    &["authorization_code", "refresh_token"],
    SCOPE,
    TokenEndpointAuthMethod::None,
  )
  .await?;
  attach_redirect(&world.pool, &world.state.keys, ACTIVE_URL, REDIRECT).await?;
  let browser = browser::begin_browser_for(
    world,
    ACTIVE_URL,
    REDIRECT,
    SCOPE,
    "cimd-registered@example.test",
    "correct-horse-28-cimd-row",
  )
  .await?;
  ensure(
    !browser.request_id.is_empty(),
    "the registered row must authorize to login",
  )?;
  let active_count = active_calls.load(Ordering::SeqCst);
  ensure(
    active_count == 0,
    format!("an active registered row must not fetch, got {active_count}"),
  )?;

  // Inactive registered row with an `https://` id: dead, zero fetches.
  const INACTIVE_URL: &str = "https://cimd.example.test/inactive.json";
  let (fetcher, inactive_calls) = failing_fetcher();
  let world = cimd_world(fetcher, true).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    INACTIVE_URL,
    None,
    &["authorization_code"],
    SCOPE,
    TokenEndpointAuthMethod::None,
  )
  .await?;
  ensure(
    client_repo::deactivate(&world.pool, INACTIVE_URL).await?,
    "deactivate must flip the row",
  )?;
  let (challenge, _) = oauth2_pkce();
  let (status, _, body) = world
    .get(&authorize_path(INACTIVE_URL, &challenge), &[])
    .await?;
  ensure_error_page(status, &body, "invalid_client")?;
  let inactive_count = inactive_calls.load(Ordering::SeqCst);
  ensure(
    inactive_count == 0,
    format!("an inactive row must never fall through to CIMD, got {inactive_count}"),
  )?;

  // CIMD disabled: an unknown `https://` id is the normal unknown client.
  const UNKNOWN_URL: &str = "https://cimd.example.test/disabled.json";
  let (fetcher, disabled_calls) = failing_fetcher();
  let world = cimd_world(fetcher, false).await?;
  let (challenge, _) = oauth2_pkce();
  let (status, _, body) = world
    .get(&authorize_path(UNKNOWN_URL, &challenge), &[])
    .await?;
  ensure_error_page(status, &body, "invalid_client")?;
  let disabled_count = disabled_calls.load(Ordering::SeqCst);
  ensure(
    disabled_count == 0,
    format!("a disabled CIMD feature must not fetch, got {disabled_count}"),
  )?;
  Ok(())
}

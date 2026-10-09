//! `test(e2e_)` abuse matrix over the live router: wired-endpoint rows.
//!
//! Every test boots the REAL production router over a REAL loopback socket
//! against the shared Postgres + Redis from `compose.test.yaml` (see
//! `e2e/harness.rs`) and asserts only observable HTTP behavior. `#[test]` names all start with
//! `e2e_` so `cargo nextest run -E 'test(e2e_)'` selects exactly this suite.
//!
//! Rows whose endpoint is wired live here; `/token` grant rows live in
//! `e2e_grants.rs` as real 4xx/success assertions.

#[path = "e2e/harness.rs"]
mod harness;

use d_oauth::db::TokenEndpointAuthMethod;
use d_oauth::protocol::token::ClientKind;
use harness::{
  TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_scope,
};

/// Confidential fixture client for the abuse suite.
const CLIENT_ID: &str = "e2e-abuse-client";
/// Fixture secret (also used to prove it never leaks into responses).
const CLIENT_SECRET: &str = "e2e-abuse-secret-9f8b7a6c5d4e3f2a1b0";
/// Public fixture client (direct `/authorize` query flow; confidential
/// clients must use PAR/JAR and page-400 without one).
const PUBLIC_ID: &str = "e2e-abuse-public";
/// Registered loopback redirect (unbound port: registration only).
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";

/// One world plus the seeded client, scopes, and redirect this suite needs.
async fn setup() -> Result<World, TestError> {
  setup_with_rate_limit(open_rate_limit()).await
}

/// One world with a caller-chosen limiter budget.
async fn setup_with_rate_limit(rate_limit: serde_json::Value) -> Result<World, TestError> {
  let world = World::start(rate_limit).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    CLIENT_ID,
    Some(CLIENT_SECRET),
    &["authorization_code", "refresh_token", "client_credentials"],
    "read write",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  seed_scope(&world.pool, "write").await?;
  attach_redirect(&world.pool, &world.state.keys, CLIENT_ID, REDIRECT_URI).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    PUBLIC_ID,
    None,
    &["authorization_code", "refresh_token"],
    "read write",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  attach_redirect(&world.pool, &world.state.keys, PUBLIC_ID, REDIRECT_URI).await?;
  Ok(world)
}

/// Unknown client fails closed with a direct 400 page (never a redirect);
/// a validated redirect carries the error (`redirect-with-error`).
#[tokio::test]
async fn e2e_redirect_fail_closed_vs_redirect_with_error() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, _) = world
    .get(
      "/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    "unknown client must page 400",
  )?;

  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=token",
        urlencoding(REDIRECT_URI)
      ),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::FOUND,
    "bad response_type must 302",
  )?;
  let location = header_str(&headers, "location")?;
  ensure(
    location.contains("error=") && location.starts_with(REDIRECT_URI),
    "error must ride the validated redirect",
  )?;

  let (status, _, _) = world
    .get(
      &format!("/authorize?client_id={PUBLIC_ID}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb"),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    "foreign redirect must page 400",
  )?;
  Ok(())
}

/// Introspection without credentials is `401 invalid_client` (+ challenge),
/// never debug output and never a successful introspection.
#[tokio::test]
async fn e2e_unauthenticated_introspection_rejected() -> Result<(), TestError> {
  let world = setup().await?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, None)
    .await?;
  let (status, headers, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      None,
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    "introspect without auth must 401",
  )?;
  ensure(
    headers.contains_key("www-authenticate"),
    "401 must carry WWW-Authenticate",
  )?;
  ensure(
    body.contains("invalid_client"),
    "body must be invalid_client",
  )?;

  let (status, _, _) = world
    .post_form("/introspect", &[("token", "bogus")], None, &[])
    .await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    "bogus token without auth must 401",
  )?;
  Ok(())
}

/// Revocation is idempotent: revoke → 200, revoke again → 200, introspect → inactive.
#[tokio::test]
async fn e2e_revocation_idempotent() -> Result<(), TestError> {
  let world = setup().await?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, None)
    .await?;
  let auth = Some((CLIENT_ID, CLIENT_SECRET));
  let (status, _, _) = world
    .post_form(
      "/revoke",
      &[("token", minted.access_token.as_str())],
      auth,
      &[],
    )
    .await?;
  ensure(status.is_success(), "first revoke must 200")?;
  let (status, _, _) = world
    .post_form(
      "/revoke",
      &[("token", minted.access_token.as_str())],
      auth,
      &[],
    )
    .await?;
  ensure(status.is_success(), "second revoke must still 200")?;

  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      auth,
      &[],
    )
    .await?;
  ensure(status.is_success(), "introspect must 200")?;
  let value = json_body(&body)?;
  ensure(
    value["active"] == false,
    "revoked token must introspect inactive",
  )?;

  let (status, _, _) = world
    .post_form("/revoke", &[("token", "unknown")], None, &[])
    .await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    "unauthenticated revoke must 401",
  )?;
  Ok(())
}

/// Scope beyond the client's registration (and unknown scopes) redirect with
/// `invalid_scope`; the flow never proceeds to login.
#[tokio::test]
async fn e2e_scope_over_request_rejected() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, _verifier) = oauth2_pkce();
  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=code\
         &scope=read%20admin&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(REDIRECT_URI)
      ),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::FOUND,
    "over-request must 302",
  )?;
  let location = header_str(&headers, "location")?;
  ensure(
    location.contains("error=invalid_scope"),
    "over-request must be invalid_scope",
  )?;
  ensure(
    !location.contains("/login"),
    "over-request must never reach login",
  )?;
  Ok(())
}

/// Error redirects echo the request's own `state` (CSRF binding); two
/// concurrent requests never see each other's state.
#[tokio::test]
async fn e2e_state_csrf_echo_isolated() -> Result<(), TestError> {
  let world = setup().await?;
  let error_url = |state: &str| {
    format!(
      "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=token&state={state}",
      urlencoding(REDIRECT_URI)
    )
  };
  let (_, first_headers, _) = world.get(&error_url("aaa-csrf-1"), &[]).await?;
  let (_, second_headers, _) = world.get(&error_url("bbb-csrf-2"), &[]).await?;
  let first = header_str(&first_headers, "location")?;
  let second = header_str(&second_headers, "location")?;
  ensure(
    first.contains("state=aaa-csrf-1"),
    "first error must echo its own state",
  )?;
  ensure(
    second.contains("state=bbb-csrf-2"),
    "second error must echo its own state",
  )?;
  ensure(
    !first.contains("bbb-csrf-2") && !second.contains("aaa-csrf-1"),
    "states must not cross",
  )?;
  Ok(())
}

/// A forged `iss` query parameter never steers the flow: the server ignores it
/// and 303-redirects into its own login with its own issuer binding.
#[tokio::test]
async fn e2e_mixup_iss_forged_is_ignored() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, _verifier) = oauth2_pkce();
  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=code\
         &code_challenge={challenge}&code_challenge_method=S256&iss=https%3A%2F%2Fevil.example",
        urlencoding(REDIRECT_URI)
      ),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    "forged iss must not break the flow",
  )?;
  let location = header_str(&headers, "location")?;
  ensure(
    location.starts_with("/login?request_id="),
    "flow must enter the server login",
  )?;
  ensure(
    !location.contains("evil.example"),
    "evil issuer must appear nowhere",
  )?;
  Ok(())
}

/// A tight per-IP budget yields `429` with `Retry-After` on a protected
/// endpoint; health and metadata stay ungated by construction.
#[tokio::test]
async fn e2e_rate_limit_429_with_retry_after() -> Result<(), TestError> {
  let budget = serde_json::json!({
    "enabled": true, "window_secs": 60,
    "per_ip": 3, "per_client": 100_000,
    "login_per_ip": 100_000, "token_per_client": 100_000,
  });
  let world = setup_with_rate_limit(budget).await?;
  let mut limited = 0;
  for _ in 0..10 {
    let (status, headers, _) = world
      .post_form("/introspect", &[("token", "x")], None, &[])
      .await?;
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
      limited += 1;
      ensure(
        headers.contains_key("retry-after"),
        "429 must carry Retry-After",
      )?;
    }
  }
  ensure(limited > 0, "tight budget must 429 eventually")?;

  let (status, _, _) = world.get("/health/live", &[]).await?;
  ensure(status.is_success(), "liveness must stay ungated")?;
  Ok(())
}

/// Forged proxy client-cert headers are never read: the request is treated as
/// uncertified (401 without credentials), and valid credentials still work
/// with the forged headers present.
#[tokio::test]
async fn e2e_forged_mtls_header_stripped() -> Result<(), TestError> {
  let world = setup().await?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, None)
    .await?;
  let forged = [
    ("x-forwarded-tls-client-cert", "Zm9yZ2Vk"),
    ("x-forwarded-tls-client-verify", "SUCCESS"),
  ];
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      None,
      &forged,
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    "forged cert alone must not authenticate",
  )?;
  ensure(
    !body.contains("active"),
    "stripped request must not introspect",
  )?;

  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &forged,
    )
    .await?;
  ensure(
    status.is_success(),
    "real credentials must work despite forged headers",
  )?;
  ensure(
    json_body(&body)?["active"] == true,
    "token must introspect active",
  )?;
  Ok(())
}

/// Unauthenticated DCR fails closed: no client is created, no secret
/// material is emitted, and the response is `401 invalid_client` with a
/// Bearer challenge (RFC 7591 §3.2.2).
#[tokio::test]
async fn e2e_unauthenticated_dcr_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let response = world
    .client
    .post(format!("{}/register", world.base))
    .json(&serde_json::json!({"redirect_uris": ["https://evil.example/cb"]}))
    .send()
    .await?;
  let status = response.status();
  let challenge = response
    .headers()
    .get("www-authenticate")
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default()
    .to_owned();
  let body = response.text().await?;
  ensure(
    status == reqwest::StatusCode::UNAUTHORIZED,
    "unauthenticated DCR must 401",
  )?;
  ensure(
    challenge.starts_with("Bearer"),
    "DCR 401 must carry a Bearer challenge",
  )?;
  ensure(
    !body.contains(CLIENT_SECRET),
    "DCR failure must not leak secrets",
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_client",
    "DCR failure must be invalid_client",
  )?;
  ensure(
    !body.contains("client_secret"),
    "DCR failure must not emit client credentials",
  )?;
  Ok(())
}

/// Disabling a scope in the catalog removes it from discovery and rejects new
/// authorize requests carrying it (`invalid_scope` redirect).
#[tokio::test]
async fn e2e_scope_catalog_disable_stops_authorize() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, body) = world
    .get("/.well-known/oauth-authorization-server", &[])
    .await
    .map(|(status, _, body)| (status, body))?;
  ensure(status.is_success(), "metadata must 200")?;
  ensure(
    json_body(&body)?["scopes_supported"].as_array().is_some(),
    "metadata lists scopes",
  )?;

  disable_scope(&world.pool, "read").await?;
  let (status, body) = world
    .get("/.well-known/oauth-authorization-server", &[])
    .await
    .map(|(status, _, body)| (status, body))?;
  ensure(status.is_success(), "metadata must still 200")?;
  let scopes = json_body(&body)?["scopes_supported"]
    .as_array()
    .cloned()
    .ok_or_else(|| fail("scopes_supported must be an array"))?;
  ensure(
    !scopes.iter().any(|scope| scope == "read"),
    "disabled scope must leave discovery",
  )?;

  let (challenge, _verifier) = oauth2_pkce();
  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=code\
         &scope=read&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(REDIRECT_URI)
      ),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::FOUND,
    "disabled scope must 302",
  )?;
  ensure(
    header_str(&headers, "location")?.contains("error=invalid_scope"),
    "disabled scope must be invalid_scope",
  )?;
  Ok(())
}

/// Disable one catalog scope (operator action; suite-local: only this suite
/// mutates the catalog directly).
async fn disable_scope(pool: &sqlx::PgPool, name: &str) -> Result<(), TestError> {
  d_oauth::db::scope_repo::set_enabled(pool, name, false)
    .await
    .map_err(|error| fail(format!("scope disable failed: {error}")))?;
  Ok(())
}

/// Read one response header or fail the test.
fn header_str(headers: &reqwest::header::HeaderMap, name: &str) -> Result<String, TestError> {
  headers
    .get(name)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
    .ok_or_else(|| fail(format!("response lacks {name} header")))
}

/// Percent-encode a redirect URI for query embedding (unreserved passthrough).
fn urlencoding(value: &str) -> String {
  let mut encoded = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
      encoded.push(byte as char);
    } else {
      encoded.push_str(&format!("%{byte:02X}"));
    }
  }
  encoded
}

/// PKCE pair from the `oauth2` crate (baseline-flow material only).
fn oauth2_pkce() -> (String, oauth2::PkceCodeVerifier) {
  let (challenge, verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
  (challenge.as_str().to_owned(), verifier)
}

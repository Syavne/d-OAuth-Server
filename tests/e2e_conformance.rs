//! `test(e2e_)` conformance over the live router: discovery, authorize,
//! PAR, device authorization, introspection, revocation, and served pages.
//!
//! Same harness contract as the sibling suites: the REAL production router
//! over REAL loopback TCP against REAL containers; assertions read only HTTP
//! behavior. The `oauth2` crate builds the authorize URL + PKCE material for
//! the happy path; everything else is hand-rolled `reqwest`.

#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/clients.rs"]
mod clients;

use d_oauth::{db::TokenEndpointAuthMethod, protocol::token::ClientKind};
use harness::{
  TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_scope,
};

/// Fixture confidential client.
const CLIENT_ID: &str = "e2e-conformance-client";
/// Fixture secret (also the leak probe).
const CLIENT_SECRET: &str = "e2e-conformance-secret-aaaabbbbccccdddd";
/// Public fixture client (direct `/authorize` query flow; confidential
/// clients must use PAR/JAR and page-400 without one).
const PUBLIC_ID: &str = "e2e-conformance-public";
/// Registered loopback redirect.
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";

/// One world plus the seeded client, scopes, and redirect.
async fn setup() -> Result<World, TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_client(
    &world.pool,
    CLIENT_ID,
    Some(CLIENT_SECRET),
    &[
      "authorization_code",
      "refresh_token",
      "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    "read write",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  seed_scope(&world.pool, "write").await?;
  attach_redirect(&world.pool, CLIENT_ID, REDIRECT_URI).await?;
  seed_client(
    &world.pool,
    PUBLIC_ID,
    None,
    &["authorization_code", "refresh_token"],
    "read write",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  attach_redirect(&world.pool, PUBLIC_ID, REDIRECT_URI).await?;
  Ok(world)
}

/// Discovery conforms: issuer, endpoint URLs, PKCE/DPoP metadata, and the
/// seeded scopes — with no secret material anywhere in the document.
#[tokio::test]
async fn e2e_metadata_conformance() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, body) = world
    .get("/.well-known/oauth-authorization-server", &[])
    .await?;
  ensure(status.is_success(), "metadata must 200")?;
  let document = json_body(&body)?;
  ensure(
    document["issuer"] == "https://auth.example.test",
    "issuer must match config",
  )?;
  for member in [
    "authorization_endpoint",
    "token_endpoint",
    "introspection_endpoint",
    "revocation_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
    "code_challenge_methods_supported",
    "scopes_supported",
  ] {
    ensure(
      !document[member].is_null(),
      format!("metadata must carry {member}"),
    )?;
  }
  let scopes = document["scopes_supported"]
    .as_array()
    .ok_or_else(|| fail("scopes_supported must be an array"))?;
  ensure(
    scopes.iter().any(|scope| scope == "read"),
    "catalog scope must be advertised",
  )?;
  ensure(
    !body.contains(CLIENT_SECRET),
    "metadata must not leak secrets",
  )?;
  Ok(())
}

/// Happy path via the `oauth2` crate: its authorize URL + PKCE challenge are
/// accepted and the flow 303-redirects into the server login.
#[tokio::test]
async fn e2e_authorize_pkce_happy_path() -> Result<(), TestError> {
  let world = setup().await?;
  let client = clients::oauth2_client(&world.base, PUBLIC_ID, None)?;
  let (challenge, _verifier) = oauth2_pkce();
  let (url, state) = client
    .authorize_url(oauth2::CsrfToken::new_random)
    .add_scope(oauth2::Scope::new("read".to_owned()))
    .set_pkce_challenge(challenge)
    .url();
  let target = format!(
    "{}{}",
    url.path(),
    url
      .query()
      .map_or(String::new(), |query| format!("?{query}"))
  );
  let (status, headers, _) = world.get(&target, &[]).await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    "valid authorize must 303",
  )?;
  let location = location_of(&headers)?;
  ensure(
    location.starts_with("/login?request_id="),
    "flow must enter login",
  )?;
  ensure(!state.secret().is_empty(), "csrf token must be non-empty")?;
  Ok(())
}

/// PAR push returns `201 {request_uri, expires_in}` and the authorize
/// endpoint consumes that `request_uri` into the same login redirect.
#[tokio::test]
async fn e2e_par_push_and_authorize() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, _verifier) = oauth2_pkce();
  let (status, _, body) = world
    .post_form(
      "/par",
      &[
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("response_type", "code"),
        ("scope", "read"),
        ("state", "par-state-1"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(status == reqwest::StatusCode::CREATED, "PAR push must 201")?;
  let pushed = json_body(&body)?;
  let request_uri = pushed["request_uri"]
    .as_str()
    .ok_or_else(|| fail("PAR must return request_uri"))?
    .to_owned();

  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={CLIENT_ID}&request_uri={}",
        encoded(&request_uri)
      ),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    "PAR authorize must 303",
  )?;
  ensure(
    location_of(&headers)?.starts_with("/login?request_id="),
    "PAR flow must enter login",
  )?;
  Ok(())
}

/// Device authorization answers with the RFC 8628 verification payload.
#[tokio::test]
async fn e2e_device_authorization_issues_codes() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, body) = world
    .post_form(
      "/device_authorization",
      &[("client_id", CLIENT_ID), ("scope", "read")],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(status.is_success(), "device authorization must 200")?;
  let payload = json_body(&body)?;
  for member in ["device_code", "user_code", "verification_uri", "expires_in"] {
    ensure(
      !payload[member].is_null(),
      format!("device response must carry {member}"),
    )?;
  }
  ensure(
    !body.contains(CLIENT_SECRET),
    "device response must not leak secrets",
  )?;
  Ok(())
}

/// Introspection reports active tokens with owner + scope, and unknown tokens
/// as inactive — with no secret material in either body.
#[tokio::test]
async fn e2e_introspect_active_and_inactive() -> Result<(), TestError> {
  let world = setup().await?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, None)
    .await?;
  let auth = Some((CLIENT_ID, CLIENT_SECRET));
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      auth,
      &[],
    )
    .await?;
  ensure(status.is_success(), "introspect must 200")?;
  let active = json_body(&body)?;
  ensure(active["active"] == true, "minted token must be active")?;
  ensure(
    active["client_id"] == CLIENT_ID,
    "introspect must report the owner",
  )?;
  ensure(
    active["scope"] == "read",
    "introspect must report the scope",
  )?;
  ensure(
    !body.contains(CLIENT_SECRET),
    "introspect must not leak the secret",
  )?;

  let (status, _, body) = world
    .post_form("/introspect", &[("token", "not-a-token")], auth, &[])
    .await?;
  ensure(status.is_success(), "unknown token still 200")?;
  ensure(
    json_body(&body)?["active"] == false,
    "unknown token must be inactive",
  )?;
  Ok(())
}

/// Revoking an unknown token is a `200` no-op (no existence oracle).
#[tokio::test]
async fn e2e_revoke_unknown_token_noop() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, _) = world
    .post_form(
      "/revoke",
      &[("token", "never-existed-token")],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(status.is_success(), "unknown-token revoke must 200")?;
  Ok(())
}

/// Served pages ride the middleware chain: 200 on dependency-free pages with
/// framing/script lockdown and a request id on every response.
#[tokio::test]
async fn e2e_pages_carry_security_headers() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, headers, _) = world.get("/device", &[]).await?;
  ensure(status.is_success(), "device page must 200")?;
  let csp = headers
    .get("content-security-policy")
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default()
    .to_owned();
  ensure(
    csp.contains("frame-ancestors 'none'"),
    "pages must deny framing",
  )?;
  ensure(
    headers.contains_key("x-request-id"),
    "responses must carry request ids",
  )?;

  let (status, headers, _) = world.get("/login", &[]).await?;
  ensure(
    !status.is_server_error(),
    "login without context must not 500",
  )?;
  ensure(
    headers.contains_key("x-request-id"),
    "error pages keep request ids",
  )?;
  Ok(())
}

/// PKCE pair from the `oauth2` crate (baseline-flow material only).
fn oauth2_pkce() -> (oauth2::PkceCodeChallenge, oauth2::PkceCodeVerifier) {
  oauth2::PkceCodeChallenge::new_random_sha256()
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

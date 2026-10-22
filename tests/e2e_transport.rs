//! `test(e2e_transport)` HTTP transport-layer robustness over the live router.
//!
//! The sibling e2e suites drive `/token`, `/par`, and `/register` only with
//! well-formed bodies. This suite pins the transport contract for requests
//! that are malformed before (or independently of) grant logic: empty bodies,
//! missing and duplicated parameters, wrong content types, malformed percent
//! encoding, and bodies past the configured limit. Expected codes come from
//! the documented contract (docs/OAUTH.md error table: "Missing or duplicated
//! parameter" is `invalid_request` 400; docs/SECURITY.md input safety) and
//! from the axum extractor contract for content type — never by copying
//! observed output. No request may panic or answer 5xx.

#[path = "e2e/harness.rs"]
#[allow(dead_code)]
mod harness;

use d_oauth::{db::TokenEndpointAuthMethod, routes::MAX_BODY_BYTES};
use harness::{
  TestError, World, ensure, fail, json_body, open_rate_limit, seed_client, seed_scope,
};
use reqwest::{
  StatusCode,
  header::{self, HeaderMap},
};

/// Fixture confidential client.
const CLIENT_ID: &str = "e2e-transport-client";
/// Fixture client secret.
const CLIENT_SECRET: &str = "e2e-transport-secret-aaaabbbbccccdddd";
/// Form content type the OAuth endpoints require.
const FORM: &str = "application/x-www-form-urlencoded";
/// A redirect URI used where validation stops before the catalog lookup.
const REDIRECT_URI: &str = "https://client.example.test/cb";

/// One world plus a seeded confidential client and enabled scope.
async fn setup() -> Result<World, TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    CLIENT_ID,
    Some(CLIENT_SECRET),
    &["authorization_code", "refresh_token", "client_credentials"],
    "read",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  Ok(world)
}

/// `POST {path}` with raw bytes and an optional explicit content type.
async fn post_body(
  world: &World,
  path: &str,
  content_type: Option<&str>,
  body: Vec<u8>,
) -> Result<(StatusCode, HeaderMap, String), TestError> {
  let mut request = world.client.post(format!("{}{path}", world.base));
  if let Some(content_type) = content_type {
    request = request.header(header::CONTENT_TYPE, content_type);
  }
  let response = request.body(body).send().await?;
  let status = response.status();
  let headers = response.headers().clone();
  let body = response.text().await?;
  Ok((status, headers, body))
}

/// `POST {path}` with a raw body and an explicit content type.
async fn post_raw(
  world: &World,
  path: &str,
  content_type: &str,
  body: &str,
) -> Result<(StatusCode, HeaderMap, String), TestError> {
  post_body(world, path, Some(content_type), body.as_bytes().to_vec()).await
}

/// Assert the documented `invalid_request` 400 JSON error, and no token.
fn ensure_invalid_request(status: StatusCode, body: &str) -> Result<(), TestError> {
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("must be a 400 invalid_request, got {status}: {body}"),
  )?;
  let error = json_body(body)?;
  ensure(
    error["error"] == "invalid_request",
    format!("must carry invalid_request, got {body}"),
  )?;
  ensure(
    !body.contains("access_token"),
    "a rejected request must not carry an access token",
  )
}

/// Read one response header or fail the test.
fn header_str(headers: &HeaderMap, name: &str) -> Result<String, TestError> {
  headers
    .get(name)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
    .ok_or_else(|| fail(format!("response lacks {name} header")))
}

/// An empty form body omits the required `grant_type`: RFC 6749 §5.2 maps a
/// missing required parameter to `invalid_request` 400 (docs/OAUTH.md).
#[tokio::test]
async fn e2e_transport_token_empty_body_is_invalid_request() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, body) = world.post_form("/token", &[], None, &[]).await?;
  ensure_invalid_request(status, &body)
}

/// RFC 6749 §5.2 and docs/OAUTH.md: a parameter "more than once" is
/// `invalid_request` 400, whether the duplicate is the grant or the client.
#[tokio::test]
async fn e2e_transport_token_duplicate_params_are_invalid_request() -> Result<(), TestError> {
  let world = setup().await?;
  let base = [
    ("grant_type", "client_credentials"),
    ("client_id", CLIENT_ID),
  ];
  let auth = Some((CLIENT_ID, CLIENT_SECRET));

  let duplicated_grant: Vec<(&str, &str)> = vec![
    ("grant_type", "client_credentials"),
    ("grant_type", "refresh_token"),
    ("client_id", CLIENT_ID),
  ];
  let (status, _, body) = world
    .post_form("/token", &duplicated_grant, auth, &[])
    .await?;
  ensure_invalid_request(status, &body)?;

  let duplicated_client = [base[0], base[1], ("client_id", "e2e-transport-other")];
  let (status, _, body) = world
    .post_form("/token", &duplicated_client, auth, &[])
    .await?;
  ensure_invalid_request(status, &body)
}

/// A request that is not a form keeps the extractor's 415: it never reaches
/// grant logic and must never 5xx.
#[tokio::test]
async fn e2e_transport_token_wrong_content_type_rejected_cleanly() -> Result<(), TestError> {
  let world = setup().await?;
  let body = format!("grant_type=client_credentials&client_id={CLIENT_ID}");
  for content_type in ["text/plain", "application/json"] {
    let (status, _, response_body) = post_raw(&world, "/token", content_type, &body).await?;
    ensure(
      status == StatusCode::UNSUPPORTED_MEDIA_TYPE,
      format!("{content_type} must 415, got {status}: {response_body}"),
    )?;
    ensure(
      !response_body.is_empty(),
      format!("{content_type} rejection must carry a clean body"),
    )?;
  }
  Ok(())
}

/// Anti-regression gate for the `Form<TokenForm>` → `Bytes` swap: `/token`
/// keeps the exact pre-swap transport contract. A non-form or missing
/// content type is 415, a body past `MAX_BODY_BYTES` is the layer's 413, a
/// repeated known field is `invalid_request` 400, and a structurally
/// unreadable (non-UTF-8) body is `invalid_request` 400. Percent escapes
/// stay lossy (pre-swap `serde_urlencoded` parity): `%ZZ` reaches grant
/// validation and fails cleanly, never the parse.
#[tokio::test]
async fn token_extractor_preserves_415_and_body_limit() -> Result<(), TestError> {
  let world = setup().await?;
  let body = format!("grant_type=client_credentials&client_id={CLIENT_ID}");

  for content_type in [Some("application/json"), Some("text/plain"), None] {
    let (status, _, response_body) =
      post_body(&world, "/token", content_type, body.as_bytes().to_vec()).await?;
    ensure(
      status == StatusCode::UNSUPPORTED_MEDIA_TYPE,
      format!("{content_type:?} must 415, got {status}: {response_body}"),
    )?;
  }

  let padding = "a".repeat(MAX_BODY_BYTES + 1024);
  let oversized = format!("grant_type=client_credentials&client_id={CLIENT_ID}&padding={padding}");
  let (status, _, response_body) =
    post_body(&world, "/token", Some(FORM), oversized.into_bytes()).await?;
  ensure(
    status == StatusCode::PAYLOAD_TOO_LARGE,
    format!("oversized token body must 413, got {status}: {response_body}"),
  )?;

  let duplicate =
    format!("grant_type=client_credentials&grant_type=refresh_token&client_id={CLIENT_ID}");
  let (status, _, response_body) =
    post_body(&world, "/token", Some(FORM), duplicate.into_bytes()).await?;
  ensure_invalid_request(status, &response_body)?;

  let (status, _, response_body) = post_body(&world, "/token", Some(FORM), vec![0xFF]).await?;
  ensure_invalid_request(status, &response_body)?;

  let (status, _, response_body) = post_body(
    &world,
    "/token",
    Some(FORM),
    b"grant_type=%ZZ&client_id=e2e-transport-client".to_vec(),
  )
  .await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("lossy percent escape must stay a clean 400, got {status}: {response_body}"),
  )?;
  ensure(
    !response_body.contains("access_token"),
    "a rejected request must not carry an access token",
  )
}

/// Malformed percent-encoding decodes lossily into an unknown `grant_type`
/// value, so the documented code for "a grant_type outside the five" is
/// `unsupported_grant_type` 400 — never a panic or 5xx.
#[tokio::test]
async fn e2e_transport_token_malformed_encoding_is_clean_4xx() -> Result<(), TestError> {
  let world = setup().await?;
  for malformed in [
    "grant_type=%ZZ&client_id=e2e-transport-client",
    "grant_type=%E0%A4%A&client_id=e2e-transport-client",
  ] {
    let (status, _, body) = post_raw(&world, "/token", FORM, malformed).await?;
    ensure(
      status == StatusCode::BAD_REQUEST,
      format!("malformed encoding must be a clean 400, got {status}: {body}"),
    )?;
    let error = json_body(&body)?;
    ensure(
      error["error"] == "unsupported_grant_type",
      format!("unknown grant value must be unsupported_grant_type, got {body}"),
    )?;
    ensure(
      !body.contains("access_token"),
      "a rejected request must not carry an access token",
    )?;
  }
  Ok(())
}

/// Bodies past the router's configured limit are rejected at the layer
/// before any handler, on both form endpoints, with the tower limit's 413.
#[tokio::test]
async fn e2e_transport_oversized_body_is_rejected() -> Result<(), TestError> {
  let world = setup().await?;
  let padding = "a".repeat(MAX_BODY_BYTES + 1024);
  let body = format!("grant_type=client_credentials&client_id={CLIENT_ID}&padding={padding}");
  for path in ["/token", "/par"] {
    let (status, _, response_body) = post_raw(&world, path, FORM, &body).await?;
    ensure(
      status == StatusCode::PAYLOAD_TOO_LARGE,
      format!("{path} oversized body must 413, got {status}: {response_body}"),
    )?;
  }
  Ok(())
}

/// PAR mirrors its core rule suite at the HTTP layer: a missing
/// `response_type` and a duplicated one whose surviving value is not `code`
/// are both `invalid_request` 400 after a valid client authentication.
#[tokio::test]
async fn e2e_transport_par_missing_and_duplicate_params() -> Result<(), TestError> {
  let world = setup().await?;
  let auth = Some((CLIENT_ID, CLIENT_SECRET));

  // Missing response_type (the authenticated client_id matches).
  let missing = [("client_id", CLIENT_ID), ("redirect_uri", REDIRECT_URI)];
  let (status, _, body) = world.post_form("/par", &missing, auth, &[]).await?;
  ensure_invalid_request(status, &body)?;

  // Duplicated response_type: the surviving (last) value is not `code`.
  let duplicated = [
    ("client_id", CLIENT_ID),
    ("response_type", "code"),
    ("response_type", "authorization_code"),
    ("redirect_uri", REDIRECT_URI),
  ];
  let (status, _, body) = world.post_form("/par", &duplicated, auth, &[]).await?;
  ensure_invalid_request(status, &body)
}

/// `/register` rejects malformed JSON cleanly before auth, and a valid body
/// without a bearer token is the documented `invalid_client` 401 challenge.
#[tokio::test]
async fn e2e_transport_register_malformed_json_and_missing_auth() -> Result<(), TestError> {
  let world = setup().await?;

  let (status, _, body) = post_raw(&world, "/register", "application/json", "{not-json").await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("malformed JSON must be a clean 400, got {status}: {body}"),
  )?;

  let payload = serde_json::json!({"redirect_uris": ["https://app.example.test/cb"]});
  let (status, headers, body) = post_raw(
    &world,
    "/register",
    "application/json",
    &payload.to_string(),
  )
  .await?;
  ensure(
    status == StatusCode::UNAUTHORIZED,
    format!("missing initial access token must 401, got {status}: {body}"),
  )?;
  ensure(
    header_str(&headers, "www-authenticate")?.starts_with("Bearer"),
    "401 must carry the Bearer challenge",
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_client",
    format!("missing auth must render invalid_client, got {body}"),
  )
}

/// Authentication precedes catalog validation on `/token`: bad credentials
/// with an unknown `resource` observe `invalid_client` 401 (never
/// `invalid_target`), while the same unknown `resource` with valid
/// credentials still fails `invalid_target` 400 (the check moved, it did
/// not disappear).
#[tokio::test]
async fn e2e_transport_token_auth_runs_before_catalog() -> Result<(), TestError> {
  let world = World::start_with(
    open_rate_limit(),
    serde_json::json!({"resource_indicators_enabled": true}),
  )
  .await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    CLIENT_ID,
    Some(CLIENT_SECRET),
    &["authorization_code", "refresh_token", "client_credentials"],
    "read",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;

  let ghost = "https://ghost.example.test/";
  let params = [
    ("grant_type", "client_credentials"),
    ("client_id", CLIENT_ID),
    ("resource", ghost),
  ];
  let (status, _, body) = world
    .post_form("/token", &params, Some((CLIENT_ID, "wrong-secret")), &[])
    .await?;
  ensure(
    status == StatusCode::UNAUTHORIZED,
    format!("bad credentials must 401, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_client",
    format!("auth must run before the catalog check, got {body}"),
  )?;
  ensure(
    !body.contains("access_token"),
    "a rejected request must not carry an access token",
  )?;

  let (status, _, body) = world
    .post_form("/token", &params, Some((CLIENT_ID, CLIENT_SECRET)), &[])
    .await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("unknown resource must 400, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "invalid_target",
    format!("the catalog check must still run after auth, got {body}"),
  )
}

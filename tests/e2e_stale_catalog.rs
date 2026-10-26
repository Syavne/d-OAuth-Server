//! `binary(e2e_stale_catalog)` — stale RFC 8707 and scope catalogs at mint.
//!
//! Every test boots the REAL production router over a loopback socket against
//! the shared Postgres + Redis, with `resource_indicators_enabled` pinned on.
//! A resource or scope disabled AFTER issuance must be dead at the next
//! mint-time check: refresh re-validates the grant's stored audience before
//! rotation (`invalid_target`, presented token left live), the device poll
//! validates before consuming, authorization-code redemption validates a
//! presented audience before consuming the code, and refresh narrows a
//! disabled scope into the replacement token without ever widening it back.
//!
//! Re-enabling each catalog row proves the disable was the cause: the same
//! live token/code then succeeds.

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

use d_oauth::{
  db::{TokenEndpointAuthMethod, resource_repo, scope_repo},
  protocol::token::ClientKind,
};
use dpop::DpopKey;
use harness::{
  TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_scope,
};
use reqwest::StatusCode;

/// Catalog resource pinned into every grant under test.
const RESOURCE: &str = "https://rs-stale.example.test/api";
/// Registered loopback redirect for the authorization-code flow.
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// Confidential refresh client.
const REFRESH_CLIENT: &str = "e2e-stale-refresh";
/// Refresh client secret.
const REFRESH_SECRET: &str = "e2e-stale-refresh-secret-1a2b3c4d5e6f";
/// Public browser client (unbound: no DPoP proof needed).
const PUBLIC_CLIENT: &str = "e2e-stale-public";
/// Confidential device client.
const DEVICE_CLIENT: &str = "e2e-stale-device";
/// Device client secret.
const DEVICE_SECRET: &str = "e2e-stale-device-secret-6f5e4d3c2b1a";
/// Provisioned login email.
const EMAIL: &str = "stale-catalog@example.test";
/// Provisioned login password.
const PASSWORD: &str = "e2e-stale-catalog-password-1a2b";

/// Start one world with the RFC 8707 gate on and one enabled catalog row.
///
/// Returns the world plus the row id needed to re-enable it: there is no
/// public enable helper, and `upsert` deliberately preserves `enabled=false`.
async fn start_world() -> Result<(World, uuid::Uuid), TestError> {
  let world = World::start_with(
    open_rate_limit(),
    serde_json::json!({"resource_indicators_enabled": true}),
  )
  .await?;
  let row = resource_repo::upsert(&world.pool, RESOURCE, "stale catalog e2e")
    .await
    .map_err(|error| fail(format!("resource upsert failed: {error}")))?;
  Ok((world, row.id))
}

/// Re-enable a catalog row through direct SQL (no production enable helper).
async fn enable_resource(pool: &sqlx::PgPool, id: uuid::Uuid) -> Result<(), TestError> {
  sqlx::query("UPDATE resource_servers SET enabled = true WHERE id = $1")
    .bind(id)
    .execute(pool)
    .await?;
  Ok(())
}

/// Disable the catalog row, proving the update applied.
async fn disable_resource(world: &World) -> Result<(), TestError> {
  ensure(
    resource_repo::disable(&world.pool, RESOURCE)
      .await
      .map_err(|error| fail(format!("resource disable failed: {error}")))?,
    "disable must update the seeded row",
  )
}

/// Assert a token endpoint failure carries the exact OAuth code and mints
/// nothing.
fn ensure_error(status: StatusCode, body: &str, code: &str) -> Result<(), TestError> {
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("must be 400, got {status}: {body}"),
  )?;
  let value = json_body(body)?;
  ensure(
    value["error"] == code,
    format!("failure must be {code}, got {value}"),
  )?;
  ensure(!body.contains("access_token"), "failure must mint nothing")
}

/// Assert a refresh token still resolves live in the store.
async fn ensure_refresh_live(world: &World, token: &str) -> Result<(), TestError> {
  let mut conn = world.state.redis.clone();
  ensure(
    world
      .service
      .find_refresh(&mut conn, &world.store, token)
      .await
      .map_err(|error| fail(format!("refresh lookup failed: {error}")))?
      .is_some(),
    "the rejected refresh token must stay live",
  )
}

/// One authorization-code browser flow that pins `resource`.
struct ResourceFlow<'a> {
  /// Public client driving the flow.
  client_id: &'a str,
  /// Registered callback.
  redirect_uri: &'a str,
  /// Requested scope.
  scope: &'a str,
  /// Audience the authorize request pins.
  resource: &'a str,
  /// Provisioned account email.
  email: &'a str,
  /// Provisioned account password.
  password: &'a str,
  /// Provisioned account TOTP secret.
  totp_secret: &'a str,
}

/// Drive `GET /authorize` (with `resource`) through login and consent and
/// return the issued code plus the PKCE verifier.
async fn authorize_with_resource(
  world: &World,
  flow: &ResourceFlow<'_>,
) -> Result<(String, String), TestError> {
  let (challenge, verifier) = browser::oauth2_pkce();
  let (status, headers, body) = world
    .get(
      &format!(
        "/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state=e2e-stale\
         &resource={}&code_challenge={challenge}&code_challenge_method=S256",
        browser::encoded(flow.client_id),
        browser::encoded(flow.redirect_uri),
        browser::encoded(flow.scope),
        browser::encoded(flow.resource)
      ),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("authorize must 303 to login: {status} {body}"),
  )?;
  let request_id = browser::query_value(&browser::location_of(&headers)?, "request_id")?;

  let (status, headers, body) = world
    .get(&format!("/login?request_id={request_id}"), &[])
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("login page must render: {status} {body}"),
  )?;
  let presession = browser::cookie_value(&headers, browser::SESSION_COOKIE)?;
  let login_csrf = browser::hidden_input(&body, "csrf")?;
  let code_2fa = browser::totp_now(flow.totp_secret).await?;
  let cookie = format!("{}={presession}", browser::SESSION_COOKIE);
  let (status, headers, body) = world
    .post_form(
      "/login",
      &[
        ("email", flow.email),
        ("password", flow.password),
        ("code", code_2fa.as_str()),
        ("csrf", login_csrf.as_str()),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("login must 303 to consent: {status} {body}"),
  )?;
  ensure(
    browser::location_of(&headers)? == "/consent",
    "login must land on consent",
  )?;
  let session = browser::cookie_value(&headers, browser::SESSION_COOKIE)?;
  let cookie = format!("{}={session}", browser::SESSION_COOKIE);
  let (status, _, body) = world
    .get("/consent", &[("cookie", cookie.as_str())])
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("consent must render: {status} {body}"),
  )?;
  ensure(
    browser::hidden_input(&body, "request_id")? == request_id,
    "consent must serve the bound authorization request",
  )?;
  let consent_csrf = browser::hidden_input(&body, "csrf")?;
  let (status, headers, body) = world
    .post_form(
      "/consent",
      &[
        ("request_id", request_id.as_str()),
        ("csrf", consent_csrf.as_str()),
        ("decision", "approve"),
      ],
      None,
      &[("cookie", cookie.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::SEE_OTHER,
    format!("consent approval must 303 to the redirect: {status} {body}"),
  )?;
  let location = browser::location_of(&headers)?;
  ensure(
    location.starts_with(flow.redirect_uri),
    format!("code must return to the registered redirect, got {location}"),
  )?;
  Ok((browser::query_value(&location, "code")?, verifier))
}

/// A resource disabled after issuance rejects refresh with `invalid_target`
/// before rotation, leaves the presented token live, and the same token
/// rotates once the catalog row is re-enabled.
#[tokio::test]
async fn e2e_refresh_rejects_disabled_resource_as_invalid_target() -> Result<(), TestError> {
  let (world, resource_id) = start_world().await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    REFRESH_CLIENT,
    Some(REFRESH_SECRET),
    &["refresh_token"],
    "read",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  let minted = world
    .mint_with_aud(
      REFRESH_CLIENT,
      "read",
      ClientKind::Confidential,
      None,
      RESOURCE,
    )
    .await?;
  disable_resource(&world).await?;

  let refresh = [
    ("grant_type", "refresh_token"),
    ("refresh_token", minted.refresh_token.as_str()),
  ];
  let basic = Some((REFRESH_CLIENT, REFRESH_SECRET));
  let (status, _, body) = world.post_form("/token", &refresh, basic, &[]).await?;
  ensure_error(status, &body, "invalid_target")?;
  ensure_refresh_live(&world, &minted.refresh_token).await?;

  enable_resource(&world.pool, resource_id).await?;
  let (status, _, body) = world.post_form("/token", &refresh, basic, &[]).await?;
  ensure(
    status == StatusCode::OK,
    format!("the re-enabled audience must rotate: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["refresh_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "the successful rotation must return a refresh token",
  )
}

/// A device code pinned to a resource that is disabled before the poll fails
/// `invalid_target`; the approval was already consumed, so a retry is
/// terminal `expired_token` and no token was ever minted.
#[tokio::test]
async fn e2e_device_poll_rejects_disabled_resource() -> Result<(), TestError> {
  let (world, _resource_id) = start_world().await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    DEVICE_CLIENT,
    Some(DEVICE_SECRET),
    &[device::DEVICE_GRANT],
    "read",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  let (status, _, body) = world
    .post_form(
      "/device_authorization",
      &[
        ("client_id", DEVICE_CLIENT),
        ("scope", "read"),
        ("resource", RESOURCE),
      ],
      Some((DEVICE_CLIENT, DEVICE_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("device authorization must 200: {status} {body}"),
  )?;
  let payload = json_body(&body)?;
  let device_code = payload["device_code"]
    .as_str()
    .ok_or_else(|| fail("device authorization must return device_code"))?
    .to_owned();
  let user_code = payload["user_code"]
    .as_str()
    .ok_or_else(|| fail("device authorization must return user_code"))?
    .to_owned();

  disable_resource(&world).await?;
  let browser = browser::login_session(world, EMAIL, PASSWORD).await?;
  let session = browser
    .session
    .as_deref()
    .ok_or_else(|| fail("login_session must return an authenticated session"))?;
  let page = device::review(&browser.world, session, &user_code).await?;
  let csrf = browser::hidden_input(&page, "csrf")?;
  device::decide(
    &browser.world,
    device::Decision {
      session,
      user_code: &user_code,
      csrf: &csrf,
      action: "approve",
    },
  )
  .await?;

  let client = device::Client {
    id: DEVICE_CLIENT,
    secret: Some(DEVICE_SECRET),
    scope: "read",
  };
  let key = DpopKey::generate()?;
  let request = device::Poll {
    client,
    device_code: &device_code,
  };
  let (status, body) = device::poll(&browser.world, request, &key).await?;
  ensure_error(status, &body, "invalid_target")?;

  let (status, body) = device::poll(&browser.world, request, &key).await?;
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("the consumed device code must be 400: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["error"] == "expired_token",
    format!("the consumed device code must be expired_token: {body}"),
  )?;
  ensure(
    !body.contains("access_token"),
    "the retry must mint nothing",
  )
}

/// A disabled `resource` on `/authorize` redirects with `invalid_target` and
/// issues no code.
#[tokio::test]
async fn e2e_authorize_rejects_disabled_resource_before_code() -> Result<(), TestError> {
  let (world, _resource_id) = start_world().await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    PUBLIC_CLIENT,
    None,
    &["authorization_code", "refresh_token"],
    "read",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  attach_redirect(&world.pool, &world.state.keys, PUBLIC_CLIENT, REDIRECT_URI).await?;
  disable_resource(&world).await?;

  let (challenge, _verifier) = browser::oauth2_pkce();
  let (status, headers, body) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_CLIENT}&redirect_uri={}&response_type=code&scope=read\
         &resource={}&code_challenge={challenge}&code_challenge_method=S256",
        browser::encoded(REDIRECT_URI),
        browser::encoded(RESOURCE)
      ),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::FOUND,
    format!("a disabled resource must redirect, got {status}: {body}"),
  )?;
  let location = browser::location_of(&headers)?;
  ensure(
    location.starts_with(REDIRECT_URI),
    format!("the error must redirect to the client, got {location}"),
  )?;
  ensure(
    location.contains("error=invalid_target"),
    format!("the redirect must carry invalid_target, got {location}"),
  )?;
  ensure(
    !browser::has_query_key(&location, "code"),
    "a rejected authorize must never issue a code",
  )
}

/// A code issued with an audience stays live when that resource is disabled
/// before redemption: the presented audience is invalid_target, never a
/// burned code, and the same code redeems after re-enable.
#[tokio::test]
async fn e2e_auth_code_rejects_resource_disabled_after_authorize() -> Result<(), TestError> {
  let (world, resource_id) = start_world().await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    PUBLIC_CLIENT,
    None,
    &["authorization_code", "refresh_token"],
    "read",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  attach_redirect(&world.pool, &world.state.keys, PUBLIC_CLIENT, REDIRECT_URI).await?;
  seed_scope(&world.pool, "read").await?;
  let totp_secret = browser::seed_user(&world, EMAIL, PASSWORD, "read").await?;
  let (code, verifier) = authorize_with_resource(
    &world,
    &ResourceFlow {
      client_id: PUBLIC_CLIENT,
      redirect_uri: REDIRECT_URI,
      scope: "read",
      resource: RESOURCE,
      email: EMAIL,
      password: PASSWORD,
      totp_secret: &totp_secret,
    },
  )
  .await?;

  disable_resource(&world).await?;
  let redemption = [
    ("grant_type", "authorization_code"),
    ("code", code.as_str()),
    ("redirect_uri", REDIRECT_URI),
    ("client_id", PUBLIC_CLIENT),
    ("code_verifier", verifier.as_str()),
    ("resource", RESOURCE),
  ];
  let (status, _, body) = world.post_form("/token", &redemption, None, &[]).await?;
  ensure_error(status, &body, "invalid_target")?;

  enable_resource(&world.pool, resource_id).await?;
  let (status, _, body) = world.post_form("/token", &redemption, None, &[]).await?;
  ensure(
    status == StatusCode::OK,
    format!("the live code must redeem after re-enable: {status} {body}"),
  )?;
  let tokens = json_body(&body)?;
  ensure(
    tokens["access_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "the re-enabled redeem must return an access token",
  )?;
  ensure(
    tokens["refresh_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "the re-enabled redeem must return a refresh token",
  )
}

/// A scope disabled after issuance drops from the rotated refresh token while
/// the grant stays live; re-enabling it never widens the grant back.
#[tokio::test]
async fn e2e_refresh_drops_disabled_scope_but_stays_live() -> Result<(), TestError> {
  let (world, _resource_id) = start_world().await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    REFRESH_CLIENT,
    Some(REFRESH_SECRET),
    &["refresh_token"],
    "read write",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  seed_scope(&world.pool, "write").await?;
  let minted = world
    .mint(REFRESH_CLIENT, "read write", ClientKind::Confidential, None)
    .await?;
  ensure(
    scope_repo::set_enabled(&world.pool, "write", false)
      .await
      .map_err(|error| fail(format!("scope disable failed: {error}")))?,
    "write must be a seeded catalog row",
  )?;

  let basic = Some((REFRESH_CLIENT, REFRESH_SECRET));
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "refresh_token"),
        ("refresh_token", minted.refresh_token.as_str()),
      ],
      basic,
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("a narrowed refresh must still rotate: {status} {body}"),
  )?;
  let rotated = json_body(&body)?;
  ensure(
    rotated["scope"] == "read",
    format!("the disabled scope must drop, got {rotated}"),
  )?;
  let rotated_refresh = rotated["refresh_token"]
    .as_str()
    .filter(|token| !token.is_empty())
    .ok_or_else(|| fail("the narrowed rotation must return a refresh token"))?
    .to_owned();

  ensure(
    scope_repo::set_enabled(&world.pool, "write", true)
      .await
      .map_err(|error| fail(format!("scope enable failed: {error}")))?,
    "write must still be a catalog row",
  )?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "refresh_token"),
        ("refresh_token", rotated_refresh.as_str()),
        ("scope", "write"),
      ],
      basic,
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_scope")?;

  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "refresh_token"),
        ("refresh_token", rotated_refresh.as_str()),
      ],
      basic,
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("the still-live refresh must rotate: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["scope"] == "read",
    "the re-enabled scope must never be widened back onto the grant",
  )
}

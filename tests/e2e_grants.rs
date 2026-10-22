//! `test(e2e_)` token-grant rows over the live router: the wired dispatcher.
//!
//! Every test boots the REAL production router ([`d_oauth::routes::build_router`])
//! over a REAL loopback socket against the shared Postgres + Redis from
//! `compose.test.yaml` and asserts only observable HTTP behavior: the five grants dispatch, the
//! sender-constraint matrix holds, and every failure is the specified 4xx.
//!
//! The `oauth2` crate drives the baseline shapes (PKCE material, code
//! redemption, client-credentials exchange); DPoP proofs and the extension
//! grants are hand-rolled `reqwest`.

#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

#[path = "e2e/clients.rs"]
mod clients;

use d_oauth::db::{
  TokenEndpointAuthMethod, client_repo, resource_repo, user_repo, user_scope_repo,
};
use d_oauth::protocol::code::{CodeClientKind, CodeIssueRequest, CodeIssuer, IssuedCode};
use d_oauth::protocol::device::hash_token;
use d_oauth::protocol::scope::ScopeSet;
use d_oauth::protocol::token::ClientKind;
use d_oauth::store::device::{DeviceStatus, decide};
use dpop::DpopKey;
use harness::{
  SeedClientOpts, TestError, World, attach_redirect, ensure, fail, json_body, open_rate_limit,
  seed_client, seed_client_bound, seed_scope,
};
use oauth2::TokenResponse as _;

/// Fixture confidential client.
const CLIENT_ID: &str = "e2e-grant-client";
/// Fixture secret.
const CLIENT_SECRET: &str = "e2e-grant-secret-1a2b3c4d5e6f708192";
/// Fixture public client (DPoP-bound by policy).
const PUBLIC_ID: &str = "e2e-grant-public";
/// Registered loopback redirect.
const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
/// First catalog-registered resource indicator (RFC 8707).
const RESOURCE_A: &str = "https://rs-a.example.test/api";
/// Second catalog-registered resource indicator (RFC 8707).
const RESOURCE_B: &str = "https://rs-b.example.test/api";

/// One world plus seeded confidential + public clients, scopes, redirect.
async fn setup() -> Result<World, TestError> {
  setup_with_resource_indicators(false).await
}

/// [`setup`] with the `resource_indicators_enabled` gate pinned.
///
/// The RFC 8707 catalog always holds [`RESOURCE_A`] and [`RESOURCE_B`]; the
/// flag decides whether a token request may pin them.
async fn setup_with_resource_indicators(enabled: bool) -> Result<World, TestError> {
  let world = World::start_with(
    open_rate_limit(),
    serde_json::json!({"resource_indicators_enabled": enabled}),
  )
  .await?;
  for resource in [RESOURCE_A, RESOURCE_B] {
    resource_repo::upsert(&world.pool, resource, "e2e resource server")
      .await
      .map_err(|error| fail(format!("resource upsert failed: {error}")))?;
  }
  seed_client(
    &world.pool,
    &world.state.keys,
    CLIENT_ID,
    Some(CLIENT_SECRET),
    &[
      "authorization_code",
      "refresh_token",
      "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
      "urn:ietf:params:oauth:grant-type:token-exchange",
    ],
    "read write",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    PUBLIC_ID,
    None,
    &["authorization_code", "refresh_token"],
    "read",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  seed_scope(&world.pool, "write").await?;
  attach_redirect(&world.pool, &world.state.keys, CLIENT_ID, REDIRECT_URI).await?;
  attach_redirect(&world.pool, &world.state.keys, PUBLIC_ID, REDIRECT_URI).await?;
  Ok(world)
}

/// Assert a token failure is the specified OAuth error, minting nothing.
fn ensure_error(status: reqwest::StatusCode, body: &str, code: &str) -> Result<(), TestError> {
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("must be 400, got {status}: {body}"),
  )?;
  let value = json_body(body)?;
  ensure(
    value["error"] == code,
    format!("failure must be {code}, got {value}"),
  )?;
  ensure(!body.contains("access_token"), "failure must mint nothing")?;
  ensure(
    !body.contains(CLIENT_SECRET),
    "failure must not leak the secret",
  )?;
  Ok(())
}

/// PKCE downgrade is rejected at the authorize layer (`plain` → 302
/// `invalid_request`); redemption of a stale code is `invalid_grant`.
#[tokio::test]
async fn e2e_pkce_downgrade_rejected() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, _verifier) = oauth2_pkce();
  let (status, headers, _) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=code\
         &code_challenge={challenge}&code_challenge_method=plain",
        encoded(REDIRECT_URI)
      ),
      &[],
    )
    .await?;
  ensure(status == reqwest::StatusCode::FOUND, "plain PKCE must 302")?;
  let location = location_of(&headers)?;
  ensure(
    location.contains("error=invalid_request"),
    "plain PKCE must be invalid_request",
  )?;

  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", "stale-code"),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;
  Ok(())
}

/// Code replay and cross-client redemption never succeed: an unknown or
/// already-consumed code is always `invalid_grant`.
#[tokio::test]
async fn e2e_code_replay_expiry_cross_client_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let redemption = [
    ("grant_type", "authorization_code"),
    ("code", "one-time-code"),
    ("redirect_uri", REDIRECT_URI),
    ("client_id", CLIENT_ID),
  ];
  for attempt in 1..=2 {
    let (status, _, body) = world
      .post_form("/token", &redemption, Some((CLIENT_ID, CLIENT_SECRET)), &[])
      .await?;
    ensure_error(status, &body, "invalid_grant")
      .map_err(|error| fail(format!("replay attempt {attempt}: {error}")))?;
  }
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", "one-time-code"),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", PUBLIC_ID),
      ],
      None,
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;
  Ok(())
}

/// A replayed DPoP `jti` mints once and is `invalid_dpop_proof` on reuse.
#[tokio::test]
async fn e2e_dpop_jti_replay_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let key = DpopKey::generate()?;
  let htu = format!("{}/token", world.state.config.issuer);
  let proof = key.proof("POST", &htu)?;
  let attempt = [("grant_type", "client_credentials")];

  let (status, _, body) = world
    .post_form(
      "/token",
      &attempt,
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("fresh proof must mint: {status} {body}"),
  )?;
  let value = json_body(&body)?;
  ensure(
    value["token_type"] == "DPoP",
    "proof-bound issuance must be DPoP",
  )?;

  let (status, _, body) = world
    .post_form(
      "/token",
      &attempt,
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure_error(status, &body, "invalid_dpop_proof")?;
  Ok(())
}

/// A DPoP proof bound to the wrong `htu` is `invalid_dpop_proof`.
#[tokio::test]
async fn e2e_dpop_htu_mismatch_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let key = DpopKey::generate()?;
  let wrong = key.proof("POST", "https://auth.example.test/wrong-token")?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[("grant_type", "client_credentials")],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", wrong.as_str())],
    )
    .await?;
  ensure_error(status, &body, "invalid_dpop_proof")?;
  Ok(())
}

/// Refresh reuse rotates once, then `invalid_grant` and cascade-revokes the
/// grant family (the first access token reads inactive).
#[tokio::test]
async fn e2e_refresh_rotation_reuse_cascade_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let key = DpopKey::generate()?;
  let jkt =
    d_oauth::jose::jwk::thumbprint(&key.jwk()).map_err(|error| fail(format!("jwk: {error}")))?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, Some(&jkt))
    .await?;
  let htu = format!("{}/token", world.state.config.issuer);
  let refresh = [
    ("grant_type", "refresh_token"),
    ("refresh_token", minted.refresh_token.as_str()),
  ];
  let first_proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &refresh,
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", first_proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("first rotation must mint: {status} {body}"),
  )?;
  let rotated = json_body(&body)?;
  ensure(
    rotated["access_token"]
      .as_str()
      .is_some_and(|t| !t.is_empty()),
    "rotation must return an access token",
  )?;
  ensure(
    rotated["refresh_token"]
      .as_str()
      .is_some_and(|t| !t.is_empty()),
    "rotation must return a refresh token",
  )?;

  let second_proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &refresh,
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", second_proof.as_str())],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;

  // The replay mapping masks the tombstone by design (a same-request retry
  // is rejected without cascading); expire it to exercise the reuse path.
  let mut conn = world.state.redis.clone();
  let found = world
    .service
    .find_refresh(&mut conn, &world.store, &minted.refresh_token)
    .await
    .map_err(|error| fail(format!("refresh lookup: {error}")))?
    .ok_or_else(|| fail("rotated refresh token must resolve to its tombstone"))?;
  let request_id = world
    .service
    .request_id_for(&found.hash)
    .map_err(|error| fail(format!("request id: {error}")))?;
  let _: () = redis::cmd("DEL")
    .arg(world.store.rotation_map_key(&request_id))
    .query_async(&mut conn)
    .await?;

  let third_proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &refresh,
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[("dpop", third_proof.as_str())],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;

  let first_access = minted.access_token.as_str();
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", first_access)],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    "introspection must answer",
  )?;
  ensure(
    json_body(&body)?["active"] == false,
    "reuse must cascade-revoke the rotated access token",
  )?;
  Ok(())
}

/// Concurrent rotations of one refresh token: exactly one mints, every other
/// racer is `invalid_grant`.
#[tokio::test]
async fn e2e_concurrent_rotation_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let key = DpopKey::generate()?;
  let jkt =
    d_oauth::jose::jwk::thumbprint(&key.jwk()).map_err(|error| fail(format!("jwk: {error}")))?;
  let minted = world
    .mint(CLIENT_ID, "read", ClientKind::Confidential, Some(&jkt))
    .await?;
  let htu = format!("{}/token", world.state.config.issuer);
  let mut proofs = Vec::with_capacity(8);
  for _ in 0..8 {
    proofs.push(key.proof("POST", &htu)?);
  }
  let mut set = tokio::task::JoinSet::new();
  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(60))
    .build()?;
  for proof in proofs {
    let client = client.clone();
    let base = world.base.clone();
    let refresh = minted.refresh_token.clone();
    set.spawn(async move {
      client
        .post(format!("{base}/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header("dpop", proof)
        .form(&[
          ("grant_type", "refresh_token"),
          ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
    });
  }
  let mut successes = 0;
  let mut rejections = 0;
  let mut unavailable = 0;
  while let Some(outcome) = set.join_next().await {
    let response = outcome.map_err(|error| fail(format!("join failed: {error}")))??;
    let status = response.status();
    let body = response.text().await?;
    if status == reqwest::StatusCode::OK {
      successes += 1;
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
      ensure(
        json_body(&body)?["error"] == "temporarily_unavailable",
        format!("store outage must be temporarily_unavailable: {body}"),
      )?;
      ensure(!body.contains("access_token"), "failure must mint nothing")?;
      unavailable += 1;
    } else {
      ensure_error(status, &body, "invalid_grant")?;
      rejections += 1;
    }
  }
  ensure(
    successes == 1,
    format!(
      "exactly one racer must rotate (got {successes}; invalid_grant={rejections}, \
       unavailable={unavailable})"
    ),
  )?;
  ensure(
    rejections + unavailable == 7,
    "every other racer must be rejected",
  )?;
  Ok(())
}

/// Concurrent redemptions of one authorization code: exactly one exchanges,
/// every other racer is `invalid_grant` — the code is consumed atomically, so
/// only that one winner can create a token family.
#[tokio::test]
async fn e2e_concurrent_code_redemption_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, verifier) = oauth2_pkce();
  let issued = issue_conf_code(&world, CLIENT_ID, &challenge).await?;
  let verifier = verifier.secret().to_owned();
  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(60))
    .build()?;
  let mut set = tokio::task::JoinSet::new();
  for _ in 0..2 {
    let client = client.clone();
    let base = world.base.clone();
    let code = issued.code.clone();
    let verifier = verifier.clone();
    set.spawn(async move {
      client
        .post(format!("{base}/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[
          ("grant_type", "authorization_code"),
          ("code", code.as_str()),
          ("redirect_uri", REDIRECT_URI),
          ("client_id", CLIENT_ID),
          ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
    });
  }
  let mut successes = 0;
  let mut rejections = 0;
  let mut unavailable = 0;
  while let Some(outcome) = set.join_next().await {
    let response = outcome.map_err(|error| fail(format!("join failed: {error}")))??;
    let status = response.status();
    let body = response.text().await?;
    if status == reqwest::StatusCode::OK {
      let minted = json_body(&body)?;
      ensure(
        minted["access_token"]
          .as_str()
          .is_some_and(|token| !token.is_empty()),
        "the winner must mint an access token",
      )?;
      ensure(
        minted["refresh_token"]
          .as_str()
          .is_some_and(|token| !token.is_empty()),
        "the single winner must create the token family",
      )?;
      successes += 1;
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
      ensure(
        json_body(&body)?["error"] == "temporarily_unavailable",
        format!("store outage must be temporarily_unavailable: {body}"),
      )?;
      ensure(!body.contains("access_token"), "failure must mint nothing")?;
      unavailable += 1;
    } else {
      ensure_error(status, &body, "invalid_grant")?;
      rejections += 1;
    }
  }
  ensure(
    successes == 1,
    format!(
      "exactly one racer must redeem the code (got {successes}; invalid_grant={rejections}, \
       unavailable={unavailable})"
    ),
  )?;
  ensure(
    rejections + unavailable == 1,
    "every other racer must be rejected",
  )?;
  Ok(())
}

/// Concurrent `/authorize` GETs on one PAR `request_uri`: exactly one proceeds
/// into login, every other racer is the fail-closed `invalid_request` — the
/// handle is consumed atomically and cannot be replayed.
#[tokio::test]
async fn e2e_concurrent_par_consumption_fail_closed() -> Result<(), TestError> {
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
        ("state", "par-race-state"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::CREATED,
    format!("PAR push must 201: {status} {body}"),
  )?;
  let request_uri = json_body(&body)?["request_uri"]
    .as_str()
    .ok_or_else(|| fail("PAR must return request_uri"))?
    .to_owned();

  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(60))
    .build()?;
  let mut set = tokio::task::JoinSet::new();
  for _ in 0..2 {
    let client = client.clone();
    let base = world.base.clone();
    let target = format!(
      "/authorize?client_id={CLIENT_ID}&request_uri={}",
      encoded(&request_uri)
    );
    set.spawn(async move { client.get(format!("{base}{target}")).send().await });
  }
  let mut winners = 0;
  let mut rejections = 0;
  let mut unavailable = 0;
  while let Some(outcome) = set.join_next().await {
    let response = outcome.map_err(|error| fail(format!("join failed: {error}")))??;
    let status = response.status();
    let location = response
      .headers()
      .get("location")
      .and_then(|value| value.to_str().ok())
      .map(str::to_owned);
    let body = response.text().await?;
    if status == reqwest::StatusCode::SEE_OTHER {
      ensure(
        location
          .as_deref()
          .is_some_and(|target| target.starts_with("/login?request_id=")),
        format!("the winner must enter login: {location:?} {body}"),
      )?;
      winners += 1;
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
      ensure(
        json_body(&body)?["error"] == "temporarily_unavailable",
        format!("store outage must be temporarily_unavailable: {body}"),
      )?;
      unavailable += 1;
    } else {
      ensure(
        status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::FOUND,
        format!("a losing PAR authorize must be rejected: {status} {body}"),
      )?;
      let rejected = body.contains("invalid_request")
        || location
          .as_deref()
          .is_some_and(|target| target.contains("error=invalid_request"));
      ensure(
        rejected,
        format!("a losing PAR authorize must be invalid_request: {status} {location:?} {body}"),
      )?;
      ensure(
        location
          .as_deref()
          .is_none_or(|target| !target.starts_with("/login")),
        "a losing racer must never enter login",
      )?;
      ensure(
        !body.contains("request_id="),
        "a losing racer must not start a flow",
      )?;
      rejections += 1;
    }
  }
  ensure(
    winners == 1,
    format!("exactly one racer must consume the PAR handle (got {winners})"),
  )?;
  ensure(
    rejections + unavailable == 1,
    "every other racer must be rejected",
  )?;
  Ok(())
}

/// Concurrent `/token` calls reusing one DPoP `jti`: exactly one mints, every
/// other racer is `invalid_dpop_proof` — the replay marker is written with
/// `SET NX`.
#[tokio::test]
async fn e2e_concurrent_dpop_jti_reuse_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let key = DpopKey::generate()?;
  let htu = format!("{}/token", world.state.config.issuer);
  let jti = uuid::Uuid::new_v4().to_string();
  let mut proofs = Vec::with_capacity(2);
  for _ in 0..2 {
    proofs.push(key.proof_with_jti("POST", &htu, &jti)?);
  }
  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(60))
    .build()?;
  let mut set = tokio::task::JoinSet::new();
  for proof in proofs {
    let client = client.clone();
    let base = world.base.clone();
    set.spawn(async move {
      client
        .post(format!("{base}/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header("dpop", proof)
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
    });
  }
  let mut successes = 0;
  let mut rejections = 0;
  let mut unavailable = 0;
  while let Some(outcome) = set.join_next().await {
    let response = outcome.map_err(|error| fail(format!("join failed: {error}")))??;
    let status = response.status();
    let body = response.text().await?;
    if status == reqwest::StatusCode::OK {
      ensure(
        json_body(&body)?["token_type"] == "DPoP",
        "the winner must mint a DPoP-bound token",
      )?;
      successes += 1;
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
      ensure(
        json_body(&body)?["error"] == "temporarily_unavailable",
        format!("store outage must be temporarily_unavailable: {body}"),
      )?;
      ensure(!body.contains("access_token"), "failure must mint nothing")?;
      unavailable += 1;
    } else {
      ensure_error(status, &body, "invalid_dpop_proof")?;
      rejections += 1;
    }
  }
  ensure(
    successes == 1,
    format!(
      "exactly one racer must mint (got {successes}; invalid_dpop_proof={rejections}, \
       unavailable={unavailable})"
    ),
  )?;
  ensure(
    rejections + unavailable == 1,
    "every other racer must be rejected",
  )?;
  Ok(())
}

/// Concurrent `/token` polls of one approved device code: exactly one mints,
/// every other racer fails closed (`expired_token`/`invalid_grant`, or the
/// RFC 8628 back-off when it races the interval stamp) — the approval is
/// consumed atomically and is never redeemed twice.
#[tokio::test]
async fn e2e_concurrent_device_poll_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let approver = user_repo::create_user(
    &world.pool,
    &world.state.keys,
    world.state.config.pii_dual_write,
    &user_repo::NewUser {
      email: "e2e-device-approver@example.test".to_owned(),
      password_hash: "e2e-not-a-login-credential".to_owned(),
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  user_scope_repo::entitle(&world.pool, approver.id, "read", None)
    .await
    .map_err(|error| fail(format!("entitle failed: {error}")))?;

  let (status, _, body) = world
    .post_form(
      "/device_authorization",
      &[("client_id", CLIENT_ID), ("scope", "read")],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status.is_success(),
    format!("device authorization must 200: {status} {body}"),
  )?;
  let device_code = json_body(&body)?["device_code"]
    .as_str()
    .ok_or_else(|| fail("device authorization must return device_code"))?
    .to_owned();

  // Approve through the store decision the `/device` UI records.
  let device_hash = hash_token(&world.state.keys, &device_code)
    .map_err(|error| fail(format!("device hash failed: {error}")))?;
  let mut conn = world.state.redis.clone();
  let approved = decide(
    &mut conn,
    &world.store,
    &device_hash,
    DeviceStatus::Approved,
    &approver.id.to_string(),
    &uuid::Uuid::new_v4().to_string(),
  )
  .await
  .map_err(|error| fail(format!("device approval failed: {error}")))?;
  ensure(approved, "the device record must be live to approve")?;

  let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(std::time::Duration::from_secs(60))
    .build()?;
  let mut set = tokio::task::JoinSet::new();
  for _ in 0..2 {
    let client = client.clone();
    let base = world.base.clone();
    let device_code = device_code.clone();
    set.spawn(async move {
      client
        .post(format!("{base}/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[
          ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
          ("device_code", device_code.as_str()),
        ])
        .send()
        .await
    });
  }
  let mut successes = 0;
  let mut rejections = 0;
  let mut unavailable = 0;
  while let Some(outcome) = set.join_next().await {
    let response = outcome.map_err(|error| fail(format!("join failed: {error}")))??;
    let status = response.status();
    let body = response.text().await?;
    if status == reqwest::StatusCode::OK {
      let minted = json_body(&body)?;
      ensure(
        minted["access_token"]
          .as_str()
          .is_some_and(|token| !token.is_empty()),
        "the winner must mint an access token",
      )?;
      ensure(
        minted["refresh_token"]
          .as_str()
          .is_some_and(|token| !token.is_empty()),
        "the winner must mint a refresh token",
      )?;
      successes += 1;
    } else if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
      ensure(
        json_body(&body)?["error"] == "temporarily_unavailable",
        format!("store outage must be temporarily_unavailable: {body}"),
      )?;
      ensure(!body.contains("access_token"), "failure must mint nothing")?;
      unavailable += 1;
    } else {
      let error_code = json_body(&body)?["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
      // A racer that lands after the winner's interval stamp gets the RFC 8628
      // back-off; one that lands after the atomic consume gets `expired_token`.
      ensure(
        matches!(
          error_code.as_str(),
          "expired_token" | "invalid_grant" | "slow_down"
        ),
        format!("a losing device poll must fail closed, got {status}: {body}"),
      )?;
      ensure(!body.contains("access_token"), "failure must mint nothing")?;
      rejections += 1;
    }
  }
  ensure(
    successes == 1,
    format!(
      "exactly one poll must mint (got {successes}; expired_or_invalid={rejections}, \
       unavailable={unavailable})"
    ),
  )?;
  ensure(
    rejections + unavailable == 1,
    "every other poll must fail closed",
  )?;
  Ok(())
}

/// A public client's refresh grant without a fresh DPoP proof is
/// `invalid_grant` (the stored `jkt` alone never mints).
#[tokio::test]
async fn e2e_public_client_without_dpop_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let minted = world
    .mint(
      PUBLIC_ID,
      "read",
      ClientKind::Public,
      Some("e2e-public-jkt"),
    )
    .await?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "refresh_token"),
        ("refresh_token", minted.refresh_token.as_str()),
        ("client_id", PUBLIC_ID),
      ],
      None,
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;
  Ok(())
}

/// A DPoP-bound confidential client must present a fresh proof at token time.
#[tokio::test]
async fn e2e_dpop_bound_client_requires_fresh_proof() -> Result<(), TestError> {
  const BOUND_ID: &str = "e2e-grant-dpop-bound";
  const BOUND_SECRET: &str = "e2e-grant-bound-secret-0f1e2d3c4b5a6978";
  let world = World::start(open_rate_limit()).await?;
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    BOUND_ID,
    Some(BOUND_SECRET),
    &SeedClientOpts {
      grants: &["client_credentials"],
      scope: "read",
      method: TokenEndpointAuthMethod::ClientSecretBasic,
      dpop_bound: true,
    },
  )
  .await?;
  seed_scope(&world.pool, "read").await?;

  let (status, _, body) = world
    .post_form(
      "/token",
      &[("grant_type", "client_credentials")],
      Some((BOUND_ID, BOUND_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;

  let key = DpopKey::generate()?;
  let proof = key.proof("POST", &format!("{}/token", world.state.config.issuer))?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[("grant_type", "client_credentials"), ("scope", "read")],
      Some((BOUND_ID, BOUND_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("fresh proof must mint: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["token_type"] == "DPoP",
    "the bound issuance must be a DPoP token",
  )?;
  Ok(())
}

/// A DPoP-bound confidential client must present a fresh proof on the
/// authorization-code grant too (not only the grants the dispatcher
/// authenticates itself); a proof-less redemption is `invalid_grant`.
#[tokio::test]
async fn e2e_dpop_bound_auth_code_requires_fresh_proof() -> Result<(), TestError> {
  const BOUND_ID: &str = "e2e-grant-bound-code";
  const BOUND_SECRET: &str = "e2e-grant-bound-code-secret-4d3c2b1a";
  let world = World::start(open_rate_limit()).await?;
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    BOUND_ID,
    Some(BOUND_SECRET),
    &SeedClientOpts {
      grants: &["authorization_code"],
      scope: "read",
      method: TokenEndpointAuthMethod::ClientSecretBasic,
      dpop_bound: true,
    },
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  attach_redirect(&world.pool, &world.state.keys, BOUND_ID, REDIRECT_URI).await?;

  let (challenge, verifier) = oauth2_pkce();
  let code = issue_conf_code(&world, BOUND_ID, &challenge).await?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", code.code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", BOUND_ID),
        ("code_verifier", verifier.secret()),
      ],
      Some((BOUND_ID, BOUND_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;

  let code = issue_conf_code(&world, BOUND_ID, &challenge).await?;
  let key = DpopKey::generate()?;
  let proof = key.proof("POST", &format!("{}/token", world.state.config.issuer))?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", code.code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", BOUND_ID),
        ("code_verifier", verifier.secret()),
      ],
      Some((BOUND_ID, BOUND_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("fresh proof must mint: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["token_type"] == "DPoP",
    "the bound redemption must be a DPoP token",
  )?;
  Ok(())
}

/// Baseline client-credentials flow via the `oauth2` crate issues a token.
#[tokio::test]
async fn e2e_grant_client_credentials_oauth2_issues_token() -> Result<(), TestError> {
  let world = setup().await?;
  let client = clients::oauth2_client(&world.base, CLIENT_ID, Some(CLIENT_SECRET))?;
  let token = client
    .exchange_client_credentials()
    .request_async(&world.client)
    .await
    .map_err(|error| fail(format!("client-credentials failed: {error}")))?;
  ensure(
    !token.access_token().secret().is_empty(),
    "client-credentials must return an access token",
  )?;
  Ok(())
}

/// RFC 8707 §2: two repeated `resource` values on a `client_credentials`
/// request are captured from the raw body and accepted; the token response
/// never echoes the audience.
#[tokio::test]
async fn token_accepts_repeated_resource() -> Result<(), TestError> {
  let world = setup_with_resource_indicators(true).await?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "client_credentials"),
        ("resource", RESOURCE_A),
        ("resource", RESOURCE_B),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("two catalog resources must mint: {status} {body}"),
  )?;
  let response = json_body(&body)?;
  ensure(
    response["access_token"]
      .as_str()
      .is_some_and(|value| !value.is_empty()),
    format!("must return an access token: {body}"),
  )?;
  for member in ["resource", "audience", "aud"] {
    ensure(
      response.get(member).is_none(),
      format!("the token response must not echo {member}: {body}"),
    )?;
  }
  // The minted token really carries the audience: the stored access record
  // pins the sorted catalog set.
  let raw = response["access_token"]
    .as_str()
    .ok_or_else(|| fail(format!("must return an access token: {body}")))?;
  let mut conn = world.state.redis.clone();
  let found = world
    .service
    .find_access(&mut conn, &world.store, raw)
    .await
    .map_err(|error| fail(format!("access record lookup failed: {error}")))?
    .ok_or_else(|| fail(format!("minted access token not found: {body}")))?;
  ensure(
    found.record.aud == [RESOURCE_A.to_owned(), RESOURCE_B.to_owned()],
    format!("access record audience not pinned: {:?}", found.record.aud),
  )?;
  Ok(())
}

/// RFC 8707 §2 fail-closed rules: a resource outside the enabled catalog, a
/// non-`https` resource, and any resource while the gate is off are all
/// `invalid_target` 400 with nothing minted.
#[tokio::test]
async fn token_rejects_unpinned_resource() -> Result<(), TestError> {
  let enabled = setup_with_resource_indicators(true).await?;
  for resource in [
    "https://unknown.example.test/api",
    "http://rs-a.example.test/api",
  ] {
    let (status, _, body) = enabled
      .post_form(
        "/token",
        &[("grant_type", "client_credentials"), ("resource", resource)],
        Some((CLIENT_ID, CLIENT_SECRET)),
        &[],
      )
      .await?;
    ensure_error(status, &body, "invalid_target")?;
  }

  let disabled = setup_with_resource_indicators(false).await?;
  let (status, _, body) = disabled
    .post_form(
      "/token",
      &[
        ("grant_type", "client_credentials"),
        ("resource", RESOURCE_A),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_target")
}

/// Token exchange keeps its RFC 8693 semantics: a `resource` member is
/// `invalid_request` before any catalog lookup (so a bogus value can never
/// surface `invalid_target`), while the resource-free request reaches the
/// existing exchange gate unchanged.
#[tokio::test]
async fn exchange_rejects_resource() -> Result<(), TestError> {
  let world = setup_with_resource_indicators(true).await?;
  for resource in [RESOURCE_A, "https://unknown.example.test/api"] {
    let (status, _, body) = world
      .post_form(
        "/token",
        &[
          (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
          ),
          ("subject_token", "opaque-subject"),
          ("resource", resource),
        ],
        Some((CLIENT_ID, CLIENT_SECRET)),
        &[],
      )
      .await?;
    ensure_error(status, &body, "invalid_request")?;
    ensure(
      json_body(&body)?["error"] != "invalid_target",
      format!("a resource on exchange must never be invalid_target: {body}"),
    )?;
  }

  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        (
          "grant_type",
          "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", "opaque-subject"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")
}

/// Baseline authorization-code + PKCE exchange via the `oauth2` crate
/// redeems a real code issued through [`CodeIssuer`].
#[tokio::test]
async fn e2e_grant_authorization_code_oauth2_issues_token() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, verifier) = oauth2_pkce();
  let issued = {
    let issuer = CodeIssuer::new(&world.state.config.ttl, &world.state.keys)
      .map_err(|error| fail(format!("issuer: {error}")))?;
    let approved = ScopeSet::parse("read").map_err(|error| fail(format!("scope: {error}")))?;
    let entitled =
      ScopeSet::parse("read write").map_err(|error| fail(format!("scope: {error}")))?;
    let mut conn = world.state.redis.clone();
    let request = CodeIssueRequest {
      client_id: CLIENT_ID,
      client_kind: CodeClientKind::Confidential,
      dpop_required: false,
      user_id: "e2e-subject",
      redirect_uri: REDIRECT_URI,
      approved_scope: &approved,
      user_entitled: &entitled,
      code_challenge: &challenge,
      dpop_jkt: None,
      state: None,
      aud: &[],
      issuer: &world.state.config.issuer,
    };
    issuer
      .issue(&mut conn, &world.store, &request)
      .await
      .map_err(|error| fail(format!("code issue failed: {error}")))?
  };
  let client = clients::oauth2_client(&world.base, CLIENT_ID, Some(CLIENT_SECRET))?;
  let token = client
    .exchange_code(oauth2::AuthorizationCode::new(issued.code))
    .set_pkce_verifier(verifier)
    .request_async(&world.client)
    .await
    .map_err(|error| fail(format!("code redemption failed: {error}")))?;
  ensure(
    !token.access_token().secret().is_empty(),
    "code redemption must return an access token",
  )?;
  ensure(
    token.refresh_token().is_some(),
    "code redemption must return a refresh token",
  )?;
  Ok(())
}

/// A stale authorization code via the `oauth2` crate is `invalid_grant`.
#[tokio::test]
async fn e2e_grant_authorization_code_stale_is_invalid_grant() -> Result<(), TestError> {
  let world = setup().await?;
  let client = clients::oauth2_client(&world.base, CLIENT_ID, Some(CLIENT_SECRET))?;
  let (_challenge, verifier) = oauth2_pkce();
  let outcome = client
    .exchange_code(oauth2::AuthorizationCode::new("stale-code".to_owned()))
    .set_pkce_verifier(verifier)
    .request_async(&world.client)
    .await;
  match outcome {
    Err(oauth2::RequestTokenError::ServerResponse(response)) => ensure(
      response.error() == &oauth2::basic::BasicErrorResponseType::InvalidGrant,
      "stale code must be invalid_grant",
    ),
    _ => Err(fail("stale code must be an invalid_grant server response")),
  }
}

/// An unknown `grant_type` — including the OAuth 2.0-only `password` — is
/// rejected as `unsupported_grant_type` without minting.
#[tokio::test]
async fn e2e_unknown_grant_type_rejected() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "password"),
        ("username", "u"),
        ("password", "p"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "unsupported_grant_type")?;
  Ok(())
}

/// Device polling of an unknown code is `expired_token`; a disabled token
/// exchange is `invalid_grant`.
#[tokio::test]
async fn e2e_grant_device_code_and_token_exchange_fail_closed() -> Result<(), TestError> {
  let world = setup().await?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", "pending-device-code"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "expired_token")?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        (
          "grant_type",
          "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", "opaque-subject"),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_error(status, &body, "invalid_grant")?;
  Ok(())
}

/// The authorize endpoint verifies a presented DPoP proof and stashes its
/// `jkt` in the pending-auth record the code issuance binds.
#[tokio::test]
async fn e2e_authorize_captures_dpop_jkt() -> Result<(), TestError> {
  let world = setup().await?;
  let (challenge, _verifier) = oauth2_pkce();
  let key = DpopKey::generate()?;
  let htu = format!("{}/authorize", world.state.config.issuer);
  let proof = key.proof("GET", &htu)?;
  let (status, headers, body) = world
    .get(
      &format!(
        "/authorize?client_id={PUBLIC_ID}&redirect_uri={}&response_type=code&scope=read\
         &code_challenge={challenge}&code_challenge_method=S256",
        encoded(REDIRECT_URI)
      ),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SEE_OTHER,
    format!("authorize with DPoP must 303: {status} {body}"),
  )?;
  let location = location_of(&headers)?;
  let request_id = location
    .split("request_id=")
    .nth(1)
    .ok_or_else(|| fail("authorize redirect must carry request_id"))?;
  let mut conn = world.state.redis.clone();
  let record = d_oauth::store::pending::get(&mut conn, &world.store, request_id)
    .await
    .map_err(|error| fail(format!("pending read failed: {error}")))?
    .ok_or_else(|| fail("pending record must exist"))?;
  let expected =
    d_oauth::jose::jwk::thumbprint(&key.jwk()).map_err(|error| fail(format!("jwk: {error}")))?;
  ensure(
    record.client_id == PUBLIC_ID,
    "pending record must bind the client",
  )?;
  ensure(
    record.dpop_jkt.as_deref() == Some(expected.as_str()),
    "pending record must carry the verified DPoP thumbprint",
  )?;
  Ok(())
}

/// PKCE pair from the `oauth2` crate (baseline-flow material only).
fn oauth2_pkce() -> (String, oauth2::PkceCodeVerifier) {
  let (challenge, verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
  (challenge.as_str().to_owned(), verifier)
}

/// Issue a fresh confidential authorization code with no DPoP binding.
async fn issue_conf_code(
  world: &World,
  client_id: &str,
  challenge: &str,
) -> Result<IssuedCode, TestError> {
  let issuer = CodeIssuer::new(&world.state.config.ttl, &world.state.keys)
    .map_err(|error| fail(format!("issuer: {error}")))?;
  let approved = ScopeSet::parse("read").map_err(|error| fail(format!("scope: {error}")))?;
  let mut conn = world.state.redis.clone();
  let request = CodeIssueRequest {
    client_id,
    client_kind: CodeClientKind::Confidential,
    dpop_required: false,
    user_id: "e2e-subject",
    redirect_uri: REDIRECT_URI,
    approved_scope: &approved,
    user_entitled: &approved,
    code_challenge: challenge,
    dpop_jkt: None,
    state: None,
    aud: &[],
    issuer: &world.state.config.issuer,
  };
  issuer
    .issue(&mut conn, &world.store, &request)
    .await
    .map_err(|error| fail(format!("code issue failed: {error}")))
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

/// 32-byte ASCII JWT signing key, mirroring the config-test fixture material.
const JWT_TEST_KEY: &str = "bcdefghijklmnopqrstuvwxyzabcdefg";

/// One world with the global JWT switch pinned and the confidential fixture
/// client seeded. The client's stored `access_token_format` stays at the
/// column default (`opaque`) so each test opts in explicitly.
async fn setup_with_jwt_flag(enabled: bool) -> Result<World, TestError> {
  let overrides = if enabled {
    serde_json::json!({
      "jwt_access_tokens_enabled": true,
      "jwt_signing_key": JWT_TEST_KEY,
      "resource_indicators_enabled": true,
    })
  } else {
    serde_json::json!({})
  };
  let world = World::start_with(open_rate_limit(), overrides).await?;
  if enabled {
    for resource in [RESOURCE_A, RESOURCE_B] {
      resource_repo::upsert(&world.pool, resource, "e2e resource server")
        .await
        .map_err(|error| fail(format!("resource upsert failed: {error}")))?;
    }
  }
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
  Ok(world)
}

/// Assert a response is the fail-closed 503 for JWT access tokens and mints
/// nothing (never the 500 `server_error`).
fn ensure_temporarily_unavailable(
  status: reqwest::StatusCode,
  body: &str,
) -> Result<(), TestError> {
  ensure(
    status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
    format!("jwt client with the global switch off must be 503, got {status}: {body}"),
  )?;
  ensure(
    status != reqwest::StatusCode::INTERNAL_SERVER_ERROR,
    "the gate must never surface server_error/500",
  )?;
  let value = json_body(body)?;
  ensure(
    value["error"] == "temporarily_unavailable",
    format!("failure must be temporarily_unavailable, got {value}"),
  )?;
  ensure(
    value.get("access_token").is_none(),
    "a failed format gate must mint nothing",
  )?;
  Ok(())
}

/// An opaque client never enters the JWT stack: with the global switch off
/// and on (with a fully valid signing key configured) `client_credentials`
/// still mints the same opaque, dot-free token.
#[tokio::test]
async fn opaque_default_ignores_jwt_stack() -> Result<(), TestError> {
  for jwt_enabled in [false, true] {
    let world = setup_with_jwt_flag(jwt_enabled).await?;
    let (status, _, body) = world
      .post_form(
        "/token",
        &[("grant_type", "client_credentials")],
        Some((CLIENT_ID, CLIENT_SECRET)),
        &[],
      )
      .await?;
    ensure(
      status == reqwest::StatusCode::OK,
      format!("flag={jwt_enabled}: an opaque client must mint: {status} {body}"),
    )?;
    let value = json_body(&body)?;
    let token = value["access_token"]
      .as_str()
      .ok_or_else(|| fail("success body lacks access_token"))?;
    ensure(
      !token.is_empty()
        && !token.contains('.')
        && token
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
      "opaque tokens are base64url without a JOSE segment separator",
    )?;
    ensure(
      value["token_type"] == "Bearer",
      "the opaque response shape is unchanged",
    )?;
  }
  Ok(())
}

/// A client switched to `jwt` while the global kill-switch is off fails
/// closed with `temporarily_unavailable` (HTTP 503, never 500) and mints
/// nothing; both dispatcher-authenticated and internally authenticated grants
/// observe the same gate.
#[tokio::test]
async fn jwt_client_flag_off_is_503() -> Result<(), TestError> {
  let world = setup_with_jwt_flag(false).await?;
  ensure(
    client_repo::set_access_token_format(&world.pool, CLIENT_ID, "jwt").await?,
    "the fixture client must switch to jwt",
  )?;

  let (status, _, body) = world
    .post_form(
      "/token",
      &[("grant_type", "client_credentials")],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_temporarily_unavailable(status, &body)?;

  // `authorization_code` authenticates inside the grant module; the
  // dispatcher resolves the candidate client id and applies the same gate.
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "authorization_code"),
        ("code", "stale-code"),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure_temporarily_unavailable(status, &body)?;
  Ok(())
}

/// The positive branch: `jwt` + the global switch on + a valid signing key
/// passes the format gate instead of 503 and mints a real JWT bound to the
/// requested `resource` (a JWT without a resource audience is
/// `invalid_target`).
#[tokio::test]
async fn jwt_client_with_flag_on_resolves_jwt() -> Result<(), TestError> {
  let world = setup_with_jwt_flag(true).await?;
  ensure(
    client_repo::set_access_token_format(&world.pool, CLIENT_ID, "jwt").await?,
    "the fixture client must switch to jwt",
  )?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", "client_credentials"),
        ("resource", RESOURCE_A),
      ],
      Some((CLIENT_ID, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status != reqwest::StatusCode::SERVICE_UNAVAILABLE,
    format!("jwt with the switch on must pass the gate, got 503: {body}"),
  )?;
  ensure(
    status == reqwest::StatusCode::OK,
    format!("the gate's positive branch must reach minting: {status} {body}"),
  )?;
  let token = json_body(&body)?["access_token"]
    .as_str()
    .map(str::to_owned)
    .ok_or_else(|| fail("the positive branch mints a token"))?;
  ensure(
    token.split('.').count() == 3,
    "the positive branch mints a JWT",
  )?;
  Ok(())
}

/// Token exchange never mints a JWT: a `jwt`-format caller fails closed with
/// `temporarily_unavailable` (503) and no token, even with the global switch
/// on and a valid signing key configured.
#[tokio::test]
async fn jwt_exchange_format_rejected() -> Result<(), TestError> {
  const EXCHANGE_CLIENT: &str = "e2e-exchange-jwt-client";
  let world = setup_with_jwt_flag(true).await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    EXCHANGE_CLIENT,
    Some(CLIENT_SECRET),
    &["urn:ietf:params:oauth:grant-type:token-exchange"],
    "read write",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  ensure(
    client_repo::set_access_token_format(&world.pool, EXCHANGE_CLIENT, "jwt").await?,
    "the fixture client must switch to jwt",
  )?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[(
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
      )],
      Some((EXCHANGE_CLIENT, CLIENT_SECRET)),
      &[],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
    format!("a jwt exchange caller must be 503, got {status}: {body}"),
  )?;
  let value = json_body(&body)?;
  ensure(
    value["error"] == "temporarily_unavailable",
    format!("failure must be temporarily_unavailable, got {value}"),
  )?;
  ensure(
    value.get("access_token").is_none(),
    "a rejected exchange must mint nothing",
  )?;
  Ok(())
}

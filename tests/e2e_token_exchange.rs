//! `test(e2e_)` token exchange (RFC 8693) over the live router.
//!
//! Same harness contract as the sibling suites: the REAL production router
//! over a REAL loopback socket against the shared Postgres + Redis, asserting
//! only HTTP behavior. The caller is a DPoP-bound confidential client holding
//! the exchange grant; the subject token is a real user's access token, whose
//! `subject` is the account EMAIL so entitlement resolution can find it.

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

use d_oauth::{
  db::{TokenEndpointAuthMethod, user_repo},
  protocol::token::{ClientKind, grants::token_exchange::exchange_ttl},
};
use dpop::DpopKey;
use harness::{
  SeedClientOpts, TestError, World, ensure, fail, json_body, open_rate_limit, seed_client,
  seed_client_bound, seed_entitled_user, seed_scope,
};

/// Grant-type URN for token exchange (RFC 8693 §2.1).
const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Access-token type URN used for `subject_token_type`/`requested_token_type`.
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// Authenticated caller holding the exchange grant (DPoP-bound).
const CALLER_ID: &str = "e2e-exchange-caller";
/// Caller secret (also the leak probe).
const CALLER_SECRET: &str = "e2e-exchange-secret-1a2b3c4d5e6f708192a0";
/// Subject client that owns the delegated access token.
const SUBJECT_ID: &str = "e2e-exchange-subject";
/// Provisioned user's email: the subject-token `subject` value.
const USER_EMAIL: &str = "exchange-user@example.test";
/// Provisioned user's password (never used for HTTP login here).
const USER_PASSWORD: &str = "e2e-exchange-password-1a2b3c4d";
/// The only scope the allowlist exposes.
const SCOPE: &str = "read";

/// One world with token exchange enabled, the allowlist pair, and the clients.
async fn setup() -> Result<World, TestError> {
  let world = World::start_with(
    open_rate_limit(),
    serde_json::json!({
      "allow_token_exchange": true,
      "token_exchange_allowlist": [
        {"caller": CALLER_ID, "subject": SUBJECT_ID, "scopes": ["read"]},
        {"caller": CALLER_ID, "subject": CALLER_ID, "scopes": ["read"]}
      ],
    }),
  )
  .await?;
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    CALLER_ID,
    Some(CALLER_SECRET),
    &SeedClientOpts {
      grants: &[EXCHANGE_GRANT],
      scope: "read write",
      method: TokenEndpointAuthMethod::ClientSecretBasic,
      dpop_bound: true,
    },
  )
  .await?;
  seed_client(
    &world.pool,
    &world.state.keys,
    SUBJECT_ID,
    None,
    &["authorization_code"],
    "read",
    TokenEndpointAuthMethod::None,
  )
  .await?;
  seed_scope(&world.pool, "read").await?;
  seed_scope(&world.pool, "write").await?;
  Ok(world)
}

/// The subject's unbound access token: user EMAIL as `subject`, `read` scope.
async fn subject_token(world: &World) -> Result<String, TestError> {
  let minted = world
    .mint_for_subject(
      SUBJECT_ID,
      USER_EMAIL,
      "read",
      ClientKind::Confidential,
      None,
    )
    .await?;
  Ok(minted.access_token)
}

/// Send one exchange request with Basic auth and a fresh DPoP proof.
async fn exchange_request(
  world: &World,
  subject_token: &str,
  scope: &str,
) -> Result<(reqwest::StatusCode, String), TestError> {
  let key = DpopKey::generate()?;
  let htu = format!("{}/token", world.state.config.issuer);
  let proof = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", subject_token),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
        ("scope", scope),
      ],
      Some((CALLER_ID, CALLER_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  Ok((status, body))
}

/// Allowlisted exchange mints a DPoP-bound, `act`-bound access token with no
/// refresh token and the shortened exchange TTL.
#[tokio::test]
async fn e2e_token_exchange_allowlisted_mints_act_bound_token() -> Result<(), TestError> {
  let world = setup().await?;
  let (user_id, _totp) = seed_entitled_user(&world, USER_EMAIL, USER_PASSWORD, SCOPE).await?;
  let user = user_repo::find_by_email(&world.pool, &world.state.keys, USER_EMAIL)
    .await?
    .ok_or_else(|| fail("seeded user must resolve by email"))?;
  ensure(
    user.id == user_id,
    "the subject-token email must resolve to the seeded account",
  )?;

  let subject = subject_token(&world).await?;
  let key = DpopKey::generate()?;
  let htu = format!("{}/token", world.state.config.issuer);
  let proof = key.proof("POST", &htu)?;
  let jkt = d_oauth::jose::jwk::thumbprint(&key.jwk())
    .map_err(|error| fail(format!("proof thumbprint: {error}")))?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", subject.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
        ("scope", SCOPE),
      ],
      Some((CALLER_ID, CALLER_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure(
    status.is_success(),
    format!("allowlisted exchange must 200, got {status}: {body}"),
  )?;
  let value = json_body(&body)?;
  ensure(
    value["token_type"] == "DPoP",
    format!("exchange must mint a DPoP token: {value}"),
  )?;
  ensure(
    value["issued_token_type"] == ACCESS_TOKEN_TYPE,
    format!("exchange must report the access-token type: {value}"),
  )?;
  ensure(
    value.get("refresh_token").is_none(),
    "exchange must never issue a refresh token",
  )?;
  let exchanged_ttl = exchange_ttl(&world.service);
  ensure(
    value["expires_in"] == exchanged_ttl.as_secs(),
    format!(
      "exchange must use the shortened TTL {}: {value}",
      exchanged_ttl.as_secs()
    ),
  )?;
  ensure(
    exchanged_ttl < world.state.config.ttl.access,
    format!(
      "the exchange TTL ({exchanged_ttl:?}) must be shorter than the access TTL ({:?})",
      world.state.config.ttl.access
    ),
  )?;
  let access = value["access_token"]
    .as_str()
    .ok_or_else(|| fail("exchange must return an access token"))?;

  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", access)],
      Some((CALLER_ID, CALLER_SECRET)),
      &[],
    )
    .await?;
  ensure(status.is_success(), "introspect must 200")?;
  let introspected = json_body(&body)?;
  ensure(
    introspected["active"] == true,
    format!("exchanged token must be active: {introspected}"),
  )?;
  ensure(
    introspected["act"]["sub"] == SUBJECT_ID,
    format!("act.sub must name the subject-token client: {introspected}"),
  )?;
  ensure(
    introspected["cnf"]["jkt"] == jkt,
    format!("cnf.jkt must carry the proof key thumbprint: {introspected}"),
  )?;
  ensure(
    !body.contains(CALLER_SECRET),
    "introspection must not leak the caller secret",
  )?;
  Ok(())
}

/// A request wider than the allowlist is `invalid_scope` and mints nothing.
#[tokio::test]
async fn e2e_token_exchange_rejects_scope_widening() -> Result<(), TestError> {
  let world = setup().await?;
  seed_entitled_user(&world, USER_EMAIL, USER_PASSWORD, SCOPE).await?;
  let subject = subject_token(&world).await?;
  let (status, body) = exchange_request(&world, &subject, "read write").await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("scope widening must 400, got {status}: {body}"),
  )?;
  let value = json_body(&body)?;
  ensure(
    value["error"] == "invalid_scope",
    format!("scope widening must be invalid_scope: {value}"),
  )?;
  ensure(
    value.get("access_token").is_none(),
    "a rejected exchange must mint nothing",
  )?;
  Ok(())
}

/// An already-`act`-bound token is not exchangeable (no chained exchanges).
#[tokio::test]
async fn e2e_token_exchange_rejects_multi_hop() -> Result<(), TestError> {
  let world = setup().await?;
  seed_entitled_user(&world, USER_EMAIL, USER_PASSWORD, SCOPE).await?;
  let subject = subject_token(&world).await?;
  let key = DpopKey::generate()?;
  let htu = format!("{}/token", world.state.config.issuer);

  let first = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", subject.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
        ("scope", SCOPE),
      ],
      Some((CALLER_ID, CALLER_SECRET)),
      &[("dpop", first.as_str())],
    )
    .await?;
  ensure(
    status.is_success(),
    format!("first exchange must 200, got {status}: {body}"),
  )?;
  let exchanged = json_body(&body)?;
  let act_bound = exchanged["access_token"]
    .as_str()
    .ok_or_else(|| fail("first exchange must return an access token"))?;

  let second = key.proof("POST", &htu)?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", act_bound),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
        ("scope", SCOPE),
      ],
      Some((CALLER_ID, CALLER_SECRET)),
      &[("dpop", second.as_str())],
    )
    .await?;
  ensure(
    status == reqwest::StatusCode::BAD_REQUEST,
    format!("multi-hop exchange must 400, got {status}: {body}"),
  )?;
  let value = json_body(&body)?;
  ensure(
    value["error"] == "invalid_grant",
    format!("multi-hop exchange must be invalid_grant: {value}"),
  )?;
  ensure(
    value.get("access_token").is_none(),
    "a chained exchange must mint nothing",
  )?;
  Ok(())
}

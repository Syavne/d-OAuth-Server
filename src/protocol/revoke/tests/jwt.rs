//! `test(jwt_)` revocation suite: direct `/revoke` of JWT access tokens.
//!
//! The opaque probes (`find_access`/`find_refresh`) miss dotted JWTs by
//! construction, so without the JWT branch every test below collapses to a
//! silent `NoOp` with the marker untouched. Each test pins the allowlist
//! behavior: ownership-scoped deletion of the literal `jwt:<jti-hash>` marker
//! plus the `access:jwt:<jti-hash>` record/member, uniform HTTP 200, and no
//! foreign revocation.

use std::sync::Arc;

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::post,
};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt as _;

use super::{TestError, TestResult, now_unix, service, test_redis, unique};
use crate::{
  config::{DurabilityMode, JwtSigningAlg, JwtSigningKey},
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    NewClient, TokenEndpointAuthMethod, client_repo,
    test_support::migrated_pool,
    user_repo::{self, NewUser},
  },
  jose::jwt_access::{JwtAccessSigner, jti_hash, marker_live, marker_live_strict},
  keys::KeyId,
  protocol::{
    introspect,
    revoke::{OwnedToken, RevokeOutcome, outcome_response, revoke_owned},
    token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService},
  },
  state::{AppState, Clock, RedisConn},
  store::Store,
  test_guard::Lease,
};

/// A fixed 32-byte ASCII signing key (the e2e JWT fixture material).
const JWT_TEST_KEY: &str = "bcdefghijklmnopqrstuvwxyzabcdefg";

/// A foreign 32-byte ASCII signing key: valid shape, unknown `kid`.
const JWT_FOREIGN_KEY: &str = "qcdefghijklmnopqrstuvwxyzabcdefg";

/// Issuer the test signer asserts.
const TEST_ISSUER: &str = "https://jwt-revoke.example.test";

/// A test signer over fixed key material.
fn test_signer() -> Result<JwtAccessSigner, TestError> {
  test_signer_with(JWT_TEST_KEY, "test-kid")
}

/// A test signer over explicit key material and `kid`.
fn test_signer_with(raw: &str, kid: &str) -> Result<JwtAccessSigner, TestError> {
  let key = JwtSigningKey::from_raw(
    KeyId::new(kid),
    JwtSigningAlg::Es256,
    &SecretString::from(raw),
    "jwt_signing_key",
  )
  .map_err(|error| TestError::Unexpected(format!("signing key rejected: {error}")))?;
  Ok(JwtAccessSigner::new(
    TEST_ISSUER.to_owned(),
    key,
    Vec::new(),
  ))
}

/// A service wired with the JWT signer.
fn jwt_service(signer: JwtAccessSigner) -> Result<TokenService, TestError> {
  service().map(|service| service.with_jwt_signer(signer))
}

/// A confidential-client JWT mint request with a fixed subject/scope.
fn jwt_mint_request(client: &str, grant: &str, subject: &str) -> MintRequest {
  MintRequest {
    client_id: client.to_owned(),
    client_kind: ClientKind::Confidential,
    dpop_required: false,
    subject: subject.to_owned(),
    scope: "orders:read".to_owned(),
    grant_id: grant.to_owned(),
    proof: SenderProof::none(),
    aud: Vec::new(),
    refresh_aud: Vec::new(),
    format: TokenFormat::Jwt,
  }
}

/// Mint one JWT for `client` and return the raw token plus its `jti` hash.
async fn mint_jwt(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  signer: &JwtAccessSigner,
  client: &str,
  subject: &str,
) -> Result<(String, String), TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &jwt_mint_request(client, &unique("grant"), subject),
      now_unix(),
    )
    .await?;
  if minted.access_token.split('.').count() != 3 {
    return Err(TestError::Unexpected(
      "a jwt mint must return three JOSE segments".to_owned(),
    ));
  }
  let verified = signer
    .verify(&minted.access_token, None)
    .map_err(|error| TestError::Unexpected(format!("fresh jwt rejected: {error:?}")))?;
  Ok((minted.access_token, jti_hash(&verified.claims.jti)))
}

/// `test(jwt_direct_revoke_deletes_marker)`: the owning client revokes its JWT
/// through the `/revoke` core path — `Revoked` plus HTTP 200, the LITERAL
/// `jwt:<jti-hash>` marker key GONE (not merely the member set), the
/// `access:jwt:<jti-hash>` record gone, and the token no longer live. A second
/// revoke of the same token is still HTTP 200 (`NoOp`).
#[tokio::test]
async fn jwt_direct_revoke_deletes_marker() -> TestResult {
  let (mut conn, store, _prefixes) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let client = unique("jwt-direct-client");
  let (token, hash) = mint_jwt(&mut conn, &store, &service, &signer, &client, "user-1").await?;
  let marker_key = store.jwt_marker_key(&hash);
  let member = format!("jwt:{hash}");

  if !marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the fresh mint must leave a live marker".to_owned(),
    ));
  }

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &token,
      token_type_hint: None,
    },
    Some(&signer),
  )
  .await?;
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(
      "the owning client must revoke its own jwt".to_owned(),
    ));
  }
  if outcome_response(outcome).status() != StatusCode::OK {
    return Err(TestError::Unexpected(
      "a revocation must render 200".to_owned(),
    ));
  }

  let marker_exists: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut conn)
    .await?;
  if marker_exists {
    return Err(TestError::Unexpected(format!(
      "direct revoke must delete the literal marker key {marker_key}"
    )));
  }
  let record_exists: bool = redis::cmd("EXISTS")
    .arg(store.access_key(&member))
    .query_async(&mut conn)
    .await?;
  if record_exists {
    return Err(TestError::Unexpected(
      "direct revoke must delete the access record".to_owned(),
    ));
  }
  let live_after: bool = marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?;
  if live_after {
    return Err(TestError::Unexpected(
      "the marker must read dead after direct revoke".to_owned(),
    ));
  }
  if marker_live_strict(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the membership-bound check must read dead after direct revoke".to_owned(),
    ));
  }

  let second = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &token,
      token_type_hint: None,
    },
    Some(&signer),
  )
  .await?;
  if second != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "a second revoke of the same jwt must be a no-op".to_owned(),
    ));
  }
  if outcome_response(second).status() != StatusCode::OK {
    return Err(TestError::Unexpected(
      "a no-op revoke must still render 200".to_owned(),
    ));
  }
  Ok(())
}

/// A foreign client revoking another client's JWT is a silent `NoOp`: the
/// marker, the record, and the grant-set member all survive untouched.
#[tokio::test]
async fn jwt_foreign_owner_revoke_is_noop_and_marker_intact() -> TestResult {
  let (mut conn, store, _prefixes) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let owner = unique("jwt-owner");
  let attacker = unique("jwt-attacker");
  let (token, hash) = mint_jwt(&mut conn, &store, &service, &signer, &owner, "user-1").await?;
  let marker_key = store.jwt_marker_key(&hash);
  let member = format!("jwt:{hash}");

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &attacker,
      token: &token,
      token_type_hint: None,
    },
    Some(&signer),
  )
  .await?;
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "a foreign jwt revoke must be a no-op".to_owned(),
    ));
  }
  if outcome_response(outcome).status() != StatusCode::OK {
    return Err(TestError::Unexpected(
      "a foreign no-op must still render 200".to_owned(),
    ));
  }
  for key in [&marker_key, &store.access_key(&member)] {
    let present: bool = redis::cmd("EXISTS").arg(key).query_async(&mut conn).await?;
    if !present {
      return Err(TestError::Unexpected(format!(
        "a foreign revoke must never delete {key}"
      )));
    }
  }
  if !marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the owner's marker must stay live after a foreign attempt".to_owned(),
    ));
  }
  Ok(())
}

/// Malformed JWT shapes and foreign-key signatures are silent `NoOp`s: the
/// endpoint never errors and never touches another client's marker.
#[tokio::test]
async fn jwt_malformed_and_foreign_signature_are_noop() -> TestResult {
  let (mut conn, store, _prefixes) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let client = unique("jwt-malformed-client");
  let (token, hash) = mint_jwt(&mut conn, &store, &service, &signer, &client, "user-1").await?;
  let marker_key = store.jwt_marker_key(&hash);

  // A well-formed foreign-key JWT (unknown `kid`): verifies against nobody.
  let foreign_signer = test_signer_with(JWT_FOREIGN_KEY, "foreign-kid")?;
  let foreign_service = jwt_service(foreign_signer.clone())?;
  let (foreign_token, _) = mint_jwt(
    &mut conn,
    &store,
    &foreign_service,
    &foreign_signer,
    &unique("jwt-foreign-client"),
    "user-1",
  )
  .await?;

  for presented in [
    "not-a-jwt",
    "aaa.bbb",
    "aaa.bbb.ccc.ddd",
    ".bb.cc",
    foreign_token.as_str(),
  ] {
    let outcome = revoke_owned(
      &mut conn,
      &store,
      &service,
      &OwnedToken {
        owner_client_id: &client,
        token: presented,
        token_type_hint: None,
      },
      Some(&signer),
    )
    .await?;
    if outcome != RevokeOutcome::NoOp {
      return Err(TestError::Unexpected(format!(
        "a malformed or foreign jwt must be a no-op, saw {outcome:?} for {presented}"
      )));
    }
    if outcome_response(outcome).status() != StatusCode::OK {
      return Err(TestError::Unexpected(
        "a malformed no-op must still render 200".to_owned(),
      ));
    }
  }
  // The owner's real marker survived every foreign attempt; the owner's own
  // well-formed token still verifies.
  let marker_exists: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut conn)
    .await?;
  if !marker_exists {
    return Err(TestError::Unexpected(
      "foreign attempts must never delete the owner's marker".to_owned(),
    ));
  }
  signer
    .verify(&token, None)
    .map_err(|error| TestError::Unexpected(format!("owner jwt rejected: {error:?}")))?;
  Ok(())
}

/// A JWT-shaped token with no signer configured (feature off / no key) is not
/// revocable and stays a silent `NoOp` with the marker untouched.
#[tokio::test]
async fn jwt_revoke_without_signer_is_noop() -> TestResult {
  let (mut conn, store, _prefixes) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let client = unique("jwt-nosigner-client");
  let (token, hash) = mint_jwt(&mut conn, &store, &service, &signer, &client, "user-1").await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &token,
      token_type_hint: None,
    },
    None,
  )
  .await?;
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "a jwt without a signer must be a no-op".to_owned(),
    ));
  }
  if !marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the marker must survive a signer-less attempt".to_owned(),
    ));
  }
  Ok(())
}

/// Live handles for the Postgres-backed JWT tests: a migrated database, the
/// shared Redis plus store, and the validated config.
struct PgHarness {
  _db: Lease<crate::db::test_support::Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  config: Arc<crate::config::Config>,
}

async fn pg_harness() -> Result<PgHarness, TestError> {
  let (db, pool) = migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg harness: {error}")))?;
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(
    state_prefix.clone(),
    ratelimit_prefix.clone(),
    DurabilityMode::WaitAof,
  );
  let redis_url = crate::test_support::test_redis_url();
  let fixture = serde_json::json!({
    "issuer": TEST_ISSUER,
    "environment": "development",
    "tls": {"cert_path": "/tmp/jwt-revoke-test-cert.pem", "key_path": "/tmp/jwt-revoke-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/jwt-revoke"},
    "redis": {
      "url": redis_url,
      "durability": "waitaof",
      "token_key_prefix": state_prefix,
      "ratelimit_key_prefix": ratelimit_prefix,
    },
    "token_pepper": "jwt-revoke-test-pepper-0123456789abcdef",
    "totp_encryption_key": "jwt-revoke-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "jwt-revoke-test-pii-key-0123456789abcdef",
    "jwt_access_tokens_enabled": true,
    "jwt_signing_key": JWT_TEST_KEY,
    "jwt_signing_kid": "test-kid",
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  let config = crate::config::Config::from_source(source)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  Ok(PgHarness {
    _db: db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    config: Arc::new(config),
  })
}

fn app_state(h: &PgHarness) -> AppState {
  AppState {
    pool: h.pool.clone(),
    redis: h.conn.clone(),
    config: Arc::clone(&h.config),
    keys: Arc::new(h.config.keys.clone()),
    transition_unsafe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    clock: Clock::system(),
  }
}

async fn insert_client(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  client_id: &str,
  secret: &str,
) -> TestResult {
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Unexpected(format!("{error:?}")))?;
  let secret_hash = Some(
    hash_secret(secret, &params).map_err(|error| TestError::Unexpected(format!("{error:?}")))?,
  );
  let new = NewClient {
    id: uuid::Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec!["client_credentials".to_owned()],
    response_types: Vec::new(),
    scope: "orders:read".to_owned(),
    token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic
      .as_str()
      .to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, keys, false, &new)
    .await
    .map_err(|error| TestError::Unexpected(format!("insert client: {error}")))?;
  Ok(())
}

fn basic_header(client_id: &str, secret: &str) -> String {
  let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
  format!("Basic {encoded}")
}

/// `test(jwt_revoked_introspects_inactive)`: the HTTP `/introspect` dual path
/// reports a live JWT as `active:true` BEFORE the revoke and
/// `{"active":false}` AFTER it. The AS-side liveness verdict backs both wire
/// assertions: the token verifies and the marker plus membership checks read
/// live before, and both read dead after (Todo 26 cascade semantics, consumed
/// through `marker_live_strict` plus the disabled-subject re-check inside
/// introspection).
#[tokio::test]
async fn jwt_revoked_introspects_inactive() -> TestResult {
  let mut h = pg_harness().await?;
  let signer = test_signer()?;
  let service = TokenService::new(&h.config.ttl, &h.config.keys)
    .map_err(TestError::from)
    .map(|service| service.with_jwt_signer(signer.clone()))?;
  let client_id = unique("jwt-introspect-client");
  insert_client(&h.pool, &h.config.keys, &client_id, "secret-jri").await?;
  let grant = unique("jwt-introspect-grant");
  let minted = service
    .mint(
      &mut h.conn,
      &h.store,
      &jwt_mint_request(&client_id, &grant, "user-1"),
      now_unix(),
    )
    .await?;
  let verified = signer
    .verify(&minted.access_token, None)
    .map_err(|error| TestError::Unexpected(format!("fresh jwt rejected: {error:?}")))?;
  let hash = jti_hash(&verified.claims.jti);

  // BEFORE: the token verifies and the allowlist binds marker plus membership.
  if !marker_live_strict(&mut h.conn, &h.store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the fresh mint must be strictly live".to_owned(),
    ));
  }

  // BEFORE: the dual-path HTTP endpoint reports the live JWT active, with
  // the caller binding and no leaked claims.
  if !http_introspect_active(&h, &client_id, "secret-jri", &minted.access_token).await? {
    return Err(TestError::Unexpected(
      "a live jwt must introspect active:true".to_owned(),
    ));
  }

  let outcome = revoke_owned(
    &mut h.conn,
    &h.store,
    &service,
    &OwnedToken {
      owner_client_id: &client_id,
      token: &minted.access_token,
      token_type_hint: None,
    },
    Some(&signer),
  )
  .await?;
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(
      "the owning client must revoke its own jwt".to_owned(),
    ));
  }

  // AFTER: the AS-side liveness verdict is inactive on both checks.
  if marker_live(&mut h.conn, &h.store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the marker must read dead after revoke".to_owned(),
    ));
  }
  if marker_live_strict(&mut h.conn, &h.store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the membership-bound check must read dead after revoke".to_owned(),
    ));
  }

  // AFTER: the wire response users observe is HTTP 200 with `active: false`.
  if http_introspect_active(&h, &client_id, "secret-jri", &minted.access_token).await? {
    return Err(TestError::Unexpected(
      "a revoked jwt must introspect inactive".to_owned(),
    ));
  }
  Ok(())
}

/// Drive the real `/introspect` HTTP handler and report the `active` bit.
///
/// The handler builds its JWT signer from the harness config (flag on, key
/// with the test `kid`), so this exercises the production dual path, not a
/// hand-rolled verifier.
async fn http_introspect_active(
  h: &PgHarness,
  client_id: &str,
  secret: &str,
  token: &str,
) -> Result<bool, TestError> {
  let app = Router::new()
    .route("/introspect", post(introspect::handler))
    .with_state(app_state(h));
  let body = format!("token={token}&token_type_hint=access_token");
  let request = Request::post("/introspect")
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    .header(header::AUTHORIZATION, basic_header(client_id, secret))
    .body(Body::from(body))
    .map_err(|error| TestError::Unexpected(format!("request build failed: {error}")))?;
  let response = app
    .oneshot(request)
    .await
    .map_err(|error| TestError::Unexpected(format!("router failed: {error}")))?;
  if response.status() != StatusCode::OK {
    return Err(TestError::Unexpected(format!(
      "introspect must render 200, got {}",
      response.status()
    )));
  }
  let bytes = response
    .into_body()
    .collect()
    .await
    .map_err(TestError::from)?
    .to_bytes();
  let json: Value = serde_json::from_slice(&bytes).map_err(TestError::from)?;
  json
    .get("active")
    .and_then(Value::as_bool)
    .ok_or_else(|| TestError::Unexpected(format!("introspect lacks active, saw {json}")))
}

/// `test(jwt_disabled_subject_inactive)`: a JWT minted for a real subject
/// reports `SubjectDisabled` from `verify_live` once the account is disabled —
/// marker presence alone never keeps a disabled subject's token alive.
#[tokio::test]
async fn jwt_disabled_subject_inactive() -> TestResult {
  let mut h = pg_harness().await?;
  let signer = test_signer()?;
  let service = TokenService::new(&h.config.ttl, &h.config.keys)
    .map_err(TestError::from)
    .map(|service| service.with_jwt_signer(signer.clone()))?;
  let client_id = unique("jwt-disabled-client");
  insert_client(&h.pool, &h.config.keys, &client_id, "secret-jrd").await?;

  let email = format!("{}@example.test", unique("jwt-disabled-user"));
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Unexpected(format!("{error:?}")))?;
  let record = user_repo::create_user(
    &h.pool,
    &h.config.keys,
    false,
    &NewUser {
      email: email.clone(),
      password_hash: hash_secret("correct-horse-01", &params)
        .map_err(|error| TestError::Unexpected(format!("{error:?}")))?,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("create user: {error}")))?;

  let grant = unique("jwt-disabled-grant");
  let minted = service
    .mint(
      &mut h.conn,
      &h.store,
      &jwt_mint_request(&client_id, &grant, &email),
      now_unix(),
    )
    .await?;

  // BEFORE: marker plus account both live.
  signer
    .verify_live(
      &mut h.conn,
      &h.store,
      &h.pool,
      &h.config.keys,
      &minted.access_token,
      None,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("fresh jwt must verify live: {error:?}")))?;

  if !user_repo::disable_user(&h.pool, record.id)
    .await
    .map_err(|error| TestError::Unexpected(format!("disable user: {error}")))?
  {
    return Err(TestError::Unexpected(
      "disable_user updated no rows".to_owned(),
    ));
  }

  match signer
    .verify_live(
      &mut h.conn,
      &h.store,
      &h.pool,
      &h.config.keys,
      &minted.access_token,
      None,
    )
    .await
  {
    Err(crate::jose::jwt_access::JwtError::SubjectDisabled) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "a disabled subject must report SubjectDisabled, got {other:?}"
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "a disabled subject's jwt must not verify live".to_owned(),
    )),
  }
}

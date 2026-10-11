//! `test(introspect)` suite: active shape, inactive misses, 401, ownership.
//!
//! Each test runs against a real Redis container plus a migrated Postgres
//! database on the shared test server, through the public [`super`] API and a
//! one-route router for the HTTP status assertions.

use std::{
  sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
  },
  time::Duration,
};

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::post,
};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

use super::{
  IntrospectContext, IntrospectHttpInputs, IntrospectStores, IntrospectionResponse, handler,
  introspect, record_act,
};
use crate::{
  config::Config,
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    NewClient, TokenEndpointAuthMethod, client_repo,
    test_support::migrated_pool,
    user_repo::{self, NewUser, UserRecord},
  },
  protocol::{
    client_auth::ClientAuthRequest,
    revoke::{RevokeContext, RevokeOutcome, RevokeRequest, RevokeStores, revoke_tokens},
    token::{ClientKind, MintRequest, SenderProof, TokenService},
  },
  state::{AppState, Clock, RedisConn},
  store::Store,
  test_guard::{ContainerGuard, Lease},
};

/// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

static NONCE: AtomicU64 = AtomicU64::new(1);

fn unique(label: &str) -> String {
  let n = NONCE.fetch_add(1, Ordering::Relaxed);
  format!("introspect-test-{n}-{label}")
}

fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// Live handles for one test: migrated Postgres, Redis, store, and config.
struct Harness {
  _db: Lease<crate::db::test_support::Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  config: Arc<Config>,
}

async fn harness() -> TestResult<(ContainerGuard, Harness)> {
  let (db, pool) = migrated_pool().await?;
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let redis_url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(redis_url.as_str())?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    crate::config::DurabilityMode::WaitAof,
  );
  let fixture = json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/introspect-test-cert.pem", "key_path": "/tmp/introspect-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/introspect"},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "introspect-test-pepper-0123456789abcdef",
    "totp_encryption_key": "introspect-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "introspect-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  let config = Config::from_source(source)?;
  Ok((
    guarded,
    Harness {
      _db: db,
      pool,
      conn: RedisConn::Single(manager),
      store,
      config: Arc::new(config),
    },
  ))
}

async fn insert_client(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
) -> TestResult {
  let params = Argon2Params::new(8, 1, 1, 32).map_err(|error| format!("{error:?}"))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec!["client_credentials".to_owned()],
    response_types: Vec::new(),
    scope: "orders:read".to_owned(),
    token_endpoint_auth_method: method.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, keys, false, &new).await?;
  Ok(())
}

fn token_service(h: &Harness) -> TestResult<TokenService> {
  Ok(TokenService::new(&h.config.ttl, &h.config.keys)?)
}

/// Mint one token pair owned by `client_id` with an explicit sender proof.
async fn mint_bound(
  h: &mut Harness,
  client_id: &str,
  proof: SenderProof,
) -> TestResult<crate::protocol::token::MintedTokens> {
  let service = token_service(h)?;
  Ok(
    service
      .mint(
        &mut h.conn,
        &h.store,
        &MintRequest {
          client_id: client_id.to_owned(),
          client_kind: ClientKind::Confidential,
          subject: "user-1".to_owned(),
          scope: "orders:read".to_owned(),
          grant_id: unique("grant"),
          proof,
        },
        now_unix(),
      )
      .await?,
  )
}

/// Mint one sender-constrained access token owned by `client_id`.
async fn mint_constrained(
  h: &mut Harness,
  client_id: &str,
) -> TestResult<crate::protocol::token::MintedTokens> {
  mint_bound(
    h,
    client_id,
    SenderProof {
      dpop_jkt: Some("jkt-thumbnail".to_owned()),
      mtls_x5t_s256: Some("x5t-thumbnail".to_owned()),
    },
  )
  .await
}

/// Drive the core with `client_secret_post` credentials.
async fn run_core(
  h: &mut Harness,
  token: &str,
  hint: Option<&str>,
  client_id: &str,
  secret: &str,
) -> TestResult<IntrospectionResponse> {
  let service = token_service(h)?;
  let mut stores = IntrospectStores {
    pool: &h.pool,
    keys: &h.config.keys,
    conn: &mut h.conn,
    store: &h.store,
  };
  let ctx = IntrospectContext {
    issuer: &h.config.issuer,
    now_unix: now_unix(),
    service: &service,
  };
  let inputs = IntrospectHttpInputs {
    token,
    token_type_hint: hint,
    client_id: Some(client_id),
    basic_header: None,
    body_secret: Some(SecretString::from(secret)),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  Ok(introspect(&mut stores, &ctx, &inputs).await?)
}

fn app_state(h: &Harness) -> AppState {
  AppState {
    pool: h.pool.clone(),
    redis: h.conn.clone(),
    config: Arc::clone(&h.config),
    keys: Arc::new(h.config.keys.clone()),
    transition_unsafe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    clock: Clock::system(),
  }
}

fn basic_header(client_id: &str, secret: &str) -> String {
  let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
  format!("Basic {encoded}")
}

async fn post_form_bytes(
  app: Router,
  auth: Option<&str>,
  body: &str,
) -> TestResult<(StatusCode, Vec<u8>)> {
  let mut builder = Request::builder()
    .method("POST")
    .uri("/introspect")
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
  if let Some(value) = auth {
    builder = builder.header(header::AUTHORIZATION, value);
  }
  let request = builder.body(Body::from(body.to_owned()))?;
  let response = app.oneshot(request).await?;
  let status = response.status();
  let bytes = response.into_body().collect().await?.to_bytes();
  Ok((status, bytes.to_vec()))
}

async fn post_form(app: Router, auth: Option<&str>, body: &str) -> TestResult<(StatusCode, Value)> {
  let (status, bytes) = post_form_bytes(app, auth, body).await?;
  Ok((status, serde_json::from_slice(&bytes)?))
}

fn router(h: &Harness) -> Router {
  Router::new()
    .route("/introspect", post(handler))
    .with_state(app_state(h))
}

#[tokio::test]
async fn test_introspect_active_access_token_reports_shape() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("owner");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-a"),
  )
  .await?;

  let minted = mint_constrained(&mut h, &client_id).await?;
  record_act(
    &mut h.conn,
    &h.store,
    &minted.access_hash,
    &json!({"sub": "actor-1"}),
    h.config.ttl.access,
  )
  .await?;

  let before = now_unix();
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-a",
  )
  .await?;

  assert!(response.active, "minted token must be active");
  assert_eq!(response.scope.as_deref(), Some("orders:read"));
  assert_eq!(response.client_id.as_deref(), Some(client_id.as_str()));
  assert_eq!(response.token_type.as_deref(), Some("Bearer"));
  assert_eq!(response.sub.as_deref(), Some("user-1"));
  let cnf = response.cnf.as_ref().ok_or("cnf missing")?;
  assert_eq!(cnf.jkt.as_deref(), Some("jkt-thumbnail"));
  assert_eq!(cnf.x5t_s256.as_deref(), Some("x5t-thumbnail"));
  assert_eq!(response.act, Some(json!({"sub": "actor-1"})));

  let iat = response.iat.ok_or("iat missing")?;
  let exp = response.exp.ok_or("exp missing")?;
  assert!(iat < exp, "iat must precede exp");
  assert!(exp > before, "exp must be in the future");
  let ttl = i64::try_from(h.config.ttl.access.as_secs())?;
  assert_eq!(exp - iat, ttl, "window must equal the access TTL");
  Ok(())
}

#[tokio::test]
async fn test_introspect_unknown_token_is_inactive_200() -> TestResult {
  let (_container, h) = harness().await?;
  let client_id = unique("unknown");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("secret-u"),
  )
  .await?;

  let auth = basic_header(&client_id, "secret-u");
  let (status, body) = post_form(
    router(&h),
    Some(&auth),
    "token=not-a-real-token&token_type_hint=access_token",
  )
  .await?;

  assert_eq!(status, StatusCode::OK, "unknown token must not 4xx");
  assert_eq!(body, json!({"active": false}), "no claims may leak");
  Ok(())
}

#[tokio::test]
async fn test_introspect_unauthenticated_is_401() -> TestResult {
  let (_container, h) = harness().await?;
  let (status, body) = post_form(router(&h), None, "token=whatever").await?;

  assert_eq!(status, StatusCode::UNAUTHORIZED);
  assert_eq!(
    body.get("error").and_then(Value::as_str),
    Some("invalid_client")
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_foreign_client_token_is_inactive_200() -> TestResult {
  let (_container, mut h) = harness().await?;
  let owner = unique("owner");
  insert_client(
    &h.pool,
    &h.config.keys,
    &owner,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("owner-secret"),
  )
  .await?;
  let foreign = unique("foreign");
  insert_client(
    &h.pool,
    &h.config.keys,
    &foreign,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("foreign-secret"),
  )
  .await?;

  let minted = mint_constrained(&mut h, &owner).await?;
  let auth = basic_header(&foreign, "foreign-secret");
  let (status, body) = post_form(
    router(&h),
    Some(&auth),
    &format!("token={}", minted.access_token),
  )
  .await?;

  assert_eq!(status, StatusCode::OK);
  assert_ne!(status, StatusCode::FORBIDDEN, "existence must not leak");
  assert_eq!(body, json!({"active": false}));
  Ok(())
}

#[tokio::test]
async fn test_introspect_revoked_token_is_inactive() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("revoked");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-r"),
  )
  .await?;

  let minted = mint_constrained(&mut h, &client_id).await?;
  let service = token_service(&h)?;
  let revoked = service
    .revoke_token(&mut h.conn, &h.store, &minted.access_token)
    .await?;
  assert!(revoked, "revoke must delete a live token");

  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-r",
  )
  .await?;
  assert!(!response.active, "revoked token must be inactive");
  assert_eq!(response, IntrospectionResponse::inactive());
  Ok(())
}

#[tokio::test]
async fn test_introspect_missing_token_form_is_400_invalid_request() -> TestResult {
  let (_container, h) = harness().await?;
  let client_id = unique("missing-token");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("secret-mt"),
  )
  .await?;

  let auth = basic_header(&client_id, "secret-mt");
  let (status, bytes) = post_form_bytes(
    router(&h),
    Some(&auth),
    "token_type_hint=access_token&client_secret=secret-mt",
  )
  .await?;

  // RFC 7662 §2.1: `token` is REQUIRED; §2.3: a malformed request is
  // `invalid_request` (HTTP 400), never a silent inactive 200.
  assert_eq!(
    status,
    StatusCode::BAD_REQUEST,
    "a missing token parameter must be invalid_request 400"
  );
  let body: Value = serde_json::from_slice(&bytes)?;
  assert_eq!(
    body.get("error").and_then(Value::as_str),
    Some("invalid_request")
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_empty_token_is_400_invalid_request() -> TestResult {
  let (_container, h) = harness().await?;
  let client_id = unique("empty-token");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("secret-et"),
  )
  .await?;

  let auth = basic_header(&client_id, "secret-et");
  let (status, bytes) = post_form_bytes(
    router(&h),
    Some(&auth),
    "token=&token_type_hint=access_token",
  )
  .await?;

  // RFC 7662 §2.1: an empty `token` is no token at all, so §2.3's
  // `invalid_request` applies rather than the inactive response.
  assert_eq!(
    status,
    StatusCode::BAD_REQUEST,
    "an empty token must be invalid_request 400"
  );
  let body: Value = serde_json::from_slice(&bytes)?;
  assert_eq!(
    body.get("error").and_then(Value::as_str),
    Some("invalid_request")
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_refresh_token_reports_active_shape() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("refresh-shape");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-rs"),
  )
  .await?;

  let minted = mint_bound(&mut h, &client_id, SenderProof::none()).await?;
  let before = now_unix();
  let response = run_core(
    &mut h,
    &minted.refresh_token,
    Some("refresh_token"),
    &client_id,
    "secret-rs",
  )
  .await?;

  assert!(response.active, "a live refresh token must be active");
  assert_eq!(response.scope.as_deref(), Some("orders:read"));
  assert_eq!(response.client_id.as_deref(), Some(client_id.as_str()));
  assert_eq!(response.sub.as_deref(), Some("user-1"));
  // RFC 7662 §2.2: `token_type` is OPTIONAL; RFC 6749 §5.1 defines a token
  // type only for access tokens, so a refresh token reports none.
  assert_eq!(response.token_type, None);
  assert_eq!(response.cnf, None, "an unbound token has no confirmation");
  let iat = response.iat.ok_or("iat missing")?;
  let exp = response.exp.ok_or("exp missing")?;
  assert!(iat < exp, "iat must precede exp");
  assert!(exp > before, "exp must be in the future");
  let ttl = i64::try_from(h.config.ttl.refresh.as_secs())?;
  assert_eq!(exp - iat, ttl, "window must equal the refresh TTL");
  Ok(())
}

#[tokio::test]
async fn test_introspect_dpop_bound_token_reports_jkt_only() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("dpop-bound");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-dp"),
  )
  .await?;

  let minted = mint_bound(
    &mut h,
    &client_id,
    SenderProof {
      dpop_jkt: Some("jkt-dpop-only".to_owned()),
      mtls_x5t_s256: None,
    },
  )
  .await?;
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-dp",
  )
  .await?;

  // RFC 9449 §5/§6: a DPoP-bound token confirms the key with `cnf.jkt`.
  let cnf = response.cnf.as_ref().ok_or("cnf missing")?;
  assert_eq!(cnf.jkt.as_deref(), Some("jkt-dpop-only"));
  assert_eq!(cnf.x5t_s256, None, "no mTLS binding was proven");
  let json = serde_json::to_value(&response)?;
  let cnf_json = json
    .get("cnf")
    .and_then(Value::as_object)
    .ok_or("cnf member missing")?;
  assert_eq!(
    cnf_json.get("jkt").and_then(Value::as_str),
    Some("jkt-dpop-only")
  );
  assert!(
    !cnf_json.contains_key("x5t#S256"),
    "the mTLS thumbprint must not leak into a DPoP-only response"
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_mtls_bound_token_reports_x5t_only() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("mtls-bound");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-mtls"),
  )
  .await?;

  let minted = mint_bound(
    &mut h,
    &client_id,
    SenderProof {
      dpop_jkt: None,
      mtls_x5t_s256: Some("x5t-mtls-only".to_owned()),
    },
  )
  .await?;
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-mtls",
  )
  .await?;

  // RFC 8705 §3.1: an mTLS-bound token confirms the certificate with
  // `cnf."x5t#S256"`.
  let cnf = response.cnf.as_ref().ok_or("cnf missing")?;
  assert_eq!(cnf.x5t_s256.as_deref(), Some("x5t-mtls-only"));
  assert_eq!(cnf.jkt, None, "no DPoP binding was proven");
  let json = serde_json::to_value(&response)?;
  let cnf_json = json
    .get("cnf")
    .and_then(Value::as_object)
    .ok_or("cnf member missing")?;
  assert_eq!(
    cnf_json.get("x5t#S256").and_then(Value::as_str),
    Some("x5t-mtls-only")
  );
  assert!(
    !cnf_json.contains_key("jkt"),
    "the DPoP thumbprint must not leak into an mTLS-only response"
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_unknown_hint_is_advisory() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("unknown-hint");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-uh"),
  )
  .await?;

  let minted = mint_bound(&mut h, &client_id, SenderProof::none()).await?;
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("password"),
    &client_id,
    "secret-uh",
  )
  .await?;

  // RFC 7662 §2.1: an unknown `token_type_hint` is advisory only; the server
  // must not reject the request and must still resolve the token.
  assert!(
    response.active,
    "an unknown hint must not inactivate the token"
  );
  assert_eq!(response.token_type.as_deref(), Some("Bearer"));
  assert_eq!(response.client_id.as_deref(), Some(client_id.as_str()));
  Ok(())
}

#[tokio::test]
async fn test_introspect_wrong_hint_still_resolves_refresh() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("wrong-hint");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-wh"),
  )
  .await?;

  let minted = mint_bound(&mut h, &client_id, SenderProof::none()).await?;
  let response = run_core(
    &mut h,
    &minted.refresh_token,
    Some("access_token"),
    &client_id,
    "secret-wh",
  )
  .await?;

  // RFC 7662 §2.1: a hint that misses must fall back to the other token type,
  // so the refresh token is still found and reported active.
  assert!(response.active, "the hint must not hide the refresh token");
  assert_eq!(response.token_type, None);
  assert_eq!(response.scope.as_deref(), Some("orders:read"));
  Ok(())
}

#[tokio::test]
async fn test_introspect_active_response_leaks_no_token_or_secret() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("no-leak");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("leak-secret"),
  )
  .await?;

  let minted = mint_bound(&mut h, &client_id, SenderProof::none()).await?;
  let auth = basic_header(&client_id, "leak-secret");
  let (status, bytes) = post_form_bytes(
    router(&h),
    Some(&auth),
    &format!("token={}", minted.access_token),
  )
  .await?;

  assert_eq!(status, StatusCode::OK);
  let raw = String::from_utf8(bytes)?;
  assert!(
    raw.contains("\"active\":true"),
    "expected an active response"
  );
  assert!(
    !raw.contains(&minted.access_token),
    "the presented token must never be echoed"
  );
  assert!(
    !raw.contains(&minted.refresh_token),
    "the sibling refresh token must never leak"
  );
  assert!(
    !raw.contains("leak-secret"),
    "the client secret must never leak"
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_after_revoke_endpoint_is_inactive() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("revoke-then-introspect");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("secret-ri"),
  )
  .await?;
  let minted = mint_bound(
    &mut h,
    &client_id,
    SenderProof {
      dpop_jkt: Some("jkt-revoked".to_owned()),
      mtls_x5t_s256: None,
    },
  )
  .await?;

  let outcome = {
    let service = token_service(&h)?;
    let auth = ClientAuthRequest {
      basic_header: None,
      client_id: Some(client_id.as_str()),
      body_secret: Some(SecretString::from("secret-ri")),
      assertion_type: None,
      assertion: None,
      peer_certs: None,
    };
    let mut stores = RevokeStores {
      pool: &h.pool,
      keys: &h.config.keys,
      conn: &mut h.conn,
      store: &h.store,
      service: &service,
    };
    let ctx = RevokeContext {
      token_endpoint: "https://auth.example.test/token",
      now: OffsetDateTime::now_utc(),
      request_id: Some("req-introspect-revoke"),
    };
    let request = RevokeRequest {
      token: &minted.access_token,
      token_type_hint: None,
      auth: &auth,
    };
    revoke_tokens(&mut stores, &ctx, &request).await?
  };
  assert_eq!(
    outcome,
    RevokeOutcome::Revoked,
    "the owner must revoke its own DPoP-bound token"
  );

  // RFC 7009 §2.2: after revocation the token is no longer usable, so
  // RFC 7662 §2.2 introspection reports the inactive shape.
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-ri",
  )
  .await?;
  assert!(!response.active, "a revoked token must not be active");
  assert_eq!(response, IntrospectionResponse::inactive());
  Ok(())
}

/// Mint one token pair owned by `client_id` with an explicit subject.
async fn mint_subject(
  h: &mut Harness,
  client_id: &str,
  subject: &str,
) -> TestResult<crate::protocol::token::MintedTokens> {
  let service = token_service(h)?;
  Ok(
    service
      .mint(
        &mut h.conn,
        &h.store,
        &MintRequest {
          client_id: client_id.to_owned(),
          client_kind: ClientKind::Confidential,
          subject: subject.to_owned(),
          scope: "orders:read".to_owned(),
          grant_id: unique("grant"),
          proof: SenderProof::none(),
        },
        now_unix(),
      )
      .await?,
  )
}

/// Provision one enabled user with a fast test password hash.
async fn provision_user(h: &Harness, email: &str) -> TestResult<UserRecord> {
  let params = Argon2Params::new(8, 1, 1, 32).map_err(|error| format!("{error:?}"))?;
  Ok(
    user_repo::create_user(
      &h.pool,
      &h.config.keys,
      false,
      &NewUser {
        email: email.to_owned(),
        password_hash: hash_secret("correct-horse-01", &params)?,
        is_admin: false,
        must_change_password: false,
      },
    )
    .await?,
  )
}

async fn introspect_client(h: &mut Harness, label: &str, secret: &str) -> TestResult<String> {
  let client_id = unique(label);
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some(secret),
  )
  .await?;
  Ok(client_id)
}

#[tokio::test]
async fn test_introspect_disabled_email_subject_is_inactive() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = introspect_client(&mut h, "disabled-email", "secret-de").await?;
  let user = provision_user(&h, "disabled-introspect@example.test").await?;
  let minted = mint_subject(&mut h, &client_id, &user.email).await?;
  assert!(user_repo::disable_user(&h.pool, user.id).await?);

  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-de",
  )
  .await?;
  assert!(!response.active, "a disabled user's token must be inactive");
  assert_eq!(response, IntrospectionResponse::inactive());
  Ok(())
}

#[tokio::test]
async fn test_introspect_disabled_uuid_subject_is_inactive() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = introspect_client(&mut h, "disabled-uuid", "secret-du").await?;
  let user = provision_user(&h, "disabled-uuid@example.test").await?;
  // Device-code tokens carry the user UUID string as subject.
  let minted = mint_subject(&mut h, &client_id, &user.id.to_string()).await?;
  assert!(user_repo::disable_user(&h.pool, user.id).await?);

  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-du",
  )
  .await?;
  assert!(!response.active, "a disabled user's token must be inactive");
  assert_eq!(response, IntrospectionResponse::inactive());
  Ok(())
}

#[tokio::test]
async fn test_introspect_enabled_email_subject_stays_active() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = introspect_client(&mut h, "enabled-email", "secret-ee").await?;
  let user = provision_user(&h, "enabled-introspect@example.test").await?;
  let minted = mint_subject(&mut h, &client_id, &user.email).await?;

  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-ee",
  )
  .await?;
  assert!(response.active, "an enabled user's token must stay active");
  assert_eq!(response.sub.as_deref(), Some(user.email.as_str()));
  Ok(())
}

#[tokio::test]
async fn test_introspect_reenabled_subject_is_active_again() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = introspect_client(&mut h, "reenabled", "secret-re").await?;
  let user = provision_user(&h, "reenabled-introspect@example.test").await?;
  let minted = mint_subject(&mut h, &client_id, &user.email).await?;
  assert!(user_repo::disable_user(&h.pool, user.id).await?);
  let disabled = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-re",
  )
  .await?;
  assert!(!disabled.active, "a disabled user's token must be inactive");

  sqlx::query("UPDATE users SET disabled = false, updated_at = now() WHERE id = $1")
    .bind(user.id)
    .execute(&h.pool)
    .await?;
  let response = run_core(
    &mut h,
    &minted.access_token,
    Some("access_token"),
    &client_id,
    "secret-re",
  )
  .await?;
  assert!(
    response.active,
    "a re-enabled user's token must be active again"
  );
  Ok(())
}

#[tokio::test]
async fn test_introspect_empty_and_unknown_subjects_stay_active() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = introspect_client(&mut h, "non-user-sub", "secret-nu").await?;
  // Client-credentials tokens carry an empty subject.
  let empty = mint_subject(&mut h, &client_id, "").await?;
  let response = run_core(
    &mut h,
    &empty.access_token,
    Some("access_token"),
    &client_id,
    "secret-nu",
  )
  .await?;
  assert!(response.active, "an empty subject must stay active");
  // Synthetic subjects resolve to no user and must stay live.
  let synthetic = mint_subject(&mut h, &client_id, "synthetic-subject-9").await?;
  let response = run_core(
    &mut h,
    &synthetic.access_token,
    Some("access_token"),
    &client_id,
    "secret-nu",
  )
  .await?;
  assert!(response.active, "an unmapped subject must stay active");
  assert_eq!(response.sub.as_deref(), Some("synthetic-subject-9"));
  Ok(())
}

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
  db::{NewClient, TokenEndpointAuthMethod, client_repo, test_support::migrated_pool},
  protocol::token::{ClientKind, MintRequest, SenderProof, TokenService},
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
  let container = GenericImage::new("redis", "7.2-alpine")
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

/// Mint one sender-constrained access token owned by `client_id`.
async fn mint_constrained(
  h: &mut Harness,
  client_id: &str,
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
          proof: SenderProof {
            dpop_jkt: Some("jkt-thumbnail".to_owned()),
            mtls_x5t_s256: Some("x5t-thumbnail".to_owned()),
          },
        },
        now_unix(),
      )
      .await?,
  )
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

async fn post_form(app: Router, auth: Option<&str>, body: &str) -> TestResult<(StatusCode, Value)> {
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

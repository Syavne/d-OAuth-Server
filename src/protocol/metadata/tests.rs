//! `test(metadata)` suite: RFC 8414 document + scope-catalog read semantics.

use std::{sync::Arc, time::Duration};

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::get,
};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

use super::{AuthorizationServerMetadata, metadata};
use crate::{
  config::{Config, ConfigError},
  db::{scope_repo, test_support::migrated_pool},
  state::{AppState, Clock, RedisConn},
};

/// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const ISSUER: &str = "https://auth.example.test";

/// A validated development config (Postgres/Redis are never dialed by the
/// metadata handler, so the URLs are placeholders).
fn test_config() -> Result<Config, ConfigError> {
  let fixture = serde_json::json!({
    "issuer": ISSUER,
    "environment": "development",
    "tls": {
      "cert_path": "/tmp/metadata-test-cert.pem",
      "key_path": "/tmp/metadata-test-key.pem"
    },
    "database": {"url": "postgres://127.0.0.1:1/metadata"},
    "redis": {"url": "redis://127.0.0.1:1", "durability": "waitaof"},
    "token_pepper": "metadata-test-pepper-0123456789abcdef",
    "totp_encryption_key": "metadata-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "metadata-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// State around a live Postgres pool and a lazy, never-dialed Redis (the
/// handler touches only `pool` + `config.issuer`).
fn test_state(pool: &sqlx::PgPool) -> TestResult<AppState> {
  let config = Arc::new(test_config()?);
  let keys = Arc::new(config.keys.clone());
  let client = redis::Client::open("redis://127.0.0.1:1")?;
  let manager = redis::aio::ConnectionManager::new_lazy_with_config(
    client,
    redis::aio::ConnectionManagerConfig::new()
      .set_number_of_retries(0)
      .set_response_timeout(Some(Duration::from_millis(200)))
      .set_connection_timeout(Some(Duration::from_millis(200))),
  )?;
  Ok(AppState {
    pool: pool.clone(),
    redis: RedisConn::Single(manager),
    config,
    keys,
    transition_unsafe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    clock: Clock::system(),
  })
}

/// Fetch `scopes_supported` through the metadata handler.
async fn fetch_scopes(router: &Router) -> TestResult<Vec<String>> {
  let request = Request::builder()
    .uri("/.well-known/oauth-authorization-server")
    .body(Body::empty())?;
  let response = router.clone().oneshot(request).await?;
  assert_eq!(response.status(), StatusCode::OK);
  let bytes = response.into_body().collect().await?.to_bytes();
  let doc: Value = serde_json::from_slice(&bytes)?;
  let scopes = doc
    .get("scopes_supported")
    .and_then(Value::as_array)
    .cloned()
    .ok_or("scopes_supported must be an array")?;
  Ok(
    scopes
      .iter()
      .filter_map(Value::as_str)
      .map(str::to_owned)
      .collect(),
  )
}

#[test]
fn metadata_document_matches_snapshot() {
  let doc = AuthorizationServerMetadata::for_issuer(
    ISSUER,
    vec!["api:read".to_owned(), "orders:write".to_owned()],
  );
  let rendered = serde_json::to_string_pretty(&doc).unwrap_or_default();
  insta::with_settings!({ prepend_module_to_snapshot => false }, {
    insta::assert_snapshot!("metadata_document", rendered);
  });
}

#[test]
fn metadata_never_advertises_plain_or_jwks_uri() {
  let doc = AuthorizationServerMetadata::for_issuer(ISSUER, Vec::new());
  let json = serde_json::to_value(&doc).unwrap_or(Value::Null);

  assert!(
    json.get("jwks_uri").is_none(),
    "no AS-signed key is published"
  );
  assert_eq!(
    json.get("code_challenge_methods_supported"),
    Some(&serde_json::json!(["S256"])),
    "S256 only"
  );
  assert_eq!(
    json.get("response_types_supported"),
    Some(&serde_json::json!(["code"]))
  );
  assert_eq!(
    json
      .get("grant_types_supported")
      .and_then(Value::as_array)
      .map(Vec::len),
    Some(5)
  );
  assert_eq!(
    json
      .get("authorization_response_iss_parameter_supported")
      .and_then(Value::as_bool),
    Some(true)
  );
  assert_eq!(
    json
      .get("tls_client_certificate_bound_access_tokens")
      .and_then(Value::as_bool),
    Some(true)
  );

  let rendered = serde_json::to_string(&doc).unwrap_or_default();
  assert!(
    !rendered.contains("\"plain\""),
    "plain must never be advertised"
  );
}

#[tokio::test]
async fn metadata_postgres_down_fails_closed() -> TestResult {
  let pool = sqlx::postgres::PgPoolOptions::new()
    .acquire_timeout(Duration::from_millis(300))
    .connect_lazy("postgres://postgres:secret@127.0.0.1:1/postgres")?;
  let router = Router::new()
    .route("/.well-known/oauth-authorization-server", get(metadata))
    .with_state(test_state(&pool)?);
  let request = Request::builder()
    .uri("/.well-known/oauth-authorization-server")
    .body(Body::empty())?;
  let response = router.oneshot(request).await?;
  assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
  Ok(())
}

/// The enabled `scopes` table is read on every request, so a catalog mutation
/// (the out-of-process CLI path) is visible on the next request with no restart
/// or explicit refresh; disabled scopes never appear.
#[tokio::test]
async fn metadata_reflects_catalog_mutation_without_restart() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  scope_repo::upsert(&pool, "api:read", "read api").await?;
  scope_repo::upsert(&pool, "admin:all", "disabled").await?;
  scope_repo::set_enabled(&pool, "admin:all", false).await?;

  let router = Router::new()
    .route("/.well-known/oauth-authorization-server", get(metadata))
    .with_state(test_state(&pool)?);

  assert_eq!(fetch_scopes(&router).await?, vec!["api:read".to_owned()]);

  scope_repo::upsert(&pool, "orders:write", "write orders").await?;
  scope_repo::set_enabled(&pool, "api:read", false).await?;

  assert_eq!(
    fetch_scopes(&router).await?,
    vec!["orders:write".to_owned()]
  );
  Ok(())
}

#[tokio::test]
async fn metadata_endpoint_serves_document() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  scope_repo::upsert(&pool, "api:read", "read api").await?;
  scope_repo::upsert(&pool, "orders:write", "write orders").await?;

  let router = Router::new()
    .route("/.well-known/oauth-authorization-server", get(metadata))
    .with_state(test_state(&pool)?);
  let request = Request::builder()
    .uri("/.well-known/oauth-authorization-server")
    .body(Body::empty())?;
  let response = router.oneshot(request).await?;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response
      .headers()
      .get(header::CONTENT_TYPE)
      .and_then(|value| value.to_str().ok()),
    Some("application/json")
  );

  let bytes = response.into_body().collect().await?.to_bytes();
  let doc: Value = serde_json::from_slice(&bytes)?;

  assert_eq!(doc.get("issuer").and_then(Value::as_str), Some(ISSUER));
  for (field, path) in [
    ("authorization_endpoint", "/authorize"),
    ("token_endpoint", "/token"),
    ("registration_endpoint", "/register"),
    ("introspection_endpoint", "/introspect"),
    ("revocation_endpoint", "/revoke"),
    ("pushed_authorization_request_endpoint", "/par"),
    ("device_authorization_endpoint", "/device_authorization"),
  ] {
    assert_eq!(
      doc.get(field).and_then(Value::as_str),
      Some(format!("{ISSUER}{path}").as_str()),
      "{field} mismatch"
    );
  }
  assert_eq!(
    doc.get("scopes_supported"),
    Some(&serde_json::json!(["api:read", "orders:write"]))
  );
  assert_eq!(
    doc.get("code_challenge_methods_supported"),
    Some(&serde_json::json!(["S256"]))
  );
  assert!(doc.get("jwks_uri").is_none());
  Ok(())
}

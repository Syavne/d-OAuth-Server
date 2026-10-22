//! `test(metadata)` suite: RFC 8414 document + scope-catalog read semantics.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

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
  config::{Config, ConfigError, JwtSigningAlg},
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

/// A validated config with RFC 9728 `protected_resources` enabled and the given
/// identifiers. The metadata handler serves these only when the flag is on.
fn test_config_protected(ids: &[&str]) -> Result<Config, ConfigError> {
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
    "protected_resources_enabled": true,
    "resource_indicators_enabled": true,
    "protected_resource_ids": ids,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// A validated config with the RFC 8707 `resource_indicators_enabled` flag
/// pinned. The metadata handler advertises the capability only when it is set.
fn test_config_resource_indicators(enabled: bool) -> Result<Config, ConfigError> {
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
    "resource_indicators_enabled": enabled,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// A validated config with the CIMD `cimd_enabled` flag pinned. The metadata
/// handler advertises `client_id_metadata_document_supported` only when it is
/// set (CIMD draft §6).
fn test_config_cimd(enabled: bool) -> Result<Config, ConfigError> {
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
    "cimd_enabled": enabled,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// Exactly 32 ASCII bytes: a valid non-zero P-256 scalar and Ed25519 seed.
const TEST_JWT_KEY: &str = "metadata-jwt-signing-key-32-byte";

/// A validated config with the JWT access-token switch in the requested state
/// and `alg` configured. The metadata handler advertises `jwks_uri` and the
/// algorithm list only when the switch is on.
fn test_config_jwt(enabled: bool, alg: &str) -> Result<Config, ConfigError> {
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
    "jwt_access_tokens_enabled": enabled,
    "jwt_signing_key": TEST_JWT_KEY,
    "jwt_access_token_signing_alg": alg,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// State around a live Postgres pool and a lazy, never-dialed Redis (the
/// handler touches only `pool` + `config`).
fn test_state(pool: &sqlx::PgPool) -> TestResult<AppState> {
  test_state_with_config(pool, Arc::new(test_config()?))
}

/// State around `pool` and an explicit config (used to toggle the RFC 9728
/// `protected_resources` flag without touching the default fixture).
fn test_state_with_config(pool: &sqlx::PgPool, config: Arc<Config>) -> TestResult<AppState> {
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

/// Fetch the metadata document through the handler.
async fn fetch_doc(router: &Router) -> TestResult<Value> {
  let request = Request::builder()
    .uri("/.well-known/oauth-authorization-server")
    .body(Body::empty())?;
  let response = router.clone().oneshot(request).await?;
  assert_eq!(response.status(), StatusCode::OK);
  let bytes = response.into_body().collect().await?.to_bytes();
  Ok(serde_json::from_slice(&bytes)?)
}

/// Fetch `scopes_supported` through the metadata handler.
async fn fetch_scopes(router: &Router) -> TestResult<Vec<String>> {
  let doc = fetch_doc(router).await?;
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
    Some(vec!["https://api.example.test".to_owned()]),
    true,
    true,
    Some(JwtSigningAlg::Es256),
  );
  let rendered = serde_json::to_string_pretty(&doc).unwrap_or_default();
  insta::with_settings!({ prepend_module_to_snapshot => false }, {
    insta::assert_snapshot!("metadata_document", rendered);
  });
}

#[test]
fn metadata_never_advertises_plain_or_jwks_uri() {
  let off = AuthorizationServerMetadata::for_issuer(ISSUER, Vec::new(), None, false, false, None);
  let json = serde_json::to_value(&off).unwrap_or(Value::Null);

  assert!(
    json.get("jwks_uri").is_none(),
    "flag off must not advertise a JWK Set"
  );
  assert!(
    json
      .get("access_token_signing_alg_values_supported")
      .is_none(),
    "flag off must not advertise access-token signing algorithms"
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

  let rendered = serde_json::to_string(&off).unwrap_or_default();
  assert!(
    !rendered.contains("\"plain\""),
    "plain must never be advertised"
  );

  for (alg, advertised) in [
    (JwtSigningAlg::Es256, "ES256"),
    (JwtSigningAlg::EdDsa, "EdDSA"),
  ] {
    let on =
      AuthorizationServerMetadata::for_issuer(ISSUER, Vec::new(), None, false, false, Some(alg));
    let json = serde_json::to_value(&on).unwrap_or(Value::Null);
    assert_eq!(
      json.get("jwks_uri").and_then(Value::as_str),
      Some("https://auth.example.test/jwks.json"),
      "flag on must point at the JWKS route for {advertised}"
    );
    assert_eq!(
      json.get("access_token_signing_alg_values_supported"),
      Some(&serde_json::json!([advertised])),
      "the advertised list must be exactly the configured algorithm"
    );
  }
}

#[test]
fn metadata_advertises_ps256_for_client_assertions() {
  let doc = AuthorizationServerMetadata::for_issuer(
    ISSUER,
    Vec::new(),
    None,
    false,
    false,
    Some(JwtSigningAlg::Es256),
  );
  let json = serde_json::to_value(&doc).unwrap_or(Value::Null);
  assert_eq!(
    json.get("token_endpoint_auth_signing_alg_values_supported"),
    Some(&serde_json::json!(
      super::CLIENT_ASSERTION_SIGNING_ALG_VALUES
    )),
    "client-assertion allowlist must include PS256"
  );
  let dpop_has_ps256 = json
    .get("dpop_signing_alg_values_supported")
    .and_then(Value::as_array)
    .is_some_and(|algs| algs.iter().any(|alg| alg.as_str() == Some("PS256")));
  assert!(
    !dpop_has_ps256,
    "DPoP allowlist is unchanged by assertion PS256"
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

/// RFC 9728 §4: `protected_resources` is emitted only when
/// `protected_resources_enabled` is set, sourced from `protected_resource_ids`.
/// `resource_metadata` is a `WWW-Authenticate` parameter owned by the resource
/// server (§5.1) and is never an AS metadata member, so it must never appear.
#[tokio::test]
async fn metadata_gates_protected_resources() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  let off = Router::new()
    .route(route, get(metadata))
    .with_state(test_state(&pool)?);
  let off_doc = fetch_doc(&off).await?;
  assert!(
    off_doc.get("protected_resources").is_none(),
    "flag off must omit protected_resources"
  );
  assert!(
    off_doc.get("resource_metadata").is_none(),
    "resource_metadata is an RS WWW-Authenticate parameter, not AS metadata"
  );

  let on = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_protected(&["https://api.example.test"])?),
    )?);
  let on_doc = fetch_doc(&on).await?;
  assert_eq!(
    on_doc.get("protected_resources"),
    Some(&serde_json::json!(["https://api.example.test"])),
    "flag on must serve config protected_resource_ids"
  );
  assert!(
    on_doc.get("resource_metadata").is_none(),
    "resource_metadata is an RS WWW-Authenticate parameter, not AS metadata"
  );
  Ok(())
}

/// RFC 8707 registers the `resource` request parameter (§5.1) and the
/// `invalid_target` error (§5.2) but no authorization-server metadata member,
/// so `resource_indicators_supported` is this server's local extension. It is
/// emitted as `true` only when `resource_indicators_enabled` is set; with the
/// flag off the member is absent from the wire document.
#[tokio::test]
async fn metadata_gates_resource_indicators() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  let off = Router::new()
    .route(route, get(metadata))
    .with_state(test_state(&pool)?);
  let off_doc = fetch_doc(&off).await?;
  assert!(
    off_doc.get("resource_indicators_supported").is_none(),
    "flag off must omit resource_indicators_supported"
  );

  let on = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_resource_indicators(true)?),
    )?);
  let on_doc = fetch_doc(&on).await?;
  assert_eq!(
    on_doc.get("resource_indicators_supported"),
    Some(&serde_json::json!(true)),
    "flag on must advertise resource_indicators_supported"
  );
  Ok(())
}

/// Advertising honesty: with `resource_indicators_enabled` off the document
/// must not advertise a capability the server rejects. That rejection
/// (`resource` present while the flag is off -> `invalid_target`) is covered at
/// the authorize, PAR, token, and device layers by the `params_*`/grant suites;
/// this test pins only the metadata side. Enabling the flag adds exactly this
/// one member and removes nothing.
#[tokio::test]
async fn metadata_never_advertises_disabled_resource_indicators() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  let off = Router::new()
    .route(route, get(metadata))
    .with_state(test_state(&pool)?);
  let off_doc = fetch_doc(&off).await?;
  let off_keys = document_keys(&off_doc);
  assert!(
    !off_keys.contains("resource_indicators_supported"),
    "flag off must not advertise resource_indicators_supported"
  );

  let on = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_resource_indicators(true)?),
    )?);
  let on_doc = fetch_doc(&on).await?;
  let on_keys = document_keys(&on_doc);

  assert_eq!(
    on_keys
      .difference(&off_keys)
      .cloned()
      .collect::<BTreeSet<String>>(),
    BTreeSet::from(["resource_indicators_supported".to_owned()]),
    "turning the flag on must add exactly the extension member"
  );
  assert!(
    off_keys.difference(&on_keys).next().is_none(),
    "turning the flag on must not remove any member"
  );
  Ok(())
}

/// CIMD draft §6 defines the RFC 8414 `client_id_metadata_document_supported`
/// Boolean: it signals that a `client_id` URL may name a Client ID Metadata
/// Document. It is emitted as `true` only when `cimd_enabled` is set and is
/// ABSENT (not `false`) otherwise, so a client never sees support the server
/// would not honor.
#[tokio::test]
async fn metadata_gates_cimd() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  let off = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_cimd(false)?),
    )?);
  let off_doc = fetch_doc(&off).await?;
  assert!(
    off_doc
      .get("client_id_metadata_document_supported")
      .is_none(),
    "flag off must omit client_id_metadata_document_supported"
  );

  let on = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_cimd(true)?),
    )?);
  let on_doc = fetch_doc(&on).await?;
  assert_eq!(
    on_doc.get("client_id_metadata_document_supported"),
    Some(&serde_json::json!(true)),
    "flag on must advertise client_id_metadata_document_supported"
  );
  Ok(())
}

/// Clients select CIMD only when the doc advertises BOTH `none` in
/// `token_endpoint_auth_methods_supported` and the CIMD flag (CIMD draft §6
/// together with §4.1's shared-secret prohibition: a CIMD client authenticates
/// as a public client unless it publishes a key). The `none` member is
/// independent of `cimd_enabled` and must never disappear.
#[tokio::test]
async fn metadata_advertises_none_and_cimd_flag() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  for (enabled, expect_flag) in [(true, Some(true)), (false, None)] {
    let router = Router::new()
      .route(route, get(metadata))
      .with_state(test_state_with_config(
        &pool,
        Arc::new(test_config_cimd(enabled)?),
      )?);
    let doc = fetch_doc(&router).await?;
    let none_advertised = doc
      .get("token_endpoint_auth_methods_supported")
      .and_then(Value::as_array)
      .is_some_and(|methods| methods.iter().any(|method| method.as_str() == Some("none")));
    assert!(
      none_advertised,
      "`none` must be advertised regardless of cimd_enabled={enabled}"
    );
    assert_eq!(
      doc
        .get("client_id_metadata_document_supported")
        .and_then(Value::as_bool),
      expect_flag,
      "CIMD flag mismatch for cimd_enabled={enabled}"
    );
  }
  Ok(())
}

/// RFC 8414 §2 `jwks_uri` + RFC 9068 §2.1
/// `access_token_signing_alg_values_supported`: both are emitted only while
/// the JWT access-token switch is on, and the algorithm list is exactly the
/// configured algorithm the signer produces.
#[tokio::test]
async fn metadata_gates_jwks_uri() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  let off = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_jwt(false, "ES256")?),
    )?);
  let off_doc = fetch_doc(&off).await?;
  assert!(
    off_doc.get("jwks_uri").is_none(),
    "flag off must omit jwks_uri"
  );
  assert!(
    off_doc
      .get("access_token_signing_alg_values_supported")
      .is_none(),
    "flag off must omit access_token_signing_alg_values_supported"
  );

  let on = Router::new()
    .route(route, get(metadata))
    .with_state(test_state_with_config(
      &pool,
      Arc::new(test_config_jwt(true, "ES256")?),
    )?);
  let on_doc = fetch_doc(&on).await?;
  let jwks_uri = on_doc
    .get("jwks_uri")
    .and_then(Value::as_str)
    .ok_or("flag on must advertise jwks_uri")?;
  assert_eq!(jwks_uri, format!("{ISSUER}/jwks.json"));
  assert!(jwks_uri.ends_with("/jwks.json"));
  assert_eq!(
    on_doc.get("access_token_signing_alg_values_supported"),
    Some(&serde_json::json!(["ES256"])),
    "the list must be exactly the configured algorithm"
  );
  Ok(())
}

/// An EdDSA deployment advertises only `EdDSA`: the signer has no RSA branch,
/// so no `RS256` may ever appear in this member.
#[tokio::test]
async fn metadata_advertises_only_the_configured_signing_alg() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let route = "/.well-known/oauth-authorization-server";

  for (configured, advertised) in [("ES256", "ES256"), ("EdDSA", "EdDSA")] {
    let router = Router::new()
      .route(route, get(metadata))
      .with_state(test_state_with_config(
        &pool,
        Arc::new(test_config_jwt(true, configured)?),
      )?);
    let doc = fetch_doc(&router).await?;
    assert_eq!(
      doc.get("access_token_signing_alg_values_supported"),
      Some(&serde_json::json!([advertised])),
      "configured {configured} must advertise exactly [{advertised}]"
    );
  }
  Ok(())
}

/// Top-level member names of a metadata document.
fn document_keys(doc: &Value) -> BTreeSet<String> {
  doc
    .as_object()
    .map(|members| members.keys().cloned().collect())
    .unwrap_or_default()
}

//! Shared scaffolding for the `test(jar)` suites.
//!
//! Fixture client projection, JWKS, shared Redis handles, and outcome
//! helpers. Included via `#[path]` from `jar.rs` and `jar_request_uri.rs`;
//! this file itself carries no tests.
//!
//! Redis comes from the shared services in `compose.test.yaml`
//! (`docker compose -f compose.test.yaml up -d`); each `store_conn` call
//! uses unique key prefixes, so parallel tests never share state (and never
//! FLUSH shared state).

use std::{collections::HashMap, time::Duration};

use d_oauth::{
  db::client_repo::Client,
  error::{AppError, OAuthErrorCode},
  state::RedisConn,
  store::Store,
};
use serde_json::{Value, json};

#[path = "common/mod.rs"]
mod common;

use common::{redis_url, unique_prefixes};

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use test_guard::{Lease, Shared};
use time::OffsetDateTime;

/// Test body result (no `unwrap`/`expect` under the deny lints).
pub type TestResult = Result<(), TestError>;

/// Errors raised by the JAR test scaffolding itself.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// The shared test service is unreachable (usually: compose not started).
  #[error("test setup: {0}")]
  Setup(String),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] d_oauth::store::StoreError),
  /// A JWT operation failed.
  #[error("jwt error: {0}")]
  Jwt(#[from] jsonwebtoken::errors::Error),
  /// A JSON operation failed.
  #[error("json error: {0}")]
  Json(#[from] serde_json::Error),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Test client id used across the suite.
pub const CLIENT_ID: &str = "jar-test-client";
/// Test server issuer (the required request-object `aud`).
pub const ISSUER: &str = "https://auth.example.test";
/// `kid` of the client's registered JAR signing key.
pub const KEY_ID: &str = "jar-test-key";

/// Modulus of the client's RSA key (base64url, no pad).
pub const CLIENT_JWK_N: &str = "s8FfX2aG2tOjxpTathl42eHWWkAwCxes1AqepAwEalfvpCeN3O7urlCzzsHqKTXohpNe0fMSpNQjMjG75GzMi8DpjdGb8SqvnR9UP21-peToq0duo8fBvrxbBrLkc_8zlQeT4EN0RIcT-kJ8Uu68AXA9kCxjt2wWVy7n6V06YhfiCCsIknc43TunHE2VQAQovC0KxDQbfxsZhrQPLuc-OEoq2aIaGDrty2G0TqdtU7aXzmYDHMgmDlG_oPQNAzVjHNl5--uOUT3UWEF1gF1Bvsvp2FqsXrzgeb_UmlGBZp8adt6GM1Ma14EoSYTEwMYYCLYZmk9L56ykT0RrykHEYQ";

/// The client's registered JWKS document (single RS256 key).
pub fn client_jwks() -> Value {
  json!({"keys": [{
    "kty": "RSA", "n": CLIENT_JWK_N, "e": "AQAB",
    "kid": KEY_ID, "alg": "RS256", "use": "sig",
  }]})
}

/// A registered client projection for the suite.
pub fn test_client(auth_method: &str, request_uris: Option<Value>) -> Client {
  let now = OffsetDateTime::now_utc();
  Client {
    id: uuid::Uuid::new_v4(),
    client_id: CLIENT_ID.to_owned(),
    client_secret_expires_at: None,
    client_id_issued_at: now,
    client_name: "jar test client".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: "read write".to_owned(),
    token_endpoint_auth_method: auth_method.to_owned(),
    jwks: Some(client_jwks()),
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    active: true,
    created_at: now,
    updated_at: now,
  }
}

/// Shared Redis server handle (no per-test container: the URL points at the
/// shared services from `compose.test.yaml`).
///
/// The lease keeps the shared slot alive; bind it (usually as `_redis`) for
/// the duration of the test.
pub struct JarRedis {
  url: String,
}

static JAR_REDIS: Shared<JarRedis> = Shared::new();

/// Resolve the shared Redis URL once; each test connects its own manager.
///
/// The returned lease keeps the shared slot alive; bind it (usually as
/// `_redis`) for the duration of the test.
async fn shared_redis() -> Result<Lease<JarRedis>, TestError> {
  JAR_REDIS
    .lease::<TestError>(async { Ok(JarRedis { url: redis_url() }) })
    .await
}

/// A connected [`RedisConn`] plus [`Store`] over the shared Redis.
///
/// The returned lease keeps the shared slot alive; bind it (usually as
/// `_redis`) for the duration of the test. Key prefixes are unique per
/// call, so parallel tests never share state.
pub async fn store_conn() -> Result<(Lease<JarRedis>, RedisConn, Store), TestError> {
  let redis = shared_redis().await?;
  let client = redis::Client::open(redis.url.as_str()).map_err(|error| {
    TestError::Setup(format!(
      "cannot reach shared test Redis at {}: {error}; run `docker compose -f compose.test.yaml up -d`",
      redis.url,
    ))
  })?;
  let config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, config)
    .await
    .map_err(|error| {
      TestError::Setup(format!(
        "cannot reach shared test Redis at {}: {error}; run `docker compose -f compose.test.yaml up -d`",
        redis.url,
      ))
    })?;
  let (token_prefix, ratelimit_prefix) = unique_prefixes();
  let store = Store::from_parts(
    token_prefix,
    ratelimit_prefix,
    d_oauth::config::DurabilityMode::WaitAof,
  );
  Ok((redis, RedisConn::Single(manager), store))
}

/// The error code of a resolve outcome, or `None` on success.
pub fn code_of(outcome: &Result<HashMap<String, String>, AppError>) -> Option<OAuthErrorCode> {
  match outcome {
    Ok(_) => None,
    Err(error) => Some(error.code()),
  }
}

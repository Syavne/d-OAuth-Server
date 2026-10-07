//! `test(client_auth)` container suite: full dispatch against real Postgres
//! and Redis (client lookup, secret verify, `jti` replay, `jwks_uri` guard).

mod assertions;
mod secrets;

use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use testcontainers::{
  GenericImage, ImageExt as _,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
  AuthContext, AuthStores, CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthRequest, token_endpoint,
};
use crate::{
  config::DurabilityMode,
  crypto::secret::{Argon2Params, hash_secret},
  db::{NewClient, TokenEndpointAuthMethod, client_repo, test_support::Db},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  state::RedisConn,
  store::Store,
  test_guard::{ContainerGuard, Lease},
};

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An application error from a repository helper.
  #[error("app error: {0}")]
  App(#[from] AppError),
  /// A crypto, encoding, or JWT operation failed.
  #[error("test crypto error: {0}")]
  Crypto(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Live handles for one dispatch test: Postgres pool, Redis, store layout,
/// and the canonical token endpoint. The container is returned separately so
/// tests hold it alive with a `_container` binding.
struct Harness {
  _db: Lease<Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  endpoint: String,
  keys: KeyRing,
}

/// Fresh Postgres database plus a throwaway Redis for one test.
///
/// The guard removes the Redis container synchronously when the test drops
/// it; the Postgres container is owned by the shared `db` lease. AOF is on
/// because the assertion-`jti` replay markers are durability-barriered.
async fn harness() -> Result<(ContainerGuard, Harness), TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(url.as_str())?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  let h = Harness {
    _db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    endpoint: token_endpoint("https://auth.example.com"),
    keys: KeyRing::from_parts(
      vec![(
        KeyId::new("v1"),
        SecretString::from("client-auth-test-pepper"),
      )],
      vec![(
        KeyId::new("v1"),
        SecretString::from("client-auth-test-totp"),
      )],
      vec![(KeyId::new("v1"), SecretString::from("client-auth-test-pii"))],
    )
    .map_err(|error| TestError::Crypto(format!("{error:?}")))?,
  };
  Ok((guarded, h))
}

/// Borrow datastore handles out of a harness.
fn stores_of(h: &mut Harness) -> AuthStores<'_> {
  AuthStores {
    pool: &h.pool,
    keys: &h.keys,
    conn: &mut h.conn,
    store: &h.store,
  }
}

/// Request context for an owned endpoint string.
///
/// Takes the endpoint by value-reference rather than the harness so callers
/// can hold the context alongside a mutable store borrow.
fn ctx_of(endpoint: &str) -> AuthContext<'_> {
  AuthContext {
    token_endpoint: endpoint,
    now: OffsetDateTime::now_utc(),
  }
}

/// Register a client row for dispatch tests.
async fn insert_client(
  pool: &PgPool,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
  expires_at: Option<OffsetDateTime>,
  jwks: Option<serde_json::Value>,
  jwks_uri: Option<&str>,
) -> TestResult {
  let keys = KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("client-auth-test-pepper"),
    )],
    vec![(
      KeyId::new("v1"),
      SecretString::from("client-auth-test-totp"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("client-auth-test-pii"))],
  )
  .map_err(|error| TestError::Crypto(format!("{error:?}")))?;
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Crypto(format!("{error}")))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()
    .map_err(|error| TestError::Crypto(format!("{error}")))?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: expires_at,
    client_name: format!("{client_id} name"),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: method.as_str().to_owned(),
    jwks,
    jwks_uri: jwks_uri.map(str::to_owned),
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, &keys, false, &new).await?;
  Ok(())
}

/// Assert an error is `invalid_client` with the expected HTTP status.
fn expect_invalid_client(error: AppError, status: u16) -> TestResult {
  if error.code() != OAuthErrorCode::InvalidClient {
    return Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    )));
  }
  if error.status().as_u16() != status {
    return Err(TestError::Unexpected(format!(
      "wrong status: {}",
      error.status()
    )));
  }
  Ok(())
}

/// Encode `client_id:secret` as an HTTP Basic header value.
fn basic_header(client_id: &str, secret: &str) -> String {
  format!(
    "Basic {}",
    base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
  )
}

/// A Basic-only request.
fn basic_request(header: &str) -> ClientAuthRequest<'_> {
  ClientAuthRequest {
    basic_header: Some(header),
    client_id: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

/// A `client_secret_post` request.
fn post_request(client_id: &str, secret: SecretString) -> ClientAuthRequest<'_> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: Some(secret),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

/// A credential-free request naming `client_id` (`none` or mTLS path).
fn bare_request(client_id: &str) -> ClientAuthRequest<'_> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

/// A `private_key_jwt` request.
fn assertion_request<'a>(client_id: &'a str, assertion: &'a str) -> ClientAuthRequest<'a> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
    assertion: Some(assertion),
    peer_certs: None,
  }
}

/// Claims minted by the container-suite signer.
#[derive(Debug, Serialize, Deserialize)]
struct ContainerClaims {
  iss: String,
  sub: String,
  aud: String,
  jti: String,
  exp: i64,
  iat: i64,
}

/// An Ed25519 signer plus the matching inline JWKS for one client.
struct ContainerKey {
  encoding: EncodingKey,
  jwks: serde_json::Value,
}

impl ContainerKey {
  fn generate(kid: &str) -> Result<Self, TestError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|_| TestError::Crypto("ed25519 keygen failed".to_owned()))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
      .map_err(|_| TestError::Crypto("ed25519 reload failed".to_owned()))?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    Ok(Self {
      encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
      jwks: serde_json::json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid }]
      }),
    })
  }

  fn mint(&self, client_id: &str, audience: &str, jti: &str) -> Result<String, TestError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = ContainerClaims {
      iss: client_id.to_owned(),
      sub: client_id.to_owned(),
      aud: audience.to_owned(),
      jti: jti.to_owned(),
      exp: now + 300,
      iat: now,
    };
    encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
      .map_err(|error| TestError::Crypto(format!("mint failed: {error}")))
  }
}

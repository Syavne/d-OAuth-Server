//! `test(device_authorize)` suite: issuance, approval, misses, brute-force cap.
//!
//! Each test runs against a real Redis container plus a migrated Postgres
//! database on the shared test server, through the public [`super`] API.

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use secrecy::SecretString;
use serde_json::json;
use sqlx::PgPool;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
  DEVICE_GRANT, DEVICE_INTERVAL_SECS, DeviceAuthorizationResponse, DeviceContext, DeviceHttpInputs,
  DeviceStores, authorize_device, hash_token, normalize_user_code, read_binding,
};
use crate::{
  config::Config,
  crypto::secret::{Argon2Params, hash_secret},
  db::{NewClient, TokenEndpointAuthMethod, client_repo},
  error::OAuthErrorCode,
  jose::jwk::thumbprint,
  state::RedisConn,
  store::{self, Store},
  test_guard::ContainerGuard,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
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
  /// Configuration was rejected.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// A JWT operation failed.
  #[error("jwt error: {0}")]
  Jwt(#[from] jsonwebtoken::errors::Error),
  /// A JWK helper failed.
  #[error("jwk error: {0}")]
  Jwk(#[from] crate::jose::jwk::JwkError),
  /// An application error escaped where success was required.
  #[error("app error: {0}")]
  App(#[from] crate::error::AppError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// Test key generation was rejected.
  #[error("test key generation failed: {0}")]
  KeyGen(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

static NONCE: AtomicU64 = AtomicU64::new(1);

fn unique(label: &str) -> String {
  let n = NONCE.fetch_add(1, Ordering::Relaxed);
  format!("device-test-{n}-{label}")
}

/// Live handles for one test: pool, Redis, store, and validated config.
struct Harness {
  _db: crate::test_guard::Lease<crate::db::test_support::Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  config: Config,
}

async fn harness() -> Result<(ContainerGuard, Harness), TestError> {
  let (db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg: {error}")))?;
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
    "tls": {"cert_path": "/tmp/device-test-cert.pem", "key_path": "/tmp/device-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/device"},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "device-test-pepper-0123456789abcdef",
    "totp_encryption_key": "device-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "device-test-pii-key-0123456789abcdef",
    "rate_limit": {"enabled": true, "window_secs": 60, "per_ip": 120,
      "per_client": 300, "login_per_ip": 20, "token_per_client": 60},
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config source: {error}")))?;
  let config = Config::from_source(source)?;
  Ok((
    guarded,
    Harness {
      _db: db,
      pool,
      conn: RedisConn::Single(manager),
      store,
      config,
    },
  ))
}

async fn insert_client(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
  scope: &str,
) -> TestResult {
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()
    .map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec![DEVICE_GRANT.to_owned()],
    response_types: Vec::new(),
    scope: scope.to_owned(),
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

/// A fresh ES256 signing key plus its public JWK for DPoP proofs.
struct TestKey {
  encoding: EncodingKey,
  jwk: serde_json::Value,
}

fn fresh_key() -> Result<TestKey, TestError> {
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
  use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
  };

  let rng = SystemRandom::new();
  let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
    .map_err(|error| TestError::KeyGen(format!("generate: {error:?}")))?;
  let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
    .map_err(|error| TestError::KeyGen(format!("parse: {error:?}")))?;
  let raw = pair.public_key().as_ref();
  let x = raw
    .get(1..33)
    .ok_or_else(|| TestError::Unexpected("bad ec key".to_owned()))?;
  let y = raw
    .get(33..65)
    .ok_or_else(|| TestError::Unexpected("bad ec key".to_owned()))?;
  Ok(TestKey {
    encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
    jwk: json!({
      "kty": "EC",
      "crv": "P-256",
      "x": URL_SAFE_NO_PAD.encode(x),
      "y": URL_SAFE_NO_PAD.encode(y),
    }),
  })
}

fn mint_proof(key: &TestKey, htu: &str, jti: &str, iat: i64) -> Result<String, TestError> {
  let mut header = Header::new(Algorithm::ES256);
  header.typ = Some("dpop+jwt".to_owned());
  let claims = json!({
    "htm": "POST",
    "htu": htu,
    "iat": iat,
    "jti": jti,
    "jwk": key.jwk,
  });
  Ok(encode(&header, &claims, &key.encoding)?)
}

fn device_htu(config: &Config) -> String {
  format!("{}/device_authorization", config.issuer)
}

fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// Issue through the public endpoint using one harness's live handles.
async fn issue(
  h: &mut Harness,
  inputs: &DeviceHttpInputs<'_>,
) -> Result<DeviceAuthorizationResponse, crate::error::AppError> {
  let mut stores = DeviceStores {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.config.keys,
  };
  let ctx = DeviceContext {
    issuer: &h.config.issuer,
    device_ttl: h.config.ttl.device,
    now_unix: now_unix(),
  };
  authorize_device(&mut stores, &ctx, inputs).await
}

#[tokio::test]
async fn test_device_authorize_public_client_issues_code_and_interval() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("public");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;

  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read"),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  let ttl = h.config.ttl.device;
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("issue rejected: {error}")))?;

  if response.device_code.len() != 43 {
    return Err(TestError::Unexpected(
      "device_code must be 43 chars".to_owned(),
    ));
  }
  if response.user_code.len() != 9 || response.user_code.as_bytes()[4] != b'-' {
    return Err(TestError::Unexpected(
      "user_code must render XXXX-XXXX".to_owned(),
    ));
  }
  if response.expires_in != ttl.as_secs() {
    return Err(TestError::Unexpected(
      "expires_in must mirror the device TTL".to_owned(),
    ));
  }
  if response.interval != DEVICE_INTERVAL_SECS {
    return Err(TestError::Unexpected(
      "interval must be advertised".to_owned(),
    ));
  }
  if response.verification_uri != format!("{}/device", h.config.issuer) {
    return Err(TestError::Unexpected("bad verification_uri".to_owned()));
  }
  if !response
    .verification_uri_complete
    .ends_with(response.user_code.as_str())
  {
    return Err(TestError::Unexpected(
      "verification_uri_complete must carry the user code".to_owned(),
    ));
  }

  // Only the keyed hashes reach Redis; the record is pending for this client.
  let device_hash = hash_token(&h.config.keys, &response.device_code)?;
  let record = store::device::poll(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("record missing".to_owned()))?;
  if record.status != store::device::DeviceStatus::Pending {
    return Err(TestError::Unexpected("record must be pending".to_owned()));
  }
  if record.client_id != client_id || record.scope != "orders:read" {
    return Err(TestError::Unexpected(
      "record must carry client and scope".to_owned(),
    ));
  }
  let user_hash = hash_token(&h.config.keys, &normalize_user_code(&response.user_code))?;
  let resolved = store::device::resolve_user_code(&mut h.conn, &h.store, &user_hash).await?;
  if resolved.as_deref() != Some(device_hash.as_str()) {
    return Err(TestError::Unexpected(
      "user code must resolve to the device".to_owned(),
    ));
  }

  // The public binding is the verified DPoP thumbprint.
  let binding = read_binding(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("binding missing".to_owned()))?;
  let expected_jkt = thumbprint(&key.jwk)?;
  if binding.jkt.as_deref() != Some(expected_jkt.as_str()) {
    return Err(TestError::Unexpected(
      "binding must hold the proof jkt".to_owned(),
    ));
  }
  if binding.x5t_s256.is_some() {
    return Err(TestError::Unexpected("no mtls binding expected".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn test_device_authorize_confidential_client_secret_post() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("conf");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("post-secret"),
    "orders:read",
  )
  .await?;

  // No DPoP proof: a secret-authenticated client is unconstrained.
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: Some(SecretString::from("post-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("valid secret rejected: {error}")))?;
  let device_hash = hash_token(&h.config.keys, &response.device_code)?;
  let binding = read_binding(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("binding missing".to_owned()))?;
  if binding.jkt.is_some() || binding.x5t_s256.is_some() {
    return Err(TestError::Unexpected(
      "unconstrained client must store no binding".to_owned(),
    ));
  }

  // A wrong secret fails as `invalid_client`, with no state written.
  let bad = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: Some(SecretString::from("wrong-secret")),
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  match issue(&mut h, &bad).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidClient => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected("wrong secret accepted".to_owned())),
  }
}

#[tokio::test]
async fn test_device_authorize_public_client_without_dpop_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("nodpop");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;

  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: None,
    peer_certs: None,
  };
  match issue(&mut h, &inputs).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidDpopProof => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "public client without DPoP was issued a code".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_device_authorize_over_registered_scope_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("scope");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;

  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: Some("orders:read orders:admin"),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  match issue(&mut h, &inputs).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidScope => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "over-scope request accepted".to_owned(),
    )),
  }
}

#[tokio::test]
async fn test_device_authorize_approval_transitions_state() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("approve");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;

  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("issue rejected: {error}")))?;

  // The verification page resolves the code to a pending request.
  let pending =
    crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, &response.user_code)
      .await?
      .ok_or_else(|| TestError::Unexpected("fresh code must resolve".to_owned()))?;
  if pending.client_id != client_id {
    return Err(TestError::Unexpected("wrong client on review".to_owned()));
  }

  // Approval binds the grant to the approving subject.
  let decided =
    crate::ui::device::decide_device(&mut h.conn, &h.store, &pending.device_hash, true, "user-1")
      .await?;
  if !decided {
    return Err(TestError::Unexpected("decide must apply".to_owned()));
  }
  let device_hash = hash_token(&h.config.keys, &response.device_code)?;
  let record = store::device::poll(&mut h.conn, &h.store, &device_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("record missing".to_owned()))?;
  if record.status != store::device::DeviceStatus::Approved {
    return Err(TestError::Unexpected("record must be approved".to_owned()));
  }
  if record.subject != "user-1" || record.grant_id.is_empty() {
    return Err(TestError::Unexpected(
      "approval must bind subject and grant".to_owned(),
    ));
  }

  // A decided code no longer resolves for display: no state leaks on retry.
  let again =
    crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, &response.user_code)
      .await?;
  if again.is_some() {
    return Err(TestError::Unexpected(
      "decided code must stop resolving".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn test_device_authorize_unknown_and_expired_user_code_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;

  // Unknown codes resolve to nothing.
  let miss =
    crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, "ZZZZ-9999").await?;
  if miss.is_some() {
    return Err(TestError::Unexpected("unknown code resolved".to_owned()));
  }

  // An issued code whose records vanished (TTL expiry) resolves to nothing.
  let client_id = unique("expired");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "",
  )
  .await?;
  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("issue rejected: {error}")))?;
  let device_hash = hash_token(&h.config.keys, &response.device_code)?;
  let user_hash = hash_token(&h.config.keys, &normalize_user_code(&response.user_code))?;
  let device_key = h.store.device_key(&device_hash);
  let user_key = h.store.user_code_key(&user_hash);
  redis::cmd("DEL")
    .arg(&device_key)
    .arg(&user_key)
    .query_async::<()>(&mut h.conn)
    .await?;
  let gone =
    crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, &response.user_code)
      .await?;
  if gone.is_some() {
    return Err(TestError::Unexpected("expired code resolved".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn test_device_authorize_eleventh_bad_guess_rate_limited() -> TestResult {
  let (_container, mut h) = harness().await?;
  let ip = unique("ip");

  for attempt in 1..=10 {
    let budget = crate::ui::device::check_guess_budget(&mut h.conn, &h.store, &ip).await?;
    if budget != crate::ui::device::GuessBudget::Allow {
      return Err(TestError::Unexpected(format!(
        "guess {attempt} limited too early"
      )));
    }
  }
  match crate::ui::device::check_guess_budget(&mut h.conn, &h.store, &ip).await? {
    crate::ui::device::GuessBudget::Limited { retry_after_secs } => {
      if retry_after_secs < 1 {
        return Err(TestError::Unexpected(
          "retry-after must be positive".to_owned(),
        ));
      }
      Ok(())
    }
    crate::ui::device::GuessBudget::Allow => Err(TestError::Unexpected(
      "11th bad guess was not rate limited".to_owned(),
    )),
  }
}

/// RFC 8628 §3.2: `verification_uri_complete` carries the `user_code` for
/// non-textual transmission (QR), while the short `verification_uri` the
/// user types stays code-free (RFC 8628 §3.3).
#[tokio::test]
async fn test_device_authorize_verification_uri_complete_carries_user_code() -> TestResult {
  let (_container, mut h) = harness().await?;
  let client_id = unique("complete");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;

  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("issue rejected: {error}")))?;

  let wire = serde_json::to_value(&response)
    .map_err(|error| TestError::Unexpected(format!("serialize response: {error}")))?;
  let complete = wire
    .get("verification_uri_complete")
    .and_then(serde_json::Value::as_str)
    .ok_or_else(|| {
      TestError::Unexpected("verification_uri_complete must be on the wire".to_owned())
    })?;
  let (base, query) = complete
    .split_once('?')
    .ok_or_else(|| TestError::Unexpected("complete URI must carry a query".to_owned()))?;
  if base != response.verification_uri {
    return Err(TestError::Unexpected(
      "complete URI must extend verification_uri".to_owned(),
    ));
  }
  let expected_query = format!("user_code={}", response.user_code);
  if query != expected_query {
    return Err(TestError::Unexpected(format!(
      "complete URI must carry user_code={}, got {query}",
      response.user_code
    )));
  }

  if response.verification_uri.contains('?')
    || response
      .verification_uri
      .contains(response.user_code.as_str())
  {
    return Err(TestError::Unexpected(
      "verification_uri must stay code-free".to_owned(),
    ));
  }
  Ok(())
}

/// RFC 8628 §3.3 and §5.1: every malformed or unknown user code is the same
/// generic miss — never an error, a panic, or a signal that separates a
/// guess from a real code. RFC 8628 §6.1 makes user-supplied punctuation
/// optional, so case and separators do not change identity.
#[tokio::test]
async fn test_device_authorize_user_code_misses_are_generic_and_normalized() -> TestResult {
  let (_container, mut h) = harness().await?;

  for raw in [
    "",
    "ABCD",
    "ABCD-EFGHI",
    "IIII-IIII",
    "0000-1111",
    "ZZZZ-9999",
    "ΩΩΩΩ-ΩΩΩΩ",
    "ZZZZ-9999-AAAA-BBBB",
  ] {
    let miss =
      crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, raw).await?;
    if miss.is_some() {
      return Err(TestError::Unexpected(format!("{raw:?} must not resolve")));
    }
  }

  let client_id = unique("normalize");
  insert_client(
    &h.pool,
    &h.config.keys,
    &client_id,
    TokenEndpointAuthMethod::None,
    None,
    "orders:read",
  )
  .await?;
  let key = fresh_key()?;
  let htu = device_htu(&h.config);
  let proof = mint_proof(&key, &htu, &unique("jti"), now_unix())?;
  let inputs = DeviceHttpInputs {
    client_id: client_id.as_str(),
    scope: None,
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    dpop_proof: Some(proof.as_str()),
    peer_certs: None,
  };
  let response = issue(&mut h, &inputs)
    .await
    .map_err(|error| TestError::Unexpected(format!("issue rejected: {error}")))?;

  let canonical =
    crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, &response.user_code)
      .await?
      .ok_or_else(|| TestError::Unexpected("a fresh code must resolve".to_owned()))?;
  let variants = [
    response.user_code.to_lowercase(),
    response.user_code.replace('-', " "),
    response.user_code.replace('-', ""),
  ];
  for variant in variants {
    let resolved =
      crate::ui::device::lookup_pending(&mut h.conn, &h.store, &h.config.keys, &variant)
        .await?
        .ok_or_else(|| TestError::Unexpected(format!("{variant:?} must resolve")))?;
    if resolved.device_hash != canonical.device_hash || resolved.client_id != client_id {
      return Err(TestError::Unexpected(
        "code formatting must not change identity".to_owned(),
      ));
    }
  }
  Ok(())
}

//! Shared harness for the `dpop_*` suite: test keys, proof minting, Redis.

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use testcontainers::{
  GenericImage, ImageExt as _,
  core::{IntoContainerPort as _, WaitFor},
  runners::AsyncRunner as _,
};
use time::OffsetDateTime;

use crate::{
  config::DurabilityMode,
  error::{AppError, OAuthErrorCode},
  jose::jwk::JwkError,
  state::RedisConn,
  store::{Store, StoreError},
  test_guard::{ContainerGuard, Lease, Shared},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
pub(super) type TestResult = Result<(), TestError>;

/// Errors raised by the `dpop` test scaffolding itself.
#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
  /// A testcontainers operation failed.
  #[error("container error")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error")]
  Store(#[from] StoreError),
  /// A JWT operation failed.
  #[error("jwt error")]
  Jwt(#[from] jsonwebtoken::errors::Error),
  /// Test key generation was rejected.
  #[error("test key generation failed: {0}")]
  KeyGen(String),
  /// A JWK helper failed.
  #[error("jwk error")]
  Jwk(#[from] JwkError),
  /// JSON scaffolding failed.
  #[error("json error")]
  Json(#[from] serde_json::Error),
  /// The verifier rejected (or accepted) unexpectedly.
  #[error("verifier error")]
  App(#[from] AppError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Method every test proof is bound to.
pub(super) const TEST_HTM: &str = "POST";
/// URI every test proof is bound to.
pub(super) const TEST_HTU: &str = "https://as.example.test/token";

/// One shared Redis 7.2 container for the whole `dpop` suite.
///
/// The slot holds a [`ContainerGuard`], so the last test releasing it removes
/// the container synchronously instead of orphaning it at process exit.
static REDIS: Shared<ContainerGuard> = Shared::new();

/// Fresh connection plus store handle against the shared container.
///
/// The returned lease keeps the shared container alive; bind it (usually as
/// `_redis`) for the duration of the test.
///
/// Timeouts are generous (10 s/5 s): the container is local and no barrier
/// runs here, so any failure is a real defect, not a budget cut.
pub(super) async fn test_redis() -> Result<(Lease<ContainerGuard>, RedisConn, Store), TestError> {
  let container = REDIS
    .lease::<TestError>(async {
      let started = GenericImage::new("redis", "7.2-alpine")
        .with_exposed_port(6379.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
        .with_cmd(["redis-server", "--appendonly", "yes"])
        .start()
        .await?;
      Ok(ContainerGuard::new(started))
    })
    .await?;
  let port = container.get_host_port_ipv4(6379).await?;
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
  Ok((container, RedisConn::Single(manager), store))
}

static JTI_NONCE: AtomicU64 = AtomicU64::new(1);

/// A `jti` no other test uses, so replay markers never collide.
pub(super) fn unique_jti() -> String {
  let n = JTI_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("dpop-test-jti-{n}")
}

/// Current time as seconds since the Unix epoch.
pub(super) fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// Base64url SHA-256 of an access token: the expected `ath` value.
pub(super) fn ath_of(token: &str) -> String {
  URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// A fresh ES256 signing key plus its public JWK.
pub(super) struct TestKey {
  /// Private signing key for minting proofs.
  pub(super) encoding: EncodingKey,
  /// Public JWK embedded in proofs.
  pub(super) jwk: Value,
}

/// Generate an ES256 keypair via `ring`; the JWK carries `x`/`y` only.
pub(super) fn fresh_es256_key() -> Result<TestKey, TestError> {
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
  let uncompressed = "EC public key is not uncompressed";
  let x = raw
    .get(1..33)
    .ok_or_else(|| TestError::Unexpected(uncompressed.to_owned()))?;
  let y = raw
    .get(33..65)
    .ok_or_else(|| TestError::Unexpected(uncompressed.to_owned()))?;
  Ok(TestKey {
    encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
    jwk: serde_json::json!({
      "kty": "EC",
      "crv": "P-256",
      "x": URL_SAFE_NO_PAD.encode(x),
      "y": URL_SAFE_NO_PAD.encode(y),
    }),
  })
}

/// Proof-minting parameters (fewer than four, grouped by construction).
pub(super) struct ProofParams<'a> {
  /// Signing key.
  pub(super) key: &'a EncodingKey,
  /// Header `alg`.
  pub(super) alg: Algorithm,
  /// Header `typ` (`None` omits it).
  pub(super) typ: Option<&'a str>,
  /// `htm` claim.
  pub(super) htm: &'a str,
  /// `htu` claim.
  pub(super) htu: &'a str,
  /// `iat` claim.
  pub(super) iat: i64,
  /// `jti` claim.
  pub(super) jti: &'a str,
  /// Embedded `jwk` (`None` omits it).
  pub(super) jwk: Option<Value>,
  /// `ath` claim (`None` omits it).
  pub(super) ath: Option<&'a str>,
}

/// A well-formed proof bound to the suite URI; tests override fields via
/// struct-update syntax for the negative cases.
pub(super) fn valid_params<'a>(
  key: &'a EncodingKey,
  jwk: Value,
  jti: &'a str,
  iat: i64,
) -> ProofParams<'a> {
  ProofParams {
    key,
    alg: Algorithm::ES256,
    typ: Some(super::DPOP_TYP),
    htm: TEST_HTM,
    htu: TEST_HTU,
    iat,
    jti,
    jwk: Some(jwk),
    ath: None,
  }
}

/// Mint a proof JWT from parameters (correctly signed unless the caller
/// mixes a key with another key's JWK).
pub(super) fn mint_proof(params: &ProofParams<'_>) -> Result<String, TestError> {
  let mut header = Header::new(params.alg);
  header.typ = params.typ.map(str::to_owned);
  let mut claims = serde_json::Map::new();
  claims.insert("htm".to_owned(), Value::String(params.htm.to_owned()));
  claims.insert("htu".to_owned(), Value::String(params.htu.to_owned()));
  claims.insert("iat".to_owned(), Value::from(params.iat));
  claims.insert("jti".to_owned(), Value::String(params.jti.to_owned()));
  if let Some(jwk) = &params.jwk {
    claims.insert("jwk".to_owned(), jwk.clone());
  }
  if let Some(ath) = params.ath {
    claims.insert("ath".to_owned(), Value::String(ath.to_owned()));
  }
  Ok(encode(&header, &Value::Object(claims), params.key)?)
}

/// Assert a verification outcome is exactly `invalid_dpop_proof`.
pub(super) fn assert_invalid(result: Result<super::VerifiedDpop, AppError>) -> TestResult {
  match result {
    Ok(_) => Err(TestError::Unexpected(
      "invalid proof was accepted".to_owned(),
    )),
    Err(err) => {
      assert_eq!(err.code(), OAuthErrorCode::InvalidDpopProof);
      Ok(())
    }
  }
}

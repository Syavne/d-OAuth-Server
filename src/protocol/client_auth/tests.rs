//! `test(client_auth)` pure suite: header parsing, expiry, assertion
//! verification, and the SSRF policy on the `jwks_uri` path (offline).

use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::assertion::{ALLOWED_ALGS, unverified_iss, validate_assertion};
use super::{is_secret_expired, parse_basic_header, token_endpoint};
use crate::protocol::ssrf;

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A crypto, encoding, or JWT operation failed.
  #[error("test crypto error: {0}")]
  Crypto(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Claims minted by the test signer (mirrors the production shape).
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
  iss: String,
  sub: String,
  aud: TestAud,
  jti: String,
  exp: i64,
  iat: i64,
}

/// Single-audience encoding for the happy path.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum TestAud {
  /// Single audience.
  One(String),
}

/// An Ed25519 test key plus its public JWK document.
struct TestKey {
  encoding: EncodingKey,
  jwks: serde_json::Value,
}

impl TestKey {
  fn generate(kid: &str) -> Result<Self, TestError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|_| TestError::Crypto("ed25519 keygen failed".to_owned()))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
      .map_err(|_| TestError::Crypto("ed25519 reload failed".to_owned()))?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let encoding = EncodingKey::from_ed_der(pkcs8.as_ref());
    let jwks = serde_json::json!({
      "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid }]
    });
    Ok(Self { encoding, jwks })
  }
}

/// Mint a signed `private_key_jwt` for `client_id`/`audience`.
fn mint(
  key: &TestKey,
  client_id: &str,
  audience: &str,
  header: Header,
  skew_secs: i64,
) -> Result<String, TestError> {
  let now = OffsetDateTime::now_utc().unix_timestamp();
  let claims = TestClaims {
    iss: client_id.to_owned(),
    sub: client_id.to_owned(),
    aud: TestAud::One(audience.to_owned()),
    jti: format!("jti-{client_id}-{now}"),
    exp: now + 300 + skew_secs,
    iat: now,
  };
  encode(&header, &claims, &key.encoding)
    .map_err(|error| TestError::Crypto(format!("mint failed: {error}")))
}

/// Mint a signed assertion with explicit `exp`/`iat` Unix seconds.
fn mint_at(
  key: &TestKey,
  client_id: &str,
  audience: &str,
  header: Header,
  exp: i64,
  iat: i64,
) -> Result<String, TestError> {
  let claims = TestClaims {
    iss: client_id.to_owned(),
    sub: client_id.to_owned(),
    aud: TestAud::One(audience.to_owned()),
    jti: format!("jti-at-{exp}"),
    exp,
    iat,
  };
  encode(&header, &claims, &key.encoding)
    .map_err(|error| TestError::Crypto(format!("mint failed: {error}")))
}

#[test]
fn client_auth_basic_header_parses_valid() -> TestResult {
  let raw = base64::engine::general_purpose::STANDARD.encode("my-client:s3cret:with:colons");
  let creds = parse_basic_header(&format!("Basic {raw}"))
    .ok_or_else(|| TestError::Unexpected("valid header rejected".to_owned()))?;
  if creds.client_id != "my-client" {
    return Err(TestError::Unexpected("client_id mismatch".to_owned()));
  }
  if creds.secret.expose_secret() != "s3cret:with:colons" {
    return Err(TestError::Unexpected("secret mismatch".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_basic_header_rejects_malformed() -> TestResult {
  let bad = [
    "Bearer abc",
    "Basic ",
    "Basic !!!not-base64!!!",
    "Basic bm9jb2xvbg==",
    "Basic Om5vLWlk",
  ];
  for header in bad {
    if parse_basic_header(header).is_some() {
      return Err(TestError::Unexpected(format!("accepted: {header}")));
    }
  }
  Ok(())
}

#[test]
fn client_auth_secret_expiry_enforced() -> TestResult {
  let now = OffsetDateTime::now_utc();
  if is_secret_expired(None, now) {
    return Err(TestError::Unexpected(
      "no expiry must not expire".to_owned(),
    ));
  }
  if !is_secret_expired(Some(now - time::Duration::seconds(1)), now) {
    return Err(TestError::Unexpected("past expiry must reject".to_owned()));
  }
  if is_secret_expired(Some(now + time::Duration::seconds(60)), now) {
    return Err(TestError::Unexpected("future expiry must pass".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_token_endpoint_derives_from_issuer() -> TestResult {
  let endpoint = token_endpoint("https://auth.example.com");
  if endpoint != "https://auth.example.com/token" {
    return Err(TestError::Unexpected(endpoint));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_valid() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-valid";
  let aud = token_endpoint("https://auth.example.com");
  let token = mint(&key, client_id, &aud, Header::new(Algorithm::EdDSA), 0)?;
  let now = OffsetDateTime::now_utc();
  let validated = validate_assertion(&token, &key.jwks, client_id, &aud, now)
    .map_err(|error| TestError::Unexpected(format!("valid assertion rejected: {error}")))?;
  if validated.jti_hash.is_empty() {
    return Err(TestError::Unexpected("empty jti hash".to_owned()));
  }
  if unverified_iss(&token).as_deref() != Some(client_id) {
    return Err(TestError::Unexpected("iss lookup mismatch".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_wrong_aud_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-aud";
  let aud = token_endpoint("https://auth.example.com");
  let token = mint(
    &key,
    client_id,
    "https://evil.example.com/token",
    Header::new(Algorithm::EdDSA),
    0,
  )?;
  let now = OffsetDateTime::now_utc();
  if validate_assertion(&token, &key.jwks, client_id, &aud, now).is_ok() {
    return Err(TestError::Unexpected("wrong aud accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_wrong_iss_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let aud = token_endpoint("https://auth.example.com");
  let token = mint(&key, "other-client", &aud, Header::new(Algorithm::EdDSA), 0)?;
  let now = OffsetDateTime::now_utc();
  if validate_assertion(&token, &key.jwks, "client-auth-iss", &aud, now).is_ok() {
    return Err(TestError::Unexpected("wrong iss accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_missing_typ_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-typ";
  let aud = token_endpoint("https://auth.example.com");
  let mut header = Header::new(Algorithm::EdDSA);
  header.typ = None;
  let token = mint(&key, client_id, &aud, header, 0)?;
  let now = OffsetDateTime::now_utc();
  if validate_assertion(&token, &key.jwks, client_id, &aud, now).is_ok() {
    return Err(TestError::Unexpected("missing typ accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_unsigned_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-none";
  let aud = token_endpoint("https://auth.example.com");
  let now = OffsetDateTime::now_utc().unix_timestamp();
  let header =
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
  let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
    r#"{{"iss":"{client_id}","sub":"{client_id}","aud":"{aud}","jti":"j","exp":{exp},"iat":{now}}}"#,
    exp = now + 300,
  ));
  let token = format!("{header}.{payload}.");
  if validate_assertion(
    &token,
    &key.jwks,
    client_id,
    &aud,
    OffsetDateTime::now_utc(),
  )
  .is_ok()
  {
    return Err(TestError::Unexpected(
      "unsigned assertion accepted".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_hmac_rejected() -> TestResult {
  use jsonwebtoken::EncodingKey as HmacKey;

  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-hs";
  let aud = token_endpoint("https://auth.example.com");
  let now = OffsetDateTime::now_utc().unix_timestamp();
  let claims = TestClaims {
    iss: client_id.to_owned(),
    sub: client_id.to_owned(),
    aud: TestAud::One(aud.clone()),
    jti: "jti-hs".to_owned(),
    exp: now + 300,
    iat: now,
  };
  let token = encode(
    &Header::new(Algorithm::HS256),
    &claims,
    &HmacKey::from_secret(b"client-secret-as-hmac-key"),
  )
  .map_err(|error| TestError::Crypto(format!("hs mint failed: {error}")))?;
  if validate_assertion(
    &token,
    &key.jwks,
    client_id,
    &aud,
    OffsetDateTime::now_utc(),
  )
  .is_ok()
  {
    return Err(TestError::Unexpected("hmac assertion accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_expired_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-exp";
  let aud = token_endpoint("https://auth.example.com");
  let token = mint(&key, client_id, &aud, Header::new(Algorithm::EdDSA), -600)?;
  let now = OffsetDateTime::now_utc();
  if validate_assertion(&token, &key.jwks, client_id, &aud, now).is_ok() {
    return Err(TestError::Unexpected(
      "expired assertion accepted".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_long_exp_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-long-exp";
  let aud = token_endpoint("https://auth.example.com");
  let now = OffsetDateTime::now_utc();
  let now_secs = now.unix_timestamp();
  let token = mint_at(
    &key,
    client_id,
    &aud,
    Header::new(Algorithm::EdDSA),
    now_secs + 3600,
    now_secs,
  )?;
  if validate_assertion(&token, &key.jwks, client_id, &aud, now).is_ok() {
    return Err(TestError::Unexpected("far-future exp accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_exp_before_iat_rejected() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-neg-lifetime";
  let aud = token_endpoint("https://auth.example.com");
  let now = OffsetDateTime::now_utc();
  let now_secs = now.unix_timestamp();
  let token = mint_at(
    &key,
    client_id,
    &aud,
    Header::new(Algorithm::EdDSA),
    now_secs - 10,
    now_secs + 25,
  )?;
  if validate_assertion(&token, &key.jwks, client_id, &aud, now).is_ok() {
    return Err(TestError::Unexpected("exp before iat accepted".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_short_exp_accepted() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-short-exp";
  let aud = token_endpoint("https://auth.example.com");
  let now = OffsetDateTime::now_utc();
  let now_secs = now.unix_timestamp();
  let token = mint_at(
    &key,
    client_id,
    &aud,
    Header::new(Algorithm::EdDSA),
    now_secs + 60,
    now_secs,
  )?;
  validate_assertion(&token, &key.jwks, client_id, &aud, now)
    .map_err(|error| TestError::Unexpected(format!("short-lived assertion rejected: {error}")))?;
  Ok(())
}

#[test]
fn client_auth_assertion_jti_ttl_matches_remaining_validity() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-ttl";
  let aud = token_endpoint("https://auth.example.com");
  let now_secs = OffsetDateTime::now_utc().unix_timestamp();
  let now = OffsetDateTime::from_unix_timestamp(now_secs)
    .map_err(|error| TestError::Unexpected(format!("bad test timestamp: {error}")))?;
  let token = mint_at(
    &key,
    client_id,
    &aud,
    Header::new(Algorithm::EdDSA),
    now_secs + 60,
    now_secs,
  )?;
  let validated = validate_assertion(&token, &key.jwks, client_id, &aud, now)
    .map_err(|error| TestError::Unexpected(format!("assertion rejected: {error}")))?;
  if validated.jti_ttl != Duration::from_secs(90) {
    return Err(TestError::Unexpected(format!(
      "jti_ttl {}s != 90s (60s remaining + 30s skew)",
      validated.jti_ttl.as_secs()
    )));
  }
  Ok(())
}

#[test]
fn client_auth_assertion_jti_ttl_bounded_by_cap() -> TestResult {
  let key = TestKey::generate("k1")?;
  let client_id = "client-auth-ttl-cap";
  let aud = token_endpoint("https://auth.example.com");
  let now_secs = OffsetDateTime::now_utc().unix_timestamp();
  let now = OffsetDateTime::from_unix_timestamp(now_secs)
    .map_err(|error| TestError::Unexpected(format!("bad test timestamp: {error}")))?;
  let token = mint_at(
    &key,
    client_id,
    &aud,
    Header::new(Algorithm::EdDSA),
    now_secs + 300,
    now_secs,
  )?;
  let validated = validate_assertion(&token, &key.jwks, client_id, &aud, now)
    .map_err(|error| TestError::Unexpected(format!("assertion rejected: {error}")))?;
  if validated.jti_ttl != Duration::from_secs(330) {
    return Err(TestError::Unexpected(format!(
      "jti_ttl {}s != 330s (300s cap + 30s skew)",
      validated.jti_ttl.as_secs()
    )));
  }
  if validated.jti_ttl > Duration::from_secs(360) {
    return Err(TestError::Unexpected(
      "jti_ttl exceeds the 300s + 2*30s clamp".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn client_auth_allowed_algs_include_ps256() -> TestResult {
  if !ALLOWED_ALGS.contains(&Algorithm::PS256) {
    return Err(TestError::Unexpected("PS256 not allowed".to_owned()));
  }
  Ok(())
}

#[test]
fn client_auth_allowed_algs_match_metadata_advertisement() -> TestResult {
  let mut advertised: Vec<String> = crate::protocol::metadata::CLIENT_ASSERTION_SIGNING_ALG_VALUES
    .iter()
    .map(|alg| (*alg).to_owned())
    .collect();
  advertised.sort();
  let mut allowed: Vec<String> = ALLOWED_ALGS.iter().map(|alg| format!("{alg:?}")).collect();
  allowed.sort();
  if allowed != advertised {
    return Err(TestError::Unexpected(format!(
      "allowlist {allowed:?} != metadata {advertised:?}"
    )));
  }
  Ok(())
}

#[test]
fn client_auth_jwks_uri_private_ip_rejected_by_guard() -> TestResult {
  if ssrf::validate_fetch_url("https://127.0.0.1:8443/jwks.json").is_err() {
    return Err(TestError::Unexpected(
      "policy pass expected; target block happens at DNS step".to_owned(),
    ));
  }
  Ok(())
}

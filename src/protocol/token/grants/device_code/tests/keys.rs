//! ES256 keys and DPoP proofs for `test(grant_device)`.
//!
//! Every proof carries a caller-supplied `jti`: proofs are single-use, so
//! each poll attempt mints its own.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

use super::TestError;
use crate::config::Config;

/// A fresh ES256 signing key plus its public JWK for DPoP proofs.
pub(super) struct TestKey {
  pub(super) encoding: EncodingKey,
  pub(super) jwk: serde_json::Value,
}

pub(super) fn fresh_key() -> Result<TestKey, TestError> {
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

pub(super) fn mint_proof(
  key: &TestKey,
  htu: &str,
  jti: &str,
  iat: i64,
) -> Result<String, TestError> {
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

pub(super) fn device_htu(config: &Config) -> String {
  format!("{}/device_authorization", config.issuer)
}

pub(super) fn token_htu(config: &Config) -> String {
  crate::protocol::client_auth::token_endpoint(&config.issuer)
}

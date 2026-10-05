//! Hand-rolled DPoP helpers for the E2E grant suite (extension payloads the
//! `oauth2` crate cannot drive).
//!
//! Included only by the grant suite, which uses every item here.

use super::harness::{TestError, ensure, fail};

/// Base64url (no-pad) engine for JWK/JWT segments.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A DPoP signing key plus its public coordinates (ES256, hand-rolled).
pub struct DpopKey {
  /// PKCS#8 signer (fixed-width ES256 signatures).
  pair: ring::signature::EcdsaKeyPair,
  /// Base64url `x` coordinate.
  x: String,
  /// Base64url `y` coordinate.
  y: String,
}

impl DpopKey {
  /// Generate a fresh P-256 key.
  pub fn generate() -> Result<Self, TestError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
      &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
      &rng,
    )
    .map_err(|error| fail(format!("dpop keygen failed: {error}")))?;
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
      &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
      pkcs8.as_ref(),
      &rng,
    )
    .map_err(|error| fail(format!("dpop key load failed: {error}")))?;
    let point: &[u8] = ring::signature::KeyPair::public_key(&pair).as_ref();
    ensure(point.len() == 65 && point[0] == 4, "unexpected P-256 point")?;
    let x = base64::Engine::encode(&B64, &point[1..33]);
    let y = base64::Engine::encode(&B64, &point[33..65]);
    Ok(Self { pair, x, y })
  }

  /// The public JWK for RFC 7638 thumbprint checks.
  pub fn jwk(&self) -> serde_json::Value {
    serde_json::json!({
      "kty": "EC",
      "crv": "P-256",
      "x": self.x,
      "y": self.y,
    })
  }

  /// Mint a DPoP proof JWT for `htm`/`htu` with a fresh `jti`.
  pub fn proof(&self, htm: &str, htu: &str) -> Result<String, TestError> {
    self.proof_with_jti(htm, htu, &uuid::Uuid::new_v4().to_string())
  }

  /// Mint a DPoP proof JWT with a caller-chosen `jti` (replay tests).
  pub fn proof_with_jti(&self, htm: &str, htu: &str, jti: &str) -> Result<String, TestError> {
    let header = format!(
      "{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\"}}}}",
      self.x, self.y
    );
    let iat = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"htm": htm, "htu": htu, "iat": iat, "jti": jti});
    let signing_input = format!(
      "{}.{}",
      base64::Engine::encode(&B64, header.as_bytes()),
      base64::Engine::encode(
        &B64,
        serde_json::to_string(&claims)
          .map_err(|error| fail(format!("claims: {error}")))?
          .as_bytes()
      )
    );
    let rng = ring::rand::SystemRandom::new();
    let signature = self
      .pair
      .sign(&rng, signing_input.as_bytes())
      .map_err(|error| fail(format!("dpop sign failed: {error}")))?;
    Ok(format!(
      "{signing_input}.{}",
      base64::Engine::encode(&B64, signature.as_ref())
    ))
  }
}

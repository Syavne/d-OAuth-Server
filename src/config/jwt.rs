//! JWT access-token signing configuration (`jwt_access_tokens_enabled`).
//!
//! The feature is a global kill-switch that defaults off. When a key is
//! configured it must be exactly 32 bytes of raw material and is turned into a
//! real JOSE signing key at load time: an out-of-range EC scalar fails at boot,
//! not at first mint. Key material never appears in `Debug`.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::ConfigError;
use crate::keys::KeyId;

/// Exactly 32 bytes of raw key material: `ES256` scalar or `Ed25519` seed.
pub(crate) const JWT_KEY_BYTES: usize = 32;

/// Allowed JWT access-token signing algorithms.
///
/// Both use exactly-32-byte raw key material. RSA is deliberately absent, so
/// there is no `RS256` branch and no PEM/modulus handling here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum JwtSigningAlg {
  /// ECDSA P-256 with SHA-256.
  #[default]
  #[serde(rename = "ES256")]
  Es256,
  /// Ed25519.
  #[serde(rename = "EdDSA")]
  EdDsa,
}

impl JwtSigningAlg {
  /// The JOSE `alg` name advertised in a public JWK (RFC 7517 §4.4).
  #[must_use]
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Es256 => "ES256",
      Self::EdDsa => "EdDSA",
    }
  }

  /// The `jsonwebtoken` algorithm this maps to.
  #[must_use]
  pub(crate) fn algorithm(self) -> Algorithm {
    match self {
      Self::Es256 => Algorithm::ES256,
      Self::EdDsa => Algorithm::EdDSA,
    }
  }
}

/// Public JWK coordinates of a [`JwtSigningKey`].
///
/// Derived from the same 32-byte raw material as the signing key, so the
/// `jwks_uri` document (task 28) can advertise exactly what this key verifies
/// with. Coordinates are public by construction and safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtPublicJwk {
  /// JWK `kty`: `"EC"` for P-256, `"OKP"` for Ed25519.
  pub kty: &'static str,
  /// JWK `crv`: `"P-256"` for P-256, `"Ed25519"` for Ed25519.
  pub crv: &'static str,
  /// Base64url-no-pad `x` coordinate (the Ed25519 public key).
  pub x: String,
  /// Base64url-no-pad `y` coordinate; `None` for `OKP` keys.
  pub y: Option<String>,
}

/// A validated JOSE signing key bound to a [`KeyId`].
///
/// The previous (rotated-out) keys use the same shape but are only ever used
/// to verify. No key material is printable.
#[derive(Clone)]
pub struct JwtSigningKey {
  kid: KeyId,
  alg: JwtSigningAlg,
  key: EncodingKey,
  decoding: DecodingKey,
  public: JwtPublicJwk,
}

impl JwtSigningKey {
  /// Build and validate a signing key from exactly 32 bytes of raw material.
  ///
  /// The raw bytes become a PKCS#8 document (P-256 scalar or Ed25519 seed) and
  /// a live [`EncodingKey`]. A probe signature is produced once so an
  /// out-of-range EC scalar or malformed material fails at load.
  ///
  /// # Errors
  /// Returns [`ConfigError::InvalidJwtSigningKey`] when the material cannot
  /// sign under `alg`.
  pub(crate) fn from_raw(
    kid: KeyId,
    alg: JwtSigningAlg,
    secret: &SecretString,
    field: &'static str,
  ) -> Result<Self, ConfigError> {
    let raw = secret.expose_secret().as_bytes();
    if alg == JwtSigningAlg::EdDsa && raw.iter().all(|byte| *byte == 0) {
      return Err(ConfigError::InvalidJwtSigningKey { key: field });
    }
    let der = Zeroizing::new(match alg {
      JwtSigningAlg::Es256 => p256_pkcs8(raw),
      JwtSigningAlg::EdDsa => ed25519_pkcs8(raw),
    });
    let key = match alg {
      JwtSigningAlg::Es256 => EncodingKey::from_ec_der(der.as_slice()),
      JwtSigningAlg::EdDsa => EncodingKey::from_ed_der(der.as_slice()),
    };
    encode(&Header::new(alg.algorithm()), &serde_json::json!({}), &key)
      .map_err(|_| ConfigError::InvalidJwtSigningKey { key: field })?;
    let (decoding, public) =
      derive_public(alg, raw).map_err(|()| ConfigError::InvalidJwtSigningKey { key: field })?;
    Ok(Self {
      kid,
      alg,
      key,
      decoding,
      public,
    })
  }

  /// The key id this key is stored under.
  #[must_use]
  pub fn kid(&self) -> &KeyId {
    &self.kid
  }

  /// The algorithm this key signs/verifies under.
  #[must_use]
  pub fn alg(&self) -> JwtSigningAlg {
    self.alg
  }

  /// The underlying JOSE signing key.
  #[must_use]
  pub fn encoding_key(&self) -> &EncodingKey {
    &self.key
  }

  /// The JOSE verification key for the public half of this key.
  #[must_use]
  pub fn decoding_key(&self) -> &DecodingKey {
    &self.decoding
  }

  /// The public JWK coordinates of this key (safe to advertise and log).
  #[must_use]
  pub fn public_jwk(&self) -> &JwtPublicJwk {
    &self.public
  }
}

impl fmt::Debug for JwtSigningKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("JwtSigningKey")
      .field("kid", &self.kid)
      .field("alg", &self.alg)
      .field("key", &"[REDACTED]")
      .finish()
  }
}

/// Derive the public verification key and JWK coordinates from the same
/// 32-byte raw material that built the signing key (`p256` scalar or
/// Ed25519 seed). The caller guarantees the length; the curve rejects an
/// out-of-range scalar.
fn derive_public(alg: JwtSigningAlg, raw: &[u8]) -> Result<(DecodingKey, JwtPublicJwk), ()> {
  match alg {
    JwtSigningAlg::Es256 => {
      use p256::elliptic_curve::sec1::ToEncodedPoint as _;
      let secret = p256::SecretKey::from_slice(raw).map_err(|_| ())?;
      let point = secret.public_key().to_encoded_point(false);
      let x = URL_SAFE_NO_PAD.encode(point.x().ok_or(())?);
      let y = URL_SAFE_NO_PAD.encode(point.y().ok_or(())?);
      let decoding = DecodingKey::from_ec_components(&x, &y).map_err(|_| ())?;
      let public = JwtPublicJwk {
        kty: "EC",
        crv: "P-256",
        x,
        y: Some(y),
      };
      Ok((decoding, public))
    }
    JwtSigningAlg::EdDsa => {
      let seed: [u8; JWT_KEY_BYTES] = raw.try_into().map_err(|_| ())?;
      let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
      let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
      let decoding = DecodingKey::from_ed_components(&x).map_err(|_| ())?;
      let public = JwtPublicJwk {
        kty: "OKP",
        crv: "Ed25519",
        x,
        y: None,
      };
      Ok((decoding, public))
    }
  }
}

/// Wrap a 32-byte P-256 scalar in an unencrypted PKCS#8 v1 document.
fn p256_pkcs8(scalar: &[u8]) -> Vec<u8> {
  const PREFIX: [u8; 35] = [
    0x30, 0x41, // SEQUENCE (PrivateKeyInfo)
    0x02, 0x01, 0x00, // version 0
    0x30, 0x13, // AlgorithmIdentifier
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
    0x04, 0x27, // privateKey OCTET STRING (39 bytes)
    0x30, 0x25, // ECPrivateKey SEQUENCE (37 bytes)
    0x02, 0x01, 0x01, // version 1
    0x04, 0x20, // privateKey OCTET STRING (32 bytes)
  ];
  let mut der = Vec::with_capacity(PREFIX.len() + scalar.len());
  der.extend_from_slice(&PREFIX);
  der.extend_from_slice(scalar);
  der
}

/// Wrap a 32-byte Ed25519 seed in an unencrypted PKCS#8 v1 document (RFC 8410).
fn ed25519_pkcs8(seed: &[u8]) -> Vec<u8> {
  const PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE (PrivateKeyInfo)
    0x02, 0x01, 0x00, // version 0
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // id-Ed25519
    0x04, 0x22, // privateKey OCTET STRING (34 bytes)
    0x04, 0x20, // inner seed OCTET STRING (32 bytes)
  ];
  let mut der = Vec::with_capacity(PREFIX.len() + seed.len());
  der.extend_from_slice(&PREFIX);
  der.extend_from_slice(seed);
  der
}

//! JWK helpers: RFC 7638 thumbprints for `jkt`/`x5t#S256`.
//!
//! Thumbprints identify `DPoP` keys and mTLS client certificates in `cnf`.
//! The [`thumbprint`] function implements RFC 7638 over the public members
//! of an embedded proof JWK; [`decoding_key`] builds a `jsonwebtoken`
//! verification key from the same object while refusing private or
//! symmetric material and enforcing the `alg`-to-key-type correspondence.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::error::AppError;

/// Failures while interpreting a proof-embedded JWK.
///
/// Every variant renders as `invalid_dpop_proof`; descriptions are fixed
/// strings that never echo key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwkError {
  /// The `jwk` value is not a JSON object.
  #[error("jwk is not an object")]
  NotAnObject,
  /// A required member is absent.
  #[error("jwk is missing a required member")]
  MissingMember(&'static str),
  /// A member is present but not a string (or not valid base64url).
  #[error("jwk member is malformed")]
  MalformedMember(&'static str),
  /// The JWK carries private or symmetric key material.
  #[error("jwk must not contain private key material")]
  PrivateMaterial,
  /// The `kty` is outside the allowlist (`EC`, `OKP`, `RSA`).
  #[error("jwk key type is not supported")]
  UnsupportedKty,
  /// The curve is outside the allowlist (`P-256`, `Ed25519`).
  #[error("jwk curve is not supported")]
  UnsupportedCurve,
  /// The header `alg` does not correspond to the JWK key type.
  #[error("jwk key type does not match the proof algorithm")]
  AlgorithmMismatch,
  /// An RSA modulus below the 2048-bit floor.
  #[error("rsa key is below the minimum size")]
  WeakRsaKey,
  /// The canonical thumbprint JSON could not be rendered.
  #[error("jwk could not be canonicalized")]
  Canonicalization,
}

impl From<JwkError> for AppError {
  /// Every JWK failure is a client-safe `invalid_dpop_proof` (RFC 9449 §9).
  fn from(error: JwkError) -> Self {
    Self::invalid_dpop_proof(error.to_string())
  }
}

/// Read a required string member of a JWK object.
fn member<'a>(
  object: &'a serde_json::Map<String, Value>,
  name: &'static str,
) -> Result<&'a str, JwkError> {
  object
    .get(name)
    .and_then(Value::as_str)
    .ok_or(JwkError::MissingMember(name))
}

/// Reject JWKs carrying private or symmetric material.
///
/// `d` (and the RSA CRT members) would let a proof smuggle a private key;
/// `k` is the symmetric secret itself. Either is refused before any
/// signature work, so an `oct` JWK can never become an HMAC key.
fn reject_private(object: &serde_json::Map<String, Value>) -> Result<(), JwkError> {
  const PRIVATE: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
  if PRIVATE.iter().any(|name| object.contains_key(*name)) {
    return Err(JwkError::PrivateMaterial);
  }
  Ok(())
}

/// Decode a base64url member and require an exact byte length.
fn fixed_bytes(
  object: &serde_json::Map<String, Value>,
  name: &'static str,
  expected: usize,
) -> Result<(), JwkError> {
  let raw = URL_SAFE_NO_PAD
    .decode(member(object, name)?)
    .map_err(|_| JwkError::MalformedMember(name))?;
  if raw.len() != expected {
    return Err(JwkError::MalformedMember(name));
  }
  Ok(())
}

/// Build a signature-verification key from a proof-embedded public JWK.
///
/// The `alg` allowlist (`ES256`/`EdDSA`/`RS256`) is enforced together with
/// the key-type correspondence: `ES256` needs `EC`/`P-256`, `EdDSA` needs
/// `OKP`/`Ed25519`, `RS256` needs `RSA` with a >= 2048-bit modulus.
/// Anything else — including `none`, HMAC families, and `oct` keys — is
/// rejected without ever verifying a signature.
pub fn decoding_key(alg: Algorithm, jwk: &Value) -> Result<DecodingKey, JwkError> {
  let object = jwk.as_object().ok_or(JwkError::NotAnObject)?;
  let kty = member(object, "kty")?;
  match kty {
    "EC" => {
      if alg != Algorithm::ES256 {
        return Err(JwkError::AlgorithmMismatch);
      }
      reject_private(object)?;
      if member(object, "crv")? != "P-256" {
        return Err(JwkError::UnsupportedCurve);
      }
      fixed_bytes(object, "x", 32)?;
      fixed_bytes(object, "y", 32)?;
      DecodingKey::from_ec_components(member(object, "x")?, member(object, "y")?)
        .map_err(|_| JwkError::MalformedMember("x"))
    }
    "OKP" => {
      if alg != Algorithm::EdDSA {
        return Err(JwkError::AlgorithmMismatch);
      }
      reject_private(object)?;
      if member(object, "crv")? != "Ed25519" {
        return Err(JwkError::UnsupportedCurve);
      }
      fixed_bytes(object, "x", 32)?;
      DecodingKey::from_ed_components(member(object, "x")?)
        .map_err(|_| JwkError::MalformedMember("x"))
    }
    "RSA" => {
      if alg != Algorithm::RS256 {
        return Err(JwkError::AlgorithmMismatch);
      }
      reject_private(object)?;
      let modulus = URL_SAFE_NO_PAD
        .decode(member(object, "n")?)
        .map_err(|_| JwkError::MalformedMember("n"))?;
      if modulus.len() < 256 {
        return Err(JwkError::WeakRsaKey);
      }
      DecodingKey::from_rsa_components(member(object, "n")?, member(object, "e")?)
        .map_err(|_| JwkError::MalformedMember("n"))
    }
    _ => Err(JwkError::UnsupportedKty),
  }
}

/// Compute the RFC 7638 JWK SHA-256 thumbprint, base64url-encoded.
///
/// Only the required public members enter the canonical form (`EC`:
/// `crv`/`kty`/`x`/`y`; `OKP`: `crv`/`kty`/`x`; `RSA`: `e`/`kty`/`n`),
/// serialized with lexicographic member order and no whitespace, then
/// hashed. The result is the `jkt` confirmation value (RFC 9449 §4.2).
pub fn thumbprint(jwk: &Value) -> Result<String, JwkError> {
  let object = jwk.as_object().ok_or(JwkError::NotAnObject)?;
  const SETS: [(&str, &[&str]); 3] = [
    ("EC", &["crv", "kty", "x", "y"]),
    ("OKP", &["crv", "kty", "x"]),
    ("RSA", &["e", "kty", "n"]),
  ];
  let kty = member(object, "kty")?;
  let members = SETS
    .iter()
    .find(|(kind, _)| *kind == kty)
    .map(|(_, names)| *names)
    .ok_or(JwkError::UnsupportedKty)?;
  let mut canonical = BTreeMap::new();
  for name in members {
    canonical.insert((*name).to_owned(), member(object, name)?.to_owned());
  }
  let json = serde_json::to_string(&canonical).map_err(|_| JwkError::Canonicalization)?;
  Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes())))
}

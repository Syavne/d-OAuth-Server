//! Signed request-object verification against the client JWKS.
//!
//! Rejects `alg:none` and symmetric algorithms, selects the verification
//! key by `kid` (or tries every key when unpinned), and enforces
//! `iss`/`aud`/`exp` through `jsonwebtoken` with zero clock-skew leeway.

use jsonwebtoken::{
  Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header,
  jwk::{Jwk, JwkSet},
};
use serde_json::Value;

use crate::{db::client_repo::Client, error::AppError};

/// `exp`/`nbf` clock-skew leeway in seconds. Zero: strict expiry.
const LEEWAY_SECS: u64 = 0;

/// Verify a signed request object and return its claim map.
///
/// # Errors
///
/// Returns `invalid_request_object` for an unparsable header, `alg:none`,
/// symmetric algorithms, unknown `kid`, signature failure, or `iss`/`aud`/
/// `exp` violations.
pub(crate) fn verify_request_object(
  client: &Client,
  issuer: &str,
  jwt: &str,
) -> Result<serde_json::Map<String, Value>, AppError> {
  let header = decode_header(jwt)
    .map_err(|_| AppError::invalid_request_object("request object header is malformed"))?;
  // Unsigned objects (`alg:none` fails header parsing above) and every
  // symmetric algorithm are rejected: client secrets are Argon2 hashes and
  // can never serve as HMAC keys, so no `oct` key is ever usable here.
  if header.alg.family() == AlgorithmFamily::Hmac {
    return Err(AppError::invalid_request_object(
      "symmetric request objects are not accepted",
    ));
  }
  let set = client
    .jwks
    .as_ref()
    .and_then(|jwks| serde_json::from_value::<JwkSet>(jwks.clone()).ok())
    .ok_or_else(|| AppError::invalid_request_object("client has no usable verification keys"))?;
  let candidates: Vec<&Jwk> = match header.kid {
    Some(ref kid) => set.find(kid).into_iter().collect(),
    None => set.keys.iter().collect(),
  };
  if candidates.is_empty() {
    return Err(AppError::invalid_request_object(
      "no verification key for the request object",
    ));
  }
  let mut validation = Validation::new(header.alg);
  validation.set_issuer(&[client.client_id.as_str()]);
  validation.set_audience(&[issuer]);
  validation.set_required_spec_claims(&["exp", "iss", "aud"]);
  validation.leeway = LEEWAY_SECS;
  validation.validate_exp = true;
  for key in candidates {
    if !key_alg_compatible(key, header.alg) {
      continue;
    }
    let decoding = match DecodingKey::from_jwk(key) {
      Ok(decoding) => decoding,
      Err(_) => continue,
    };
    if let Ok(data) = decode::<Value>(jwt, &decoding, &validation) {
      if let Some(object) = data.claims.as_object() {
        return Ok(object.clone());
      }
      return Err(AppError::invalid_request_object(
        "request object claims must be a JSON object",
      ));
    }
  }
  Err(AppError::invalid_request_object(
    "request object signature or claims are invalid",
  ))
}

/// Whether a JWK may verify `alg`: an absent key-level `alg` restriction
/// imposes nothing; a present one must name exactly `alg`.
fn key_alg_compatible(key: &Jwk, alg: Algorithm) -> bool {
  match &key.common.key_algorithm {
    None => true,
    Some(restriction) => {
      let restricted = serde_json::to_value(restriction).ok();
      let wanted = serde_json::to_value(alg).ok();
      match (restricted, wanted) {
        (Some(Value::String(have)), Some(Value::String(want))) => have == want,
        _ => false,
      }
    }
  }
}

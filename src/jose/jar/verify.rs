//! Signed request-object verification against the client JWKS.
//!
//! Rejects `alg:none` and every algorithm outside the `RS256`/`PS256`/
//! `ES256`/`EdDSA` allowlist, selects the verification
//! key by `kid` (or tries every key when unpinned), and enforces
//! `iss`/`aud`/`exp` through `jsonwebtoken` with zero clock-skew leeway.

use jsonwebtoken::{
  Algorithm, DecodingKey, Validation, decode, decode_header,
  jwk::{Jwk, JwkSet},
};
use serde_json::Value;

use crate::{db::client_repo::Client, error::AppError};

/// `exp`/`nbf` clock-skew leeway in seconds. Zero: strict expiry.
const LEEWAY_SECS: u64 = 0;

/// Allowed request-object signing algorithms (RFC 9101 §4.1 asymmetric
/// only; mirrors `protocol::client_auth::assertion::ALLOWED_ALGS`).
const ALLOWED_ALGS: [Algorithm; 4] = [
  Algorithm::RS256,
  Algorithm::PS256,
  Algorithm::ES256,
  Algorithm::EdDSA,
];

/// Verify a signed request object and return its claim map.
///
/// # Errors
///
/// Returns `invalid_request_object` for an unparsable header, `alg:none`,
/// a non-allowlisted algorithm, unknown `kid`, signature failure, or `iss`/`aud`/
/// `exp` violations.
pub(crate) fn verify_request_object(
  client: &Client,
  issuer: &str,
  jwt: &str,
) -> Result<serde_json::Map<String, Value>, AppError> {
  let header = decode_header(jwt)
    .map_err(|_| AppError::invalid_request_object("request object header is malformed"))?;
  // Unsigned objects (`alg:none` fails header parsing above) and every
  // algorithm outside the asymmetric allowlist are rejected before key
  // selection: client secrets are Argon2 hashes and can never serve as
  // HMAC keys, so no `oct` key is ever usable here.
  if !ALLOWED_ALGS.contains(&header.alg) {
    return Err(AppError::invalid_request_object(
      "request object signing algorithm is not allowed",
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

#[cfg(test)]
mod tests {
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

  use super::*;
  use crate::error::OAuthErrorCode;

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult = Result<(), TestError>;

  /// Errors raised by the `jar::verify` test scaffolding itself.
  #[derive(Debug, thiserror::Error)]
  enum TestError {
    /// The verifier rejected (or accepted) unexpectedly.
    #[error("verifier error")]
    App(#[from] AppError),
    /// A test assertion observed an unexpected value.
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  fn fixture() -> Client {
    Client {
      id: uuid::Uuid::nil(),
      client_id: "jar-verify-fixture".to_owned(),
      client_secret_expires_at: None,
      client_id_issued_at: time::OffsetDateTime::UNIX_EPOCH,
      client_name: "JAR Verify Fixture".to_owned(),
      grant_types: Vec::new(),
      response_types: Vec::new(),
      scope: String::new(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      access_token_format: "opaque".to_owned(),
      active: true,
      created_at: time::OffsetDateTime::UNIX_EPOCH,
      updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
  }

  fn forged_jwt(alg: &str) -> String {
    let header =
      URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": alg, "typ": "JWT" }).to_string());
    let payload =
      URL_SAFE_NO_PAD.encode(serde_json::json!({ "iss": "jar-verify-fixture" }).to_string());
    format!("{header}.{payload}.AAAA")
  }

  fn assert_rejected_at_allowlist(jwt: &str, alg: &str) -> TestResult {
    let client = fixture();
    match verify_request_object(&client, "https://issuer.example.test", jwt) {
      Ok(_) => Err(TestError::Unexpected(format!(
        "{alg} request object was accepted"
      ))),
      Err(err) => {
        assert_eq!(err.code(), OAuthErrorCode::InvalidRequestObject);
        if err.description().contains("algorithm is not allowed") {
          Ok(())
        } else {
          Err(TestError::Unexpected(format!(
            "{alg} unexpected description: {}",
            err.description()
          )))
        }
      }
    }
  }

  #[test]
  fn jar_verify_rejects_hs256_request_object() -> TestResult {
    assert_rejected_at_allowlist(&forged_jwt("HS256"), "HS256")
  }

  #[test]
  fn jar_verify_rejects_non_allowlisted_asymmetric_alg() -> TestResult {
    for alg in [
      "RS384", "RS512", "PS384", "PS512", "ES384", "HS384", "HS512",
    ] {
      assert_rejected_at_allowlist(&forged_jwt(alg), alg)?;
    }
    Ok(())
  }
}

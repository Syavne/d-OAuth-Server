//! `GET /jwks.json`: the public JWK Set for JWT access-token verification.
//!
//! Resource servers verify AS-minted `at+jwt` tokens (RFC 9068 §3) against the
//! public halves of the configured signing ring. The document is a JWK Set
//! (RFC 7517 §5): `{"keys": [...]}` with the current key first, then every
//! retained verify-only key. Each JWK carries `kid`, `kty`, `crv`, `x` (and
//! `y` for EC per RFC 7518 §6.2.1; OKP carries only `x` per RFC 8037 §2),
//! `use: "sig"`, and the configured `alg` (RFC 7517 §4.4). No private member
//! (`d`, its CRT parameters, or the symmetric `k`) is ever rendered.
//!
//! The route is public and read-only: these coordinates are public by
//! definition, and RFC 9068 §4 has resource servers fetch them without
//! credentials. Ordering is the configured key order, so the same ring yields
//! a byte-stable document an intermediary can reuse.
//!
//! With `jwt_access_tokens_enabled` off (or no key configured) the endpoint
//! still answers `200` with `{"keys":[]}`. An empty key array is a valid JWK
//! Set (RFC 7517 §5), it discloses nothing the disabled feature would not, and
//! it avoids a cacheable `404`: the security-headers middleware assigns the
//! short JWKS window by path, so a `404` would pin "not found" for five
//! minutes after the operator enables the feature.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use crate::jose::jwt_access::JwtAccessSigner;
use crate::state::AppState;

/// Media type registered for a JWK Set (RFC 7517 §8.5.1).
pub const JWKS_CONTENT_TYPE: &str = "application/jwk-set+json";

/// Build the JWK Set document from the signer's current and retained keys.
#[must_use]
pub fn key_set(signer: &JwtAccessSigner) -> Value {
  let keys: Vec<Value> = signer
    .public_keys()
    .map(|(kid, alg, public)| {
      let mut jwk = Map::new();
      jwk.insert("kty".to_owned(), json!(public.kty));
      jwk.insert("crv".to_owned(), json!(public.crv));
      jwk.insert("x".to_owned(), json!(public.x));
      if let Some(y) = &public.y {
        jwk.insert("y".to_owned(), json!(y));
      }
      jwk.insert("use".to_owned(), json!("sig"));
      jwk.insert("alg".to_owned(), json!(alg.as_str()));
      jwk.insert("kid".to_owned(), json!(kid.as_str()));
      Value::Object(jwk)
    })
    .collect();
  json!({ "keys": keys })
}

/// `GET /jwks.json`: render the public JWK Set.
pub async fn handler(State(state): State<AppState>) -> Response {
  let document = if state.config.jwt_access_tokens_enabled {
    match JwtAccessSigner::from_config(&state.config) {
      Ok(signer) => key_set(&signer),
      Err(_) => empty_set(),
    }
  } else {
    empty_set()
  };
  (
    StatusCode::OK,
    [(header::CONTENT_TYPE, JWKS_CONTENT_TYPE)],
    document.to_string(),
  )
    .into_response()
}

/// The deterministic no-keys document (see the module note on feature-off).
fn empty_set() -> Value {
  json!({ "keys": [] })
}

#[cfg(test)]
mod tests {
  use secrecy::SecretString;
  use serde_json::Value;

  use super::key_set;
  use crate::{
    config::{JwtSigningAlg, JwtSigningKey},
    jose::jwt_access::JwtAccessSigner,
    keys::KeyId,
  };

  type TestError = Box<dyn std::error::Error + Send + Sync>;

  /// A validated signing key from a repeated printable byte.
  fn signing_key(kid: &str, seed: char, alg: JwtSigningAlg) -> Result<JwtSigningKey, TestError> {
    let raw = SecretString::from(seed.to_string().repeat(32));
    Ok(JwtSigningKey::from_raw(
      KeyId::new(kid),
      alg,
      &raw,
      "jwt_signing_key",
    )?)
  }

  /// Current key first, retained key second, public members only.
  #[test]
  fn key_set_lists_current_then_retained() -> Result<(), TestError> {
    let current = signing_key("v2", 'c', JwtSigningAlg::Es256)?;
    let previous = signing_key("v1", 'd', JwtSigningAlg::Es256)?;
    let signer = JwtAccessSigner::new(
      "https://as.example.test".to_owned(),
      current,
      vec![previous],
    );
    let set = key_set(&signer);
    let keys = set["keys"].as_array().ok_or("JWK Set lacks keys")?;
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "v2");
    assert_eq!(keys[1]["kid"], "v1");
    for key in keys {
      assert_eq!(key["use"], "sig");
      assert_eq!(key["alg"], "ES256");
      assert_eq!(key["kty"], "EC");
      assert_eq!(key["crv"], "P-256");
      for coordinate in ["x", "y"] {
        assert!(
          key[coordinate]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
          "EC JWK must carry a non-empty {coordinate}"
        );
      }
      assert_no_private_members(key);
    }
    Ok(())
  }

  /// An Ed25519 ring renders `OKP`/`Ed25519` with `x` only (RFC 8037 §2).
  #[test]
  fn key_set_emits_okp_without_y() -> Result<(), TestError> {
    let current = signing_key("v1", 'e', JwtSigningAlg::EdDsa)?;
    let signer = JwtAccessSigner::new("https://as.example.test".to_owned(), current, Vec::new());
    let set = key_set(&signer);
    let keys = set["keys"].as_array().ok_or("JWK Set lacks keys")?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
    assert_eq!(keys[0]["use"], "sig");
    assert!(keys[0]["x"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(keys[0].get("y").is_none());
    assert_no_private_members(&keys[0]);
    Ok(())
  }

  /// RFC 7518 §6.2.1 private coordinates and the symmetric `k` never appear.
  fn assert_no_private_members(key: &Value) {
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
      assert!(
        key.get(private).is_none(),
        "private member {private} leaked"
      );
    }
  }
}

//! `private_key_jwt` client-auth fixture for `tests/e2e_edge_matrix.rs`.
//!
//! The harness `seed_client_bound` hardcodes `jwks: None`, so this module
//! seeds the row directly with an inline JWKS and signs assertions through the
//! same Ed25519 path the container suite uses.

use base64::Engine as _;
use d_oauth::db::{NewClient, TokenEndpointAuthMethod, client_repo};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};

use super::harness::{TestError, World, fail};

/// Base64url (no pad) for the Ed25519 public key.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Directly seeded `private_key_jwt` client.
pub const CLIENT_ID: &str = "e2e-edge-pkjwt";

/// An Ed25519 assertion signer plus the matching inline JWKS.
pub struct AssertionKey {
  /// PKCS#8 signer.
  encoding: EncodingKey,
  /// Public JWK set stored on the client row.
  jwks: Value,
}

impl AssertionKey {
  /// Generate one key pair and its inline JWKS.
  pub fn generate(kid: &str) -> Result<Self, TestError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| fail("ed25519 keygen failed"))?;
    let pair =
      Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| fail("ed25519 reload failed"))?;
    let x = B64.encode(pair.public_key().as_ref());
    Ok(Self {
      encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
      jwks: json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid}]}),
    })
  }

  /// The inline JWKS to store on the client row.
  #[must_use]
  pub fn jwks(&self) -> Value {
    self.jwks.clone()
  }

  /// Sign one assertion for `client_id`/`audience` with a fixed `jti`.
  pub fn mint(&self, client_id: &str, audience: &str, jti: &str) -> Result<String, TestError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({
      "iss": client_id,
      "sub": client_id,
      "aud": audience,
      "jti": jti,
      "exp": now + 300,
      "iat": now,
    });
    encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
      .map_err(|error| fail(format!("assertion mint failed: {error}")))
  }
}

/// Seed a `private_key_jwt` client row with an inline `jwks`.
pub async fn seed_assertion_client(world: &World, jwks: Value) -> Result<(), TestError> {
  let new = NewClient {
    id: uuid::Uuid::new_v4(),
    client_id: CLIENT_ID.to_owned(),
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: "edge private_key_jwt".to_owned(),
    grant_types: vec!["client_credentials".to_owned()],
    response_types: vec!["token".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt.as_str().to_owned(),
    jwks: Some(jwks),
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(&world.pool, &world.state.keys, false, &new).await?;
  Ok(())
}

//! `private_key_jwt` client authentication (RFC 7521/7523, RFC 9700 §2.5).
//!
//! The assertion is verified against the client's inline `jwks`, or against
//! `jwks_uri` fetched ONLY through the SSRF guard. Enforced: `alg`
//! allowlist (`RS256`/`ES256`/`EdDSA`; never `none`/HMAC), `typ`, `iss` and
//! `sub` equal to `client_id`, `aud` equal to the token endpoint, `exp`
//! with clock-skew leeway, and single-use `jti` via the
//! `oauth:client_assertion_jti:<hash>` replay store.

use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use time::OffsetDateTime;

use super::{AuthContext, AuthStores, AuthenticatedClient};
use crate::{
  db::{Client, TokenEndpointAuthMethod},
  error::AppError,
  protocol::ssrf,
  store::{self, dcr},
};

/// Allowed client-assertion signing algorithms (matches the metadata
/// `token_endpoint_auth_signing_alg_values_supported` allowlist).
const ALLOWED_ALGS: [Algorithm; 3] = [Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA];

/// Clock-skew leeway applied to `exp`/`nbf`/`iat` (seconds).
const CLOCK_SKEW_SECS: u64 = 30;

/// How long a consumed assertion `jti` stays reserved (bounded TTL).
const JTI_TTL: Duration = Duration::from_secs(300);

/// Maximum assertion compact-serialization length accepted.
const MAX_ASSERTION_BYTES: usize = 16 * 1024;

/// Maximum `jti` length accepted (unbounded ids become unbounded keys).
const MAX_JTI_LEN: usize = 256;

/// `aud` is either a single string or an array of strings (RFC 7523 §3).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
  /// A single audience value.
  One(String),
  /// Several audience values; one must be the token endpoint.
  Many(Vec<String>),
}

impl Aud {
  /// Whether `token_endpoint` is among the audiences (exact match only).
  fn contains(&self, token_endpoint: &str) -> bool {
    match self {
      Self::One(one) => one == token_endpoint,
      Self::Many(many) => many.iter().any(|a| a == token_endpoint),
    }
  }
}

/// Registered claims of a `private_key_jwt` assertion (RFC 7523 §3).
#[derive(Debug, Deserialize)]
struct AssertionClaims {
  /// Issuer: must equal `client_id`.
  iss: String,
  /// Subject: must equal `client_id`.
  sub: String,
  /// Audience: must contain the token endpoint.
  aud: Aud,
  /// Unique id: single-use via the replay store.
  jti: String,
  /// Expiry (Unix seconds, enforced with leeway).
  exp: i64,
  /// Issued-at (Unix seconds, optional; when present must be sane).
  iat: Option<i64>,
}

/// A verified assertion: the `jti` hash reserved for the replay claim.
#[derive(Debug)]
pub struct ValidatedAssertion {
  /// Hex hash of the `jti`, the replay-store key suffix.
  pub jti_hash: String,
}

/// Read `iss` from an assertion WITHOUT verifying the signature.
///
/// Used only to locate the candidate client row; every security decision
/// happens in [`validate_assertion`] after signature verification.
#[must_use]
pub fn unverified_iss(assertion: &str) -> Option<String> {
  use base64::Engine as _;

  let payload = assertion.split('.').nth(1)?;
  let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(payload)
    .ok()?;
  let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
  value
    .get("iss")
    .and_then(|iss| iss.as_str())
    .map(str::to_owned)
}

/// Resolve the client's JWKS document: inline `jwks` preferred, else fetch
/// `jwks_uri` through the SSRF guard. A client with neither is rejected.
async fn resolve_jwks(client: &Client) -> Result<serde_json::Value, AppError> {
  if let Some(inline) = client.jwks.clone() {
    return Ok(inline);
  }
  if let Some(uri) = client.jwks_uri.as_deref() {
    return ssrf::fetch_guarded_json(uri)
      .await
      .map_err(|_| AppError::invalid_client_non_basic());
  }
  Err(AppError::invalid_client_non_basic())
}

/// Verify the assertion signature and claims (no I/O).
///
/// Every failure maps to `invalid_client` (400: assertions travel in the
/// body, never via Basic).
pub fn validate_assertion(
  assertion: &str,
  jwks_doc: &serde_json::Value,
  client_id: &str,
  token_endpoint: &str,
  now: OffsetDateTime,
) -> Result<ValidatedAssertion, AppError> {
  let invalid = AppError::invalid_client_non_basic;
  if assertion.len() > MAX_ASSERTION_BYTES {
    return Err(invalid());
  }
  let header = decode_header(assertion).map_err(|_| invalid())?;
  if !ALLOWED_ALGS.contains(&header.alg) {
    return Err(invalid());
  }
  if header.typ.as_deref() != Some("JWT") {
    return Err(invalid());
  }
  // `jku`/`x5u` are fetch directives: never honored (SSRF bypass), so a
  // token carrying them is rejected outright.
  if header.jku.is_some() || header.x5u.is_some() {
    return Err(invalid());
  }

  let set: jsonwebtoken::jwk::JwkSet =
    serde_json::from_value(jwks_doc.clone()).map_err(|_| invalid())?;
  if set.keys.is_empty() {
    return Err(invalid());
  }
  let wanted = header.kid.clone().unwrap_or_default();
  let mut candidates: Vec<DecodingKey> = Vec::new();
  for key in &set.keys {
    if (wanted.is_empty() || key.common.key_id.as_deref() == Some(wanted.as_str()))
      && let Ok(decoding) = DecodingKey::try_from(key)
    {
      candidates.push(decoding);
    }
  }
  // Without a `kid` the set must hold exactly one usable key; otherwise the
  // assertion does not name its key.
  if candidates.len() != 1 {
    return Err(invalid());
  }
  let Some(decoding) = candidates.pop() else {
    return Err(invalid());
  };

  let mut validation = Validation::new(header.alg);
  validation.leeway = CLOCK_SKEW_SECS;
  validation.validate_exp = true;
  validation.validate_nbf = true;
  validation.set_required_spec_claims(&["exp"]);
  validation.validate_aud = false;
  let claims = decode::<AssertionClaims>(assertion, &decoding, &validation)
    .map_err(|_| invalid())?
    .claims;

  if claims.iss != client_id || claims.sub != client_id {
    return Err(invalid());
  }
  if !claims.aud.contains(token_endpoint) {
    return Err(invalid());
  }
  if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_LEN {
    return Err(invalid());
  }
  let skew = i64::try_from(CLOCK_SKEW_SECS).unwrap_or(i64::MAX);
  let now_secs = now.unix_timestamp();
  if claims.exp.saturating_add(skew) < now_secs {
    return Err(invalid());
  }
  if let Some(iat) = claims.iat
    && iat > now_secs.saturating_add(skew)
  {
    return Err(invalid());
  }
  Ok(ValidatedAssertion {
    jti_hash: store::sha256_hex(claims.jti.as_bytes()),
  })
}

/// Authenticate a client by `private_key_jwt`: resolve JWKS, verify the
/// assertion, then single-use claim its `jti` (replay → `invalid_client`).
///
/// # Errors
///
/// Returns `invalid_client` for any verification, fetch-guard, or replay
/// failure; internal errors only surface when the replay store itself fails
/// in a non-client-attributable way (mapped by the store layer).
pub async fn authenticate(
  stores: &mut AuthStores<'_>,
  client: &Client,
  assertion_str: &str,
  ctx: &AuthContext<'_>,
) -> Result<AuthenticatedClient, AppError> {
  let jwks_doc = resolve_jwks(client).await?;
  let validated = validate_assertion(
    assertion_str,
    &jwks_doc,
    &client.client_id,
    ctx.token_endpoint,
    ctx.now,
  )?;
  let claimed =
    dcr::claim_client_assertion_jti(stores.conn, stores.store, &validated.jti_hash, JTI_TTL)
      .await?;
  if !claimed {
    return Err(AppError::invalid_client_non_basic());
  }
  Ok(AuthenticatedClient {
    client: client.clone(),
    method: TokenEndpointAuthMethod::PrivateKeyJwt,
  })
}

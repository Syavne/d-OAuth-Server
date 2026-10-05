//! `DPoP` proof verification and `jkt` binding (RFC 9449).
//!
//! Verifies the proof JWT, enforces `htm`/`htu`/freshness, caches `jti`
//! replay markers, and binds the grant/token to the proof key (`cnf.jkt`).

#[cfg(test)]
mod reject;
#[cfg(test)]
mod reject_key;
#[cfg(test)]
mod support;
#[cfg(test)]
mod tests;

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::jwk::{decoding_key, thumbprint};
use crate::{
  crypto::ct::ct_eq,
  error::AppError,
  state::RedisConn,
  store::{self, Store},
};

/// Required JOSE header `typ` for a `DPoP` proof (RFC 9449 §4.2).
pub const DPOP_TYP: &str = "dpop+jwt";
/// How far back a proof `iat` may lie (seconds).
pub const DPOP_IAT_WINDOW_SECS: i64 = 60;
/// How far in the future a proof `iat` may lie (clock-skew tolerance).
pub const DPOP_FUTURE_SKEW_SECS: i64 = 30;
/// `jti` replay-marker TTL: bounds marker growth while comfortably
/// outliving the acceptance window above.
pub const DPOP_JTI_TTL: Duration = Duration::from_secs(300);
/// Upper bound on the proof JWT size (DoS hygiene; real proofs are ~1 KiB).
pub const MAX_PROOF_LEN: usize = 8192;

/// One `DPoP` proof verification request.
///
/// `htu` is the server's own request URI (query and fragment are stripped
/// before comparison); `access_token` is `Some` only for resource-bound
/// use, where the proof must carry a matching `ath`. `now_unix` is the
/// caller's clock, so tests pin time without a clock seam.
pub struct DpopRequest<'a> {
  /// The raw proof JWT, or `None` when the client sent no `DPoP` header.
  pub proof: Option<&'a str>,
  /// Expected HTTP method (e.g. `"POST"`), compared exactly.
  pub htm: &'a str,
  /// Expected HTTP URI (query/fragment ignored), compared exactly.
  pub htu: &'a str,
  /// Access token the proof is presented with, if any.
  pub access_token: Option<&'a str>,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// A verified `DPoP` proof: the key binding plus the consumed replay marker.
pub struct VerifiedDpop {
  /// RFC 7638 thumbprint of the proof key: the `cnf.jkt` binding value.
  pub jkt: String,
  /// The consumed `jti` (now marked in the replay store).
  pub jti: String,
  /// The proof `iat`, for audit.
  pub iat: i64,
}

/// `DPoP` proof claims (RFC 9449 §4.2). Every member is optional here so a
/// missing member maps to its own `invalid_dpop_proof` description instead
/// of a generic decode failure; mistyped members still fail the decode.
#[derive(Debug, Deserialize)]
struct DpopClaims {
  /// Unique identifier for this proof (replay marker).
  jti: Option<String>,
  /// HTTP method the proof is bound to.
  htm: Option<String>,
  /// HTTP URI the proof is bound to (no query or fragment).
  htu: Option<String>,
  /// Issued-at, seconds since the Unix epoch.
  iat: Option<i64>,
  /// Base64url SHA-256 of the access token (resource-bound use only).
  ath: Option<String>,
  /// Embedded public JWK the proof is signed with.
  jwk: Option<serde_json::Value>,
}

/// Strip the query and fragment from a URI; `DPoP` `htu` excludes both.
fn strip_query_fragment(url: &str) -> &str {
  let end = url.find(['?', '#']).unwrap_or(url.len());
  &url[..end]
}

/// Verify a `DPoP` proof and return its `cnf.jkt` binding.
///
/// Order is load-bearing: the signature is verified against the embedded
/// `jwk` before any claim is trusted, and the `jti` replay marker is
/// claimed only after every other check passes, so invalid proofs never
/// consume store writes. Any failure is `invalid_dpop_proof` (RFC 9449 §9);
///
/// a Redis failure maps through the store error type (fail closed).
pub async fn verify_dpop(
  conn: &mut RedisConn,
  store: &Store,
  request: &DpopRequest<'_>,
) -> Result<VerifiedDpop, AppError> {
  let proof = request
    .proof
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing"))?;
  if proof.len() > MAX_PROOF_LEN {
    return Err(AppError::invalid_dpop_proof("DPoP proof is too large"));
  }
  let segments: Vec<&str> = proof.split('.').collect();
  if segments.len() != 3 {
    return Err(AppError::invalid_dpop_proof("DPoP proof is malformed"));
  }

  let header =
    decode_header(proof).map_err(|_| AppError::invalid_dpop_proof("DPoP proof is malformed"))?;
  if !matches!(
    header.alg,
    Algorithm::ES256 | Algorithm::EdDSA | Algorithm::RS256
  ) {
    return Err(AppError::invalid_dpop_proof(
      "DPoP proof uses an unsupported algorithm",
    ));
  }
  if header.typ.as_deref() != Some(DPOP_TYP) {
    return Err(AppError::invalid_dpop_proof(
      "DPoP proof has an invalid type",
    ));
  }

  // The embedded JWK selects the verification key. RFC 9449 §4.2 puts it in
  // the JOSE header; a payload `jwk` is also accepted for compatibility. The
  // key is self-asserted either way: possession is proven by the signature
  // over header plus payload, and the thumbprint is read only after the
  // signature verifies.
  let header_json: serde_json::Value = URL_SAFE_NO_PAD
    .decode(segments[0])
    .ok()
    .and_then(|raw| serde_json::from_slice(&raw).ok())
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is malformed"))?;
  let payload: serde_json::Value = URL_SAFE_NO_PAD
    .decode(segments[1])
    .ok()
    .and_then(|raw| serde_json::from_slice(&raw).ok())
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is malformed"))?;
  let unverified_jwk = header_json
    .get("jwk")
    .or_else(|| payload.get("jwk"))
    .cloned()
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing jwk"))?;
  let key = decoding_key(header.alg, &unverified_jwk)?;

  // `DPoP` proofs carry `iat`, never `exp`: disable every time claim the
  // library would otherwise require so only the manual window below rules.
  let mut validation = Validation::new(header.alg);
  validation.validate_exp = false;
  validation.required_spec_claims.clear();
  let claims = decode::<DpopClaims>(proof, &key, &validation)
    .map_err(|_| AppError::invalid_dpop_proof("DPoP proof signature is invalid"))?
    .claims;
  let jwk = claims.jwk.unwrap_or(unverified_jwk);
  let htm = claims
    .htm
    .filter(|value| !value.is_empty())
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing htm"))?;
  let htu = claims
    .htu
    .filter(|value| !value.is_empty())
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing htu"))?;
  let jti = claims
    .jti
    .filter(|value| !value.is_empty())
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing jti"))?;
  let iat = claims
    .iat
    .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is missing iat"))?;

  if htm != request.htm {
    return Err(AppError::invalid_dpop_proof("DPoP proof htm mismatch"));
  }
  // The proof `htu` must already exclude query and fragment (RFC 9449
  // §4.2); the server side strips them from its own request URI.
  if htu.find(['?', '#']).is_some() || htu != strip_query_fragment(request.htu) {
    return Err(AppError::invalid_dpop_proof("DPoP proof htu mismatch"));
  }
  let age = request.now_unix.saturating_sub(iat);
  if !(-DPOP_FUTURE_SKEW_SECS..=DPOP_IAT_WINDOW_SECS).contains(&age) {
    return Err(AppError::invalid_dpop_proof(
      "DPoP proof is outside the freshness window",
    ));
  }
  if let Some(token) = request.access_token {
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    let bound = claims
      .ath
      .as_ref()
      .is_some_and(|got| ct_eq(got.as_bytes(), expected.as_bytes()));
    if !bound {
      return Err(AppError::invalid_dpop_proof(
        "DPoP proof access-token hash mismatch",
      ));
    }
  }

  // Last step: first claimant wins (`SET NX` with a bounded TTL, so markers
  // cannot grow without bound); a lost race is a replay.
  let jti_hash = store::sha256_hex(jti.as_bytes());
  let fresh = crate::store::dcr::claim_dpop_jti(conn, store, &jti_hash, DPOP_JTI_TTL).await?;
  if !fresh {
    return Err(AppError::invalid_dpop_proof(
      "DPoP proof jti was already used",
    ));
  }

  Ok(VerifiedDpop {
    jkt: thumbprint(&jwk)?,
    jti,
    iat,
  })
}

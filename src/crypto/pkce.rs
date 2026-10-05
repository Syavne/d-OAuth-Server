//! PKCE S256 verification (RFC 9700: mandatory for every authorization-code flow).
//!
//! Only `S256` is accepted: `plain` and unknown methods are rejected. The
//! challenge is bound to the grant at issuance and re-verified at the token
//! endpoint with downgrade protection — a present challenge demands a present
//! verifier, and a present verifier demands a stored challenge, so neither side
//! can be dropped to weaken the binding.
//!
//! Every verifier is validated for the RFC 7636 §4.1 charset and 43–128 length
//! before use, and the digest is compared through [`ct_eq`](super::ct::ct_eq),
//! never `==`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

use super::ct::ct_eq;

/// Minimum `code_verifier` length (RFC 7636 §4.1).
pub const VERIFIER_MIN_LEN: usize = 43;
/// Maximum `code_verifier` length (RFC 7636 §4.1).
pub const VERIFIER_MAX_LEN: usize = 128;
/// Exact S256 `code_challenge` length: base64url-nopad of a 32-byte digest.
pub const CHALLENGE_LEN: usize = 43;
/// The only accepted `code_challenge_method` (RFC 9700 §2.1.1).
pub const S256_METHOD: &str = "S256";

/// Errors from PKCE method validation and challenge verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PkceError {
  /// `plain` or any method other than `S256` was requested.
  #[error("unsupported code_challenge_method; only S256 is accepted")]
  UnsupportedMethod,
  /// A challenge was supplied without its verifier (downgrade attempt).
  #[error("code_challenge present without code_verifier")]
  MissingVerifier,
  /// A verifier was supplied without a stored challenge (downgrade attempt).
  #[error("code_verifier present without code_challenge")]
  MissingChallenge,
  /// The verifier violates the RFC 7636 §4.1 length or charset.
  #[error("malformed code_verifier")]
  MalformedVerifier,
  /// The challenge is not a 43-character base64url S256 digest.
  #[error("malformed code_challenge")]
  MalformedChallenge,
  /// The verifier does not hash to the challenge.
  #[error("code_verifier does not match code_challenge")]
  Mismatch,
}

/// Validate an authorize-time `code_challenge_method`.
///
/// # Errors
///
/// Returns [`PkceError::UnsupportedMethod`] for `plain` or any unknown value;
/// only the exact, case-sensitive `"S256"` is accepted.
pub fn verify_method(method: &str) -> Result<(), PkceError> {
  if method == S256_METHOD {
    Ok(())
  } else {
    Err(PkceError::UnsupportedMethod)
  }
}

/// Derive the S256 challenge `BASE64URL-NOPAD(SHA256(ASCII(verifier)))`.
///
/// # Errors
///
/// Returns [`PkceError::MalformedVerifier`] when the verifier is outside the
/// RFC 7636 §4.1 bounds (43–128 characters from `ALPHA / DIGIT / "-" / "." /
/// "_" / "~"`).
pub fn challenge_from_verifier(verifier: &str) -> Result<String, PkceError> {
  if !is_valid_verifier(verifier) {
    return Err(PkceError::MalformedVerifier);
  }
  Ok(URL_SAFE_NO_PAD.encode(s256_digest(verifier)))
}

/// Verify a `code_verifier` against a stored S256 `code_challenge`.
///
/// The recomputed digest is compared with [`ct_eq`](super::ct::ct_eq); `==` is
/// never used on the digest bytes.
///
/// # Errors
///
/// Returns [`PkceError::MalformedVerifier`] or
/// [`PkceError::MalformedChallenge`] for out-of-spec inputs, and
/// [`PkceError::Mismatch`] when the digests differ.
pub fn verify_s256(verifier: &str, challenge: &str) -> Result<(), PkceError> {
  if !is_valid_verifier(verifier) {
    return Err(PkceError::MalformedVerifier);
  }
  if challenge.len() != CHALLENGE_LEN
    || !challenge
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
  {
    return Err(PkceError::MalformedChallenge);
  }
  let expected = URL_SAFE_NO_PAD.encode(s256_digest(verifier));
  if ct_eq(expected.as_bytes(), challenge.as_bytes()) {
    Ok(())
  } else {
    Err(PkceError::Mismatch)
  }
}

/// Verify PKCE at the token endpoint with downgrade protection.
///
/// `challenge` is the value stored with the grant (always an S256 challenge
/// under this server); `verifier` is the client-supplied `code_verifier`.
/// Presence must be symmetric — a challenge without a verifier and a verifier
/// without a challenge are both rejected, and PKCE is mandatory, so neither
/// present is rejected too. Empty strings count as absent.
///
/// # Errors
///
/// Returns [`PkceError::MissingVerifier`] or [`PkceError::MissingChallenge`]
/// for an asymmetric (downgrade) pair, otherwise the [`verify_s256`] error.
pub fn verify(verifier: Option<&str>, challenge: Option<&str>) -> Result<(), PkceError> {
  match (non_empty(verifier), non_empty(challenge)) {
    (Some(verifier), Some(challenge)) => verify_s256(verifier, challenge),
    (None, Some(_)) => Err(PkceError::MissingVerifier),
    (Some(_), None) => Err(PkceError::MissingChallenge),
    (None, None) => Err(PkceError::MissingChallenge),
  }
}

/// The 32-byte SHA-256 digest of the verifier's ASCII bytes.
fn s256_digest(verifier: &str) -> [u8; 32] {
  let digest = Sha256::digest(verifier.as_bytes());
  let mut out = [0u8; 32];
  out.copy_from_slice(digest.as_slice());
  out
}

/// RFC 7636 §4.1: 43–128 characters from the unreserved set
/// `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_valid_verifier(verifier: &str) -> bool {
  (VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&verifier.len())
    && verifier
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Treat `None` and `""` alike: an absent parameter.
fn non_empty(value: Option<&str>) -> Option<&str> {
  value.filter(|s| !s.is_empty())
}

#[cfg(test)]
mod crypto_tests {
  use super::*;

  /// RFC 7636 Appendix B test vector.
  const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  #[test]
  fn pkce_rfc7636_vector_verifies() -> Result<(), PkceError> {
    assert_eq!(RFC_VERIFIER.len(), VERIFIER_MIN_LEN);
    assert_eq!(challenge_from_verifier(RFC_VERIFIER)?, RFC_CHALLENGE);
    verify_s256(RFC_VERIFIER, RFC_CHALLENGE)
  }

  #[test]
  fn pkce_wrong_verifier_rejected() {
    // Same shape as the RFC vector, different first byte.
    let wrong = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(wrong.len(), RFC_VERIFIER.len());
    assert_eq!(verify_s256(wrong, RFC_CHALLENGE), Err(PkceError::Mismatch));
  }

  #[test]
  fn pkce_plain_method_rejected() {
    assert_eq!(verify_method("plain"), Err(PkceError::UnsupportedMethod));
    assert_eq!(verify_method("s256"), Err(PkceError::UnsupportedMethod));
    assert_eq!(verify_method("S512"), Err(PkceError::UnsupportedMethod));
    assert_eq!(verify_method(""), Err(PkceError::UnsupportedMethod));
    assert_eq!(verify_method(S256_METHOD), Ok(()));
  }

  #[test]
  fn pkce_short_verifier_rejected() {
    let short = &RFC_VERIFIER[..VERIFIER_MIN_LEN - 1];
    assert_eq!(short.len(), VERIFIER_MIN_LEN - 1);
    assert_eq!(
      verify_s256(short, RFC_CHALLENGE),
      Err(PkceError::MalformedVerifier)
    );
    assert_eq!(
      challenge_from_verifier(short),
      Err(PkceError::MalformedVerifier)
    );
  }

  #[test]
  fn pkce_verifier_without_challenge_rejected() {
    assert_eq!(
      verify(Some(RFC_VERIFIER), None),
      Err(PkceError::MissingChallenge)
    );
    assert_eq!(
      verify(Some(RFC_VERIFIER), Some("")),
      Err(PkceError::MissingChallenge)
    );
  }

  #[test]
  fn pkce_challenge_without_verifier_rejected() {
    assert_eq!(
      verify(None, Some(RFC_CHALLENGE)),
      Err(PkceError::MissingVerifier)
    );
    assert_eq!(
      verify(Some(""), Some(RFC_CHALLENGE)),
      Err(PkceError::MissingVerifier)
    );
  }

  #[test]
  fn pkce_verifier_and_challenge_both_absent_rejected() {
    assert_eq!(verify(None, None), Err(PkceError::MissingChallenge));
  }

  #[test]
  fn pkce_verifier_charset_and_length_bounds() -> Result<(), PkceError> {
    let mut bad_charset = "a".repeat(VERIFIER_MIN_LEN);
    bad_charset.pop();
    bad_charset.push(' ');
    assert_eq!(
      verify_s256(&bad_charset, RFC_CHALLENGE),
      Err(PkceError::MalformedVerifier)
    );

    let max = "A".repeat(VERIFIER_MAX_LEN);
    assert!(verify_s256(&max, &challenge_from_verifier(&max)?).is_ok());
    let too_long = "A".repeat(VERIFIER_MAX_LEN + 1);
    assert_eq!(
      verify_s256(&too_long, RFC_CHALLENGE),
      Err(PkceError::MalformedVerifier)
    );
    Ok(())
  }

  #[test]
  fn pkce_malformed_challenge_rejected() {
    assert_eq!(
      verify_s256(RFC_VERIFIER, &RFC_CHALLENGE[..CHALLENGE_LEN - 1]),
      Err(PkceError::MalformedChallenge)
    );
    let bad_charset = "!".repeat(CHALLENGE_LEN);
    assert_eq!(
      verify_s256(RFC_VERIFIER, &bad_charset),
      Err(PkceError::MalformedChallenge)
    );
  }
}

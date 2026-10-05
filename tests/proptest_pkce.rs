//! `test(proptest_pkce)` — PKCE round-trip property suite (task 42).
//!
//! Properties over `crypto::pkce` (RFC 7636 S256, mandatory under RFC 9700):
//! a derived challenge always verifies, a tampered challenge never does,
//! presence is symmetric (downgrade protection), and malformed verifiers are
//! rejected at derivation. No `unwrap`/`expect`/`panic` anywhere.

use d_oauth::crypto::pkce::{PkceError, challenge_from_verifier, verify, verify_s256};
use proptest::prelude::*;

/// RFC 7636 §4.1 verifier alphabet, 43–128 characters.
fn verifier() -> impl Strategy<Value = String> {
  "[A-Za-z0-9_.~-]{43,128}"
}

proptest! {
  #[test]
  fn pkce_challenge_round_trips(v in verifier()) {
    match challenge_from_verifier(&v) {
      Ok(challenge) => {
        prop_assert_eq!(challenge.len(), 43);
        prop_assert!(verify_s256(&v, &challenge).is_ok());
        prop_assert!(verify(Some(&v), Some(&challenge)).is_ok());
      }
      Err(_) => prop_assert!(false, "alphabet verifier must derive: {:?}", v),
    }
  }

  #[test]
  fn pkce_tampered_challenge_never_verifies(
    v in verifier(),
    tamper_at in 0..43_usize,
    replacement in "[A-Za-z0-9_-]",
  ) {
    let challenge = match challenge_from_verifier(&v) {
      Ok(challenge) => challenge,
      Err(_) => return Ok(()),
    };
    let mut tampered = challenge.clone();
    tampered.replace_range(tamper_at..tamper_at + 1, &replacement);
    if tampered == challenge {
      return Ok(());
    }
    // A changed challenge is either malformed or a digest mismatch — never
    // accepted.
    prop_assert!(verify_s256(&v, &tampered).is_err());
    prop_assert!(verify(Some(&v), Some(&tampered)).is_err());
  }

  #[test]
  fn pkce_presence_is_symmetric(v in verifier()) {
    let challenge = match challenge_from_verifier(&v) {
      Ok(challenge) => challenge,
      Err(_) => return Ok(()),
    };
    // Asymmetric presence is a downgrade attempt and always fails.
    prop_assert_eq!(verify(Some(&v), None), Err(PkceError::MissingChallenge));
    prop_assert_eq!(
      verify(None, Some(&challenge)),
      Err(PkceError::MissingVerifier)
    );
    // PKCE is mandatory: absent on both sides fails closed too.
    prop_assert!(verify(None, None).is_err());
  }

  #[test]
  fn pkce_malformed_verifiers_are_rejected(raw in "\\PC{0,200}") {
    if challenge_from_verifier(&raw).is_ok() {
      // Accepted values satisfy the §4.1 grammar by construction.
      prop_assert!((43..=128).contains(&raw.len()));
      prop_assert!(
        raw
          .bytes()
          .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
      );
    }
  }
}

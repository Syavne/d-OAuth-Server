//! Fuzz PKCE S256 derivation and verification (`crypto::pkce`).
//!
//! The input is a verifier line; anything after a newline is an arbitrary
//! presented challenge. [`challenge_from_verifier`] accepts only the RFC 7636
//! §4.1 verifier shape; when it derives a challenge, the same verifier must
//! verify against it, and a one-character challenge tamper must fail.

#![no_main]

use d_oauth::crypto::pkce::{challenge_from_verifier, verify_s256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let (verifier, presented) = match text.split_once('\n') {
    Some((verifier, presented)) => (verifier, Some(presented)),
    None => (text, None),
  };

  if let Ok(challenge) = challenge_from_verifier(verifier) {
    assert!(
      verify_s256(verifier, &challenge).is_ok(),
      "a derived S256 challenge did not verify"
    );

    // Flip one base64url character; the digest can no longer match.
    if let Some(first) = challenge.as_bytes().first().copied() {
      let replacement = if first == b'A' { "B" } else { "A" };
      let mut tampered = challenge.clone();
      tampered.replace_range(0..1, replacement);
      assert!(
        verify_s256(verifier, &tampered).is_err(),
        "a one-character tampered challenge verified"
      );
    }
  }

  // Exercise the verifier against an arbitrary presented challenge.
  if let Some(presented) = presented {
    let _ = verify_s256(verifier, presented);
  }
});

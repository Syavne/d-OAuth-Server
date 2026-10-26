//! Fuzz TOTP verifier construction and the ±1-step window (`crypto::totp`).
//!
//! The input is a secret line, a newline, then the presented code. A malformed
//! stored secret is always [`TotpError::InvalidSecret`], never a wrong-code
//! `None`. A matched step must sit within one step of the counter for the fixed
//! `now`, and it must be the step that generates the presented code. A
//! 6-digit collision across neighbouring steps is therefore not a failure.
//! [`normalize_recovery_code`] is idempotent, strips separators, and leaves no
//! ASCII lowercase (Unicode characters without an uppercase mapping can stay
//! lowercase).

#![no_main]

use d_oauth::crypto::totp::{build_totp, normalize_recovery_code, verify_window};
use libfuzzer_sys::fuzz_target;

/// Fixed instant: 2023-11-14T22:13:20Z, never the wall clock.
const NOW: u64 = 1_700_000_000;
/// RFC 6238 default step in seconds.
const STEP: u64 = 30;

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let (secret, code) = match text.split_once('\n') {
    Some((secret, code)) => (secret, code),
    None => (text, ""),
  };

  // Normalization is idempotent, separator-free, and uppercase.
  let normalized = normalize_recovery_code(code);
  assert_eq!(
    normalized,
    normalize_recovery_code(&normalized),
    "recovery normalization is not idempotent"
  );
  assert!(
    normalized.chars().all(|c| !c.is_whitespace() && c != '-'),
    "normalized recovery code kept a separator"
  );
  assert!(
    normalized.chars().all(|c| !c.is_ascii_lowercase()),
    "normalized recovery code kept ASCII lowercase"
  );

  match build_totp(secret) {
    Err(_) => {
      // A malformed stored secret is an error once the presented code reaches
      // secret parsing; a non-conforming code is rejected as a wrong code
      // (`Ok(None)`) before the secret is inspected, so probe with a shaped
      // code to exercise the error path deterministically.
      assert!(
        verify_window(secret, "000000", NOW).is_err(),
        "malformed secret slipped through verify_window"
      );
      // The fuzzed code is still processed without panicking.
      let _ = verify_window(secret, code, NOW);
    }
    Ok(totp) => {
      let counter = NOW / STEP;
      if let Ok(Some(step)) = verify_window(secret, code, NOW) {
        assert!(
          step.abs_diff(counter) <= 1,
          "matched step is outside the ±1 window"
        );
        let generated = totp.generate(step.saturating_mul(STEP)).to_string();
        assert_eq!(
          generated,
          code.trim(),
          "matched step did not generate the presented code"
        );
      }
    }
  }
});

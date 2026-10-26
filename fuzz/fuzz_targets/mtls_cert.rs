//! Fuzz mTLS leaf-certificate parsing (`tls_client_auth`, RFC 8705).
//!
//! Arbitrary DER is hostile input: [`subject_dn`] and [`ensure_within_validity`]
//! must fail closed on malformed bytes without panicking, and
//! [`thumbprint_b64url`] hashes any bytes unconditionally. Validity is read
//! against the wall clock, so this target never asserts a fixed verdict — only
//! no-panic behavior and the fixed 43-character thumbprint length.

#![no_main]

use d_oauth::protocol::mtls::{ensure_within_validity, subject_dn, thumbprint_b64url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let _ = subject_dn(data);
  let _ = ensure_within_validity(data);
  let thumbprint = thumbprint_b64url(data);
  // base64url (no pad) of a SHA-256 digest is always 43 characters.
  assert_eq!(
    thumbprint.len(),
    43,
    "thumbprint length is not the fixed SHA-256 rendering"
  );
});

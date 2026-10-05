//! `login_totp` unit suite: RFC 6238 vectors, ±1-step window, AEAD wrap.

use base32::Alphabet;
use secrecy::SecretString;

use super::{
  RECOVERY_CODE_COUNT, TOTP_STEP_SECS, TotpError, build_totp, decrypt_secret, encrypt_secret,
  generate_recovery_codes, generate_secret, normalize_recovery_code, otpauth_uri, qr_svg,
  replay_fingerprint, verify_window,
};
use crate::keys::{KeyId, KeyRing};

/// Test KeyRing with one pepper generation and one TOTP-encryption key.
fn test_ring() -> Result<KeyRing, TotpError> {
  KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("test-pepper-0123456789abcdef"),
    )],
    vec![(
      KeyId::new("v1"),
      SecretString::from("test-totp-key-0123456789abcdef"),
    )],
  )
  .map_err(|_| TotpError::Encrypt)
}

/// RFC 6238 Appendix B SHA-1 secret, base32-encoded like stored secrets are.
fn rfc_secret() -> String {
  base32::encode(
    Alphabet::Rfc4648 { padding: false },
    b"12345678901234567890",
  )
}

#[test]
fn login_totp_rfc6238_vector_matches() -> Result<(), TotpError> {
  // Appendix B: T = 59 s (counter 1) yields 94287082, i.e. 287082 at 6 digits.
  let matched = verify_window(&rfc_secret(), "287082", 59)?;
  if matched != Some(1) {
    return Err(TotpError::InvalidSecret);
  }
  Ok(())
}

#[test]
fn login_totp_window_accepts_adjacent_steps() -> Result<(), TotpError> {
  let secret = rfc_secret();
  // Counter 1 code "287082" is visible from counters 0 (ahead), 1, and 2 (behind).
  for now in [29, 59, 89] {
    let matched = verify_window(&secret, "287082", now)?;
    if matched != Some(1) {
      return Err(TotpError::InvalidSecret);
    }
  }
  Ok(())
}

#[test]
fn login_totp_window_rejects_two_steps_away() -> Result<(), TotpError> {
  let secret = rfc_secret();
  // Counter 3 starts at t = 90 s + one full step: the counter-1 code is out.
  for now in [119, 120, 10_000] {
    if verify_window(&secret, "287082", now)?.is_some() {
      return Err(TotpError::InvalidSecret);
    }
  }
  Ok(())
}

#[test]
fn login_totp_malformed_codes_are_misses_not_errors() -> Result<(), TotpError> {
  let secret = rfc_secret();
  for bad in ["", "12345", "1234567", "abcdef", "12 34"] {
    if verify_window(&secret, bad, 59)?.is_some() {
      return Err(TotpError::InvalidSecret);
    }
  }
  // Surrounding whitespace is tolerated.
  if verify_window(&secret, "287082 ", 59)? != Some(1) {
    return Err(TotpError::InvalidSecret);
  }
  Ok(())
}

#[test]
fn login_totp_malformed_secret_is_error() {
  for bad in ["", "!!!not-base32!!!"] {
    assert!(
      build_totp(bad).is_err(),
      "malformed secret must be rejected"
    );
  }
}

#[test]
fn login_totp_secret_round_trip() -> Result<(), TotpError> {
  let ring = test_ring()?;
  let secret = generate_secret()?;
  if secret.len() != 32 {
    return Err(TotpError::InvalidSecret);
  }
  let blob = encrypt_secret(&ring, &secret)?;
  let back = decrypt_secret(&ring, &blob)?;
  if back != secret {
    return Err(TotpError::Decrypt);
  }
  // The blob carries no plaintext.
  if String::from_utf8_lossy(&blob).contains(&secret) {
    return Err(TotpError::Encrypt);
  }
  Ok(())
}

#[test]
fn login_totp_decrypt_rejects_tampered_and_foreign_blobs() -> Result<(), TotpError> {
  let ring = test_ring()?;
  let mut blob = encrypt_secret(&ring, "GEZDGNBVGY3TQOJQ")?;
  let last = blob.len() - 1;
  blob[last] ^= 0x01;
  if decrypt_secret(&ring, &blob).is_ok() {
    return Err(TotpError::Decrypt);
  }
  if decrypt_secret(&ring, b"short").is_ok() {
    return Err(TotpError::Decrypt);
  }
  let foreign = KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("other-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("other-totp-key"))],
  )
  .map_err(|_| TotpError::Encrypt)?;
  let blob = encrypt_secret(&ring, "GEZDGNBVGY3TQOJQ")?;
  if decrypt_secret(&foreign, &blob).is_ok() {
    return Err(TotpError::Decrypt);
  }
  Ok(())
}

#[test]
fn login_totp_recovery_codes_shape_and_normalize() -> Result<(), TotpError> {
  let codes = generate_recovery_codes()?;
  if codes.len() != RECOVERY_CODE_COUNT {
    return Err(TotpError::InvalidSecret);
  }
  for code in &codes {
    if code.len() != 16
      || !code
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
      return Err(TotpError::InvalidSecret);
    }
  }
  let first = codes.first().ok_or(TotpError::InvalidSecret)?;
  let grouped = format!(
    "{}-{}-{}-{}",
    &first[0..4],
    &first[4..8],
    &first[8..12],
    &first[12..16]
  );
  if normalize_recovery_code(&grouped) != *first {
    return Err(TotpError::InvalidSecret);
  }
  if normalize_recovery_code(&first.to_ascii_lowercase()) != *first {
    return Err(TotpError::InvalidSecret);
  }
  Ok(())
}

#[test]
fn login_totp_replay_fingerprint_binds_owner_code_and_step() {
  let base = replay_fingerprint("user-1", "287082", 1);
  assert_eq!(base.len(), 64, "fingerprint must be sha256 hex");
  let variants = [
    replay_fingerprint("user-2", "287082", 1),
    replay_fingerprint("user-1", "287083", 1),
    replay_fingerprint("user-1", "287082", 2),
  ];
  for other in variants {
    assert_ne!(other, base, "fingerprint must bind owner, code, and step");
  }
  assert_eq!(
    replay_fingerprint("user-1", "287082", 1),
    base,
    "fingerprint must be deterministic"
  );
}

#[test]
fn login_totp_generated_code_verifies_in_window() -> Result<(), TotpError> {
  let secret = generate_secret()?;
  let totp = build_totp(&secret)?;
  let now = 1_747_000_000_u64;
  let counter = now / TOTP_STEP_SECS;
  let code = totp.generate(counter * TOTP_STEP_SECS).to_string();
  if verify_window(&secret, &code, now)? != Some(counter) {
    return Err(TotpError::InvalidSecret);
  }
  Ok(())
}

#[test]
fn login_totp_otpauth_uri_carries_secret_and_params() -> Result<(), TotpError> {
  let uri = otpauth_uri("Example AS", "user@example.test", "GEZDGNBVGY3TQOJQ");
  if !uri.starts_with("otpauth://totp/") || !uri.contains("secret=GEZDGNBVGY3TQOJQ") {
    return Err(TotpError::InvalidSecret);
  }
  Ok(())
}

#[test]
fn login_totp_qr_svg_is_self_contained() -> Result<(), TotpError> {
  let uri = otpauth_uri("Example AS", "user@example.test", &rfc_secret());
  let svg = qr_svg(&uri)?;
  if !svg.starts_with("<svg") || !svg.trim_end().ends_with("</svg>") {
    return Err(TotpError::Qr);
  }
  for forbidden in ["<script", "<image", "href="] {
    if svg.contains(forbidden) {
      return Err(TotpError::Qr);
    }
  }
  Ok(())
}

#[test]
fn login_totp_qr_svg_rejects_oversized_uri() -> Result<(), TotpError> {
  let oversized = "A".repeat(4000);
  if !matches!(qr_svg(&oversized), Err(TotpError::Qr)) {
    return Err(TotpError::Qr);
  }
  Ok(())
}

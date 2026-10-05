//! Constant-time comparison via `subtle`.
//!
//! Secret equality MUST use [`ct_eq`] here; `==` on secret bytes is forbidden.
//! Lengths are not secret, so a length mismatch short-circuits to `false`
//! before the constant-time byte loop runs.

use subtle::ConstantTimeEq as _;

/// Compare two byte strings without leaking contents through timing.
///
/// Returns `false` for unequal lengths; otherwise accumulates the XOR of
/// every byte pair and reduces to a single [`subtle`] equality check, so the
/// runtime does not depend on where (or whether) the inputs differ.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  let mut diff = 0u8;
  for (x, y) in a.iter().zip(b.iter()) {
    diff |= x ^ y;
  }
  bool::from(diff.ct_eq(&0u8))
}

#[cfg(test)]
mod crypto_tests {
  use super::*;

  #[test]
  fn crypto_ct_eq_accepts_equal_bytes() {
    assert!(ct_eq(b"correct-horse", b"correct-horse"));
    assert!(ct_eq(b"", b""));
  }

  #[test]
  fn crypto_ct_eq_rejects_unequal_bytes_and_lengths() {
    assert!(!ct_eq(b"correct-horse", b"correct-horsf"));
    assert!(!ct_eq(b"short", b"much-longer-input"));
    assert!(!ct_eq(b"", b"non-empty"));
    assert!(!ct_eq(b"non-empty", b""));
  }
}

//! Opaque token minting and versioned keyed hash-at-rest.
//!
//! Tokens are 256-bit OS-random values encoded base64url without padding.
//! Only a versioned keyed HMAC-SHA256 hash is persisted: the [`KeyId`] selects
//! the pepper generation, so [`token_hash`] is deterministic per key id and
//! distinct per pepper. Raw tokens never touch storage, logs, or error values.
//!
//! The HMAC key schedule below is RFC 2104 §2 verbatim (keys longer than the
//! SHA-256 block are hashed, shorter keys are zero-padded) so the public API
//! stays infallible without `unwrap`/`expect`: [`hmac::Hmac::new_from_slice`]
//! returns a `Result` that is `Ok` for every key length, which cannot be
//! collapsed without panicking. `crypto_token_hash_matches_library_hmac`
//! locks byte-equivalence with the library constructor.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{
  Hmac,
  digest::{KeyInit, Mac},
};
use rand::{TryRng as _, rngs::SysRng};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::ct::ct_eq;

/// Raw entropy per minted token: 256 bits from the OS RNG.
pub const TOKEN_BYTES: usize = 32;
/// Base64url-nopad length of a 32-byte token.
pub const TOKEN_STR_LEN: usize = 43;
/// Upper bound on retained pepper generations consulted by [`verify_token_hash`].
pub const MAX_RETAINED_KEYS: usize = 8;

/// Errors from token minting and stored-hash parsing.
///
/// Hashing itself is infallible; failures surface only here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
  /// The operating system RNG failed.
  #[error("operating-system randomness unavailable")]
  UnavailableRandomness,
  /// A stored hash did not parse as `v<key-id>.<base64url-digest>`.
  #[error("malformed stored token hash")]
  MalformedHash,
}

/// Pepper-generation identifier selecting the HMAC key for [`token_hash`].
///
/// Bumping the id while retaining the old pepper keeps previously issued
/// hashes verifiable via [`verify_token_hash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(u32);

impl KeyId {
  /// Build a generation identifier.
  #[must_use]
  pub const fn new(id: u32) -> Self {
    Self(id)
  }

  /// The raw generation number.
  #[must_use]
  pub const fn value(self) -> u32 {
    self.0
  }
}

impl core::fmt::Display for KeyId {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// Versioned keyed hash of a token: safe to persist and compare.
///
/// Holds the issuing [`KeyId`] plus the 32-byte HMAC-SHA256 digest. Never
/// contains the raw token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenHash {
  key_id: KeyId,
  digest: [u8; 32],
}

impl TokenHash {
  /// The key id this hash was computed under.
  #[must_use]
  pub const fn key_id(self) -> KeyId {
    self.key_id
  }

  /// The raw 32-byte digest. Compare with [`ct_eq`], never `==`.
  #[must_use]
  pub const fn digest(&self) -> &[u8; 32] {
    &self.digest
  }

  /// Encode for storage as `v<key-id>.<base64url-nopad-digest>`.
  #[must_use]
  pub fn to_storage_string(self) -> String {
    format!("v{}.{}", self.key_id, URL_SAFE_NO_PAD.encode(self.digest))
  }

  /// Parse [`TokenHash::to_storage_string`] output.
  ///
  /// # Errors
  ///
  /// Returns [`TokenError::MalformedHash`] for any deviation from the format.
  pub fn parse_storage_string(s: &str) -> Result<Self, TokenError> {
    let rest = s.strip_prefix('v').ok_or(TokenError::MalformedHash)?;
    let (id, digest) = rest.split_once('.').ok_or(TokenError::MalformedHash)?;
    let key_id = KeyId::new(id.parse::<u32>().map_err(|_| TokenError::MalformedHash)?);
    let raw = URL_SAFE_NO_PAD
      .decode(digest)
      .map_err(|_| TokenError::MalformedHash)?;
    if raw.len() != 32 {
      return Err(TokenError::MalformedHash);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(Self {
      key_id,
      digest: out,
    })
  }
}

/// Mint a fresh 256-bit token, base64url-encoded without padding.
///
/// # Errors
///
/// Returns [`TokenError::UnavailableRandomness`] if the OS RNG fails.
pub fn mint_token() -> Result<String, TokenError> {
  let mut raw = Zeroizing::new([0u8; TOKEN_BYTES]);
  let mut rng = SysRng;
  rng
    .try_fill_bytes(&mut raw[..])
    .map_err(|_| TokenError::UnavailableRandomness)?;
  Ok(URL_SAFE_NO_PAD.encode(&raw[..]))
}

/// Block width of SHA-256: HMAC peppers normalise to this length.
const HMAC_BLOCK_BYTES: usize = 64;

/// Normalise a pepper to the HMAC block width (RFC 2104 §2): keys longer
/// than the block are hashed, shorter keys are zero-padded. Returns the key
/// directly as the `Hmac` key type so construction stays infallible.
fn hmac_key(pepper: &[u8]) -> Zeroizing<[u8; HMAC_BLOCK_BYTES]> {
  let mut key = Zeroizing::new([0u8; HMAC_BLOCK_BYTES]);
  if pepper.len() > key.len() {
    let hashed = Sha256::digest(pepper);
    key[..hashed.len()].copy_from_slice(&hashed);
  } else {
    key[..pepper.len()].copy_from_slice(pepper);
  }
  key
}

/// Keyed hash of `token` under (`key_id`, `pepper`).
///
/// The key id is domain-mixed into the message, so the same token hashes
/// differently per generation even if a pepper were reused. Deterministic
/// per (`key_id`, `pepper`, `token`); the raw token is never retained.
#[must_use]
pub fn token_hash(key_id: &KeyId, pepper: &[u8], token: &str) -> TokenHash {
  let mut msg = Zeroizing::new(Vec::with_capacity(4 + token.len()));
  msg.extend_from_slice(&key_id.value().to_be_bytes());
  msg.extend_from_slice(token.as_bytes());
  let key = hmac_key(pepper);
  let mac_key: &hmac::digest::Key<Hmac<Sha256>> = (&*key).into();
  let mut mac = <Hmac<Sha256> as KeyInit>::new(mac_key);
  mac.update(&msg[..]);
  let out = mac.finalize().into_bytes();
  let mut digest = [0u8; 32];
  digest.copy_from_slice(&out);
  TokenHash {
    key_id: *key_id,
    digest,
  }
}

/// Verify `token` against `expected`, retrying retained peppers newest-first.
///
/// `keys` must be ordered newest-first and is capped at
/// [`MAX_RETAINED_KEYS`] entries so rotation windows stay bounded. Digest
/// comparison uses [`ct_eq`].
#[must_use]
pub fn verify_token_hash(expected: &TokenHash, keys: &[(KeyId, &[u8])], token: &str) -> bool {
  for (id, pepper) in keys.iter().take(MAX_RETAINED_KEYS) {
    let candidate = token_hash(id, pepper, token);
    if ct_eq(candidate.digest(), expected.digest()) {
      return true;
    }
  }
  false
}

/// Redact a token for logs and error values: always the constant
/// `"[redacted]"`, never a prefix of the secret.
#[must_use]
pub const fn redact_token(_token: &str) -> &'static str {
  "[redacted]"
}

#[cfg(test)]
mod crypto_tests {
  use super::*;
  use std::collections::HashSet;

  fn is_base64url(s: &str) -> bool {
    s.bytes()
      .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
  }

  #[test]
  fn crypto_mint_token_is_43_char_base64url() -> Result<(), TokenError> {
    let token = mint_token()?;
    assert_eq!(token.len(), TOKEN_STR_LEN);
    assert_eq!(token.len(), 43);
    assert!(is_base64url(&token));
    Ok(())
  }

  #[test]
  fn crypto_mint_token_unique_over_10k_draws() -> Result<(), TokenError> {
    let mut seen = HashSet::with_capacity(10_000);
    for _ in 0..10_000 {
      seen.insert(mint_token()?);
    }
    assert_eq!(seen.len(), 10_000);
    Ok(())
  }

  #[test]
  fn crypto_token_hash_deterministic_per_key_id() {
    let id = KeyId::new(3);
    let first = token_hash(&id, b"pepper-one", "token-abc");
    let second = token_hash(&id, b"pepper-one", "token-abc");
    assert_eq!(first, second);
    assert_eq!(first.key_id(), id);
  }

  #[test]
  fn crypto_token_hash_differs_per_pepper() {
    let id = KeyId::new(3);
    let a = token_hash(&id, b"pepper-one", "token-abc");
    let b = token_hash(&id, b"pepper-two", "token-abc");
    assert_ne!(a, b);
  }

  #[test]
  fn crypto_token_hash_differs_per_key_id() {
    let a = token_hash(&KeyId::new(1), b"same-pepper", "token-abc");
    let b = token_hash(&KeyId::new(2), b"same-pepper", "token-abc");
    assert_ne!(a, b);
  }

  #[test]
  fn crypto_token_hash_matches_library_hmac() -> Result<(), TokenError> {
    let id = KeyId::new(7);
    let ours = token_hash(
      &id,
      b"a-much-longer-pepper-than-thirty-two-bytes-for-sure-0123456789",
      "t",
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(
      b"a-much-longer-pepper-than-thirty-two-bytes-for-sure-0123456789",
    )
    .map_err(|_| TokenError::MalformedHash)?;
    mac.update(&id.value().to_be_bytes());
    mac.update(b"t");
    let out = mac.finalize().into_bytes();
    assert_eq!(ours.digest(), out.as_slice());
    Ok(())
  }

  #[test]
  fn crypto_old_key_id_verifies_during_rotation() {
    let old = (KeyId::new(1), b"old-pepper".as_slice());
    let new = (KeyId::new(2), b"new-pepper".as_slice());
    let stored = token_hash(&old.0, old.1, "refresh-token-xyz");
    let keys = [new, old];
    assert!(verify_token_hash(&stored, &keys, "refresh-token-xyz"));
    assert!(!verify_token_hash(&stored, &keys, "wrong-token"));
    assert!(!verify_token_hash(&stored, &[new], "refresh-token-xyz"));
  }

  #[test]
  fn crypto_verify_is_bounded_to_retained_keys() {
    let id = KeyId::new(99);
    let stored = token_hash(&id, b"pepper-99", "bounded-token");
    let mut keys: Vec<(KeyId, &[u8])> = Vec::with_capacity(MAX_RETAINED_KEYS + 1);
    for _ in 0..MAX_RETAINED_KEYS {
      keys.push((KeyId::new(1), b"decoy".as_slice()));
    }
    keys.push((id, b"pepper-99".as_slice()));
    assert!(!verify_token_hash(&stored, &keys, "bounded-token"));
    let mut head: Vec<(KeyId, &[u8])> = vec![(id, b"pepper-99".as_slice())];
    head.extend(keys.into_iter().take(MAX_RETAINED_KEYS - 1));
    assert!(verify_token_hash(&stored, &head, "bounded-token"));
  }

  #[test]
  fn crypto_hash_never_exposes_raw_token() {
    let raw = "super-secret-token-value";
    let hash = token_hash(&KeyId::new(1), b"pepper", raw);
    let stored = hash.to_storage_string();
    assert!(!stored.contains(raw));
    assert!(!stored.contains(&raw[..8]));
    assert_eq!(redact_token(raw), "[redacted]");
    assert!(!redact_token(raw).contains(&raw[..4]));
  }

  #[test]
  fn crypto_storage_string_round_trip() -> Result<(), TokenError> {
    let hash = token_hash(&KeyId::new(12), b"pepper", "round-trip-token");
    let parsed = TokenHash::parse_storage_string(&hash.to_storage_string())?;
    assert_eq!(parsed, hash);
    Ok(())
  }

  #[test]
  fn crypto_storage_string_rejects_malformed() {
    for bad in ["", "1.abc", "v.abc", "vx.abc", "v1.!!!", "v1.aGk"] {
      assert!(TokenHash::parse_storage_string(bad).is_err(), "{bad}");
    }
  }
}

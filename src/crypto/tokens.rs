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
  /// A stored hash did not parse as `<key-id>.<base64url-digest>`.
  #[error("malformed stored token hash")]
  MalformedHash,
}

/// Pepper-generation identifier selecting the HMAC key for [`token_hash`].
///
/// The full configured key id string is preserved verbatim (`v1`, `v2`, or any
/// custom label). Ids of the form `v<N>` mix the 4-byte big-endian generation
/// number into the HMAC message (the pre-string-id encoding, so stored hashes
/// keep verifying); any other id mixes its UTF-8 bytes, so two generations
/// hash differently even when their peppers match. The id is never trimmed.
///
/// Bumping the id while retaining the old pepper keeps previously issued
/// hashes verifiable via [`verify_token_hash`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
  /// Build a generation identifier, preserving the id verbatim.
  #[must_use]
  pub fn new(id: impl Into<String>) -> Self {
    Self(id.into())
  }

  /// Borrow the identifier as a string slice.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl From<&str> for KeyId {
  fn from(value: &str) -> Self {
    Self::new(value)
  }
}

impl From<String> for KeyId {
  fn from(value: String) -> Self {
    Self::new(value)
  }
}

impl core::fmt::Display for KeyId {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(&self.0)
  }
}

/// Versioned keyed hash of a token: safe to persist and compare.
///
/// Holds the issuing [`KeyId`] plus the 32-byte HMAC-SHA256 digest. Never
/// contains the raw token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHash {
  key_id: KeyId,
  digest: [u8; 32],
}

impl TokenHash {
  /// The key id this hash was computed under.
  #[must_use]
  pub fn key_id(&self) -> &KeyId {
    &self.key_id
  }

  /// The raw 32-byte digest. Compare with [`ct_eq`], never `==`.
  #[must_use]
  pub const fn digest(&self) -> &[u8; 32] {
    &self.digest
  }

  /// Encode for storage as `<key-id>.<base64url-nopad-digest>`.
  #[must_use]
  pub fn to_storage_string(&self) -> String {
    format!("{}.{}", self.key_id, URL_SAFE_NO_PAD.encode(self.digest))
  }

  /// Parse [`TokenHash::to_storage_string`] output.
  ///
  /// The key id is taken verbatim (everything before the first `.`); only an
  /// empty id or a malformed digest is rejected.
  ///
  /// # Errors
  ///
  /// Returns [`TokenError::MalformedHash`] for any deviation from the format.
  pub fn parse_storage_string(s: &str) -> Result<Self, TokenError> {
    let (id, digest) = s.split_once('.').ok_or(TokenError::MalformedHash)?;
    if id.is_empty() {
      return Err(TokenError::MalformedHash);
    }
    let key_id = KeyId::new(id.to_owned());
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

/// Domain-separation prefix for [`token_hash`]: the 4-byte big-endian
/// generation for ids matching `v<N>`, `None` for any other id (which mixes
/// its UTF-8 bytes instead). An out-of-`u32`-range suffix falls back to the
/// string encoding; such ids cannot verify against legacy rows, but the hash
/// stays deterministic.
fn numeric_key_id_prefix(id: &str) -> Option<[u8; 4]> {
  let digits = id.strip_prefix('v')?;
  if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
    return None;
  }
  digits.parse::<u32>().ok().map(|n| n.to_be_bytes())
}

/// Keyed hash of `token` under (`key_id`, `pepper`).
///
/// A `v<N>` id mixes the 4-byte big-endian generation number ahead of the
/// token bytes (byte-identical to the pre-string-id scheme); any other id
/// mixes its UTF-8 bytes. Deterministic per (`key_id`, `pepper`, `token`);
/// the raw token is never retained.
///
/// The returned [`TokenHash`] owns a clone of `key_id`: ids are short
/// (`v<N>`) so this is one small allocation, cheaper than reference-counting
/// across every [`verify_token_hash`] retry.
#[must_use]
pub fn token_hash(key_id: &KeyId, pepper: &[u8], token: &str) -> TokenHash {
  let id = key_id.as_str();
  let prefix = numeric_key_id_prefix(id);
  let mut msg = Zeroizing::new(Vec::with_capacity(4.max(id.len()) + token.len()));
  match prefix {
    Some(bytes) => msg.extend_from_slice(&bytes),
    None => msg.extend_from_slice(id.as_bytes()),
  }
  msg.extend_from_slice(token.as_bytes());
  let key = hmac_key(pepper);
  let mac_key: &hmac::digest::Key<Hmac<Sha256>> = (&*key).into();
  let mut mac = <Hmac<Sha256> as KeyInit>::new(mac_key);
  mac.update(&msg[..]);
  let out = mac.finalize().into_bytes();
  let mut digest = [0u8; 32];
  digest.copy_from_slice(&out);
  TokenHash {
    key_id: key_id.clone(),
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
    let id = KeyId::new("v3");
    let first = token_hash(&id, b"pepper-one", "token-abc");
    let second = token_hash(&id, b"pepper-one", "token-abc");
    assert_eq!(first, second);
    assert_eq!(first.key_id(), &id);
  }

  #[test]
  fn crypto_token_hash_differs_per_pepper() {
    let id = KeyId::new("v3");
    let a = token_hash(&id, b"pepper-one", "token-abc");
    let b = token_hash(&id, b"pepper-two", "token-abc");
    assert_ne!(a, b);
  }

  #[test]
  fn crypto_token_hash_differs_per_key_id() {
    let a = token_hash(&KeyId::new("v1"), b"same-pepper", "token-abc");
    let b = token_hash(&KeyId::new("v2"), b"same-pepper", "token-abc");
    assert_ne!(a, b);
  }

  #[test]
  fn crypto_token_hash_differs_per_non_numeric_key_id() {
    let a = token_hash(&KeyId::new("pepper-2026"), b"same-pepper", "token-abc");
    let b = token_hash(&KeyId::new("v1"), b"same-pepper", "token-abc");
    assert_ne!(a, b);
    assert_eq!(a.key_id().as_str(), "pepper-2026");
    assert!(a.to_storage_string().starts_with("pepper-2026."));
  }

  #[test]
  fn crypto_token_hash_matches_library_hmac() -> Result<(), TokenError> {
    let id = KeyId::new("v7");
    let ours = token_hash(
      &id,
      b"a-much-longer-pepper-than-thirty-two-bytes-for-sure-0123456789",
      "t",
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(
      b"a-much-longer-pepper-than-thirty-two-bytes-for-sure-0123456789",
    )
    .map_err(|_| TokenError::MalformedHash)?;
    mac.update(&7u32.to_be_bytes());
    mac.update(b"t");
    let out = mac.finalize().into_bytes();
    assert_eq!(ours.digest(), out.as_slice());
    Ok(())
  }

  #[test]
  fn crypto_token_hash_legacy_v1_known_answer() {
    // Pre-change scheme mixed the numeric generation as 4-byte big-endian
    // (`v1` -> `[0, 0, 0, 1]`) ahead of the token bytes. Stored hashes
    // (Postgres DCR registration hashes, Redis token/code/device/PAR hashes)
    // must keep verifying, so this vector pins the legacy `v1` digest.
    let hash = token_hash(
      &KeyId::new("v1"),
      b"0123456789abcdef0123456789abcdef",
      "kat-legacy-v1-token",
    );
    assert_eq!(
      URL_SAFE_NO_PAD.encode(hash.digest()),
      "GPdRQqgBMQi_frpfRECk3H0dBQZndDsxxxQczlg3IqI"
    );
  }

  #[test]
  fn crypto_old_key_id_verifies_during_rotation() {
    let old = (KeyId::new("v1"), b"old-pepper".as_slice());
    let new = (KeyId::new("v2"), b"new-pepper".as_slice());
    let stored = token_hash(&old.0, old.1, "refresh-token-xyz");
    let keys = [new.clone(), old];
    assert!(verify_token_hash(&stored, &keys, "refresh-token-xyz"));
    assert!(!verify_token_hash(&stored, &keys, "wrong-token"));
    assert!(!verify_token_hash(&stored, &[new], "refresh-token-xyz"));
  }

  #[test]
  fn crypto_verify_is_bounded_to_retained_keys() {
    let id = KeyId::new("v99");
    let stored = token_hash(&id, b"pepper-99", "bounded-token");
    let mut keys: Vec<(KeyId, &[u8])> = Vec::with_capacity(MAX_RETAINED_KEYS + 1);
    for _ in 0..MAX_RETAINED_KEYS {
      keys.push((KeyId::new("v1"), b"decoy".as_slice()));
    }
    keys.push((id.clone(), b"pepper-99".as_slice()));
    assert!(!verify_token_hash(&stored, &keys, "bounded-token"));
    let mut head: Vec<(KeyId, &[u8])> = vec![(id, b"pepper-99".as_slice())];
    head.extend(keys.into_iter().take(MAX_RETAINED_KEYS - 1));
    assert!(verify_token_hash(&stored, &head, "bounded-token"));
  }

  #[test]
  fn crypto_hash_never_exposes_raw_token() {
    let raw = "super-secret-token-value";
    let hash = token_hash(&KeyId::new("v1"), b"pepper", raw);
    let stored = hash.to_storage_string();
    assert!(!stored.contains(raw));
    assert!(!stored.contains(&raw[..8]));
    assert_eq!(redact_token(raw), "[redacted]");
    assert!(!redact_token(raw).contains(&raw[..4]));
  }

  #[test]
  fn crypto_storage_string_round_trip() -> Result<(), TokenError> {
    let hash = token_hash(&KeyId::new("v12"), b"pepper", "round-trip-token");
    let parsed = TokenHash::parse_storage_string(&hash.to_storage_string())?;
    assert_eq!(parsed, hash);
    Ok(())
  }

  #[test]
  fn crypto_storage_string_preserves_non_numeric_id() -> Result<(), TokenError> {
    let hash = token_hash(&KeyId::new("pepper-2026"), b"pepper", "round-trip-token");
    let stored = hash.to_storage_string();
    assert!(stored.starts_with("pepper-2026."));
    let parsed = TokenHash::parse_storage_string(&stored)?;
    assert_eq!(parsed, hash);
    assert_eq!(parsed.key_id().as_str(), "pepper-2026");
    Ok(())
  }

  #[test]
  fn crypto_storage_string_rejects_malformed() {
    for bad in ["", ".abc", "1.abc", "v.abc", "vx.abc", "v1.!!!", "v1.aGk"] {
      assert!(TokenHash::parse_storage_string(bad).is_err(), "{bad}");
    }
  }

  #[test]
  fn crypto_token_hash_leading_zero_id_matches_v1() {
    // `v01` parses to generation 1, so its digest must equal `v1`; the id is
    // preserved verbatim, so the storage strings must differ.
    let plain = token_hash(&KeyId::new("v1"), b"pepper", "pin-token");
    let padded = token_hash(&KeyId::new("v01"), b"pepper", "pin-token");
    assert_eq!(padded.digest(), plain.digest());
    assert_ne!(padded.to_storage_string(), plain.to_storage_string());
    assert!(padded.to_storage_string().starts_with("v01."));
    assert!(plain.to_storage_string().starts_with("v1."));
  }

  #[test]
  fn crypto_token_hash_overflow_suffix_is_deterministic() -> Result<(), TokenError> {
    // `v4294967296` overflows `u32`, so it falls back to the UTF-8 string
    // encoding: deterministic, distinct from `v1`, and byte-identical to the
    // library HMAC over the id bytes plus the token bytes.
    let id = KeyId::new("v4294967296");
    let first = token_hash(&id, b"pepper", "pin-token");
    let second = token_hash(&id, b"pepper", "pin-token");
    assert_eq!(first, second);
    let v1 = token_hash(&KeyId::new("v1"), b"pepper", "pin-token");
    assert_ne!(first.digest(), v1.digest());
    let mut mac =
      Hmac::<Sha256>::new_from_slice(b"pepper").map_err(|_| TokenError::MalformedHash)?;
    mac.update(b"v4294967296");
    mac.update(b"pin-token");
    let out = mac.finalize().into_bytes();
    assert_eq!(first.digest(), out.as_slice());
    let parsed = TokenHash::parse_storage_string(&first.to_storage_string())?;
    assert_eq!(parsed, first);
    Ok(())
  }
}

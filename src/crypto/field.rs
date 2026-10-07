//! Versioned AES-256-GCM codec for PII field values at rest.
//!
//! Fields (emails, client names, redirect URIs, mTLS identities) are sealed
//! into an opaque blob and only the ciphertext is stored. The AEAD key is
//! derived per key-ring generation from the PII-encryption key via HKDF-SHA256
//! (RFC 5869, empty salt, info `pii-field-gcm-v1`), so the field codec is
//! domain-separated from the TOTP-encryption use of its own key chain.
//!
//! Blob layout:
//!
//! ```text
//! version(1)=1 || kid_len(1) || kid || nonce(12) || AES-256-GCM ct+tag
//! ```
//!
//! The reader resolves the named `kid` through [`KeyRing::pii_key_by_id`], so a
//! retained key keeps opening values written before a rotation. Every failure
//! (unknown kid, malformed blob, tampered ciphertext, bad tag) collapses to the
//! same opaque [`FieldError::Decrypt`]: the reason is never distinguished and no
//! plaintext or key material ever reaches a log or an error message.
//!
//! Transient derived key bytes are wrapped in [`zeroize::Zeroizing`] and wiped
//! when they leave scope.
//!
//! The same PII key chain feeds a keyed **blind index** for equality lookups.
//! [`blind_index_active`] and [`blind_index_candidates`] derive an HMAC-SHA256
//! key under a distinct HKDF info label (`pii-blind-index-v1`) and format each
//! entry as `"{kid}:{lowercase_hex_digest}"`. The index never exposes the
//! plaintext, and its HMAC key is cryptographically independent of the
//! field-encryption key.

use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  hkdf, hmac,
  rand::{SecureRandom as _, SystemRandom},
};
use secrecy::ExposeSecret as _;
use zeroize::Zeroizing;

use crate::keys::KeyRing;

/// Current field-blob format version.
const FIELD_BLOB_VERSION: u8 = 1;
/// HKDF domain-separation label for the PII field-encryption key.
const HKDF_INFO: &[u8] = b"pii-field-gcm-v1";
/// HKDF domain-separation label for the PII blind-index HMAC key.
const BLIND_INDEX_INFO: &[u8] = b"pii-blind-index-v1";
/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;
/// Maximum key-id length encodable by the one-byte length prefix.
const MAX_KID_LEN: usize = u8::MAX as usize;

/// Failures sealing or opening a PII field.
///
/// Every variant carries a static, payload-free message: no plaintext, token,
/// or key material can appear in a log, a metric, or a `Debug` rendering.
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
  /// No PII key is configured, or the AEAD rejected the input.
  #[error("PII field encryption failed")]
  Encrypt,
  /// The blob is malformed, names an unknown key, or fails authentication.
  #[error("PII field cannot be decrypted")]
  Decrypt,
  /// The operating-system random number generator failed.
  #[error("operating-system randomness unavailable")]
  UnavailableRandomness,
}

/// Seal a UTF-8 string under the active PII key.
///
/// # Errors
///
/// Returns [`FieldError::Encrypt`] when no PII key is configured or the AEAD
/// rejects the input, or [`FieldError::UnavailableRandomness`] when the
/// operating-system RNG fails.
pub fn seal_text(keys: &KeyRing, plaintext: &str) -> Result<Vec<u8>, FieldError> {
  seal_bytes(keys, plaintext.as_bytes())
}

/// Seal a JSON-serializable value under the active PII key.
///
/// # Errors
///
/// Returns [`FieldError::Encrypt`] when the value cannot be serialized, no PII
/// key is configured, or the AEAD rejects the input; see also
/// [`FieldError::UnavailableRandomness`].
pub fn seal_json<T: serde::Serialize>(keys: &KeyRing, value: &T) -> Result<Vec<u8>, FieldError> {
  let encoded = serde_json::to_vec(value).map_err(|_| FieldError::Encrypt)?;
  seal_bytes(keys, &encoded)
}

/// Seal raw bytes under the active PII key.
///
/// Blob layout: `version(1)=1 || kid_len(1) || kid || nonce(12) || ct+tag`.
///
/// # Errors
///
/// Returns [`FieldError::Encrypt`] when no PII key is configured or the AEAD
/// rejects the input, or [`FieldError::UnavailableRandomness`] when the
/// operating-system RNG fails.
pub fn seal_bytes(keys: &KeyRing, plaintext: &[u8]) -> Result<Vec<u8>, FieldError> {
  let (key_id, secret) = keys.active_pii_key().ok_or(FieldError::Encrypt)?;
  let kid = key_id.as_str().as_bytes();
  if kid.is_empty() || kid.len() > MAX_KID_LEN {
    return Err(FieldError::Encrypt);
  }
  let key =
    Zeroizing::new(derive_key(secret.expose_secret().as_bytes()).map_err(|_| FieldError::Encrypt)?);
  let mut nonce_bytes = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut nonce_bytes)
    .map_err(|_| FieldError::UnavailableRandomness)?;
  let sealing =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(|_| FieldError::Encrypt)?);
  let mut in_out = plaintext.to_vec();
  sealing
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::empty(),
      &mut in_out,
    )
    .map_err(|_| FieldError::Encrypt)?;
  let mut blob = Vec::with_capacity(2 + kid.len() + NONCE_LEN + in_out.len());
  blob.push(FIELD_BLOB_VERSION);
  blob.push(kid.len() as u8);
  blob.extend_from_slice(kid);
  blob.extend_from_slice(&nonce_bytes);
  blob.extend_from_slice(&in_out);
  Ok(blob)
}

/// Open a sealed UTF-8 string, resolving the key named in the blob.
///
/// # Errors
///
/// Returns [`FieldError::Decrypt`] for a malformed blob, an unknown key id, a
/// non-UTF-8 plaintext, or an authentication failure. The reason is never
/// distinguished.
pub fn open_text(keys: &KeyRing, blob: &[u8]) -> Result<String, FieldError> {
  String::from_utf8(open_bytes(keys, blob)?).map_err(|_| FieldError::Decrypt)
}

/// Open a sealed JSON value, resolving the key named in the blob.
///
/// # Errors
///
/// Returns [`FieldError::Decrypt`] for a malformed blob, an unknown key id, an
/// authentication failure, or a value that is not valid JSON for `T`. The
/// reason is never distinguished.
pub fn open_json<T: serde::de::DeserializeOwned>(
  keys: &KeyRing,
  blob: &[u8],
) -> Result<T, FieldError> {
  serde_json::from_slice(&open_bytes(keys, blob)?).map_err(|_| FieldError::Decrypt)
}

/// Open sealed raw bytes, resolving the key named in the blob.
///
/// # Errors
///
/// Returns [`FieldError::Decrypt`] for a malformed blob, an unknown key id, or
/// an authentication failure. The reason is never distinguished.
pub fn open_bytes(keys: &KeyRing, blob: &[u8]) -> Result<Vec<u8>, FieldError> {
  if blob.len() < 2 + NONCE_LEN || blob[0] != FIELD_BLOB_VERSION {
    return Err(FieldError::Decrypt);
  }
  let kid_len = usize::from(blob[1]);
  let header = 2 + kid_len;
  if blob.len() < header + NONCE_LEN {
    return Err(FieldError::Decrypt);
  }
  let kid = core::str::from_utf8(blob.get(2..header).unwrap_or_default())
    .map_err(|_| FieldError::Decrypt)?;
  let secret = keys.pii_key_by_id(kid).ok_or(FieldError::Decrypt)?;
  let key =
    Zeroizing::new(derive_key(secret.expose_secret().as_bytes()).map_err(|_| FieldError::Decrypt)?);
  let mut nonce_bytes = [0u8; NONCE_LEN];
  nonce_bytes.copy_from_slice(&blob[header..header + NONCE_LEN]);
  let ciphertext = &blob[header + NONCE_LEN..];
  let mut in_out = ciphertext.to_vec();
  let opening =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(|_| FieldError::Decrypt)?);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::empty(),
      &mut in_out,
    )
    .map_err(|_| FieldError::Decrypt)?;
  Ok(plaintext.to_vec())
}

/// Derive a 256-bit AES key from PII key material via HKDF-SHA256 (RFC 5869,
/// empty salt, info `pii-field-gcm-v1`).
fn derive_key(pii_key: &[u8]) -> Result<[u8; 32], ring::error::Unspecified> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(pii_key);
  let okm = prk.expand(&[HKDF_INFO], HkdfAesKey)?;
  let mut key = [0u8; 32];
  okm.fill(&mut key)?;
  Ok(key)
}

/// `ring::hkdf` output-length marker for a 256-bit AES key.
struct HkdfAesKey;

impl hkdf::KeyType for HkdfAesKey {
  fn len(&self) -> usize {
    32
  }
}

/// `ring::hkdf` output-length marker for the 256-bit blind-index HMAC key.
struct HkdfIndexKey;

impl hkdf::KeyType for HkdfIndexKey {
  fn len(&self) -> usize {
    32
  }
}

/// Compute the active blind index for a canonicalized value.
///
/// The caller MUST pass the canonical form (for example
/// [`crate::db::user_repo::normalize_email`] for emails, or the exact stored
/// string for redirect URIs and mTLS identities); this function never
/// normalizes. The result is `"{kid}:{lowercase_hex_hmac_sha256}"`, where `kid`
/// is the active PII key id.
///
/// # Key generation
///
/// The HMAC key is derived from one PII key generation, so a value's index is
/// stable only within that generation: two logically equal values indexed under
/// different keys have different stored indexes. Reads must therefore query
/// [`blind_index_candidates`], which spans every retained generation. The
/// `pii rotate` command re-indexes every row and runs under a write freeze.
#[must_use]
pub fn blind_index_active(keys: &KeyRing, normalized: &str) -> String {
  // A `KeyRing` is only built with a non-empty PII chain (`from_parts` rejects
  // an empty one), so the active key always exists.
  keys
    .active_pii_key()
    .map(|(key_id, secret)| {
      index_value(
        key_id.as_str(),
        secret.expose_secret().as_bytes(),
        normalized,
      )
    })
    .unwrap_or_default()
}

/// Compute the blind index under every retained PII key, newest-first.
///
/// The first entry equals [`blind_index_active`]. Reads match a stored index
/// against this whole list so a value written before a rotation is still found
/// while the old key is retained. The list length equals the PII key chain
/// length.
#[must_use]
pub fn blind_index_candidates(keys: &KeyRing, normalized: &str) -> Vec<String> {
  keys
    .pii_keys_newest_first()
    .map(|(key_id, secret)| {
      index_value(
        key_id.as_str(),
        secret.expose_secret().as_bytes(),
        normalized,
      )
    })
    .collect()
}

/// Format `"{kid}:{lowercase_hex_hmac_sha256}"` for one PII key generation.
fn index_value(kid: &str, pii_key: &[u8], normalized: &str) -> String {
  let key = derive_index_key(pii_key);
  let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &key[..]);
  let tag = hmac::sign(&mac_key, normalized.as_bytes());
  format!("{kid}:{}", hex_lower(tag.as_ref()))
}

/// Derive the 256-bit blind-index HMAC key via HKDF-SHA256 (RFC 5869, empty
/// salt, info `pii-blind-index-v1`).
///
/// A 32-byte expand/fill for SHA-256 cannot fail; a failure leaves the key
/// zeroed rather than panicking in a request path. The returned bytes are wiped
/// on drop.
fn derive_index_key(pii_key: &[u8]) -> Zeroizing<[u8; 32]> {
  let mut key = Zeroizing::new([0u8; 32]);
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(pii_key);
  if let Ok(okm) = prk.expand(&[BLIND_INDEX_INFO], HkdfIndexKey) {
    let _ = okm.fill(&mut key[..]);
  }
  key
}

/// Lowercase hexadecimal encoding.
fn hex_lower(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  out
}

#[cfg(test)]
mod tests {
  use secrecy::SecretString;

  use super::{
    FieldError, blind_index_active, blind_index_candidates, open_bytes, open_json, open_text,
    seal_bytes, seal_json, seal_text,
  };
  use crate::keys::{KeyId, KeyRing};

  /// Test key ring with one pepper, one TOTP key, and one PII key generation.
  fn test_ring() -> Result<KeyRing, FieldError> {
    KeyRing::from_parts(
      vec![(
        KeyId::new("v1"),
        SecretString::from("test-pepper-0123456789abcdef"),
      )],
      vec![(
        KeyId::new("v1"),
        SecretString::from("test-totp-key-0123456789abcdef"),
      )],
      vec![(
        KeyId::new("v1"),
        SecretString::from("test-pii-key-0123456789abcdef"),
      )],
    )
    .map_err(|_| FieldError::Encrypt)
  }

  fn ring_with_pii(pii: Vec<(&str, &str)>) -> Result<KeyRing, FieldError> {
    let pii_keys = pii
      .into_iter()
      .map(|(id, value)| (KeyId::new(id), SecretString::from(value)))
      .collect();
    KeyRing::from_parts(
      vec![(
        KeyId::new("v1"),
        SecretString::from("test-pepper-0123456789abcdef"),
      )],
      vec![(
        KeyId::new("v1"),
        SecretString::from("test-totp-key-0123456789abcdef"),
      )],
      pii_keys,
    )
    .map_err(|_| FieldError::Encrypt)
  }

  #[test]
  fn blind_index_is_deterministic() -> Result<(), FieldError> {
    let keys = test_ring()?;
    let first = blind_index_active(&keys, "alice@example.com");
    let second = blind_index_active(&keys, "alice@example.com");
    assert_eq!(first, second);

    // Format is `"{kid}:{lowercase_hex_hmac_sha256}"`.
    let (kid, digest) = first.split_once(':').ok_or(FieldError::Encrypt)?;
    assert_eq!(kid, "v1");
    assert_eq!(digest.len(), 64);
    assert!(
      digest
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
      "digest must be lowercase hex: {digest}"
    );

    assert_ne!(
      blind_index_active(&keys, "alice@example.com"),
      blind_index_active(&keys, "bob@example.com")
    );

    // Two different PII keys produce different indexes for the same input,
    // even under the same key id: the HMAC key, not just the kid, is bound.
    let other = ring_with_pii(vec![("v1", "test-pii-key-fedcba9876543210")])?;
    assert_ne!(
      blind_index_active(&keys, "alice@example.com"),
      blind_index_active(&other, "alice@example.com")
    );
    Ok(())
  }

  #[test]
  fn blind_index_candidates_order_newest_first() -> Result<(), FieldError> {
    let keys = ring_with_pii(vec![
      ("v2", "test-pii-key-new-0123456789abcdef"),
      ("v1", "test-pii-key-old-0123456789abcdef"),
    ])?;
    let candidates = blind_index_candidates(&keys, "alice@example.com");
    assert_eq!(candidates.len(), 2);
    assert!(candidates[0].starts_with("v2:"));
    assert!(candidates[1].starts_with("v1:"));
    assert_ne!(candidates[0], candidates[1]);
    assert_eq!(
      Some(blind_index_active(&keys, "alice@example.com")),
      candidates.first().cloned()
    );
    Ok(())
  }

  #[test]
  fn field_seal_open_round_trip() -> Result<(), FieldError> {
    let keys = test_ring()?;
    let plaintext = "alice@example.com";
    let sealed = seal_text(&keys, plaintext)?;
    // Blob layout: version=1, kid_len=2, kid="v1", nonce(12), ct+tag.
    assert_eq!(sealed[0], 1);
    assert_eq!(usize::from(sealed[1]), 2);
    assert_eq!(&sealed[2..4], b"v1");
    assert!(sealed.len() > 2 + 2 + 12 + 16);
    // A sealed UTF-8 value must not contain the plaintext substring.
    assert!(
      !sealed
        .windows(plaintext.len())
        .any(|window| window == plaintext.as_bytes())
    );
    assert_eq!(open_text(&keys, &sealed)?, plaintext);

    // A JSON value round-trips through the same blob codec.
    let value = serde_json::json!({ "email": "alice@example.com", "age": 30 });
    let sealed_json = seal_json(&keys, &value)?;
    let restored: serde_json::Value = open_json(&keys, &sealed_json)?;
    assert_eq!(restored, value);

    // Raw bytes round-trip unchanged.
    let bytes = [0u8, 255, 1, 2, 3];
    let sealed_bytes = seal_bytes(&keys, &bytes)?;
    assert_eq!(open_bytes(&keys, &sealed_bytes)?, bytes);
    Ok(())
  }

  #[test]
  fn field_rejects_tampered_blob() -> Result<(), FieldError> {
    let keys = test_ring()?;
    let sealed = seal_text(&keys, "secret@example.com")?;
    // Flipping one ciphertext byte must fail authentication.
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
      open_text(&keys, &tampered),
      Err(FieldError::Decrypt)
    ));
    // A truncated blob fails closed too, without panicking.
    assert!(matches!(
      open_text(&keys, &sealed[..5]),
      Err(FieldError::Decrypt)
    ));
    Ok(())
  }

  #[test]
  fn field_rejects_unknown_kid() -> Result<(), FieldError> {
    let keys = test_ring()?;
    let mut sealed = seal_text(&keys, "secret@example.com")?;
    // Overwrite the kid with a same-length id that is not in the ring.
    assert_eq!(usize::from(sealed[1]), 2);
    sealed[2] = b'v';
    sealed[3] = b'9';
    assert!(matches!(
      open_text(&keys, &sealed),
      Err(FieldError::Decrypt)
    ));
    Ok(())
  }
}

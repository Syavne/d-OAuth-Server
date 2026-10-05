//! Secret handling for the CLI: password hashing, token hashing, TOTP-secret
//! encryption, and ES256 keygen.
//!
//! Nothing here ever logs or prints a secret. TOTP secrets are encrypted with
//! AES-256-GCM under a key derived from the active [`crate::keys::KeyRing`]
//! TOTP key via HKDF-SHA256 (info `totp-gcm-v2`); the stored blob carries the
//! key id so retained keys keep decrypting after rotation. Version-1 blobs
//! (bare `SHA256(totp_key)`) still decrypt via a legacy fallback. `keygen`
//! emits an ES256 keypair for test fixtures
//! and client-side DPoP keys only — never an AS signing key.

use base64::{
  Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  hkdf,
  rand::{SecureRandom as _, SystemRandom},
  signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use secrecy::ExposeSecret as _;
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use super::context::CliError;
use crate::config::Config;

/// Current TOTP-blob format version (HKDF-SHA256 writes).
const TOTP_BLOB_VERSION: u8 = 2;
/// Legacy blob version (bare-`SHA256(totp_key)` writes): decrypt-only.
#[cfg(test)]
const TOTP_BLOB_V1: u8 = 1;
/// HKDF domain-separation label binding the derived key to TOTP AES-GCM use.
const HKDF_INFO: &[u8] = b"totp-gcm-v2";
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256 key length.
const KEY_LEN: usize = 32;

/// A generated ES256 keypair, serialized for test fixtures / DPoP clients.
pub struct KeypairPem {
  /// PKCS#8 v1 PEM private key.
  pub private_key_pem: String,
  /// Public JWK JSON (`kty=EC`, `crv=P-256`, `alg=ES256`).
  pub public_jwk: String,
}

/// Hash a user password with the configured Argon2id parameters.
///
/// # Errors
/// Returns [`CliError::Secret`] when the parameters are invalid or hashing
/// fails.
pub fn hash_password(config: &Config, password: &str) -> Result<String, CliError> {
  let configured = &config.argon2;
  let params = crate::crypto::secret::Argon2Params::new(
    configured.memory_kib,
    configured.iterations,
    configured.parallelism,
    32,
  )?;
  Ok(crate::crypto::secret::hash_secret(password, &params)?)
}

/// Keyed token hash for at-rest storage under the active pepper.
///
/// The numeric generation is derived from the configured key id (`v1` → `1`)
/// so rotated peppers retain distinct storage strings.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active pepper is configured.
pub fn token_hash(config: &Config, token: &str) -> Result<String, CliError> {
  let (key_id, pepper) = config
    .keys
    .active_pepper()
    .ok_or_else(|| CliError::Crypto("no active token pepper configured".to_owned()))?;
  let generation = numeric_key_id(key_id.as_str());
  let hash = crate::crypto::tokens::token_hash(
    &crate::crypto::tokens::KeyId::new(generation),
    pepper.expose_secret().as_bytes(),
    token,
  );
  Ok(hash.to_storage_string())
}

/// Encrypt a TOTP secret with the active TOTP-encryption key.
///
/// Blob layout: `version(2) || kid_len(1) || kid || nonce(12) || ciphertext+tag`.
/// The key id travels with the blob so retained keys decrypt after rotation.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no TOTP key is configured or the AEAD
/// fails.
pub fn encrypt_totp(config: &Config, plaintext: &str) -> Result<Vec<u8>, CliError> {
  let (key_id, secret) = config
    .keys
    .active_totp_key()
    .ok_or_else(|| CliError::Crypto("no TOTP encryption key configured".to_owned()))?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > u8::MAX as usize {
    return Err(CliError::Crypto("TOTP key id is too long".to_owned()));
  }
  let key = derive_key(secret.expose_secret().as_bytes())
    .map_err(|_| CliError::Crypto("TOTP key derivation failed".to_owned()))?;
  let mut nonce_bytes = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut nonce_bytes)
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;

  let unbound = UnboundKey::new(&AES_256_GCM, &key)
    .map_err(|_| CliError::Crypto("TOTP key rejected by AEAD".to_owned()))?;
  let sealing = LessSafeKey::new(unbound);
  let mut in_out = plaintext.as_bytes().to_vec();
  sealing
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::empty(),
      &mut in_out,
    )
    .map_err(|_| CliError::Crypto("TOTP secret encryption failed".to_owned()))?;

  let mut blob = Vec::with_capacity(2 + kid.len() + NONCE_LEN + in_out.len());
  blob.push(TOTP_BLOB_VERSION);
  blob.push(kid.len() as u8);
  blob.extend_from_slice(kid);
  blob.extend_from_slice(&nonce_bytes);
  blob.extend_from_slice(&in_out);
  Ok(blob)
}

/// Decrypt a TOTP secret previously produced by [`encrypt_totp`].
///
/// Version-2 blobs open under the HKDF-SHA256 key; legacy version-1 blobs
/// first try the HKDF key, then fall back to the bare-`SHA256(totp_key)` key,
/// so rows written before the HKDF migration keep decrypting.
///
/// Currently exercised only by tests; the login/verification path (a later
/// task) is the production consumer.
///
/// # Errors
/// Returns [`CliError::Crypto`] for a malformed blob, an unknown key id, or an
/// authentication failure.
#[cfg(test)]
pub fn decrypt_totp(config: &Config, blob: &[u8]) -> Result<String, CliError> {
  if blob.len() < 2 + NONCE_LEN || (blob[0] != TOTP_BLOB_VERSION && blob[0] != TOTP_BLOB_V1) {
    return Err(CliError::Crypto("malformed TOTP blob".to_owned()));
  }
  let version = blob[0];
  let kid_len = blob[1] as usize;
  let header = 2 + kid_len;
  if blob.len() < header + NONCE_LEN {
    return Err(CliError::Crypto("malformed TOTP blob".to_owned()));
  }
  let kid = std::str::from_utf8(&blob[2..header])
    .map_err(|_| CliError::Crypto("malformed TOTP key id".to_owned()))?;
  let secret = config
    .keys
    .totp_key_by_id(kid)
    .ok_or_else(|| CliError::Crypto(format!("unknown TOTP key id: {kid}")))?;
  let ikm = secret.expose_secret().as_bytes();

  let mut nonce_bytes = [0u8; NONCE_LEN];
  nonce_bytes.copy_from_slice(&blob[header..header + NONCE_LEN]);
  let ciphertext = &blob[header + NONCE_LEN..];

  if version == TOTP_BLOB_VERSION {
    let key =
      derive_key(ikm).map_err(|_| CliError::Crypto("TOTP key derivation failed".to_owned()))?;
    return open_with_key(&key, &nonce_bytes, ciphertext);
  }
  if let Ok(key) = derive_key(ikm)
    && let Ok(plaintext) = open_with_key(&key, &nonce_bytes, ciphertext)
  {
    return Ok(plaintext);
  }
  open_with_key(&derive_key_legacy(ikm), &nonce_bytes, ciphertext)
}

#[cfg(test)]
fn open_with_key(
  key: &[u8; KEY_LEN],
  nonce_bytes: &[u8; NONCE_LEN],
  ciphertext: &[u8],
) -> Result<String, CliError> {
  let mut in_out = ciphertext.to_vec();
  let unbound = UnboundKey::new(&AES_256_GCM, key)
    .map_err(|_| CliError::Crypto("TOTP key rejected by AEAD".to_owned()))?;
  let opening = LessSafeKey::new(unbound);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(*nonce_bytes),
      Aad::empty(),
      &mut in_out,
    )
    .map_err(|_| CliError::Crypto("TOTP secret decryption failed".to_owned()))?;
  String::from_utf8(plaintext.to_vec())
    .map_err(|_| CliError::Crypto("decrypted TOTP secret is not UTF-8".to_owned()))
}

/// Generate a fresh 160-bit TOTP secret, base32 (RFC 4648, no padding).
///
/// # Errors
/// Returns [`CliError::Crypto`] when the OS RNG fails.
pub fn generate_totp_secret() -> Result<String, CliError> {
  let mut bytes = [0u8; 20];
  SystemRandom::new()
    .fill(&mut bytes)
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  Ok(base32::encode(
    base32::Alphabet::Rfc4648 { padding: false },
    &bytes,
  ))
}

/// Build an `otpauth://` enrollment URI for a generated TOTP secret.
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
  format!(
    "otpauth://totp/{}:{}?secret={}&issuer={}",
    percent_encode(issuer),
    percent_encode(account),
    secret,
    percent_encode(issuer)
  )
}

/// Generate an ES256 keypair for test fixtures / client DPoP keys only.
///
/// # Errors
/// Returns [`CliError::Crypto`] when generation or serialization fails.
pub fn generate_es256() -> Result<KeypairPem, CliError> {
  let rng = SystemRandom::new();
  let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
    .map_err(|_| CliError::Crypto("ES256 key generation failed".to_owned()))?;
  let der = document.as_ref();
  let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
    .map_err(|_| CliError::Crypto("generated ES256 key failed to parse".to_owned()))?;
  let point = key_pair.public_key().as_ref();
  if point.len() != 65 || point[0] != 0x04 {
    return Err(CliError::Crypto(
      "ES256 public key was not an uncompressed P-256 point".to_owned(),
    ));
  }
  let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
  let y = URL_SAFE_NO_PAD.encode(&point[33..65]);
  let jwk = serde_json::json!({
    "kty": "EC",
    "crv": "P-256",
    "alg": "ES256",
    "use": "sig",
    "x": x,
    "y": y,
  });
  let public_jwk =
    serde_json::to_string_pretty(&jwk).map_err(|error| CliError::Crypto(error.to_string()))?;
  Ok(KeypairPem {
    private_key_pem: pem_encode("PRIVATE KEY", der),
    public_jwk,
  })
}

fn derive_key(totp_key: &[u8]) -> Result<[u8; KEY_LEN], ring::error::Unspecified> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(totp_key);
  let okm = prk.expand(&[HKDF_INFO], HkdfAesKey)?;
  let mut key = [0u8; KEY_LEN];
  okm.fill(&mut key)?;
  Ok(key)
}

#[cfg(test)]
fn derive_key_legacy(totp_key: &[u8]) -> [u8; KEY_LEN] {
  let digest = Sha256::digest(totp_key);
  let mut key = [0u8; KEY_LEN];
  key.copy_from_slice(&digest);
  key
}

struct HkdfAesKey;

impl hkdf::KeyType for HkdfAesKey {
  fn len(&self) -> usize {
    KEY_LEN
  }
}

fn numeric_key_id(key_id: &str) -> u32 {
  key_id.trim_start_matches('v').parse::<u32>().unwrap_or(1)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
  let encoded = STANDARD.encode(der);
  let mut out = format!("-----BEGIN {label}-----\n");
  for chunk in encoded.as_bytes().chunks(64) {
    out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    out.push('\n');
  }
  out.push_str(&format!("-----END {label}-----\n"));
  out
}

fn percent_encode(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(char::from(byte));
    } else {
      out.push('%');
      out.push_str(&format!("{byte:02X}"));
    }
  }
  out
}

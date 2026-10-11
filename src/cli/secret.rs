//! Secret handling for the CLI: password hashing, token hashing, TOTP-secret
//! encryption, and ES256 keygen.
//!
//! Nothing here ever logs or prints a secret. TOTP secrets use the same blob
//! format as [`crate::crypto::totp`]: the writer is version-gated, emitting the
//! v3 per-row-DEK envelope when `envelope = true` and the legacy v2
//! HKDF-SHA256 blob (info `totp-gcm-v2`) otherwise. Version-3 blobs wrap a
//! random DEK under HKDF-SHA256 (`totp-kek-v1`) and seal the data with a fixed
//! AAD that never names the kid, so `totp rewrap` can move a DEK to a new key
//! without touching the ciphertext. Version-2 and legacy version-1
//! (bare `SHA256(totp_key)`) blobs still decrypt. The two implementations are
//! intentionally small duplicates: `crypto` cannot depend on `cli`. `keygen`
//! emits an ES256 keypair for test fixtures and client-side DPoP keys only —
//! never an AS signing key.

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
use zeroize::Zeroizing;

use super::context::CliError;
use crate::config::Config;

/// Legacy v2 blob version (HKDF-SHA256 writes while `pii_dual_write` is on).
const TOTP_BLOB_VERSION: u8 = 2;
/// Envelope blob version (per-row DEK): written when `envelope = true`.
const TOTP_BLOB_V3: u8 = 3;
/// Legacy blob version (bare-`SHA256(totp_key)` writes): decrypt-only.
#[cfg(test)]
const TOTP_BLOB_V1: u8 = 1;
/// HKDF domain-separation label binding the derived key to TOTP AES-GCM use.
const HKDF_INFO: &[u8] = b"totp-gcm-v2";
/// HKDF domain-separation label for the key-encryption key that wraps v3 DEKs.
const KEK_INFO: &[u8] = b"totp-kek-v1";
/// AAD sealing the v3 data ciphertext: format tag plus version only. It must
/// NOT name the wrapping key, so a DEK re-wrap changes the wrap without
/// touching this ciphertext.
const DATA_AAD: &[u8] = b"totp-v3\x03";
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256 key length.
const KEY_LEN: usize = 32;
/// Wrapped-DEK length: a 32-byte DEK sealed under AES-256-GCM (16-byte tag).
const WRAPPED_DEK_LEN: usize = 32 + 16;

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
/// The configured key id is preserved verbatim, so rotated peppers retain
/// distinct storage strings.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active pepper is configured.
pub fn token_hash(config: &Config, token: &str) -> Result<String, CliError> {
  let (key_id, pepper) = config
    .keys
    .active_pepper()
    .ok_or_else(|| CliError::Crypto("no active token pepper configured".to_owned()))?;
  let hash = crate::crypto::tokens::token_hash(
    &crate::crypto::tokens::KeyId::new(key_id.as_str()),
    pepper.expose_secret().as_bytes(),
    token,
  );
  Ok(hash.to_storage_string())
}

/// Encrypt a TOTP secret with the active TOTP-encryption key.
///
/// The writer is version-gated: `envelope = false` (while `pii_dual_write` is
/// on) writes the legacy v2 blob so old replicas keep reading; `envelope =
/// true` writes the v3 per-row-DEK envelope. Callers pass
/// `!config.pii_dual_write`.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no TOTP key is configured or the AEAD
/// fails.
pub fn encrypt_totp(config: &Config, plaintext: &str, envelope: bool) -> Result<Vec<u8>, CliError> {
  if envelope {
    encrypt_v3(config, plaintext)
  } else {
    encrypt_v2(config, plaintext)
  }
}

/// Legacy v2 write: `version(2) || kid_len(1) || kid || nonce(12) ||
/// ciphertext+tag`, AES-256-GCM under HKDF-SHA256 with empty AAD.
fn encrypt_v2(config: &Config, plaintext: &str) -> Result<Vec<u8>, CliError> {
  let (key_id, secret) = config
    .keys
    .active_totp_key()
    .ok_or_else(|| CliError::Crypto("no TOTP encryption key configured".to_owned()))?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > u8::MAX as usize {
    return Err(CliError::Crypto("TOTP key id is too long".to_owned()));
  }
  let key = Zeroizing::new(
    derive_key(secret.expose_secret().as_bytes())
      .map_err(|_| CliError::Crypto("TOTP key derivation failed".to_owned()))?,
  );
  let mut nonce_bytes = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut nonce_bytes)
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;

  let unbound = UnboundKey::new(&AES_256_GCM, &key[..])
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

/// Envelope write: `version(3) || kid_len(1) || kid || wrap_nonce(12) ||
/// wrapped_dek(32+16) || data_nonce(12) || secret_ct+tag`.
///
/// A random 32-byte DEK is generated per write, wrapped under a KEK derived
/// via HKDF-SHA256 (info `totp-kek-v1`) from the active TOTP key, and the
/// secret is sealed under the DEK. The data nonce is generated FIRST because
/// the wrap AAD binds it: a wrapped DEK lifted from another row names the
/// wrong nonce and fails to unwrap.
fn encrypt_v3(config: &Config, plaintext: &str) -> Result<Vec<u8>, CliError> {
  let (key_id, secret) = config
    .keys
    .active_totp_key()
    .ok_or_else(|| CliError::Crypto("no TOTP encryption key configured".to_owned()))?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > u8::MAX as usize {
    return Err(CliError::Crypto("TOTP key id is too long".to_owned()));
  }
  let kek = Zeroizing::new(
    derive_labeled(secret.expose_secret().as_bytes(), KEK_INFO)
      .map_err(|_| CliError::Crypto("TOTP key derivation failed".to_owned()))?,
  );
  let rng = SystemRandom::new();
  let mut data_nonce = [0u8; NONCE_LEN];
  rng
    .fill(&mut data_nonce)
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  let mut wrap_nonce = [0u8; NONCE_LEN];
  rng
    .fill(&mut wrap_nonce)
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  let mut dek = Zeroizing::new([0u8; KEY_LEN]);
  rng
    .fill(&mut dek[..])
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  let mut wrapped: Vec<u8> = dek.to_vec();
  seal_with_aad(
    &kek[..],
    wrap_nonce,
    &wrap_aad(kid, &data_nonce),
    &mut wrapped,
  )?;
  let mut data_ct = plaintext.as_bytes().to_vec();
  seal_with_aad(&dek[..], data_nonce, DATA_AAD, &mut data_ct)?;
  let mut blob =
    Vec::with_capacity(2 + kid.len() + NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + data_ct.len());
  blob.push(TOTP_BLOB_V3);
  blob.push(kid.len() as u8);
  blob.extend_from_slice(kid);
  blob.extend_from_slice(&wrap_nonce);
  blob.extend_from_slice(&wrapped);
  blob.extend_from_slice(&data_nonce);
  blob.extend_from_slice(&data_ct);
  Ok(blob)
}

/// Wrap AAD binding a wrapped DEK to its row: format tag, version, wrapping
/// kid, and the data nonce the DEK was sealed for.
fn wrap_aad(kid: &[u8], data_nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
  let mut aad = Vec::with_capacity(DATA_AAD.len() + 1 + kid.len() + NONCE_LEN);
  aad.extend_from_slice(DATA_AAD);
  aad.push(kid.len() as u8);
  aad.extend_from_slice(kid);
  aad.extend_from_slice(data_nonce);
  aad
}

/// Seal `in_out` in place under `key` and `aad`, appending the GCM tag.
fn seal_with_aad(
  key: &[u8],
  nonce_bytes: [u8; NONCE_LEN],
  aad: &[u8],
  in_out: &mut Vec<u8>,
) -> Result<(), CliError> {
  let sealing = LessSafeKey::new(
    UnboundKey::new(&AES_256_GCM, key)
      .map_err(|_| CliError::Crypto("TOTP key rejected by AEAD".to_owned()))?,
  );
  sealing
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::from(aad),
      in_out,
    )
    .map_err(|_| CliError::Crypto("TOTP secret encryption failed".to_owned()))
}

/// Decrypt a TOTP secret previously produced by [`encrypt_totp`].
///
/// Version-3 envelopes unwrap the per-row DEK under the HKDF-SHA256 KEK, then
/// open the data ciphertext; version-2 blobs open under the HKDF-SHA256 key;
/// legacy version-1 blobs first try the HKDF key, then fall back to the
/// bare-`SHA256(totp_key)` key, so rows written before the HKDF migration keep
/// decrypting.
///
/// Currently exercised only by tests; the login/verification path (a later
/// task) is the production consumer.
///
/// # Errors
/// Returns [`CliError::Crypto`] for a malformed blob, an unknown key id, or an
/// authentication failure.
#[cfg(test)]
pub fn decrypt_totp(config: &Config, blob: &[u8]) -> Result<String, CliError> {
  if blob.len() < 2 + NONCE_LEN
    || (blob[0] != TOTP_BLOB_V3 && blob[0] != TOTP_BLOB_VERSION && blob[0] != TOTP_BLOB_V1)
  {
    return Err(CliError::Crypto("malformed TOTP blob".to_owned()));
  }
  let version = blob[0];
  let kid_len = blob[1] as usize;
  let header = 2 + kid_len;
  if blob.len() < header + NONCE_LEN {
    return Err(CliError::Crypto("malformed TOTP blob".to_owned()));
  }
  let kid_bytes = blob
    .get(2..header)
    .ok_or_else(|| CliError::Crypto("malformed TOTP blob".to_owned()))?;
  let kid = std::str::from_utf8(kid_bytes)
    .map_err(|_| CliError::Crypto("malformed TOTP key id".to_owned()))?;
  let secret = config
    .keys
    .totp_key_by_id(kid)
    .ok_or_else(|| CliError::Crypto(format!("unknown TOTP key id: {kid}")))?;
  let ikm = secret.expose_secret().as_bytes();
  if version == TOTP_BLOB_V3 {
    return decrypt_v3(ikm, kid_bytes, &blob[header..]);
  }

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

/// Open a v3 envelope body: `wrap_nonce(12) || wrapped_dek(32+16) ||
/// data_nonce(12) || secret_ct+tag`.
///
/// The KEK is re-derived from the key named in the blob; the wrap AAD rebinds
/// that kid plus the stored data nonce, so a wrapped DEK copied from another
/// row fails closed.
#[cfg(test)]
fn decrypt_v3(ikm: &[u8], kid: &[u8], body: &[u8]) -> Result<String, CliError> {
  if body.len() < NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + 16 {
    return Err(CliError::Crypto("malformed TOTP blob".to_owned()));
  }
  let (wrap_nonce, rest) = body.split_at(NONCE_LEN);
  let (wrapped_dek, rest) = rest.split_at(WRAPPED_DEK_LEN);
  let (data_nonce, ciphertext) = rest.split_at(NONCE_LEN);
  let mut wrap_nonce_bytes = [0u8; NONCE_LEN];
  wrap_nonce_bytes.copy_from_slice(wrap_nonce);
  let mut data_nonce_bytes = [0u8; NONCE_LEN];
  data_nonce_bytes.copy_from_slice(data_nonce);
  let kek = Zeroizing::new(
    derive_labeled(ikm, KEK_INFO)
      .map_err(|_| CliError::Crypto("TOTP key derivation failed".to_owned()))?,
  );
  let dek_bytes = open_with_aad(
    &kek[..],
    &wrap_nonce_bytes,
    &wrap_aad(kid, &data_nonce_bytes),
    wrapped_dek,
  )?;
  if dek_bytes.len() != KEY_LEN {
    return Err(CliError::Crypto("TOTP secret decryption failed".to_owned()));
  }
  let mut dek_key = [0u8; KEY_LEN];
  dek_key.copy_from_slice(&dek_bytes);
  let dek = Zeroizing::new(dek_key);
  let plaintext = open_with_aad(&dek[..], &data_nonce_bytes, DATA_AAD, ciphertext)?;
  String::from_utf8(plaintext)
    .map_err(|_| CliError::Crypto("decrypted TOTP secret is not UTF-8".to_owned()))
}

/// Open `ciphertext` (with trailing GCM tag) under `key` with empty AAD,
/// returning UTF-8.
#[cfg(test)]
fn open_with_key(
  key: &[u8; KEY_LEN],
  nonce_bytes: &[u8; NONCE_LEN],
  ciphertext: &[u8],
) -> Result<String, CliError> {
  let plaintext = open_with_aad(key, nonce_bytes, &[], ciphertext)?;
  String::from_utf8(plaintext)
    .map_err(|_| CliError::Crypto("decrypted TOTP secret is not UTF-8".to_owned()))
}

/// Open `ciphertext` (with trailing GCM tag) under `key` and `aad`, returning
/// the raw plaintext.
#[cfg(test)]
fn open_with_aad(
  key: &[u8],
  nonce_bytes: &[u8; NONCE_LEN],
  aad: &[u8],
  ciphertext: &[u8],
) -> Result<Vec<u8>, CliError> {
  let mut in_out = ciphertext.to_vec();
  let unbound = UnboundKey::new(&AES_256_GCM, key)
    .map_err(|_| CliError::Crypto("TOTP key rejected by AEAD".to_owned()))?;
  let opening = LessSafeKey::new(unbound);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(*nonce_bytes),
      Aad::from(aad),
      &mut in_out,
    )
    .map_err(|_| CliError::Crypto("TOTP secret decryption failed".to_owned()))?;
  Ok(plaintext.to_vec())
}

/// Generate a fresh 160-bit TOTP secret, base32 (RFC 4648, no padding).
///
/// The secret is held in [`Zeroizing`] so it is wiped on drop.
///
/// # Errors
/// Returns [`CliError::Crypto`] when the OS RNG fails.
pub fn generate_totp_secret() -> Result<Zeroizing<String>, CliError> {
  let mut bytes = Zeroizing::new([0u8; 20]);
  SystemRandom::new()
    .fill(&mut bytes[..])
    .map_err(|_| CliError::Crypto("operating-system randomness unavailable".to_owned()))?;
  Ok(Zeroizing::new(base32::encode(
    base32::Alphabet::Rfc4648 { padding: false },
    &bytes[..],
  )))
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
  derive_labeled(totp_key, HKDF_INFO)
}

/// HKDF-SHA256 (RFC 5869, empty salt) under an explicit domain-separation
/// label: `totp-gcm-v2` seals data directly, `totp-kek-v1` wraps v3 DEKs.
fn derive_labeled(totp_key: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN], ring::error::Unspecified> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(totp_key);
  let info_labels = [info];
  let okm = prk.expand(&info_labels, HkdfAesKey)?;
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

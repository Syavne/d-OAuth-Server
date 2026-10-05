//! TOTP helpers (RFC 6238, ±1 step, used-code replay cache).
//!
//! Secrets are stored encrypted (see [`crate::keys::KeyRing`]); verification
//! enforces the acceptance window and claims used codes in Redis to block
//! replay. The wire format is RFC 6238 §5.2 verbatim: `T0 = 0`, `Tx = 30 s`,
//! SHA-1, 6 digits, with the validator accepting one step of look-ahead and
//! look-behind.
//!
//! The encrypted-secret blob layout mirrors `cli::secret` (`version(1) ||
//! kid_len(1) || kid || nonce(12) || ciphertext+tag`, AES-256-GCM under
//! `SHA256(totp_key)`), so CLI-provisioned secrets decrypt here and
//! login-provisioned secrets stay CLI-readable. The two implementations are
//! intentionally small duplicates: `crypto` cannot depend on `cli`.
//!
//! No error variant carries a secret, code, or key: failures collapse to
//! static messages.

use std::time::Duration;

use base32::Alphabet;
use rand::{TryRng as _, rngs::SysRng};
use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  rand::{SecureRandom as _, SystemRandom},
};
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use totp_rs::{Algorithm, Builder, Secret};

use crate::{crypto::ct::ct_eq, keys::KeyRing};

/// TOTP time-step in seconds (RFC 6238 §5.2 `Tx`).
pub const TOTP_STEP_SECS: u64 = 30;
/// Accepted clock drift in steps, each side of the current step.
pub const TOTP_SKEW_STEPS: u16 = 1;
/// Digits per code (RFC 6238 default).
pub const TOTP_DIGITS: u8 = 6;
/// How long a consumed code stays claimed: the 90 s window plus margin.
pub const USED_CODE_TTL: Duration = Duration::from_secs(180);
/// Recovery codes minted per enrollment.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Current encrypted-secret blob format version.
const TOTP_BLOB_VERSION: u8 = 1;
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;

/// Failures from TOTP enrollment and verification.
///
/// Every variant renders a static message: secrets, codes, and key material
/// never reach logs or clients.
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
  /// The stored secret is not valid base32 or builds no compliant verifier.
  #[error("invalid TOTP secret")]
  InvalidSecret,
  /// The operating-system RNG failed.
  #[error("operating-system randomness unavailable")]
  UnavailableRandomness,
  /// Encryption failed (no TOTP key configured or the AEAD rejected input).
  #[error("TOTP encryption failed")]
  Encrypt,
  /// The blob is malformed, names an unknown key, or fails authentication.
  #[error("TOTP secret cannot be decrypted")]
  Decrypt,
  /// The replay store was unreachable.
  #[error("TOTP replay store unavailable")]
  Store(#[from] redis::RedisError),
  /// The replay store answered with an unexpected reply (fail closed).
  #[error("TOTP replay store returned an unexpected reply")]
  UnexpectedReply,
}

impl From<TotpError> for crate::error::AppError {
  /// Every TOTP failure is an internal, masked failure: the client sees
  /// `server_error`, never secret material or store detail.
  fn from(error: TotpError) -> Self {
    Self::internal(error)
  }
}

/// Whether a replay-marker claim saw the code for the first time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
  /// First presentation of this code in this step.
  Fresh,
  /// This code was already consumed in this step: reject it.
  Replay,
}

/// Generate a fresh 160-bit secret, base32 (RFC 4648, no padding).
///
/// # Errors
///
/// Returns [`TotpError::UnavailableRandomness`] when the OS RNG fails.
pub fn generate_secret() -> Result<String, TotpError> {
  let mut bytes = [0u8; 20];
  SysRng
    .try_fill_bytes(&mut bytes)
    .map_err(|_| TotpError::UnavailableRandomness)?;
  Ok(base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes))
}

/// Generate one-time recovery codes (each 80-bit, base32, no padding).
///
/// Callers hash every code (Argon2id) before storage and show the plaintext
/// exactly once.
///
/// # Errors
///
/// Returns [`TotpError::UnavailableRandomness`] when the OS RNG fails.
pub fn generate_recovery_codes() -> Result<Vec<String>, TotpError> {
  let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
  for _ in 0..RECOVERY_CODE_COUNT {
    let mut bytes = [0u8; 10];
    SysRng
      .try_fill_bytes(&mut bytes)
      .map_err(|_| TotpError::UnavailableRandomness)?;
    codes.push(base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes));
  }
  Ok(codes)
}

/// Normalize user input for comparison: trim, then require 6 ASCII digits.
///
/// Returns `None` for anything else (a wrong code, never an error).
fn normalize_code(code: &str) -> Option<&str> {
  let trimmed = code.trim();
  if trimmed.len() == usize::from(TOTP_DIGITS) && trimmed.bytes().all(|b| b.is_ascii_digit()) {
    Some(trimmed)
  } else {
    None
  }
}

/// Normalize a presented recovery code: drop separators/whitespace, uppercase.
#[must_use]
pub fn normalize_recovery_code(code: &str) -> String {
  code
    .chars()
    .filter(|c| !c.is_whitespace() && *c != '-')
    .flat_map(|c| c.to_uppercase())
    .collect()
}

/// Build the RFC 6238 verifier for a stored base32 secret.
///
/// # Errors
///
/// Returns [`TotpError::InvalidSecret`] when the secret is not decodable
/// base32 or the parameters fail validation. The offending value is never
/// attached to the error.
pub fn build_totp(secret_b32: &str) -> Result<totp_rs::Totp, TotpError> {
  let upper = secret_b32.trim().to_ascii_uppercase();
  let raw =
    base32::decode(Alphabet::Rfc4648 { padding: false }, &upper).ok_or(TotpError::InvalidSecret)?;
  if raw.is_empty() {
    return Err(TotpError::InvalidSecret);
  }
  Builder::new()
    .with_secret(Secret::from(raw.as_slice()))
    .with_algorithm(Algorithm::SHA1)
    .with_digits(TOTP_DIGITS)
    .with_skew(TOTP_SKEW_STEPS)
    .with_step_duration(TOTP_STEP_SECS)
    .build()
    .map_err(|_| TotpError::InvalidSecret)
}

/// Check `code` against the ±1-step window around `now_unix`.
///
/// Returns the matched time-step counter, or `None` for a wrong code. Only a
/// malformed stored secret is an error; a wrong code is `Ok(None)`.
///
/// # Errors
///
/// Returns [`TotpError::InvalidSecret`] when the stored secret is malformed.
pub fn verify_window(
  secret_b32: &str,
  code: &str,
  now_unix: u64,
) -> Result<Option<u64>, TotpError> {
  let Some(presented) = normalize_code(code) else {
    return Ok(None);
  };
  let totp = build_totp(secret_b32)?;
  let counter = now_unix / TOTP_STEP_SECS;
  let skew = u64::from(TOTP_SKEW_STEPS);
  for step in [
    counter.saturating_sub(skew),
    counter,
    counter.saturating_add(skew),
  ] {
    let candidate = totp
      .generate(step.saturating_mul(TOTP_STEP_SECS))
      .to_string();
    if ct_eq(candidate.as_bytes(), presented.as_bytes()) {
      return Ok(Some(step));
    }
  }
  Ok(None)
}

/// Domain-separated fingerprint binding a used code to its owner and step.
///
/// The fingerprint (never the code) becomes the Redis replay-marker key.
#[must_use]
pub fn replay_fingerprint(user_id: &str, code: &str, step: u64) -> String {
  let mut hasher = Sha256::new();
  hasher.update(b"totp-replay-v1|");
  hasher.update(user_id.as_bytes());
  hasher.update(b"|");
  hasher.update(code.as_bytes());
  hasher.update(b"|");
  hasher.update(step.to_be_bytes());
  hex_bytes(&hasher.finalize())
}

/// Atomically claim a replay-marker key (`SET key 1 PX ttl NX`).
///
/// `Ok(Claim::Fresh)` claims first presentation; `Ok(Claim::Replay)` reports
/// a replay. Any transport failure or surprising reply is an error (fail
/// closed), never a silent accept.
///
/// # Errors
///
/// Returns [`TotpError::Store`] when Redis fails and
/// [`TotpError::UnexpectedReply`] for a non-`SET`-shaped reply.
pub async fn claim_code(
  conn: &mut impl redis::aio::ConnectionLike,
  key: &str,
  ttl: Duration,
) -> Result<Claim, TotpError> {
  let millis = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
  let cmd = redis::cmd("SET")
    .arg(key)
    .arg("1")
    .arg("PX")
    .arg(millis)
    .arg("NX")
    .to_owned();
  let reply: redis::Value = conn.req_packed_command(&cmd).await?;
  match reply {
    redis::Value::Okay => Ok(Claim::Fresh),
    redis::Value::Nil => Ok(Claim::Replay),
    redis::Value::SimpleString(text) if text == "OK" => Ok(Claim::Fresh),
    _ => Err(TotpError::UnexpectedReply),
  }
}

/// Verify `code` in the ±1-step window and atomically claim it on first use.
///
/// `replay_key_for_step` maps the matched step counter to the full Redis
/// replay-marker key (built by the caller from [`replay_fingerprint`] plus
/// the store prefix). Returns `false` for a wrong code AND for a replayed
/// one; callers must not distinguish the two.
///
/// # Errors
///
/// Returns [`TotpError::InvalidSecret`] for a malformed stored secret and
/// [`TotpError::Store`] when the replay store fails.
pub async fn verify_and_claim(
  conn: &mut impl redis::aio::ConnectionLike,
  replay_key_for_step: impl Fn(u64) -> String,
  secret_b32: &str,
  code: &str,
  now_unix: u64,
  ttl: Duration,
) -> Result<bool, TotpError> {
  let Some(step) = verify_window(secret_b32, code, now_unix)? else {
    return Ok(false);
  };
  match claim_code(conn, &replay_key_for_step(step), ttl).await? {
    Claim::Fresh => Ok(true),
    Claim::Replay => Ok(false),
  }
}

/// Encrypt a TOTP secret under the active TOTP-encryption key.
///
/// Blob layout mirrors `cli::secret`: `version(1) || kid_len(1) || kid ||
/// nonce(12) || ciphertext+tag`.
///
/// # Errors
///
/// Returns [`TotpError::Encrypt`] when no TOTP key is configured or the AEAD
/// fails.
pub fn encrypt_secret(keys: &KeyRing, plaintext: &str) -> Result<Vec<u8>, TotpError> {
  let (key_id, secret) = keys.active_totp_key().ok_or(TotpError::Encrypt)?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > usize::from(u8::MAX) {
    return Err(TotpError::Encrypt);
  }
  let key = derive_key(secret.expose_secret().as_bytes());
  let mut nonce_bytes = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut nonce_bytes)
    .map_err(|_| TotpError::UnavailableRandomness)?;
  let sealing =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| TotpError::Encrypt)?);
  let mut in_out = plaintext.as_bytes().to_vec();
  sealing
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::empty(),
      &mut in_out,
    )
    .map_err(|_| TotpError::Encrypt)?;
  let mut blob = Vec::with_capacity(2 + kid.len() + NONCE_LEN + in_out.len());
  blob.push(TOTP_BLOB_VERSION);
  blob.push(kid.len() as u8);
  blob.extend_from_slice(kid);
  blob.extend_from_slice(&nonce_bytes);
  blob.extend_from_slice(&in_out);
  Ok(blob)
}

/// Decrypt a secret previously produced by [`encrypt_secret`], trying the key
/// named in the blob (retained keys keep decrypting after rotation).
///
/// # Errors
///
/// Returns [`TotpError::Decrypt`] for a malformed blob, an unknown key id, or
/// an authentication failure. The reason is never distinguished.
pub fn decrypt_secret(keys: &KeyRing, blob: &[u8]) -> Result<String, TotpError> {
  if blob.len() < 2 + NONCE_LEN || blob[0] != TOTP_BLOB_VERSION {
    return Err(TotpError::Decrypt);
  }
  let kid_len = usize::from(blob[1]);
  let header = 2 + kid_len;
  if blob.len() < header + NONCE_LEN {
    return Err(TotpError::Decrypt);
  }
  let kid = core::str::from_utf8(blob.get(2..header).unwrap_or_default())
    .map_err(|_| TotpError::Decrypt)?;
  let secret = keys.totp_key_by_id(kid).ok_or(TotpError::Decrypt)?;
  let key = derive_key(secret.expose_secret().as_bytes());
  let mut nonce_bytes = [0u8; NONCE_LEN];
  nonce_bytes.copy_from_slice(&blob[header..header + NONCE_LEN]);
  let mut ciphertext = blob[header + NONCE_LEN..].to_vec();
  let opening =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| TotpError::Decrypt)?);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::empty(),
      &mut ciphertext,
    )
    .map_err(|_| TotpError::Decrypt)?;
  String::from_utf8(plaintext.to_vec()).map_err(|_| TotpError::Decrypt)
}

/// Build an `otpauth://` enrollment URI (same shape as `cli::secret`).
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
  format!(
    "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
    percent_encode(issuer),
    percent_encode(account),
    secret_b32,
    percent_encode(issuer)
  )
}

/// Derive the AES-256 key from configured TOTP key material (SHA-256).
fn derive_key(totp_key: &[u8]) -> [u8; 32] {
  let digest = Sha256::digest(totp_key);
  let mut key = [0u8; 32];
  key.copy_from_slice(&digest);
  key
}

/// Lowercase hex encoding of raw bytes.
fn hex_bytes(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    out.push_str(&format!("{b:02x}"));
  }
  out
}

/// Percent-encode a URI component (unreserved passthrough, uppercase hex).
fn percent_encode(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(char::from(byte));
    } else {
      out.push_str(&format!("%{byte:02X}"));
    }
  }
  out
}

#[cfg(test)]
mod tests;

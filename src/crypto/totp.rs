//! TOTP helpers (RFC 6238, ±1 step, used-code replay cache).
//!
//! Secrets are stored encrypted (see [`crate::keys::KeyRing`]); verification
//! enforces the acceptance window and claims used codes in Redis to block
//! replay. The wire format is RFC 6238 §5.2 verbatim: `T0 = 0`, `Tx = 30 s`,
//! SHA-1, 6 digits, with the validator accepting one step of look-ahead and
//! look-behind.
//!
//! The encrypted-secret blob layout mirrors `cli::secret`. Fresh writes use
//! the v3 envelope (`version(3) || kid_len(1) || kid || wrap_nonce(12) ||
//! wrapped_dek(32+16) || data_nonce(12) || ciphertext+tag`): a random 32-byte
//! DEK per row, wrapped under HKDF-SHA256(`totp_key`, info `totp-kek-v1`).
//! The wrap AAD binds the data nonce; the data AAD carries only the format
//! tag plus version, never the kid, so `totp rewrap` can move a DEK to a new
//! key without touching the data ciphertext. The writer is version-gated
//! (`envelope = !pii_dual_write`) so old replicas keep reading v2 during the
//! rolling upgrade. Version-2 blobs (HKDF `totp-gcm-v2`, empty AAD) and
//! version-1 blobs (bare `SHA256(totp_key)`) still decrypt. The two
//! implementations are intentionally small duplicates: `crypto` cannot depend
//! on `cli`.
//!
//! No error variant carries a secret, code, or key: failures collapse to
//! static messages.

use std::time::Duration;

use base32::Alphabet;
use qrcode::{QrCode, render::svg};
use rand::{TryRng as _, rngs::SysRng};
use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  hkdf,
  rand::{SecureRandom as _, SystemRandom},
};
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use totp_rs::{Algorithm, Builder, Secret};
use zeroize::Zeroizing;

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
/// Current encrypted-secret blob format version (HKDF-SHA256 writes).
const TOTP_BLOB_VERSION: u8 = 2;
/// Envelope-encrypted blob version (per-row DEK): written when the caller
/// passes `envelope = true`.
const TOTP_BLOB_V3: u8 = 3;
/// Legacy blob version (bare-`SHA256(totp_key)` writes): decrypt-only.
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
/// Wrapped-DEK length: a 32-byte DEK sealed under AES-256-GCM (16-byte tag).
const WRAPPED_DEK_LEN: usize = 32 + 16;

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
  /// The enrollment URI is too long to encode as a QR code.
  #[error("TOTP QR rendering failed")]
  Qr,
  /// The replay store was unreachable.
  #[error("TOTP replay store unavailable")]
  Store(#[from] redis::RedisError),
  /// The replay store answered with an unexpected reply (fail closed).
  #[error("TOTP replay store returned an unexpected reply")]
  UnexpectedReply,
}

impl From<TotpError> for crate::error::AppError {
  /// Fail-closed mapping: a stored ciphertext that fails to open is
  /// [`AppError::PiiDecrypt`] (503 + `pii.decrypt_failure` at the route
  /// layer); store and sealing failures are `temporarily_unavailable` (503),
  /// never a 500 and never fail-open. Only QR rendering — a server-side
  /// rendering defect, not a decrypt or dependency failure — stays
  /// `server_error`. Every target is payload-free: no secret, code, key, or
  /// store detail reaches the client.
  fn from(error: TotpError) -> Self {
    match error {
      TotpError::Decrypt => Self::PiiDecrypt,
      TotpError::Store(_)
      | TotpError::UnexpectedReply
      | TotpError::Encrypt
      | TotpError::UnavailableRandomness
      | TotpError::InvalidSecret => Self::temporarily_unavailable(),
      TotpError::Qr => Self::server_error(),
    }
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
/// HMAC-SHA256 under a token pepper over the domain-separated
/// message, so the Redis replay marker reveals nothing to brute force: a
/// dump of the marker key cannot be reversed into the 6-digit code within
/// its TTL without the pepper. The fingerprint (never the code) becomes the
/// Redis replay-marker key. Markers are stored under the active pepper;
/// verification probes every retained pepper generation newest-first (see
/// [`replay_fingerprints`] and [`verify_and_claim_with_ring`]), so a code
/// claimed before a rotation still counts as a replay after it within the
/// 180 s claim window.
///
/// The HMAC key schedule is RFC 2104 §2 verbatim (long peppers are hashed,
/// short peppers zero-padded), infallible by construction, mirroring
/// `store::hmac_sha256` without depending on `store`. It is byte-equivalent
/// with `Hmac::<Sha256>::new_from_slice` over the same message.
#[must_use]
pub fn replay_fingerprint(pepper: &[u8], user_id: &str, code: &str, step: u64) -> String {
  use hmac::digest::{KeyInit, Mac as _};
  use sha2::digest::Key;
  let mut block = Zeroizing::new([0u8; 64]);
  if pepper.len() > block.len() {
    let hashed = Sha256::digest(pepper);
    block[..hashed.len()].copy_from_slice(&hashed);
  } else {
    block[..pepper.len()].copy_from_slice(pepper);
  }
  let key: &Key<hmac::Hmac<Sha256>> = (&*block).into();
  let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new(key);
  mac.update(b"totp-replay-v1|");
  mac.update(user_id.as_bytes());
  mac.update(b"|");
  mac.update(code.as_bytes());
  mac.update(b"|");
  mac.update(&step.to_be_bytes());
  hex_bytes(&mac.finalize().into_bytes())
}

/// Fingerprints for one code under every retained pepper generation,
/// newest-first (one entry per [`KeyRing::peppers_newest_first`] item).
///
/// Callers store new markers under the first entry (the active pepper) and
/// treat any entry as a replay hit, so a pepper rotation inside the claim
/// window cannot reopen a consumed code.
#[must_use]
pub fn replay_fingerprints(keys: &KeyRing, user_id: &str, code: &str, step: u64) -> Vec<String> {
  keys
    .peppers_newest_first()
    .map(|(_, secret)| replay_fingerprint(secret.expose_secret().as_bytes(), user_id, code, step))
    .collect()
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

/// One TOTP presentation to verify and claim across pepper generations.
pub struct TotpClaim<'a> {
  /// Owner label bound into the replay fingerprint (user id string).
  pub user_id: &'a str,
  /// Stored base32 secret to verify against.
  pub secret_b32: &'a str,
  /// Presented code (whitespace trimmed before fingerprinting).
  pub code: &'a str,
  /// Current Unix time selecting the ±1-step window.
  pub now_unix: u64,
  /// How long a consumed code stays claimed.
  pub ttl: Duration,
}

/// Verify `code` and claim it across every retained pepper generation.
///
/// The matched step's fingerprint is computed under each pepper newest-first
/// (see [`replay_fingerprints`]); any hit is a replay. New markers are stored
/// under the active pepper only. `replay_key` maps a fingerprint hex to the
/// full Redis key (store prefix). Returns `false` for a wrong code AND for a
/// replayed one; callers must not distinguish the two.
///
/// Ordering (F7): older generations are probed read-only (`EXISTS`) before
/// the active generation is claimed atomically (`SET key 1 PX ttl NX`). This
/// order is deliberate. The only shared write is the single `SET NX` on the
/// active key, so concurrent presentations of the same code collapse there:
/// exactly one observes `Fresh`, every other observes `Replay`, and no
/// interleaving can accept the same code twice. Probing older generations
/// first also avoids writing a spurious active marker when the code was
/// already claimed before a pepper rotation (the pre-rotation fingerprint
/// still hits within the claim window). Reversing the order — claim first,
/// then probe — would widen that race and leave junk markers on replays.
///
/// # Errors
///
/// Returns [`TotpError::InvalidSecret`] for a malformed stored secret,
/// [`TotpError::Encrypt`] when the ring holds no pepper, and
/// [`TotpError::Store`] when the replay store fails.
pub async fn verify_and_claim_with_ring(
  conn: &mut impl redis::aio::ConnectionLike,
  keys: &KeyRing,
  replay_key: impl Fn(&str) -> String,
  claim: &TotpClaim<'_>,
) -> Result<bool, TotpError> {
  let Some(step) = verify_window(claim.secret_b32, claim.code, claim.now_unix)? else {
    return Ok(false);
  };
  let trimmed = claim.code.trim();
  let fingerprints = replay_fingerprints(keys, claim.user_id, trimmed, step);
  let Some(active) = fingerprints.first() else {
    return Err(TotpError::Encrypt);
  };
  for fingerprint in fingerprints.iter().skip(1) {
    let exists: i64 = redis::cmd("EXISTS")
      .arg(replay_key(fingerprint))
      .query_async(conn)
      .await?;
    if exists != 0 {
      return Ok(false);
    }
  }
  match claim_code(conn, &replay_key(active), claim.ttl).await? {
    Claim::Fresh => Ok(true),
    Claim::Replay => Ok(false),
  }
}

/// Encrypt a TOTP secret under the active TOTP-encryption key.
///
/// The writer is version-gated for the rolling upgrade: `envelope = false`
/// (while `pii_dual_write` is on) writes the legacy v2 blob so old replicas
/// keep reading; `envelope = true` writes the v3 per-row-DEK envelope.
/// Callers pass `!config.pii_dual_write`.
///
/// # Errors
///
/// Returns [`TotpError::Encrypt`] when no TOTP key is configured or the AEAD
/// fails.
pub fn encrypt_secret(
  keys: &KeyRing,
  plaintext: &str,
  envelope: bool,
) -> Result<Vec<u8>, TotpError> {
  if envelope {
    encrypt_v3(keys, plaintext)
  } else {
    encrypt_v2(keys, plaintext)
  }
}

/// Legacy v2 write: `version(2) || kid_len(1) || kid || nonce(12) ||
/// ciphertext+tag`, AES-256-GCM under HKDF-SHA256 with empty AAD.
fn encrypt_v2(keys: &KeyRing, plaintext: &str) -> Result<Vec<u8>, TotpError> {
  let (key_id, secret) = keys.active_totp_key().ok_or(TotpError::Encrypt)?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > usize::from(u8::MAX) {
    return Err(TotpError::Encrypt);
  }
  let key = derive_key(secret.expose_secret().as_bytes()).map_err(|_| TotpError::Encrypt)?;
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

/// Envelope write: `version(3) || kid_len(1) || kid || wrap_nonce(12) ||
/// wrapped_dek(32+16) || data_nonce(12) || secret_ct+tag`.
///
/// A random 32-byte DEK is generated per write, wrapped under a KEK derived
/// via HKDF-SHA256 (info `totp-kek-v1`) from the active TOTP key, and the
/// secret is sealed under the DEK. The data nonce is generated FIRST because
/// the wrap AAD binds it: a wrapped DEK lifted from another row names the
/// wrong nonce and fails to unwrap.
fn encrypt_v3(keys: &KeyRing, plaintext: &str) -> Result<Vec<u8>, TotpError> {
  let (key_id, secret) = keys.active_totp_key().ok_or(TotpError::Encrypt)?;
  let kid = key_id.as_str().as_bytes();
  if kid.len() > usize::from(u8::MAX) {
    return Err(TotpError::Encrypt);
  }
  let kek = Zeroizing::new(
    derive_labeled(secret.expose_secret().as_bytes(), KEK_INFO).map_err(|_| TotpError::Encrypt)?,
  );
  let rng = SystemRandom::new();
  let mut data_nonce = [0u8; NONCE_LEN];
  rng
    .fill(&mut data_nonce)
    .map_err(|_| TotpError::UnavailableRandomness)?;
  let mut wrap_nonce = [0u8; NONCE_LEN];
  rng
    .fill(&mut wrap_nonce)
    .map_err(|_| TotpError::UnavailableRandomness)?;
  let mut dek = Zeroizing::new([0u8; 32]);
  rng
    .fill(&mut dek[..])
    .map_err(|_| TotpError::UnavailableRandomness)?;
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

/// Seal `in_out` in place under `key`, appending the GCM tag.
///
/// # Errors
///
/// Returns [`TotpError::Encrypt`] when the AEAD rejects the key.
fn seal_with_aad(
  key: &[u8],
  nonce_bytes: [u8; NONCE_LEN],
  aad: &[u8],
  in_out: &mut Vec<u8>,
) -> Result<(), TotpError> {
  let sealing =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| TotpError::Encrypt)?);
  sealing
    .seal_in_place_append_tag(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::from(aad),
      in_out,
    )
    .map_err(|_| TotpError::Encrypt)
}

/// Decrypt a secret previously produced by [`encrypt_secret`], trying the key
/// named in the blob (retained keys keep decrypting after rotation).
///
/// Version-3 envelopes unwrap the per-row DEK under the HKDF-SHA256 KEK, then
/// open the data ciphertext; version-2 blobs open under the HKDF-SHA256 key;
/// legacy version-1 blobs first try the HKDF key, then fall back to the
/// bare-`SHA256(totp_key)` key, so rows written before the HKDF migration
/// keep decrypting.
///
/// # Errors
///
/// Returns [`TotpError::Decrypt`] for a malformed blob, an unknown key id, or
/// an authentication failure. The reason is never distinguished.
pub fn decrypt_secret(keys: &KeyRing, blob: &[u8]) -> Result<String, TotpError> {
  if blob.len() < 2 + NONCE_LEN
    || (blob[0] != TOTP_BLOB_V3 && blob[0] != TOTP_BLOB_VERSION && blob[0] != TOTP_BLOB_V1)
  {
    return Err(TotpError::Decrypt);
  }
  let version = blob[0];
  let kid_len = usize::from(blob[1]);
  let header = 2 + kid_len;
  if blob.len() < header + NONCE_LEN {
    return Err(TotpError::Decrypt);
  }
  let kid_bytes = blob.get(2..header).ok_or(TotpError::Decrypt)?;
  let kid = core::str::from_utf8(kid_bytes).map_err(|_| TotpError::Decrypt)?;
  let secret = keys.totp_key_by_id(kid).ok_or(TotpError::Decrypt)?;
  let ikm = secret.expose_secret().as_bytes();
  if version == TOTP_BLOB_V3 {
    return decrypt_v3(ikm, kid_bytes, &blob[header..]);
  }
  let mut nonce_bytes = [0u8; NONCE_LEN];
  nonce_bytes.copy_from_slice(&blob[header..header + NONCE_LEN]);
  let ciphertext = &blob[header + NONCE_LEN..];
  if version == TOTP_BLOB_VERSION {
    let key = derive_key(ikm).map_err(|_| TotpError::Decrypt)?;
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
/// The KEK is re-derived from the key named in the blob; the wrap AAD
/// rebinds that kid plus the stored data nonce, so a wrapped DEK copied from
/// another row fails closed.
///
/// # Errors
///
/// Returns [`TotpError::Decrypt`] for a malformed body, an unknown key, or
/// an authentication failure. The reason is never distinguished.
fn decrypt_v3(ikm: &[u8], kid: &[u8], body: &[u8]) -> Result<String, TotpError> {
  if body.len() < NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + 16 {
    return Err(TotpError::Decrypt);
  }
  let (wrap_nonce, rest) = body.split_at(NONCE_LEN);
  let (wrapped_dek, rest) = rest.split_at(WRAPPED_DEK_LEN);
  let (data_nonce, ciphertext) = rest.split_at(NONCE_LEN);
  let mut wrap_nonce_bytes = [0u8; NONCE_LEN];
  wrap_nonce_bytes.copy_from_slice(wrap_nonce);
  let mut data_nonce_bytes = [0u8; NONCE_LEN];
  data_nonce_bytes.copy_from_slice(data_nonce);
  let kek = Zeroizing::new(derive_labeled(ikm, KEK_INFO).map_err(|_| TotpError::Decrypt)?);
  let dek_bytes = open_with_aad(
    &kek[..],
    &wrap_nonce_bytes,
    &wrap_aad(kid, &data_nonce_bytes),
    wrapped_dek,
  )?;
  if dek_bytes.len() != 32 {
    return Err(TotpError::Decrypt);
  }
  let mut dek_key = [0u8; 32];
  dek_key.copy_from_slice(&dek_bytes);
  let dek = Zeroizing::new(dek_key);
  let plaintext = open_with_aad(&dek[..], &data_nonce_bytes, DATA_AAD, ciphertext)?;
  String::from_utf8(plaintext).map_err(|_| TotpError::Decrypt)
}

/// Open `ciphertext` (with trailing GCM tag) under `key`, returning UTF-8.
///
/// # Errors
///
/// Returns [`TotpError::Decrypt`] for an authentication failure or
/// non-UTF-8 plaintext. The reason is never distinguished.
fn open_with_key(
  key: &[u8; 32],
  nonce_bytes: &[u8; NONCE_LEN],
  ciphertext: &[u8],
) -> Result<String, TotpError> {
  let plaintext = open_with_aad(key, nonce_bytes, &[], ciphertext)?;
  String::from_utf8(plaintext).map_err(|_| TotpError::Decrypt)
}

/// Open `ciphertext` (with trailing GCM tag) under `key` and `aad`,
/// returning the raw plaintext.
///
/// # Errors
///
/// Returns [`TotpError::Decrypt`] for an authentication failure. The reason
/// is never distinguished.
fn open_with_aad(
  key: &[u8],
  nonce_bytes: &[u8; NONCE_LEN],
  aad: &[u8],
  ciphertext: &[u8],
) -> Result<Vec<u8>, TotpError> {
  let mut in_out = ciphertext.to_vec();
  let opening =
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| TotpError::Decrypt)?);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(*nonce_bytes),
      Aad::from(aad),
      &mut in_out,
    )
    .map_err(|_| TotpError::Decrypt)?;
  Ok(plaintext.to_vec())
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

/// Render an `otpauth://` enrollment URI as a self-contained SVG QR code.
///
/// The output is inline SVG with no external references, no `<image>`, and no
/// script, so it embeds directly in a server-rendered page under a
/// `script-src 'none'` policy. An over-long URI maps to [`TotpError::Qr`]; no
/// secret or URI content is logged.
pub fn qr_svg(uri: &str) -> Result<String, TotpError> {
  let code = QrCode::new(uri.as_bytes()).map_err(|_| TotpError::Qr)?;
  let mut svg = code.render::<svg::Color>().min_dimensions(200, 200).build();
  Ok(match svg.find("<svg") {
    Some(start) => svg.split_off(start),
    None => svg,
  })
}

/// Derive the AES-256 key from configured TOTP key material via HKDF-SHA256
/// (RFC 5869, empty salt, info `totp-gcm-v2` domain-separating TOTP use).
fn derive_key(totp_key: &[u8]) -> Result<[u8; 32], ring::error::Unspecified> {
  derive_labeled(totp_key, HKDF_INFO)
}

/// HKDF-SHA256 (RFC 5869, empty salt) under an explicit domain-separation
/// label: `totp-gcm-v2` seals data directly, `totp-kek-v1` wraps v3 DEKs.
fn derive_labeled(totp_key: &[u8], info: &[u8]) -> Result<[u8; 32], ring::error::Unspecified> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(totp_key);
  let info_labels = [info];
  let okm = prk.expand(&info_labels, HkdfAesKey)?;
  let mut key = [0u8; 32];
  okm.fill(&mut key)?;
  Ok(key)
}

/// Legacy derivation (bare `SHA256(totp_key)`): decrypt-only fallback for
/// version-1 blobs written before the HKDF migration.
fn derive_key_legacy(totp_key: &[u8]) -> [u8; 32] {
  let digest = Sha256::digest(totp_key);
  let mut key = [0u8; 32];
  key.copy_from_slice(&digest);
  key
}

/// `ring::hkdf` output-length marker for a 256-bit AES key.
struct HkdfAesKey;

impl hkdf::KeyType for HkdfAesKey {
  fn len(&self) -> usize {
    32
  }
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

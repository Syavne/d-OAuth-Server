//! `totp rewrap`: re-wrap v3 TOTP DEKs under the active TOTP-encryption key.
//!
//! A v3 blob is `version(3) || kid_len(1) || kid || wrap_nonce(12) ||
//! wrapped_dek(32+16) || data_nonce(12) || secret_ct+tag`. Because the data
//! AAD binds only the format tag and version (never the wrapping kid), moving a
//! row to a new key means unwrapping its per-row DEK with the key named in the
//! blob and re-wrapping that SAME DEK under the active key: the data nonce and
//! the secret ciphertext+tag stay byte-identical, and only `kid`, `wrap_nonce`,
//! and `wrapped_dek` change. The secret plaintext is never decrypted here.
//!
//! Rows already wrapped by the active key are skipped, leaving v1/v2 rows to
//! `pii backfill` (they have no DEK to re-wrap). A scan processes bounded
//! batches; each batch runs in its own transaction holding
//! `pg_advisory_xact_lock` on the connection that owns that transaction, so the
//! lock and the batch commit/rollback are atomic. The command prints counts
//! only and never emits blob or key material.

use std::fmt;

use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  hkdf,
  rand::{SecureRandom as _, SystemRandom},
};
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::context::{CliError, Context, audit};
use crate::keys::KeyRing;

/// Envelope-encrypted blob version (per-row DEK).
const TOTP_BLOB_V3: u8 = 3;
/// HKDF domain-separation label for the key-encryption key wrapping v3 DEKs.
const KEK_INFO: &[u8] = b"totp-kek-v1";
/// AAD sealing the v3 data ciphertext: format tag plus version only.
const DATA_AAD: &[u8] = b"totp-v3\x03";
/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;
/// AES-256 key length.
const KEY_LEN: usize = 32;
/// Wrapped-DEK length: a 32-byte DEK sealed under AES-256-GCM.
const WRAPPED_DEK_LEN: usize = KEY_LEN + TAG_LEN;
/// Rows scanned/rewrapped per batch transaction.
const BATCH_SIZE: usize = 100;
/// Advisory-lock key, stable across processes.
const REWRAP_LOCK: &str = "d_oauth_totp_rewrap";

/// What a single row's blob implies for the re-wrap pass.
enum RewrapDecision {
  /// Already wrapped by the active key: leave untouched.
  AlreadyActive,
  /// v1/v2 (or an unknown version): no DEK to re-wrap; `pii backfill` owns it.
  Legacy,
  /// A v3 blob that cannot be parsed or opened: skipped, never overwritten.
  Malformed,
  /// The blob re-wrapped under the active key (this exact byte string is stored).
  Rewritten(Vec<u8>),
}

/// Counts from one `totp rewrap` run (plaintext counts, never blob material).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RewrapReport {
  /// Non-null `totp_secret_enc` rows examined.
  pub(super) scanned: u64,
  /// v3 rows re-wrapped under the active key.
  pub(super) rewrapped: u64,
  /// v3 rows already wrapped by the active key.
  pub(super) already_active: u64,
  /// v1/v2 rows left for `pii backfill`.
  pub(super) legacy: u64,
  /// v3 rows that could not be parsed or opened (skipped).
  pub(super) malformed: u64,
}

impl fmt::Display for RewrapReport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "totp rewrap: scanned={} rewrapped={} already_active={} skipped_legacy={} skipped_malformed={}",
      self.scanned, self.rewrapped, self.already_active, self.legacy, self.malformed
    )
  }
}

/// `totp rewrap`: re-wrap every v3 DEK under the active TOTP key.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active TOTP key is configured or a
/// cryptographic operation fails, and [`CliError::Database`] for PostgreSQL
/// failures.
pub(super) async fn rewrap(context: &Context) -> Result<RewrapReport, CliError> {
  rewrap_with(context.pool(), &context.config().keys).await
}

/// Re-wrap `users.totp_secret_enc` v3 blobs under the active key in bounded
/// batches.
///
/// Each batch is one transaction holding `pg_advisory_xact_lock` on its own
/// connection, so the lock and the batch commit/rollback are atomic. Keyset
/// pagination on `id` bounds each batch and keeps a re-run idempotent.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active TOTP key exists or a required
/// cryptographic operation fails, and [`CliError::Database`] for PostgreSQL
/// failures.
async fn rewrap_with(pool: &PgPool, keys: &KeyRing) -> Result<RewrapReport, CliError> {
  let (active_key_id, active_secret) = keys
    .active_totp_key()
    .ok_or_else(|| CliError::Crypto("no active TOTP encryption key configured".to_owned()))?;
  let active_kid = active_key_id.as_str();
  if active_kid.len() > usize::from(u8::MAX) {
    return Err(CliError::Crypto("TOTP key id is too long".to_owned()));
  }

  let mut report = RewrapReport::default();
  let mut after = Uuid::nil();
  loop {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
      .bind(REWRAP_LOCK)
      .execute(&mut *tx)
      .await?;
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
      "SELECT id, totp_secret_enc FROM users
        WHERE totp_secret_enc IS NOT NULL AND id > $1
        ORDER BY id
        LIMIT $2",
    )
    .bind(after)
    .bind(BATCH_SIZE as i64)
    .fetch_all(&mut *tx)
    .await?;
    if rows.is_empty() {
      tx.commit().await?;
      break;
    }
    let fetched = rows.len();
    for (id, blob) in &rows {
      report.scanned = report.scanned.saturating_add(1);
      match rewrap_v3_blob(keys, blob, active_kid, active_secret)? {
        RewrapDecision::Rewritten(new_blob) => {
          sqlx::query("UPDATE users SET totp_secret_enc = $2 WHERE id = $1")
            .bind(id)
            .bind(&new_blob)
            .execute(&mut *tx)
            .await?;
          report.rewrapped = report.rewrapped.saturating_add(1);
        }
        RewrapDecision::AlreadyActive => {
          report.already_active = report.already_active.saturating_add(1);
        }
        RewrapDecision::Legacy => {
          report.legacy = report.legacy.saturating_add(1);
        }
        RewrapDecision::Malformed => {
          report.malformed = report.malformed.saturating_add(1);
        }
      }
      after = *id;
    }
    tx.commit().await?;
    if fetched < BATCH_SIZE {
      break;
    }
  }
  audit("totp.rewrap", "users.totp_secret_enc");
  Ok(report)
}

/// Decide what to do with one stored blob: skip a non-v3 or an active-key row,
/// or re-wrap the DEK onto `active_kid` while preserving the data nonce and
/// ciphertext+tag.
///
/// A v3 blob that cannot be parsed, names an unknown key, or fails to unwrap is
/// reported as [`RewrapDecision::Malformed`] and left untouched — never
/// overwritten with garbage.
///
/// # Errors
/// Returns [`CliError::Crypto`] for an active-key derivation, RNG, or sealing
/// failure (a system fault that must abort the batch).
fn rewrap_v3_blob(
  keys: &KeyRing,
  blob: &[u8],
  active_kid: &str,
  active_secret: &SecretString,
) -> Result<RewrapDecision, CliError> {
  if blob.first().copied() != Some(TOTP_BLOB_V3) {
    return Ok(RewrapDecision::Legacy);
  }
  let Some(&kid_len_raw) = blob.get(1) else {
    return Ok(RewrapDecision::Malformed);
  };
  let header = 2 + usize::from(kid_len_raw);
  let Some(kid_bytes) = blob.get(2..header) else {
    return Ok(RewrapDecision::Malformed);
  };
  let Ok(kid) = std::str::from_utf8(kid_bytes) else {
    return Ok(RewrapDecision::Malformed);
  };
  if kid == active_kid {
    return Ok(RewrapDecision::AlreadyActive);
  }
  let Some(body) = blob.get(header..) else {
    return Ok(RewrapDecision::Malformed);
  };
  if body.len() < NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + TAG_LEN {
    return Ok(RewrapDecision::Malformed);
  }
  let Some(source_secret) = keys.totp_key_by_id(kid) else {
    return Ok(RewrapDecision::Malformed);
  };

  let (wrap_nonce, rest) = body.split_at(NONCE_LEN);
  let (wrapped_dek, rest) = rest.split_at(WRAPPED_DEK_LEN);
  let (data_nonce, data_ct) = rest.split_at(NONCE_LEN);
  let data_nonce = to_nonce(data_nonce)?;

  let source_kek = Zeroizing::new(
    derive_labeled(source_secret.expose_secret().as_bytes(), KEK_INFO)
      .map_err(|_| crypto_error("TOTP key derivation failed"))?,
  );
  let Some(dek_bytes) = unwrap_dek(
    &source_kek[..],
    wrap_nonce,
    &wrap_aad(kid_bytes, &data_nonce),
    wrapped_dek,
  ) else {
    return Ok(RewrapDecision::Malformed);
  };
  if dek_bytes.len() != KEY_LEN {
    return Ok(RewrapDecision::Malformed);
  }

  let active_kek = Zeroizing::new(
    derive_labeled(active_secret.expose_secret().as_bytes(), KEK_INFO)
      .map_err(|_| crypto_error("TOTP key derivation failed"))?,
  );
  let mut new_wrap_nonce = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut new_wrap_nonce)
    .map_err(|_| crypto_error("operating-system randomness unavailable"))?;
  let mut dek = Zeroizing::new(dek_bytes);
  seal_with_aad(
    &active_kek[..],
    new_wrap_nonce,
    &wrap_aad(active_kid.as_bytes(), &data_nonce),
    &mut dek,
  )?;

  let mut out = Vec::with_capacity(
    2 + active_kid.len() + NONCE_LEN + WRAPPED_DEK_LEN + NONCE_LEN + data_ct.len(),
  );
  out.push(TOTP_BLOB_V3);
  out.push(active_kid.len() as u8);
  out.extend_from_slice(active_kid.as_bytes());
  out.extend_from_slice(&new_wrap_nonce);
  out.extend_from_slice(&dek[..]);
  out.extend_from_slice(data_nonce.as_slice());
  out.extend_from_slice(data_ct);
  Ok(RewrapDecision::Rewritten(out))
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

/// Unwrap a v3 DEK under `kek`, returning `None` on any parse or AEAD failure
/// (the caller treats that as a malformed row).
fn unwrap_dek(kek: &[u8], nonce: &[u8], aad: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
  let nonce = to_nonce(nonce).ok()?;
  let mut in_out = wrapped.to_vec();
  let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, kek).ok()?);
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(nonce),
      Aad::from(aad),
      &mut in_out,
    )
    .ok()?;
  Some(plaintext.to_vec())
}

/// Seal `in_out` in place under `key`, appending the GCM tag.
///
/// # Errors
/// Returns [`CliError::Crypto`] when the AEAD rejects the key or the seal.
fn seal_with_aad(
  key: &[u8],
  nonce: [u8; NONCE_LEN],
  aad: &[u8],
  in_out: &mut Vec<u8>,
) -> Result<(), CliError> {
  let sealing = LessSafeKey::new(
    UnboundKey::new(&AES_256_GCM, key).map_err(|_| crypto_error("TOTP key rejected by AEAD"))?,
  );
  sealing
    .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), in_out)
    .map_err(|_| crypto_error("TOTP DEK wrap failed"))
}

/// HKDF-SHA256 (RFC 5869, empty salt) under an explicit domain-separation
/// label: `totp-kek-v1` wraps v3 DEKs.
fn derive_labeled(totp_key: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN], ring::error::Unspecified> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(totp_key);
  let info_labels = [info];
  let okm = prk.expand(&info_labels, HkdfAesKey)?;
  let mut key = [0u8; KEY_LEN];
  okm.fill(&mut key)?;
  Ok(key)
}

/// `ring::hkdf` output-length marker for a 256-bit AES key.
struct HkdfAesKey;

impl hkdf::KeyType for HkdfAesKey {
  fn len(&self) -> usize {
    KEY_LEN
  }
}

/// Convert a byte slice to a fixed 12-byte nonce.
///
/// # Errors
/// Returns [`CliError::Crypto`] when the slice is not exactly [`NONCE_LEN`].
fn to_nonce(bytes: &[u8]) -> Result<[u8; NONCE_LEN], CliError> {
  bytes
    .try_into()
    .map_err(|_| crypto_error("malformed TOTP blob"))
}

/// Build a payload-free CLI crypto error (never carries key or blob material).
fn crypto_error(message: &str) -> CliError {
  CliError::Crypto(message.to_owned())
}

#[cfg(test)]
mod tests;

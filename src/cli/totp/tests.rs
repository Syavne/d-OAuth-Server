//! `test(totp_rewrap_)` suite: DEK re-wrap onto the active TOTP key.

use secrecy::SecretString;
use sqlx::PgPool;
use uuid::Uuid;

use super::*;
use crate::cli::test_support::TestError;
use crate::crypto::totp as crypto_totp;
use crate::keys::{KeyId, KeyRing};

const OLD_ID: &str = "old";
const NEW_ID: &str = "new";
const OLD_MATERIAL: &str = "old-totp-material-0123456789abcdef";
const NEW_MATERIAL: &str = "new-totp-material-0123456789abcdef";

/// A parsed v3 body, borrowing the blob.
struct Parsed<'a> {
  kid: &'a str,
  wrap_nonce: &'a [u8],
  wrapped_dek: &'a [u8],
  data_nonce: &'a [u8],
  data_ct: &'a [u8],
}

fn key(id: &str, material: &str) -> (KeyId, SecretString) {
  (KeyId::new(id), SecretString::from(material.to_owned()))
}

/// A ring whose TOTP chain is `totp` (newest first), with throwaway pepper/PII
/// chains (untouched by re-wrap).
fn ring_with_totp(totp: &[(&str, &str)]) -> Result<KeyRing, TestError> {
  let totp_keys = totp
    .iter()
    .map(|(id, material)| key(id, material))
    .collect();
  KeyRing::from_parts(
    vec![key("p1", "pepper-material-0123456789abcdef")],
    totp_keys,
    vec![key("k1", "pii-material-0123456789abcdef")],
  )
  .map_err(|error| TestError::Harness(error.to_string()))
}

async fn insert_user(pool: &PgPool, id: Uuid, blob: &[u8]) -> Result<(), TestError> {
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, totp_secret_enc, totp_enabled, created_at, updated_at)
     VALUES ($1, NULL, 'x', $2, true, now(), now())",
  )
  .bind(id)
  .bind(blob)
  .execute(pool)
  .await?;
  Ok(())
}

async fn stored_blob(pool: &PgPool, id: Uuid) -> Result<Vec<u8>, TestError> {
  let blob: Option<Vec<u8>> = sqlx::query_scalar("SELECT totp_secret_enc FROM users WHERE id = $1")
    .bind(id)
    .fetch_one(pool)
    .await?;
  blob.ok_or(TestError::Missing("totp_secret_enc"))
}

fn parse(blob: &[u8]) -> Result<Parsed<'_>, TestError> {
  let kid_len = usize::from(*blob.get(1).ok_or(TestError::Missing("kid_len"))?);
  let header = 2 + kid_len;
  let kid = std::str::from_utf8(blob.get(2..header).ok_or(TestError::Missing("kid"))?)
    .map_err(|_| TestError::Missing("kid utf8"))?;
  let body = blob.get(header..).ok_or(TestError::Missing("body"))?;
  let wrap_nonce = body
    .get(..NONCE_LEN)
    .ok_or(TestError::Missing("wrap_nonce"))?;
  let wrapped_dek = body
    .get(NONCE_LEN..NONCE_LEN + WRAPPED_DEK_LEN)
    .ok_or(TestError::Missing("wrapped_dek"))?;
  let data_start = NONCE_LEN + WRAPPED_DEK_LEN;
  let data_nonce = body
    .get(data_start..data_start + NONCE_LEN)
    .ok_or(TestError::Missing("data_nonce"))?;
  let data_ct = body
    .get(data_start + NONCE_LEN..)
    .ok_or(TestError::Missing("data_ct"))?;
  Ok(Parsed {
    kid,
    wrap_nonce,
    wrapped_dek,
    data_nonce,
    data_ct,
  })
}

#[tokio::test]
async fn totp_rewrap_moves_v3_rows_to_active_key() -> Result<(), TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;

  let old = ring_with_totp(&[(OLD_ID, OLD_MATERIAL)])?;
  let full = ring_with_totp(&[(NEW_ID, NEW_MATERIAL), (OLD_ID, OLD_MATERIAL)])?;
  let new_only = ring_with_totp(&[(NEW_ID, NEW_MATERIAL)])?;

  let plaintext = crate::cli::secret::generate_totp_secret()?;
  let v3 = crypto_totp::encrypt_secret(&old, &plaintext, true)?;
  let v2 = crypto_totp::encrypt_secret(&old, &plaintext, false)?;
  // A v3 header that names a key but carries no body: malformed, must be skipped.
  let malformed = vec![3u8, 3, b'o', b'l', b'd'];

  let v3_id = Uuid::new_v4();
  let v2_id = Uuid::new_v4();
  let bad_id = Uuid::new_v4();
  insert_user(&pool, v3_id, &v3).await?;
  insert_user(&pool, v2_id, &v2).await?;
  insert_user(&pool, bad_id, &malformed).await?;

  let report = rewrap_with(&pool, &full).await?;
  assert_eq!(report.scanned, 3);
  assert_eq!(report.rewrapped, 1);
  assert_eq!(report.legacy, 1);
  assert_eq!(report.malformed, 1);
  assert_eq!(report.already_active, 0);

  let after = stored_blob(&pool, v3_id).await?;
  let before = parse(&v3)?;
  let now = parse(&after)?;
  assert_eq!(now.kid, NEW_ID, "row must now name the active key");
  assert_eq!(
    now.data_nonce, before.data_nonce,
    "data nonce must be preserved byte-for-byte"
  );
  assert_eq!(
    now.data_ct, before.data_ct,
    "secret ciphertext+tag must be preserved byte-for-byte"
  );
  assert_ne!(
    now.wrap_nonce, before.wrap_nonce,
    "wrap nonce must be fresh"
  );
  assert_ne!(
    now.wrapped_dek, before.wrapped_dek,
    "wrapped DEK must be re-sealed under the active key"
  );
  assert_eq!(crypto_totp::decrypt_secret(&new_only, &after)?, plaintext);

  // v1/v2 and malformed blobs are skipped and never overwritten.
  assert_eq!(stored_blob(&pool, v2_id).await?, v2);
  assert_eq!(stored_blob(&pool, bad_id).await?, malformed);
  Ok(())
}

#[tokio::test]
async fn totp_rewrap_is_idempotent() -> Result<(), TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;

  let old = ring_with_totp(&[(OLD_ID, OLD_MATERIAL)])?;
  let full = ring_with_totp(&[(NEW_ID, NEW_MATERIAL), (OLD_ID, OLD_MATERIAL)])?;

  let plaintext = crate::cli::secret::generate_totp_secret()?;
  let v3 = crypto_totp::encrypt_secret(&old, &plaintext, true)?;
  let id = Uuid::new_v4();
  insert_user(&pool, id, &v3).await?;

  let first = rewrap_with(&pool, &full).await?;
  assert_eq!(first.rewrapped, 1);
  let after_first = stored_blob(&pool, id).await?;

  let second = rewrap_with(&pool, &full).await?;
  assert_eq!(second.rewrapped, 0, "a re-run must rewrite nothing");
  assert_eq!(second.already_active, 1);
  assert_eq!(
    stored_blob(&pool, id).await?,
    after_first,
    "a re-run must not touch an already-active row"
  );
  Ok(())
}

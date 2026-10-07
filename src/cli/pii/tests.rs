//! `test(pii_backfill_)` / `test(pii_verify_)` suite: cutover backfill + checks.
//!
//! Every test gets a fresh migrated database from
//! [`crate::db::test_support`]: `pii backfill` and `pii verify` scan whole
//! tables, so the shared CLI harness would race other suites. Only counts are
//! asserted, never values or key material.

use secrecy::SecretString;
use serde_json::json;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::backfill::backfill_with;
use super::ensure_clean;
use super::rotate::rotate_with;
use super::verify::verify_with;
use crate::cli::test_support::TestError;
use crate::crypto::field::{blind_index_active, open_text, seal_text};
use crate::crypto::totp as crypto_totp;
use crate::db::test_support::migrated_pool;
use crate::db::user_repo::normalize_email;
use crate::keys::{KeyId, KeyRing};

/// Fixed TOTP secret plaintext (base32, deterministic across runs).
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn key(id: &str, material: &str) -> (KeyId, SecretString) {
  (KeyId::new(id), SecretString::from(material.to_owned()))
}

/// A ring with throwaway pepper, TOTP, and PII chains (newest first).
fn test_keys() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![key("p1", "pii-test-pepper-0123456789abcdef")],
    vec![key("t1", "pii-test-totp-key-0123456789abcdef")],
    vec![key("k1", "pii-test-pii-key-0123456789abcdef")],
  )
  .map_err(|error| TestError::Harness(error.to_string()))
}

/// Bind a fresh migrated database: whole-table scans need isolation, so never
/// the shared CLI harness. Keeps the shared container alive via `_db`.
macro_rules! fresh_pool {
  () => {
    migrated_pool()
      .await
      .map_err(|error| TestError::Harness(error.to_string()))
  };
}

/// Insert a legacy `users` row: plaintext email plus an optional TOTP blob.
async fn insert_user(
  pool: &PgPool,
  id: Uuid,
  email: Option<&str>,
  totp: Option<&[u8]>,
) -> Result<(), TestError> {
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, totp_secret_enc, totp_enabled, created_at, updated_at) \
     VALUES ($1, $2, 'x', $3, false, now(), now())",
  )
  .bind(id)
  .bind(email)
  .bind(totp)
  .execute(pool)
  .await?;
  Ok(())
}

/// Insert a legacy `oauth_clients` row with every PII column in plaintext.
async fn insert_client(pool: &PgPool, client_id: &str) -> Result<Uuid, TestError> {
  let id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name, grant_types, \
       response_types, scope, token_endpoint_auth_method, jwks_uri, tls_client_auth_subject_dn, \
       tls_client_auth_cert_thumbprint, software_id, contacts, request_uris, created_at, updated_at) \
     VALUES ($1, $2, now(), 'Legacy Client', ARRAY['authorization_code'], ARRAY['code'], \
       'api:read', 'none', 'https://legacy.example.test/jwks', 'CN=legacy', 'THUMB-LEGACY', \
       'sw-legacy', $3, $4, now(), now())",
  )
  .bind(id)
  .bind(client_id)
  .bind(json!({"email": "ops@legacy.example.test"}))
  .bind(json!(["https://legacy.example.test/request.jwk"]))
  .execute(pool)
  .await?;
  Ok(id)
}

/// Insert a legacy `redirect_uris` row with the URI in plaintext.
async fn insert_redirect(pool: &PgPool, uri: &str) -> Result<Uuid, TestError> {
  let id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, enabled, description, created_at, updated_at) \
     VALUES ($1, $2, 'authorize', true, '', now(), now())",
  )
  .bind(id)
  .bind(uri)
  .execute(pool)
  .await?;
  Ok(id)
}

/// The stored plaintext of one column, if still present.
async fn plaintext(
  pool: &PgPool,
  sql: &'static str,
  id: Uuid,
) -> Result<Option<String>, TestError> {
  let row = sqlx::query(sql).bind(id).fetch_one(pool).await?;
  Ok(row.try_get::<Option<String>, _>(0)?)
}

/// Every `oauth_clients` plaintext PII column of one row must be blanked.
async fn assert_client_plaintext_blank(pool: &PgPool, id: Uuid) -> Result<(), TestError> {
  let row = sqlx::query(
    "SELECT client_name, contacts, request_uris, jwks_uri, software_id, \
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint \
     FROM oauth_clients WHERE id = $1",
  )
  .bind(id)
  .fetch_one(pool)
  .await?;
  assert_eq!(row.try_get::<Option<String>, _>("client_name")?, None);
  assert_eq!(
    row.try_get::<Option<serde_json::Value>, _>("contacts")?,
    None
  );
  assert_eq!(
    row.try_get::<Option<serde_json::Value>, _>("request_uris")?,
    None
  );
  assert_eq!(row.try_get::<Option<String>, _>("jwks_uri")?, None);
  assert_eq!(row.try_get::<Option<String>, _>("software_id")?, None);
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_subject_dn")?,
    None
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_cert_thumbprint")?,
    None
  );
  Ok(())
}

#[tokio::test]
async fn pii_backfill_encrypts_and_blanks_plaintext() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let mixed_email = "Backfill-Me@Example.Test";
  let canonical = normalize_email(mixed_email);
  let v2 = crypto_totp::encrypt_secret(&keys, TOTP_SECRET, false)
    .map_err(|error| TestError::Harness(error.to_string()))?;
  let user_id = Uuid::new_v4();
  insert_user(&pool, user_id, Some(mixed_email), Some(&v2)).await?;
  let client_id = insert_client(&pool, "backfill-client").await?;
  let redirect_id = insert_redirect(&pool, "https://app.example.test/callback").await?;

  let report = backfill_with(&pool, &keys, false)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(report.users_sealed, 1);
  assert_eq!(report.clients_sealed, 1);
  assert_eq!(report.redirects_sealed, 1);
  assert_eq!(report.totp_upgraded, 1);

  // Users: plaintext blanked, ciphertext opens to the canonical email, the
  // blind index matches the active key, and the TOTP blob is now v3.
  assert_eq!(
    plaintext(&pool, "SELECT email FROM users WHERE id = $1", user_id).await?,
    None
  );
  let row = sqlx::query("SELECT email_enc, email_index, totp_secret_enc FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
  let email_enc = row.try_get::<Option<Vec<u8>>, _>("email_enc")?;
  let email_index = row.try_get::<Option<String>, _>("email_index")?;
  let totp = row.try_get::<Option<Vec<u8>>, _>("totp_secret_enc")?;
  let blob = email_enc.ok_or(TestError::Missing("email_enc"))?;
  assert_eq!(
    open_text(&keys, &blob).map_err(|error| TestError::Harness(error.to_string()))?,
    canonical
  );
  assert_eq!(email_index, Some(blind_index_active(&keys, &canonical)));
  let totp_blob = totp.ok_or(TestError::Missing("totp_secret_enc"))?;
  assert_eq!(totp_blob.first().copied(), Some(3));
  assert_eq!(
    crypto_totp::decrypt_secret(&keys, &totp_blob)
      .map_err(|error| TestError::Harness(error.to_string()))?,
    TOTP_SECRET
  );

  // Clients: every plaintext column blanked, every `_enc` opens, and both
  // mTLS blind indexes match the active key under the exact string.
  assert_client_plaintext_blank(&pool, client_id).await?;
  let row = sqlx::query(
    "SELECT client_name_enc, contacts_enc, request_uris_enc, jwks_uri_enc, software_id_enc, \
       tls_client_auth_subject_dn_enc, tls_client_auth_cert_thumbprint_enc, \
       tls_client_auth_subject_dn_index, tls_client_auth_cert_thumbprint_index \
     FROM oauth_clients WHERE id = $1",
  )
  .bind(client_id)
  .fetch_one(&pool)
  .await?;
  let name: Vec<u8> = row.try_get("client_name_enc")?;
  assert_eq!(
    open_text(&keys, &name).map_err(|error| TestError::Harness(error.to_string()))?,
    "Legacy Client"
  );
  let dn: Vec<u8> = row.try_get("tls_client_auth_subject_dn_enc")?;
  assert_eq!(
    open_text(&keys, &dn).map_err(|error| TestError::Harness(error.to_string()))?,
    "CN=legacy"
  );
  let thumb: Vec<u8> = row.try_get("tls_client_auth_cert_thumbprint_enc")?;
  assert_eq!(
    open_text(&keys, &thumb).map_err(|error| TestError::Harness(error.to_string()))?,
    "THUMB-LEGACY"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_subject_dn_index")?,
    Some(blind_index_active(&keys, "CN=legacy"))
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_cert_thumbprint_index")?,
    Some(blind_index_active(&keys, "THUMB-LEGACY"))
  );

  // Redirects: plaintext blanked, ciphertext opens, index matches exactly.
  assert_eq!(
    plaintext(
      &pool,
      "SELECT uri FROM redirect_uris WHERE id = $1",
      redirect_id
    )
    .await?,
    None
  );
  let row = sqlx::query("SELECT uri_enc, uri_index FROM redirect_uris WHERE id = $1")
    .bind(redirect_id)
    .fetch_one(&pool)
    .await?;
  let uri_enc: Vec<u8> = row.try_get("uri_enc")?;
  assert_eq!(
    open_text(&keys, &uri_enc).map_err(|error| TestError::Harness(error.to_string()))?,
    "https://app.example.test/callback"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("uri_index")?,
    Some(blind_index_active(
      &keys,
      "https://app.example.test/callback"
    ))
  );

  // A fully backfilled database verifies clean (the exit-0 path).
  let report = verify_with(&pool, &keys)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert!(report.is_clean());
  ensure_clean(&report).map_err(|error| TestError::Harness(error.to_string()))?;
  Ok(())
}

#[tokio::test]
async fn pii_backfill_is_idempotent() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let user_id = Uuid::new_v4();
  insert_user(&pool, user_id, Some("idem@example.test"), None).await?;
  let first = backfill_with(&pool, &keys, false)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(first.users_sealed, 1);
  let sealed: Vec<u8> = sqlx::query_scalar("SELECT email_enc FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;

  let second = backfill_with(&pool, &keys, false)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(second.users_sealed, 0, "a re-run must seal zero users");
  assert_eq!(second.clients_sealed, 0, "a re-run must seal zero clients");
  assert_eq!(
    second.redirects_sealed, 0,
    "a re-run must seal zero redirects"
  );
  assert_eq!(
    second.totp_upgraded, 0,
    "a re-run must upgrade zero TOTP blobs"
  );
  let again: Vec<u8> = sqlx::query_scalar("SELECT email_enc FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
  assert_eq!(sealed, again, "a re-run must not touch sealed bytes");
  Ok(())
}

#[tokio::test]
async fn pii_verify_detects_plaintext() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  insert_user(&pool, Uuid::new_v4(), Some("plain@example.test"), None).await?;
  let report = verify_with(&pool, &keys)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert!(report.plaintext > 0, "legacy plaintext must be counted");
  assert!(
    ensure_clean(&report).is_err(),
    "plaintext must exit non-zero"
  );
  Ok(())
}

#[tokio::test]
async fn pii_verify_detects_corrupt_ciphertext() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let id = Uuid::new_v4();
  let sealed = seal_text(&keys, "sealed@example.test")
    .map_err(|error| TestError::Harness(error.to_string()))?;
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, email_enc, email_index, totp_enabled, created_at, updated_at) \
     VALUES ($1, NULL, 'x', $2, 'k1:00', false, now(), now())",
  )
  .bind(id)
  .bind(&sealed)
  .execute(&pool)
  .await?;
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE users SET email_enc = $2 WHERE id = $1")
    .bind(id)
    .bind(corrupt)
    .execute(&pool)
    .await?;

  let report = verify_with(&pool, &keys)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert!(
    report.undecryptable > 0,
    "a corrupt ciphertext must be counted"
  );
  assert!(
    ensure_clean(&report).is_err(),
    "corruption must exit non-zero"
  );
  Ok(())
}

#[tokio::test]
async fn pii_verify_rejects_non_v3_totp() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let v2 = crypto_totp::encrypt_secret(&keys, TOTP_SECRET, false)
    .map_err(|error| TestError::Harness(error.to_string()))?;
  insert_user(&pool, Uuid::new_v4(), None, Some(&v2)).await?;
  let report = verify_with(&pool, &keys)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(report.totp_below_v3, 1);
  assert_eq!(
    report.undecryptable, 0,
    "a v2 blob still opens under a retained key"
  );
  assert!(
    ensure_clean(&report).is_err(),
    "a pre-v3 blob must exit non-zero"
  );
  Ok(())
}

#[tokio::test]
async fn pii_verify_detects_inconsistent_index() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let sealed = seal_text(&keys, "indexed@example.test")
    .map_err(|error| TestError::Harness(error.to_string()))?;
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, email_enc, email_index, totp_enabled, created_at, updated_at) \
     VALUES ($1, NULL, 'x', $2, NULL, false, now(), now())",
  )
  .bind(Uuid::new_v4())
  .bind(&sealed)
  .execute(&pool)
  .await?;
  let report = verify_with(&pool, &keys)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert!(
    report.index_mismatch > 0,
    "a NULL blind index must be counted"
  );
  assert_eq!(report.undecryptable, 0, "the ciphertext itself still opens");
  assert!(
    ensure_clean(&report).is_err(),
    "an index mismatch must exit non-zero"
  );
  Ok(())
}

#[tokio::test]
async fn pii_backfill_refuses_while_dual_write() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let refused = backfill_with(&pool, &keys, true).await;
  assert!(
    refused.is_err(),
    "backfill must refuse while pii_dual_write=true"
  );
  Ok(())
}

/// A ring whose active PII key is `k2` with `k1` retained (post-rotation shape).
fn rotated_keys() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![key("p1", "pii-test-pepper-0123456789abcdef")],
    vec![key("t1", "pii-test-totp-key-0123456789abcdef")],
    vec![
      key("k2", "pii-test-pii-next-0123456789abcdef"),
      key("k1", "pii-test-pii-key-0123456789abcdef"),
    ],
  )
  .map_err(|error| TestError::Harness(error.to_string()))
}

/// A ring holding ONLY the new PII key (the retired-previous shape).
fn new_key_only() -> Result<KeyRing, TestError> {
  KeyRing::from_parts(
    vec![key("p1", "pii-test-pepper-0123456789abcdef")],
    vec![key("t1", "pii-test-totp-key-0123456789abcdef")],
    vec![key("k2", "pii-test-pii-next-0123456789abcdef")],
  )
  .map_err(|error| TestError::Harness(error.to_string()))
}

/// Seal one legacy `users` row directly under the old key (post-backfill shape:
/// plaintext NULL, `_enc` + `_index` present).
async fn insert_sealed_user(pool: &PgPool, keys: &KeyRing, email: &str) -> Result<Uuid, TestError> {
  let id = Uuid::new_v4();
  let canonical = normalize_email(email);
  let sealed =
    seal_text(keys, &canonical).map_err(|error| TestError::Harness(error.to_string()))?;
  let index = blind_index_active(keys, &canonical);
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, email_enc, email_index, totp_enabled, created_at, updated_at) \
     VALUES ($1, NULL, 'x', $2, $3, false, now(), now())",
  )
  .bind(id)
  .bind(&sealed)
  .bind(&index)
  .execute(pool)
  .await?;
  Ok(id)
}

#[tokio::test]
async fn pii_rotate_reencrypts_and_reindexes() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let old = test_keys()?;
  let rotated = rotated_keys()?;

  // Seed every table under the old key via the proven backfill path.
  let user_id = Uuid::new_v4();
  insert_user(&pool, user_id, Some("Rotate-Me@Example.Test"), None).await?;
  let client_id = insert_client(&pool, "rotate-client").await?;
  let redirect_id = insert_redirect(&pool, "https://app.example.test/rotated").await?;
  backfill_with(&pool, &old, false)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;

  let report = rotate_with(&pool, &rotated)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(report.users_rotated, 1);
  assert_eq!(report.clients_rotated, 1);
  assert_eq!(report.redirects_rotated, 1);

  // After the old key is retired, every `_enc` opens under the new key alone
  // and every blind index names the active key.
  let fresh = new_key_only()?;
  let row = sqlx::query("SELECT email_enc, email_index FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
  let email_enc = row.try_get::<Option<Vec<u8>>, _>("email_enc")?;
  let blob = email_enc.ok_or(TestError::Missing("email_enc"))?;
  assert_eq!(
    open_text(&fresh, &blob).map_err(|error| TestError::Harness(error.to_string()))?,
    "rotate-me@example.test"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("email_index")?,
    Some(blind_index_active(&fresh, "rotate-me@example.test"))
  );

  let row = sqlx::query(
    "SELECT tls_client_auth_subject_dn_enc, tls_client_auth_subject_dn_index, \
       tls_client_auth_cert_thumbprint_enc, tls_client_auth_cert_thumbprint_index \
     FROM oauth_clients WHERE id = $1",
  )
  .bind(client_id)
  .fetch_one(&pool)
  .await?;
  let dn = row.try_get::<Option<Vec<u8>>, _>("tls_client_auth_subject_dn_enc")?;
  let dn_blob = dn.ok_or(TestError::Missing("tls_client_auth_subject_dn_enc"))?;
  assert_eq!(
    open_text(&fresh, &dn_blob).map_err(|error| TestError::Harness(error.to_string()))?,
    "CN=legacy"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_subject_dn_index")?,
    Some(blind_index_active(&fresh, "CN=legacy"))
  );
  let thumb = row.try_get::<Option<Vec<u8>>, _>("tls_client_auth_cert_thumbprint_enc")?;
  let thumb_blob = thumb.ok_or(TestError::Missing("tls_client_auth_cert_thumbprint_enc"))?;
  assert_eq!(
    open_text(&fresh, &thumb_blob).map_err(|error| TestError::Harness(error.to_string()))?,
    "THUMB-LEGACY"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("tls_client_auth_cert_thumbprint_index")?,
    Some(blind_index_active(&fresh, "THUMB-LEGACY"))
  );

  let row = sqlx::query("SELECT uri_enc, uri_index FROM redirect_uris WHERE id = $1")
    .bind(redirect_id)
    .fetch_one(&pool)
    .await?;
  let uri_enc = row.try_get::<Option<Vec<u8>>, _>("uri_enc")?;
  let uri_blob = uri_enc.ok_or(TestError::Missing("uri_enc"))?;
  assert_eq!(
    open_text(&fresh, &uri_blob).map_err(|error| TestError::Harness(error.to_string()))?,
    "https://app.example.test/rotated"
  );
  assert_eq!(
    row.try_get::<Option<String>, _>("uri_index")?,
    Some(blind_index_active(
      &fresh,
      "https://app.example.test/rotated"
    ))
  );

  // Plaintext columns stay blank and the new-key lookup resolves the user.
  assert_eq!(
    plaintext(&pool, "SELECT email FROM users WHERE id = $1", user_id).await?,
    None
  );
  let found = crate::db::user_repo::find_by_email(&pool, &fresh, "rotate-me@example.test").await?;
  assert_eq!(found.map(|record| record.id), Some(user_id));
  Ok(())
}

#[tokio::test]
async fn pii_rotate_is_idempotent() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let old = test_keys()?;
  let rotated = rotated_keys()?;

  let user_id = Uuid::new_v4();
  insert_user(&pool, user_id, Some("idem-rotate@example.test"), None).await?;
  backfill_with(&pool, &old, false)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  let first = rotate_with(&pool, &rotated)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(first.users_rotated, 1);
  let sealed: Vec<u8> = sqlx::query_scalar("SELECT email_enc FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;

  let second = rotate_with(&pool, &rotated)
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  assert_eq!(second.users_rotated, 0, "a re-run must rotate zero users");
  assert_eq!(
    second.clients_rotated, 0,
    "a re-run must rotate zero clients"
  );
  assert_eq!(
    second.redirects_rotated, 0,
    "a re-run must rotate zero redirects"
  );
  let again: Vec<u8> = sqlx::query_scalar("SELECT email_enc FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&pool)
    .await?;
  assert_eq!(sealed, again, "a re-run must not touch rotated bytes");
  Ok(())
}

#[tokio::test]
async fn pii_rotate_aborts_batch_on_collision() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let old = test_keys()?;
  let rotated = rotated_keys()?;

  // Two rows for the same canonical email, both sealed under the old key. The
  // second carries a NULL index (partial unique indexes skip NULLs), so both
  // inserts succeed; rotating them in one batch must collide on the new index.
  let first_id = insert_sealed_user(&pool, &old, "dupe@example.test").await?;
  let second_id = Uuid::new_v4();
  let sealed =
    seal_text(&old, "dupe@example.test").map_err(|error| TestError::Harness(error.to_string()))?;
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, email_enc, email_index, totp_enabled, created_at, updated_at) \
     VALUES ($1, NULL, 'x', $2, NULL, false, now(), now())",
  )
  .bind(second_id)
  .bind(&sealed)
  .execute(&pool)
  .await?;

  let failed = rotate_with(&pool, &rotated).await;
  assert!(
    failed.is_err(),
    "a cross-generation duplicate must abort the batch"
  );

  // The batch rolled back: neither row was re-encrypted under the new key.
  let fresh = new_key_only()?;
  for id in [first_id, second_id] {
    let blob: Option<Vec<u8>> = sqlx::query_scalar("SELECT email_enc FROM users WHERE id = $1")
      .bind(id)
      .fetch_one(&pool)
      .await?;
    let blob = blob.ok_or(TestError::Missing("email_enc"))?;
    assert!(
      open_text(&fresh, &blob).is_err(),
      "a rolled-back row must not open under the new key alone"
    );
  }
  Ok(())
}

#[tokio::test]
async fn pii_backfill_aborts_on_malformed_ciphertext() -> Result<(), TestError> {
  let (_db, pool) = fresh_pool!()?;
  let keys = test_keys()?;

  let id = Uuid::new_v4();
  insert_user(&pool, id, Some("retry@example.test"), None).await?;
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE users SET email_enc = $2 WHERE id = $1")
    .bind(id)
    .bind(corrupt)
    .execute(&pool)
    .await?;

  let failed = backfill_with(&pool, &keys, false).await;
  assert!(
    failed.is_err(),
    "a malformed ciphertext must abort the batch"
  );
  assert_eq!(
    plaintext(&pool, "SELECT email FROM users WHERE id = $1", id).await?,
    Some("retry@example.test".to_owned()),
    "the aborted batch must leave the plaintext intact for retry"
  );
  Ok(())
}

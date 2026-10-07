//! `test(health)` startup-guard suite: fail-closed PII transition state.
//!
//! The guard is computed once in [`AppState::connect`], never per probe: with
//! `pii_dual_write=false` and any legacy plaintext PII column still non-NULL,
//! readiness is 503 until the backfill blanks the columns and the process
//! restarts.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;

use super::{
  AppState,
  test_support::{
    TestError, TestResult, get_health, postgres_container, redis_single_container,
    single_redis_block, test_config,
  },
};

/// Seed one legacy row per PII table: every blanked plaintext column non-NULL.
async fn seed_legacy(pool: &sqlx::PgPool) -> Result<(), TestError> {
  let tag = uuid::Uuid::new_v4().simple().to_string();
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
     VALUES ($1, $2, 'hash', now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(format!("legacy-{tag}@example.test"))
  .execute(pool)
  .await?;
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name, \
     grant_types, response_types, scope, token_endpoint_auth_method, contacts, \
     request_uris, jwks_uri, software_id, tls_client_auth_subject_dn, \
     tls_client_auth_cert_thumbprint, created_at, updated_at) \
     VALUES ($1, $2, now(), 'Legacy', '{}', '{}', '', 'none', '[]', '[]', \
     'https://auth.example.test/jwks.json', 'legacy-software', 'CN=legacy', \
     'AA:BB', now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(format!("legacy-client-{tag}"))
  .execute(pool)
  .await?;
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, created_at, updated_at) \
     VALUES ($1, 'https://app.example.test/callback', 'authorize', now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .execute(pool)
  .await?;
  Ok(())
}

/// Seed fully backfilled rows: every plaintext column NULL beside ciphertext.
async fn seed_backfilled(pool: &sqlx::PgPool) -> Result<(), TestError> {
  let sealed: &[u8] = b"sealed";
  sqlx::query(
    "INSERT INTO users (id, email, email_enc, password_hash, created_at, updated_at) \
     VALUES ($1, NULL, $2, 'hash', now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(sealed)
  .execute(pool)
  .await?;
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name, \
     grant_types, response_types, scope, token_endpoint_auth_method, \
     client_name_enc, contacts_enc, request_uris_enc, jwks_uri_enc, \
     software_id_enc, tls_client_auth_subject_dn_enc, \
     tls_client_auth_cert_thumbprint_enc, created_at, updated_at) \
     VALUES ($1, $2, now(), NULL, '{}', '{}', '', 'none', $3, $3, $3, $3, $3, \
     $3, $3, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(format!(
    "backfilled-client-{}",
    uuid::Uuid::new_v4().simple()
  ))
  .bind(sealed)
  .execute(pool)
  .await?;
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, uri_enc, kind, created_at, updated_at) \
     VALUES ($1, NULL, $2, 'authorize', now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(sealed)
  .execute(pool)
  .await?;
  Ok(())
}

/// One blanking statement per covered plaintext column, in a fixed order.
const BLANKS: [&str; 9] = [
  "UPDATE users SET email = NULL",
  "UPDATE oauth_clients SET client_name = NULL",
  "UPDATE oauth_clients SET contacts = NULL",
  "UPDATE oauth_clients SET request_uris = NULL",
  "UPDATE oauth_clients SET jwks_uri = NULL",
  "UPDATE oauth_clients SET software_id = NULL",
  "UPDATE oauth_clients SET tls_client_auth_subject_dn = NULL",
  "UPDATE oauth_clients SET tls_client_auth_cert_thumbprint = NULL",
  "UPDATE redirect_uris SET uri = NULL",
];

/// Encrypt-only with any legacy plaintext PII still present is not ready.
#[tokio::test]
async fn startup_guard_blocks_encrypt_only_with_legacy_plaintext() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(&pg_url)
    .await?;
  super::MIGRATOR.run(&admin).await?;
  seed_legacy(&admin).await?;
  // Helper level: encrypt-only sees the legacy plaintext; dual-write exempts.
  assert!(super::probe_transition_unsafe(&admin, false).await?);
  assert!(!super::probe_transition_unsafe(&admin, true).await?);
  // Every covered column keeps the guard set until the last one is blanked.
  for (index, blank) in BLANKS.iter().enumerate() {
    sqlx::query(*blank).execute(&admin).await?;
    let remaining = BLANKS.len() - index - 1;
    assert_eq!(
      super::probe_transition_unsafe(&admin, false).await?,
      remaining > 0
    );
  }
  // Startup level: a legacy row present at connect time makes ready 503.
  seed_legacy(&admin).await?;
  admin.close().await;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  let (status, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(status, 503);
  Ok(())
}

/// A fresh install (no rows) and a fully backfilled DB are ready.
#[tokio::test]
async fn startup_guard_ok_when_backfilled() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(&pg_url)
    .await?;
  super::MIGRATOR.run(&admin).await?;
  // Fresh install: no rows at all.
  assert!(!super::probe_transition_unsafe(&admin, false).await?);
  // Fully backfilled: plaintext NULL beside ciphertext.
  seed_backfilled(&admin).await?;
  assert!(!super::probe_transition_unsafe(&admin, false).await?);
  admin.close().await;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  let (status, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(status, 200);
  Ok(())
}

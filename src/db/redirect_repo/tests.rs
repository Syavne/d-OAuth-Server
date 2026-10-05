//! `test(redirect_repo)` — real-Postgres tests for `db::redirect_repo`.
//!
//! Covers catalog upsert/list/enable/disable, delete-only-when-unattached,
//! attachment idempotence, and the effective attached+enabled set. Every test
//! gets a fresh migrated database from [`crate::db::test_support`].

use sqlx::PgPool;
use uuid::Uuid;

use super::{
  RedirectKind, attach, delete_if_unattached, disable, effective_for_client, enable, list,
  list_for_client, set_enabled, upsert,
};
use crate::db::client_repo::{NewClient, insert};
use crate::db::test_support::{TestError, migrated_pool};

/// Insert a minimal client so attachment FKs resolve.
async fn insert_client(pool: &PgPool, client_id: &str) -> Result<(), TestError> {
  insert(
    pool,
    &NewClient {
      id: Uuid::new_v4(),
      client_id: client_id.to_owned(),
      client_secret_hash: None,
      client_secret_expires_at: None,
      client_name: "Redirect Test Client".to_owned(),
      grant_types: vec!["authorization_code".to_owned()],
      response_types: vec!["code".to_owned()],
      scope: String::new(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      registration_access_token_hash: None,
    },
  )
  .await
  .map(|_| ())
  .map_err(TestError::from)
}

/// Upsert is idempotent by URI, preserves an admin-disabled entry, and the
/// catalog list can include or exclude disabled rows.
#[tokio::test]
async fn redirect_repo_catalog_upsert_list_and_enable() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let first = upsert(
    &pool,
    Uuid::new_v4(),
    "https://app.example.test/cb",
    RedirectKind::Authorize,
    "admin",
    None,
  )
  .await?;
  assert!(first.enabled);
  assert_eq!(first.description, "admin");

  let disabled = disable(&pool, first.id)
    .await?
    .ok_or("disable returned None")?;
  assert!(!disabled.enabled);

  // Re-upserting the same URI returns the SAME row and does not re-enable it.
  let again = upsert(
    &pool,
    Uuid::new_v4(),
    "https://app.example.test/cb",
    RedirectKind::Authorize,
    "dynamic",
    None,
  )
  .await?;
  assert_eq!(again.id, first.id);
  assert!(!again.enabled, "upsert must not resurrect a disabled entry");

  let enabled_row = enable(&pool, first.id)
    .await?
    .ok_or("enable returned None")?;
  assert!(enabled_row.enabled);
  assert!(
    set_enabled(&pool, first.id, false)
      .await?
      .is_some_and(|row| !row.enabled)
  );
  assert!(
    set_enabled(&pool, first.id, true)
      .await?
      .is_some_and(|row| row.enabled)
  );

  let enabled = list(&pool, false).await?;
  assert_eq!(enabled.len(), 1);
  assert_eq!(enabled[0].id, first.id);
  let all = list(&pool, true).await?;
  assert_eq!(all.len(), 1);
  Ok(())
}

/// A catalog URI can be deleted only while no client is attached.
#[tokio::test]
async fn redirect_repo_delete_only_when_unattached() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  insert_client(&pool, "client-a").await?;
  let uri = upsert(
    &pool,
    Uuid::new_v4(),
    "https://a.example.test/cb",
    RedirectKind::Authorize,
    "",
    None,
  )
  .await?;

  assert!(attach(&pool, "client-a", uri.id, None).await?);
  // Attached: deletion is refused (returns false, row survives).
  assert!(!delete_if_unattached(&pool, uri.id).await?);
  assert_eq!(list_for_client(&pool, "client-a").await?.len(), 1);

  assert!(super::detach(&pool, "client-a", uri.id).await?);
  assert!(delete_if_unattached(&pool, uri.id).await?);
  // Deleting again is a no-op.
  assert!(!delete_if_unattached(&pool, uri.id).await?);
  Ok(())
}

/// Attachment is idempotent, and the effective set excludes disabled URIs
/// while the management view keeps them.
#[tokio::test]
async fn redirect_repo_attach_detach_and_effective_set() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  insert_client(&pool, "client-b").await?;
  let live = upsert(
    &pool,
    Uuid::new_v4(),
    "https://b.example.test/live",
    RedirectKind::Authorize,
    "",
    None,
  )
  .await?;
  let dead = upsert(
    &pool,
    Uuid::new_v4(),
    "https://b.example.test/dead",
    RedirectKind::Authorize,
    "",
    None,
  )
  .await?;

  assert!(attach(&pool, "client-b", live.id, None).await?);
  assert!(attach(&pool, "client-b", dead.id, None).await?);
  // Re-attaching is a no-op.
  assert!(!attach(&pool, "client-b", live.id, None).await?);
  assert_eq!(list_for_client(&pool, "client-b").await?.len(), 2);

  disable(&pool, dead.id).await?;
  let effective = effective_for_client(&pool, "client-b").await?;
  assert_eq!(effective.len(), 1);
  assert_eq!(effective[0].id, live.id);
  // Management view still lists the disabled attached URI.
  assert_eq!(list_for_client(&pool, "client-b").await?.len(), 2);

  assert!(super::detach(&pool, "client-b", live.id).await?);
  assert!(!super::detach(&pool, "client-b", live.id).await?);
  assert_eq!(super::detach_all(&pool, "client-b").await?, 1);
  assert!(effective_for_client(&pool, "client-b").await?.is_empty());
  Ok(())
}

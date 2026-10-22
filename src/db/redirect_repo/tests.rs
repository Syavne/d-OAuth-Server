//! `test(redirect_repo)` — real-Postgres tests for `db::redirect_repo`.
//!
//! Covers encrypted catalog upsert/list/enable/disable, delete-only-when-unattached,
//! attachment idempotence, the effective attached+enabled set, legacy
//! NULL-index row adoption, ciphertext-at-rest, and fail-closed corrupt rows.
//! Every test gets a fresh migrated database from [`crate::db::test_support`].

use secrecy::SecretString;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::{
  NewRedirectUri, RedirectKind, UpsertOutcome, attach, delete_if_unattached, disable,
  effective_for_client, effective_post_logout_for_client, enable, list, list_for_client,
  post_logout_for_client, set_enabled, upsert,
};
use crate::db::client_repo::{NewClient, insert};
use crate::db::test_support::{TestError, migrated_pool};
use crate::error::AppError;
use crate::keys::{KeyId, KeyRing};

/// Await a fallible repository call that must fail, returning its error.
async fn expect_err<T>(result: Result<T, AppError>, what: &str) -> Result<AppError, TestError> {
  match result {
    Err(error) => Ok(error),
    Ok(_) => Err(format!("{what} unexpectedly succeeded").into()),
  }
}
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("redirect-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("redirect-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("redirect-test-pii"))],
  )?)
}

/// Upsert input with a fresh id and no admin attribution.
fn new_uri<'a>(uri: &'a str, kind: RedirectKind, description: &'a str) -> NewRedirectUri<'a> {
  NewRedirectUri {
    id: Uuid::new_v4(),
    uri,
    kind,
    description,
    created_by: None,
  }
}

/// Insert a minimal client so attachment FKs resolve.
async fn insert_client(pool: &PgPool, keys: &KeyRing, client_id: &str) -> Result<(), TestError> {
  insert(
    pool,
    keys,
    false,
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
      access_token_format: "opaque".to_owned(),
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
  let keys = test_keys()?;
  let (first, outcome) = upsert(
    &pool,
    &keys,
    false,
    &new_uri(
      "https://app.example.test/cb",
      RedirectKind::Authorize,
      "admin",
    ),
  )
  .await?;
  assert_eq!(outcome, UpsertOutcome::Created);
  assert!(first.enabled);
  assert_eq!(first.description, "admin");

  let disabled = disable(&pool, &keys, first.id)
    .await?
    .ok_or("disable returned None")?;
  assert!(!disabled.enabled);

  // Re-upserting the same URI returns the SAME row and does not re-enable it.
  let (again, outcome) = upsert(
    &pool,
    &keys,
    false,
    &new_uri(
      "https://app.example.test/cb",
      RedirectKind::Authorize,
      "dynamic",
    ),
  )
  .await?;
  assert_eq!(outcome, UpsertOutcome::Updated);
  assert_eq!(again.id, first.id);
  assert!(!again.enabled, "upsert must not resurrect a disabled entry");
  assert_eq!(
    again.description, "admin",
    "upsert must not overwrite description"
  );

  let enabled_row = enable(&pool, &keys, first.id)
    .await?
    .ok_or("enable returned None")?;
  assert!(enabled_row.enabled);
  assert!(
    set_enabled(&pool, &keys, first.id, false)
      .await?
      .is_some_and(|row| !row.enabled)
  );
  assert!(
    set_enabled(&pool, &keys, first.id, true)
      .await?
      .is_some_and(|row| row.enabled)
  );

  let enabled = list(&pool, &keys, false).await?;
  assert_eq!(enabled.len(), 1);
  assert_eq!(enabled[0].id, first.id);
  let all = list(&pool, &keys, true).await?;
  assert_eq!(all.len(), 1);
  Ok(())
}

/// A catalog URI can be deleted only while no client is attached.
#[tokio::test]
async fn redirect_repo_delete_only_when_unattached() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_client(&pool, &keys, "client-a").await?;
  let (uri, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://a.example.test/cb", RedirectKind::Authorize, ""),
  )
  .await?;

  assert!(attach(&pool, "client-a", uri.id, None).await?);
  // Attached: deletion is refused (returns false, row survives).
  assert!(!delete_if_unattached(&pool, uri.id).await?);
  assert_eq!(list_for_client(&pool, &keys, "client-a").await?.len(), 1);

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
  let keys = test_keys()?;
  insert_client(&pool, &keys, "client-b").await?;
  let (live, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://b.example.test/live", RedirectKind::Authorize, ""),
  )
  .await?;
  let (dead, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://b.example.test/dead", RedirectKind::Authorize, ""),
  )
  .await?;

  assert!(attach(&pool, "client-b", live.id, None).await?);
  assert!(attach(&pool, "client-b", dead.id, None).await?);
  // Re-attaching is a no-op.
  assert!(!attach(&pool, "client-b", live.id, None).await?);
  assert_eq!(list_for_client(&pool, &keys, "client-b").await?.len(), 2);

  disable(&pool, &keys, dead.id).await?;
  let effective = effective_for_client(&pool, &keys, "client-b").await?;
  assert_eq!(effective.len(), 1);
  assert_eq!(effective[0].id, live.id);
  // Management view still lists the disabled attached URI.
  assert_eq!(list_for_client(&pool, &keys, "client-b").await?.len(), 2);

  assert!(super::detach(&pool, "client-b", live.id).await?);
  assert!(!super::detach(&pool, "client-b", live.id).await?);
  assert_eq!(super::detach_all(&pool, "client-b").await?, 1);
  assert!(
    effective_for_client(&pool, &keys, "client-b")
      .await?
      .is_empty()
  );
  Ok(())
}

/// Encrypt-only upsert round-trips through ciphertext: a duplicate
/// `(uri, kind)` updates in place (no second row), plaintext stays NULL at
/// rest, and the list is ordered by the DECRYPTED uri.
#[tokio::test]
async fn redirect_repo_upsert_and_list_round_trip() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let (second, created) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://example.test/b", RedirectKind::Authorize, "second"),
  )
  .await?;
  assert_eq!(created, UpsertOutcome::Created);
  let (first, created) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://example.test/a", RedirectKind::Authorize, "first"),
  )
  .await?;
  assert_eq!(created, UpsertOutcome::Created);

  // A duplicate (uri, kind) does not create a second row and keeps the
  // original description.
  let (repeat, outcome) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://example.test/a", RedirectKind::Authorize, "changed"),
  )
  .await?;
  assert_eq!(outcome, UpsertOutcome::Updated);
  assert_eq!(repeat.id, first.id);
  assert_eq!(repeat.description, "first");

  // A disabled entry stays disabled across upserts.
  disable(&pool, &keys, second.id).await?;
  let (resurrected, outcome) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://example.test/b", RedirectKind::Authorize, "second"),
  )
  .await?;
  assert_eq!(outcome, UpsertOutcome::Updated);
  assert_eq!(resurrected.id, second.id);
  assert!(!resurrected.enabled);

  // Ciphertext at rest: no plaintext URI is stored while dual-write is off.
  let stored = sqlx::query("SELECT uri, uri_enc, uri_index FROM redirect_uris")
    .fetch_all(&pool)
    .await?;
  assert_eq!(stored.len(), 2);
  for row in &stored {
    let plain: Option<String> = row.try_get("uri")?;
    let enc: Option<Vec<u8>> = row.try_get("uri_enc")?;
    let index: Option<String> = row.try_get("uri_index")?;
    assert!(plain.is_none(), "plaintext uri must be NULL at rest");
    assert!(enc.is_some(), "uri_enc must be sealed");
    assert!(index.is_some(), "uri_index must be indexed");
  }

  // The returned list is ordered by the DECRYPTED uri even though the
  // plaintext column is blank.
  let all = list(&pool, &keys, true).await?;
  let uris: Vec<&str> = all.iter().map(|entry| entry.uri.as_str()).collect();
  assert_eq!(
    uris,
    vec!["https://example.test/a", "https://example.test/b"]
  );
  assert!(
    !format!("{first:?}").contains("https://example.test/a"),
    "RedirectUri Debug must not leak the sealed URI"
  );
  Ok(())
}

/// Upserting a URI that already exists as a legacy NULL-index row updates it
/// in place (backfilling `uri_enc`/`uri_index`) instead of inserting a
/// duplicate row.
#[tokio::test]
async fn redirect_repo_upsert_updates_legacy_row() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let legacy_id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, description, created_by, created_at, updated_at) \
     VALUES ($1, $2, 'authorize', 'legacy', NULL, now(), now())",
  )
  .bind(legacy_id)
  .bind("https://legacy.example.test/cb")
  .execute(&pool)
  .await?;

  // The legacy row still reads through the plaintext fallback.
  let before = list(&pool, &keys, true).await?;
  assert_eq!(before.len(), 1);
  assert_eq!(before[0].id, legacy_id);
  assert_eq!(before[0].uri, "https://legacy.example.test/cb");

  let (adopted, outcome) = upsert(
    &pool,
    &keys,
    false,
    &new_uri(
      "https://legacy.example.test/cb",
      RedirectKind::Authorize,
      "dynamic",
    ),
  )
  .await?;
  assert_eq!(outcome, UpsertOutcome::Updated);
  assert_eq!(adopted.id, legacy_id);
  assert_eq!(
    adopted.description, "legacy",
    "upsert must preserve a legacy description"
  );

  // No second row was created, and the legacy row now carries ciphertext.
  let after = list(&pool, &keys, true).await?;
  assert_eq!(after.len(), 1);
  let stored = sqlx::query("SELECT uri_enc, uri_index FROM redirect_uris")
    .fetch_one(&pool)
    .await?;
  let enc: Option<Vec<u8>> = stored.try_get("uri_enc")?;
  let index: Option<String> = stored.try_get("uri_index")?;
  assert!(enc.is_some(), "legacy row must gain uri_enc");
  assert!(index.is_some(), "legacy row must gain uri_index");
  Ok(())
}

/// The effective set holds only attached+enabled `authorize` URIs (decrypted,
/// sorted); post-logout URIs surface only through the post-logout readers.
#[tokio::test]
async fn redirect_repo_effective_for_client() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_client(&pool, &keys, "client-c").await?;
  let (zeta, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://c.example.test/zeta", RedirectKind::Authorize, ""),
  )
  .await?;
  let (alpha, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://c.example.test/alpha", RedirectKind::Authorize, ""),
  )
  .await?;
  let (dead, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://c.example.test/dead", RedirectKind::Authorize, ""),
  )
  .await?;
  let (landing, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri(
      "https://c.example.test/landing",
      RedirectKind::PostLogout,
      "",
    ),
  )
  .await?;
  for id in [zeta.id, alpha.id, dead.id, landing.id] {
    assert!(attach(&pool, "client-c", id, None).await?);
  }
  disable(&pool, &keys, dead.id).await?;

  let effective = effective_for_client(&pool, &keys, "client-c").await?;
  let uris: Vec<&str> = effective.iter().map(|entry| entry.uri.as_str()).collect();
  assert_eq!(
    uris,
    vec![
      "https://c.example.test/alpha",
      "https://c.example.test/zeta"
    ]
  );

  let post_logout = effective_post_logout_for_client(&pool, &keys, "client-c").await?;
  assert_eq!(post_logout, vec!["https://c.example.test/landing"]);
  assert_eq!(
    post_logout_for_client(&pool, &keys, "client-c")
      .await?
      .as_deref(),
    Some("https://c.example.test/landing")
  );
  Ok(())
}

/// A corrupt `uri_enc` fails closed as `PiiDecrypt` (503), never as a 500 and
/// never through a plaintext fallback.
#[tokio::test]
async fn redirect_repo_corrupt_ciphertext_fails_closed() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_client(&pool, &keys, "client-d").await?;
  let (row, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri("https://d.example.test/cb", RedirectKind::Authorize, ""),
  )
  .await?;
  attach(&pool, "client-d", row.id, None).await?;
  let (landing, _) = upsert(
    &pool,
    &keys,
    false,
    &new_uri(
      "https://d.example.test/landing",
      RedirectKind::PostLogout,
      "",
    ),
  )
  .await?;
  attach(&pool, "client-d", landing.id, None).await?;
  sqlx::query("UPDATE redirect_uris SET uri_enc = $1")
    .bind(b"corrupt-blob".to_vec())
    .execute(&pool)
    .await?;

  let error = expect_err(list(&pool, &keys, true).await, "list with corrupt row").await?;
  assert!(
    matches!(error, AppError::PiiDecrypt),
    "corrupt uri_enc must map to PiiDecrypt, got {error:?}"
  );
  let error = expect_err(
    effective_for_client(&pool, &keys, "client-d").await,
    "effective_for_client with corrupt row",
  )
  .await?;
  assert!(
    matches!(error, AppError::PiiDecrypt),
    "corrupt uri_enc must map to PiiDecrypt, got {error:?}"
  );
  let error = expect_err(
    effective_post_logout_for_client(&pool, &keys, "client-d").await,
    "effective_post_logout_for_client with corrupt row",
  )
  .await?;
  assert!(
    matches!(error, AppError::PiiDecrypt),
    "corrupt uri_enc must map to PiiDecrypt, got {error:?}"
  );
  let error = expect_err(
    post_logout_for_client(&pool, &keys, "client-d").await,
    "post_logout_for_client with corrupt row",
  )
  .await?;
  assert!(
    matches!(error, AppError::PiiDecrypt),
    "corrupt uri_enc must map to PiiDecrypt, got {error:?}"
  );
  Ok(())
}

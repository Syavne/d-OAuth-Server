//! `test(resource_repo_enabled_filter)` — real-Postgres tests for
//! `db::resource_repo`.
//!
//! Covers exact-match lookup, the enabled filter on every read path, idempotent
//! upsert preserving the operator's disabled state, and fail-closed `503` when
//! the database is unavailable. Every test gets a fresh migrated database from
//! [`crate::db::test_support`].

use axum::http::StatusCode;

use super::{disable, find_enabled, list_enabled, upsert};
use crate::db::test_support::{TestError, migrated_pool};
use crate::error::AppError;

/// Await a fallible repository call that must fail, returning its error.
async fn expect_err<T>(result: Result<T, AppError>, what: &str) -> Result<AppError, TestError> {
  match result {
    Err(error) => Ok(error),
    Ok(_) => Err(format!("{what} unexpectedly succeeded").into()),
  }
}

/// Only an enabled row resolves, matching the identifier exactly; the catalog
/// never normalizes case or a trailing slash.
#[tokio::test]
async fn resource_repo_enabled_filter_resolves_only_enabled() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let identifier = "https://api.example.test";

  let created = upsert(&pool, identifier, "Example API").await?;
  assert_eq!(created.identifier, identifier);
  assert_eq!(created.description, "Example API");
  assert!(created.enabled, "a new resource server is enabled");

  let found = find_enabled(&pool, identifier).await?;
  assert_eq!(
    found.as_ref().map(|row| row.id),
    Some(created.id),
    "the enabled identifier resolves"
  );

  // Exact match only: no case folding, no trailing-slash normalization, no
  // prefix/suffix/wildcard behavior.
  for variant in [
    "https://API.example.test",
    "https://api.example.test/",
    "https://api.example.test/v1",
    "https://api.example",
    "https://*.example.test",
  ] {
    assert!(
      find_enabled(&pool, variant).await?.is_none(),
      "variant {variant:?} must not resolve"
    );
  }

  let listed = list_enabled(&pool).await?;
  assert_eq!(listed.len(), 1, "the enabled row is listed");
  assert_eq!(listed[0].identifier, identifier);

  // Disabled and unknown identifiers are not found.
  assert!(disable(&pool, identifier).await?, "disable updates the row");
  assert!(
    find_enabled(&pool, identifier).await?.is_none(),
    "a disabled identifier does not resolve"
  );
  assert!(
    list_enabled(&pool).await?.is_empty(),
    "a disabled row is not listed"
  );
  assert!(
    find_enabled(&pool, "https://unknown.example.test")
      .await?
      .is_none(),
    "an unknown identifier does not resolve"
  );
  assert!(
    !disable(&pool, "https://unknown.example.test").await?,
    "disabling an unknown identifier is a no-op"
  );

  // Re-upserting updates the description but preserves the disabled state and
  // the existing row id.
  let updated = upsert(&pool, identifier, "Updated API").await?;
  assert_eq!(updated.id, created.id, "upsert keeps the existing row id");
  assert_eq!(updated.description, "Updated API");
  assert!(
    !updated.enabled,
    "upsert must not silently re-enable a disabled resource server"
  );
  assert!(
    find_enabled(&pool, identifier).await?.is_none(),
    "the disabled identifier stays invisible after upsert"
  );

  Ok(())
}

/// A database outage on any read path fails closed as `503`, never a `500`.
#[tokio::test]
async fn resource_repo_enabled_filter_db_outage_is_503() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let identifier = upsert(&pool, "https://outage.example.test", "")
    .await?
    .identifier;

  // Closing the pool makes every subsequent acquire fail with the same
  // connectivity class (`PoolClosed`) a real outage produces; `AppError` maps
  // that to `temporarily_unavailable`.
  pool.close().await;

  for (name, result) in [
    (
      "find_enabled",
      find_enabled(&pool, &identifier).await.map(|_| ()),
    ),
    ("list_enabled", list_enabled(&pool).await.map(|_| ())),
    ("upsert", upsert(&pool, &identifier, "x").await.map(|_| ())),
    ("disable", disable(&pool, &identifier).await.map(|_| ())),
  ] {
    let error = expect_err(result, name).await?;
    assert_eq!(
      error.status(),
      StatusCode::SERVICE_UNAVAILABLE,
      "{name} must fail closed as 503"
    );
  }

  Ok(())
}

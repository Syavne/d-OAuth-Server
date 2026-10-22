//! Schema contract for the `resource_servers` catalog and the per-client
//! `oauth_clients.access_token_format` column (plan todo 2).
//!
//! Compose-first: the test connects to the shared external Postgres started by
//! `docker compose -f compose.test.yaml up -d` and applies every embedded
//! migration to a freshly created database, matching the rest of the migration
//! suites.
//!
//! The single test name contains `resource_catalog_crud` so
//! `cargo nextest run -E 'test(resource_catalog_crud)'` selects exactly it.

mod common;

use common::{TestError, insert_client, is_unique_violation};

/// The catalog round-trips insert / list / disable, rejects a duplicate
/// identifier, and `oauth_clients.access_token_format` accepts only the
/// `opaque`/`jwt` pair while every existing row reads back `opaque`.
#[tokio::test]
async fn resource_catalog_crud() -> Result<(), TestError> {
  let pool = common::fresh_migrated_db().await?;

  // Insert -> read back -> list.
  let id = uuid::Uuid::new_v4();
  sqlx::query(
    "INSERT INTO resource_servers (id, identifier, description, created_at) \
     VALUES ($1, $2, $3, now())",
  )
  .bind(id)
  .bind("https://api.example.test")
  .bind("Example API")
  .execute(&pool)
  .await?;

  let (identifier, description, enabled): (String, String, bool) =
    sqlx::query_as("SELECT identifier, description, enabled FROM resource_servers WHERE id = $1")
      .bind(id)
      .fetch_one(&pool)
      .await?;
  assert_eq!(
    identifier, "https://api.example.test",
    "identifier round-trips"
  );
  assert_eq!(description, "Example API", "description round-trips");
  assert!(enabled, "a new resource server is enabled by default");

  let listed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM resource_servers")
    .fetch_one(&pool)
    .await?;
  assert_eq!(listed, 1, "the inserted resource server is listed");

  // Disable round-trip.
  let updated = sqlx::query("UPDATE resource_servers SET enabled = false WHERE id = $1")
    .bind(id)
    .execute(&pool)
    .await?;
  assert_eq!(
    updated.rows_affected(),
    1,
    "disable updates exactly one row"
  );
  let enabled_after: bool =
    sqlx::query_scalar("SELECT enabled FROM resource_servers WHERE id = $1")
      .bind(id)
      .fetch_one(&pool)
      .await?;
  assert!(!enabled_after, "the resource server is disabled");

  // A duplicate identifier is rejected by the unique constraint.
  let duplicate =
    sqlx::query("INSERT INTO resource_servers (id, identifier, created_at) VALUES ($1, $2, now())")
      .bind(uuid::Uuid::new_v4())
      .bind("https://api.example.test")
      .execute(&pool)
      .await
      .err();
  assert!(
    matches!(duplicate.as_ref(), Some(err) if is_unique_violation(err)),
    "duplicate identifier was accepted: {duplicate:?}"
  );

  // Omitted columns take their defaults (empty description, enabled true).
  let default_id = uuid::Uuid::new_v4();
  sqlx::query("INSERT INTO resource_servers (id, identifier, created_at) VALUES ($1, $2, now())")
    .bind(default_id)
    .bind("https://other.example.test")
    .execute(&pool)
    .await?;
  let (description, enabled): (String, bool) =
    sqlx::query_as("SELECT description, enabled FROM resource_servers WHERE id = $1")
      .bind(default_id)
      .fetch_one(&pool)
      .await?;
  assert_eq!(description, "", "description defaults to empty");
  assert!(enabled, "enabled defaults to true");

  // An existing client reads back `opaque` without setting the column.
  insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "resource-catalog-client",
    None,
    None,
  )
  .await?;
  let format: String =
    sqlx::query_scalar("SELECT access_token_format FROM oauth_clients WHERE client_id = $1")
      .bind("resource-catalog-client")
      .fetch_one(&pool)
      .await?;
  assert_eq!(
    format, "opaque",
    "an omitted access_token_format defaults to opaque"
  );

  // The `jwt` value is accepted.
  sqlx::query("UPDATE oauth_clients SET access_token_format = 'jwt' WHERE client_id = $1")
    .bind("resource-catalog-client")
    .execute(&pool)
    .await?;

  // An unknown format is rejected by the CHECK constraint.
  let bad =
    sqlx::query("UPDATE oauth_clients SET access_token_format = 'bogus' WHERE client_id = $1")
      .bind("resource-catalog-client")
      .execute(&pool)
      .await
      .err();
  assert!(
    matches!(bad.as_ref(), Some(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23514")),
    "the CHECK must reject an unknown access_token_format: {bad:?}"
  );

  Ok(())
}

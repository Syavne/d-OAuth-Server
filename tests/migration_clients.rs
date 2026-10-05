//! Schema contract for the `oauth_clients` migration (plan todo 8).
//!
//! Runs the real migration file against a throwaway Postgres container and
//! asserts the plan's column set, the named unique/partial-unique indexes,
//! and the duplicate-key rejections the plan depends on (duplicate
//! `client_id`; one certificate identity claimed by two clients).
//!
//! Test names contain `migration_clients` so
//! `cargo nextest run -E 'test(migration_clients)'` selects exactly them.

mod common;

use std::collections::BTreeSet;

use common::{
  OAUTH_CLIENTS_SQL, OAUTH_CLIENTS_VERSION, TestError, client_columns, client_indexes,
  insert_client, is_unique_violation, migrate, postgres,
};

/// The migration is compiled into the binary's embedded migrator.
#[test]
fn migration_clients_is_embedded_in_migrator() {
  use d_oauth::state::MIGRATOR;
  assert!(
    MIGRATOR
      .migrations
      .iter()
      .any(|migration| migration.version == OAUTH_CLIENTS_VERSION),
    "oauth_clients migration ({OAUTH_CLIENTS_VERSION}) is not embedded in MIGRATOR"
  );
}

/// Every plan column exists with the plan's type and nullability, and no
/// column outside the plan was added.
#[tokio::test]
async fn migration_clients_columns_match_plan() -> Result<(), TestError> {
  let (_container, pool) = postgres().await?;
  migrate(&pool, OAUTH_CLIENTS_SQL).await?;

  let expected: BTreeSet<(String, String, String)> = [
    ("id", "uuid", "NO"),
    ("client_id", "text", "NO"),
    ("client_secret_hash", "text", "YES"),
    ("client_secret_expires_at", "timestamptz", "YES"),
    ("client_id_issued_at", "timestamptz", "NO"),
    ("client_name", "text", "NO"),
    ("grant_types", "_text", "NO"),
    ("response_types", "_text", "NO"),
    ("scope", "text", "NO"),
    ("token_endpoint_auth_method", "text", "NO"),
    ("jwks", "jsonb", "YES"),
    ("jwks_uri", "text", "YES"),
    ("tls_client_auth_subject_dn", "text", "YES"),
    ("tls_client_auth_cert_thumbprint", "text", "YES"),
    ("request_uris", "jsonb", "YES"),
    ("contacts", "jsonb", "YES"),
    ("software_id", "text", "YES"),
    ("active", "bool", "NO"),
    ("registration_access_token_hash", "text", "YES"),
    ("created_at", "timestamptz", "NO"),
    ("updated_at", "timestamptz", "NO"),
  ]
  .iter()
  .map(|(name, udt, nullable)| {
    (
      (*name).to_owned(),
      (*udt).to_owned(),
      (*nullable).to_owned(),
    )
  })
  .collect();

  let actual = client_columns(&pool).await?;
  assert_eq!(
    actual, expected,
    "oauth_clients columns diverged from the plan"
  );
  Ok(())
}

/// The primary key, the `client_id` unique index, and the two partial unique
/// indexes on the mTLS identity columns exist and are shaped as specified.
#[tokio::test]
async fn migration_clients_indexes_are_unique_and_partial() -> Result<(), TestError> {
  let (_container, pool) = postgres().await?;
  migrate(&pool, OAUTH_CLIENTS_SQL).await?;

  let defs = client_indexes(&pool).await?;
  let names: BTreeSet<&str> = defs.keys().map(String::as_str).collect();
  assert_eq!(
    names,
    BTreeSet::from([
      "oauth_clients_pkey",
      "ux_oauth_clients_client_id",
      "ux_oauth_clients_tls_subject_dn",
      "ux_oauth_clients_tls_cert_thumbprint",
    ]),
    "unexpected index set on oauth_clients"
  );

  for name in [
    "oauth_clients_pkey",
    "ux_oauth_clients_client_id",
    "ux_oauth_clients_tls_subject_dn",
    "ux_oauth_clients_tls_cert_thumbprint",
  ] {
    let def = defs.get(name).map(String::as_str).unwrap_or_default();
    assert!(def.contains("UNIQUE INDEX"), "{name} is not unique: {def}");
  }

  let subject = defs
    .get("ux_oauth_clients_tls_subject_dn")
    .map(String::as_str)
    .unwrap_or_default();
  assert!(
    subject.contains("tls_client_auth_subject_dn IS NOT NULL"),
    "subject-dn index is not partial: {subject}"
  );

  let thumbprint = defs
    .get("ux_oauth_clients_tls_cert_thumbprint")
    .map(String::as_str)
    .unwrap_or_default();
  assert!(
    thumbprint.contains("tls_client_auth_cert_thumbprint IS NOT NULL"),
    "cert-thumbprint index is not partial: {thumbprint}"
  );
  Ok(())
}

/// Duplicate `client_id`, shared subject DN, and shared cert thumbprint each
/// violate a unique index; NULL identity fields remain unconstrained.
#[tokio::test]
async fn migration_clients_reject_ambiguous_identities() -> Result<(), TestError> {
  let (_container, pool) = postgres().await?;
  migrate(&pool, OAUTH_CLIENTS_SQL).await?;

  let alpha = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-alpha",
    Some("CN=alpha"),
    Some("aaaa"),
  )
  .await;
  assert!(alpha.is_ok(), "baseline insert failed: {alpha:?}");

  // Two clients may both leave either identity column NULL.
  let beta = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-beta",
    Some("CN=beta"),
    None,
  )
  .await;
  assert!(beta.is_ok(), "NULL thumbprint reject: {beta:?}");
  let gamma = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-gamma",
    None,
    Some("bbbb"),
  )
  .await;
  assert!(gamma.is_ok(), "NULL subject DN reject: {gamma:?}");

  // Duplicate client_id.
  let dup_client_id = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-alpha",
    Some("CN=other"),
    Some("cccc"),
  )
  .await
  .err();
  assert!(
    matches!(dup_client_id.as_ref(), Some(err) if is_unique_violation(err)),
    "duplicate client_id was accepted: {dup_client_id:?}"
  );

  // One subject DN cannot map to a second client.
  let dup_subject = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-delta",
    Some("CN=alpha"),
    Some("dddd"),
  )
  .await
  .err();
  assert!(
    matches!(dup_subject.as_ref(), Some(err) if is_unique_violation(err)),
    "duplicate tls_client_auth_subject_dn was accepted: {dup_subject:?}"
  );

  // One cert thumbprint cannot map to a second client.
  let dup_thumbprint = insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-epsilon",
    Some("CN=epsilon"),
    Some("aaaa"),
  )
  .await
  .err();
  assert!(
    matches!(dup_thumbprint.as_ref(), Some(err) if is_unique_violation(err)),
    "duplicate tls_client_auth_cert_thumbprint was accepted: {dup_thumbprint:?}"
  );
  Ok(())
}

/// The forward-only DPoP-bound migration adds a NOT NULL boolean defaulting
/// to false, so pre-existing rows stay unconstrained.
#[tokio::test]
async fn migration_clients_dpop_bound_column_defaults_false() -> Result<(), TestError> {
  let (_container, pool) = postgres().await?;
  migrate(&pool, OAUTH_CLIENTS_SQL).await?;
  migrate(
    &pool,
    include_str!("../migrations/1791244800_client_dpop_bound.sql"),
  )
  .await?;

  let columns = client_columns(&pool).await?;
  let entry = columns
    .iter()
    .find(|(name, _, _)| name == "dpop_bound_access_tokens")
    .ok_or_else(|| {
      TestError::Database(sqlx::Error::Protocol(
        "dpop_bound_access_tokens column missing".to_owned(),
      ))
    })?;
  assert_eq!(entry.1, "bool", "dpop column must be boolean");
  assert_eq!(entry.2, "NO", "dpop column must be NOT NULL");

  insert_client(
    &pool,
    uuid::Uuid::new_v4(),
    "client-dpop-default",
    None,
    None,
  )
  .await?;
  let stored: bool =
    sqlx::query_scalar("SELECT dpop_bound_access_tokens FROM oauth_clients WHERE client_id = $1")
      .bind("client-dpop-default")
      .fetch_one(&pool)
      .await?;
  assert!(!stored, "omitted dpop column must default to false");
  Ok(())
}

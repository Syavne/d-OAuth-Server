//! Shared scaffolding for Postgres-backed migration integration tests.
//!
//! The migration SQL is embedded byte-for-byte from the repo so assertions
//! run against the exact shipped file. Test bodies use `Result` and `?`
//! (`unwrap`/`expect`/`panic` are denied workspace-wide).

use sqlx::{PgPool, Row as _};
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

#[path = "../../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use test_guard::ContainerGuard;

/// The `oauth_clients` migration under test (todo 8).
pub const OAUTH_CLIENTS_SQL: &str = include_str!("../../migrations/1791072000_oauth_clients.sql");

/// Version encoded in the `oauth_clients` migration filename.
pub const OAUTH_CLIENTS_VERSION: i64 = 1_791_072_000;

/// Throwaway Postgres superuser password.
const PG_PASSWORD: &str = "migration-clients-secret";

/// Aggregate error so test bodies use `?` instead of panicking.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
}

/// Start a fresh Postgres and connect a pool to it.
///
/// The returned guard must stay alive for the duration of the test; dropping
/// it removes the container synchronously.
pub async fn postgres() -> Result<(ContainerGuard, PgPool), TestError> {
  let container = GenericImage::new("postgres", "latest")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_wait_for(WaitFor::message_on_stdout(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  let pool = PgPool::connect(&url).await?;
  Ok((guarded, pool))
}

/// Apply a migration script exactly as the migrator would (multi-statement).
///
/// `sqlx::raw_sql` requires a `'static` string, so callers pass an embedded
/// `include_str!` constant.
pub async fn migrate(pool: &PgPool, sql: &'static str) -> Result<(), TestError> {
  sqlx::raw_sql(sql).execute(pool).await?;
  Ok(())
}

/// Insert one `oauth_clients` row, returning the raw driver error (if any).
pub async fn insert_client(
  pool: &PgPool,
  id: uuid::Uuid,
  client_id: &str,
  subject_dn: Option<&str>,
  thumbprint: Option<&str>,
) -> Result<(), sqlx::Error> {
  sqlx::query(
    "INSERT INTO oauth_clients (
       id, client_id, client_id_issued_at, client_name,
       grant_types, response_types, scope, token_endpoint_auth_method,
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint,
       created_at, updated_at
     ) VALUES ($1, $2, now(), $3,
               ARRAY['client_credentials'], ARRAY['token'], 'api:read',
               'client_secret_basic', $4, $5, now(), now())",
  )
  .bind(id)
  .bind(client_id)
  .bind("Migration Test Client")
  .bind(subject_dn)
  .bind(thumbprint)
  .execute(pool)
  .await
  .map(|_| ())
}

/// Whether `err` is Postgres `unique_violation` (SQLSTATE 23505).
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
  matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// Collect `oauth_clients` columns as `(name, udt_name, is_nullable)`.
pub async fn client_columns(
  pool: &PgPool,
) -> Result<std::collections::BTreeSet<(String, String, String)>, TestError> {
  let rows = sqlx::query(
    "SELECT column_name, udt_name, is_nullable
       FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'oauth_clients'",
  )
  .fetch_all(pool)
  .await?;
  let mut columns = std::collections::BTreeSet::new();
  for row in &rows {
    columns.insert((
      row.try_get::<String, _>("column_name")?,
      row.try_get::<String, _>("udt_name")?,
      row.try_get::<String, _>("is_nullable")?,
    ));
  }
  Ok(columns)
}

/// Collect `oauth_clients` indexes as `indexname -> indexdef`.
pub async fn client_indexes(
  pool: &PgPool,
) -> Result<std::collections::BTreeMap<String, String>, TestError> {
  let rows = sqlx::query(
    "SELECT indexname, indexdef
       FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'oauth_clients'",
  )
  .fetch_all(pool)
  .await?;
  let mut defs = std::collections::BTreeMap::new();
  for row in &rows {
    defs.insert(
      row.try_get::<String, _>("indexname")?,
      row.try_get::<String, _>("indexdef")?,
    );
  }
  Ok(defs)
}

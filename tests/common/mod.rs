// Dead code is expected here: this file is `#[path]`-included by several
// test binaries (`migration_clients`, the e2e harness), each using a
// different subset of these shared helpers.
#![allow(dead_code)]

//! Shared scaffolding for Postgres-backed migration integration tests.
//!
//! Compose-first: tests connect to the shared external services from
//! `compose.test.yaml` (`docker compose -f compose.test.yaml up -d`) instead
//! of booting per-test containers. Per-test isolation comes from a freshly
//! created database per `postgres()` call, so parallel tests never share
//! state (and never FLUSH shared state).
//!
//! The migration SQL is embedded byte-for-byte from the repo so assertions
//! run against the exact shipped file. Test bodies use `Result` and `?`
//! (`unwrap`/`expect`/`panic` are denied workspace-wide).
//!
//! Reachability: this module is included via `#[path]` both as
//! `tests/common/mod.rs` (from `tests/migration_clients.rs`) and as
//! `../common/mod.rs` (from `tests/e2e/harness.rs`), so the helpers below
//! (`pg_server_url`, `redis_url`, `fresh_migrated_db`, `unique_prefixes`)
//! are the single shared definition — no duplication needed.

use sqlx::{Executor as _, PgPool, Row as _, postgres::PgPoolOptions};

/// The `oauth_clients` migration under test (todo 8).
pub const OAUTH_CLIENTS_SQL: &str = include_str!("../../migrations/1791072000_oauth_clients.sql");

/// Version encoded in the `oauth_clients` migration filename.
pub const OAUTH_CLIENTS_VERSION: i64 = 1_791_072_000;

/// Hint shown when the shared test services are unreachable.
const COMPOSE_HINT: &str = "run `docker compose -f compose.test.yaml up -d`";

/// Aggregate error so test bodies use `?` instead of panicking.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// The shared test service is unreachable (usually: compose not started).
  #[error("test setup: {0}")]
  Setup(String),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
}

/// URL of the shared test Postgres server (the `postgres` maintenance DB).
///
/// Overridable via `D_OAUTH_TEST_POSTGRES_URL`; the default matches
/// `compose.test.yaml` (`test-db`, port 5433).
pub fn pg_server_url() -> String {
  match std::env::var("D_OAUTH_TEST_POSTGRES_URL") {
    Ok(url) => url,
    Err(_) => {
      "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres?sslmode=disable".to_owned()
    }
  }
}

/// URL of the shared test Redis server.
///
/// Overridable via `D_OAUTH_TEST_REDIS_URL`; the default matches
/// `compose.test.yaml` (`test-redis`, port 6380).
pub fn redis_url() -> String {
  match std::env::var("D_OAUTH_TEST_REDIS_URL") {
    Ok(url) => url,
    Err(_) => "redis://127.0.0.1:6380".to_owned(),
  }
}

/// Per-test unique Redis key prefixes (token + rate-limit keyspaces).
///
/// Each prefix carries its cluster hash tag (`{state}` / `{rl}`) so the
/// server/store validation accepts them, plus a uuid so parallel tests never
/// see each other's keys. Shared state is never flushed.
pub fn unique_prefixes() -> (String, String) {
  let tag = uuid::Uuid::new_v4().simple().to_string();
  (
    format!("oauth:{{state}}:t{tag}:"),
    format!("oauth:{{rl}}:r{tag}:"),
  )
}

/// Connect a pool on a FRESH uniquely-named database on the shared server.
///
/// The database is empty (not migrated); callers apply exactly the migration
/// SQL they assert on. A connection failure names the compose file to start.
pub async fn postgres() -> Result<PgPool, TestError> {
  fresh_db(&pg_server_url()).await
}

/// A fresh database on the shared server with every embedded migration applied.
pub async fn fresh_migrated_db() -> Result<PgPool, TestError> {
  let pool = fresh_db(&pg_server_url()).await?;
  d_oauth::state::MIGRATOR
    .run(&pool)
    .await
    .map_err(|error| TestError::Setup(format!("migrations failed to apply: {error}")))?;
  Ok(pool)
}

/// Create a uniquely named database on the shared server and pool to it.
async fn fresh_db(server_url: &str) -> Result<PgPool, TestError> {
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(server_url)
    .await
    .map_err(|error| connect_hint(server_url, &error))?;
  let name = format!("mig_{}", uuid::Uuid::new_v4().simple());
  // `CREATE DATABASE` cannot take a bind parameter, and `Pool`'s `Executor`
  // requires a `'static` query, so leak this one tiny test-only string.
  let ddl: &'static str = Box::leak(format!("CREATE DATABASE \"{name}\"").into_boxed_str());
  let created = admin
    .execute(ddl)
    .await
    .map_err(|error| TestError::Setup(format!("failed to create test database {name}: {error}")));
  admin.close().await;
  created?;
  let target = server_url.replacen("/postgres?", &format!("/{name}?"), 1);
  PgPoolOptions::new()
    .max_connections(4)
    .connect(&target)
    .await
    .map_err(|error| connect_hint(&target, &error))
}

/// Helpful error for an unreachable shared Postgres (never a bare driver error).
fn connect_hint(url: &str, error: &sqlx::Error) -> TestError {
  TestError::Setup(format!(
    "cannot reach shared test Postgres at {url}: {error}; {COMPOSE_HINT}"
  ))
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

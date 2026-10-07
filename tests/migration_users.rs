//! `test(migration_users)` — real-Postgres (shared external server) tests for
//! `migrations/*_users.sql`: the users / scopes / user_scopes / redirect_uris
//! / client_redirect_uris half of the six-table schema.
//!
//! Verifies schema shape and the negative invariants the plan pins:
//! case-insensitive email uniqueness, encrypted (non-plaintext) TOTP storage,
//! the absence of failed-login/lockout columns, safe privilege defaults, the
//! normalized-exact redirect-URI and per-client attachment uniqueness, a clean
//! second migration run, and the checksum guard rejecting a tampered
//! already-applied migration.
//!
//! The shared Postgres server comes from `compose.test.yaml`
//! (`docker compose -f compose.test.yaml up -d`); each test migrates a
//! freshly created database so the tests stay isolated under parallel execution.

use std::{
  collections::BTreeSet,
  error::Error,
  io,
  path::{Path, PathBuf},
};

use sqlx::{
  Executor as _, PgPool, Row as _,
  migrate::{MigrateError, Migrator},
  postgres::PgPoolOptions,
};

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use test_guard::{Lease, Shared};

/// Embedded migrations — the exact compile-time set `d_oauth::state::MIGRATOR`
/// serves from (task 8's `oauth_clients` + this task's `users`).
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// URL of the shared test Postgres server (the `postgres` maintenance DB).
///
/// Overridable via `D_OAUTH_TEST_POSTGRES_URL`; the default matches
/// `compose.test.yaml` (`test-db`, port 5433). Start it with
/// `docker compose -f compose.test.yaml up -d`.
fn pg_server_url() -> String {
  match std::env::var("D_OAUTH_TEST_POSTGRES_URL") {
    Ok(url) => url,
    Err(_) => {
      "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres?sslmode=disable".to_owned()
    }
  }
}

/// The shared Postgres server address.
///
/// Compose-first: no container is booted here. The lease only keeps the
/// address alive for the test; the server itself is shared across all test
/// processes via `compose.test.yaml`.
struct Db {
  url: String,
}

/// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
type TestError = Box<dyn Error + Send + Sync>;

/// Fallible test body.
type TestResult = Result<(), TestError>;

/// The one Postgres server reused by every test in this binary.
static DB: Shared<Db> = Shared::new();

/// Resolve (once) and return a lease on the shared Postgres server.
///
/// Compose-first: no container is booted. The lease must stay alive as long
/// as the server is used; bind it (usually as `_db`) for the test duration.
/// A connection failure names the compose file to start instead of surfacing
/// a bare driver error.
async fn shared_db() -> Result<Lease<Db>, TestError> {
  DB.lease::<TestError>(async {
    let url = pg_server_url();
    let probe = PgPoolOptions::new()
      .max_connections(1)
      .connect(&url)
      .await
      .map_err(|error| {
        format!(
          "cannot reach shared test Postgres at {url}: {error}; \
           run `docker compose -f compose.test.yaml up -d`"
        )
      })?;
    probe.close().await;
    Ok(Db { url })
  })
  .await
}

/// Create a uniquely named database on the shared server and pool to it.
async fn fresh_pool(server_url: &str) -> Result<PgPool, TestError> {
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(server_url)
    .await?;
  let name = format!("mig_{}", uuid::Uuid::new_v4().simple());
  // `CREATE DATABASE` cannot take a bind parameter, and `Pool`'s `Executor`
  // requires a `'static` query, so leak this one tiny test-only string.
  let ddl: &'static str = Box::leak(format!("CREATE DATABASE \"{name}\"").into_boxed_str());
  admin.execute(ddl).await?;
  admin.close().await;
  let target = server_url.replacen("/postgres?", &format!("/{name}?"), 1);
  let pool = PgPoolOptions::new()
    .max_connections(4)
    .connect(&target)
    .await?;
  Ok(pool)
}

/// A fresh database with every embedded migration applied.
///
/// The returned lease keeps the shared server alive; bind it (usually as
/// `_db`) for the duration of the test.
async fn migrated_pool() -> Result<(Lease<Db>, PgPool), TestError> {
  let db = shared_db().await?;
  let pool = fresh_pool(&db.url).await?;
  MIGRATOR.run(&pool).await?;
  Ok((db, pool))
}

/// Insert a minimal user (only the NOT-NULL columns without defaults).
async fn insert_user(
  pool: &PgPool,
  email: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
  sqlx::query(
    "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
     VALUES ($1, $2, $3, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(email)
  .bind("$argon2id$v=19$m=19456,t=2,p=1$placeholder")
  .execute(pool)
  .await
}

/// Insert a minimal client so URI attachments have an FK target.
async fn insert_client(pool: &PgPool, client_id: &str) -> Result<(), sqlx::Error> {
  sqlx::query(
    "INSERT INTO oauth_clients \
       (id, client_id, client_id_issued_at, client_name, grant_types, \
        response_types, scope, token_endpoint_auth_method, created_at, updated_at) \
     VALUES ($1, $2, now(), $3, $4, $5, $6, $7, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(client_id)
  .bind("Migration Users Test Client")
  .bind(vec!["authorization_code".to_owned()])
  .bind(vec!["code".to_owned()])
  .bind("")
  .bind("client_secret_basic")
  .execute(pool)
  .await?;
  Ok(())
}

/// Insert a catalog redirect URI.
async fn insert_redirect_uri(
  pool: &PgPool,
  id: uuid::Uuid,
  uri: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, created_at, updated_at) VALUES ($1, $2, now(), now())",
  )
  .bind(id)
  .bind(uri)
  .execute(pool)
  .await
}

/// Attach a catalog redirect URI to a client.
async fn attach(
  pool: &PgPool,
  client_id: &str,
  redirect_uri_id: uuid::Uuid,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
  sqlx::query(
    "INSERT INTO client_redirect_uris (client_id, redirect_uri_id, attached_at) \
     VALUES ($1, $2, now())",
  )
  .bind(client_id)
  .bind(redirect_uri_id)
  .execute(pool)
  .await
}

/// Assert the write failed with a unique-violation (SQLSTATE 23505).
fn assert_unique_violation(
  result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
) -> TestResult {
  match result {
    Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(()),
    other => Err(format!("expected a unique violation, got: {other:?}").into()),
  }
}

/// A table's columns as `(name, udt_name, is_nullable)`.
async fn columns_of(
  pool: &PgPool,
  table: &str,
) -> Result<Vec<(String, String, String)>, TestError> {
  let rows = sqlx::query(
    "SELECT column_name, udt_name, is_nullable FROM information_schema.columns \
     WHERE table_schema = 'public' AND table_name = $1",
  )
  .bind(table)
  .fetch_all(pool)
  .await?;
  let mut columns = Vec::with_capacity(rows.len());
  for row in &rows {
    columns.push((
      row.try_get::<String, _>("column_name")?,
      row.try_get::<String, _>("udt_name")?,
      row.try_get::<String, _>("is_nullable")?,
    ));
  }
  Ok(columns)
}

/// Assert a table has `column` of the given Postgres `udt_name`.
fn assert_udt(columns: &[(String, String, String)], column: &str, udt: &str) -> TestResult {
  let found = columns
    .iter()
    .find(|(name, _, _)| name == column)
    .ok_or_else(|| io::Error::other(format!("column {column} missing")))?;
  assert_eq!(found.1, udt, "{column} is {udt}");
  Ok(())
}

/// Assert a table has `column` and it accepts NULL.
fn assert_nullable(columns: &[(String, String, String)], column: &str) -> TestResult {
  let found = columns
    .iter()
    .find(|(name, _, _)| name == column)
    .ok_or_else(|| io::Error::other(format!("column {column} missing")))?;
  assert_eq!(found.2, "YES", "{column} is nullable");
  Ok(())
}

/// Assert a unique partial index on `table` is keyed by `column` with an
/// `IS NOT NULL` predicate (so NULL rows stay unconstrained).
async fn assert_partial_unique_index(
  pool: &PgPool,
  index: &str,
  table: &str,
  column: &str,
) -> TestResult {
  let def = index_def(pool, table, index).await?;
  assert!(def.contains("UNIQUE INDEX"), "{index} is unique: {def}");
  assert!(def.contains(column), "{index} keys on {column}: {def}");
  assert!(def.contains("IS NOT NULL"), "{index} is partial: {def}");
  Ok(())
}

/// Assert an index exists on `table`.
async fn assert_index_exists(pool: &PgPool, table: &str, index: &str) -> TestResult {
  index_def(pool, table, index).await.map(|_| ())
}

/// The `pg_indexes.indexdef` for `table`'s `index`, or an error naming it.
async fn index_def(pool: &PgPool, table: &str, index: &str) -> Result<String, TestError> {
  sqlx::query_scalar(
    "SELECT indexdef FROM pg_indexes \
     WHERE schemaname = 'public' AND tablename = $1 AND indexname = $2",
  )
  .bind(table)
  .bind(index)
  .fetch_optional(pool)
  .await?
  .ok_or_else(|| io::Error::other(format!("index {index} missing on {table}")).into())
}

/// Assert a table constraint (unique/check) still exists after the expansion.
async fn assert_constraint_kept(pool: &PgPool, table: &str, constraint: &str) -> TestResult {
  let exists: bool = sqlx::query_scalar(
    "SELECT EXISTS (SELECT 1 FROM pg_constraint c \
       JOIN pg_class t ON t.oid = c.conrelid \
       JOIN pg_namespace n ON n.oid = t.relnamespace \
      WHERE n.nspname = 'public' AND t.relname = $1 AND c.conname = $2)",
  )
  .bind(table)
  .bind(constraint)
  .fetch_one(pool)
  .await?;
  assert!(exists, "legacy constraint {constraint} is kept");
  Ok(())
}

/// Run all migrations on an empty DB: full schema, empty scope catalog, and a
/// second run is a clean no-op.
#[tokio::test]
async fn migration_users_creates_schema_and_second_run_is_noop() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
    .fetch_one(&pool)
    .await?;
  assert_eq!(
    usize::try_from(applied)?,
    MIGRATOR.iter().count(),
    "every embedded migration is applied"
  );

  // Second run: no error and no newly-applied rows.
  MIGRATOR.run(&pool).await?;
  let applied_again: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
    .fetch_one(&pool)
    .await?;
  assert_eq!(applied_again, applied, "second migration run is a no-op");

  for table in [
    "users",
    "scopes",
    "user_scopes",
    "redirect_uris",
    "client_redirect_uris",
    "oauth_clients",
  ] {
    let exists: bool = sqlx::query_scalar(
      "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
       WHERE table_schema = 'public' AND table_name = $1)",
    )
    .bind(table)
    .fetch_one(&pool)
    .await?;
    assert!(exists, "table {table} exists");
  }

  let scope_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scopes")
    .fetch_one(&pool)
    .await?;
  assert_eq!(
    scope_count, 0,
    "scope catalog is created empty (no seed rows)"
  );
  Ok(())
}

/// `users.email` is `citext`, so uniqueness is case-insensitive.
#[tokio::test]
async fn migration_users_email_uniqueness_is_case_insensitive() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  insert_user(&pool, "A@x.com").await?;
  let duplicate = insert_user(&pool, "a@x.com").await;
  assert_unique_violation(duplicate)?;

  // A genuinely different address still inserts.
  insert_user(&pool, "b@x.com").await?;
  Ok(())
}

/// The TOTP secret is an encrypted `bytea` column and no lockout columns exist.
#[tokio::test]
async fn migration_users_totp_is_ciphertext_and_no_lockout_columns() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  let columns: Vec<(String, String, String)> = sqlx::query_as(
    "SELECT column_name, data_type, udt_name FROM information_schema.columns \
     WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name",
  )
  .fetch_all(&pool)
  .await?;
  let names: BTreeSet<&str> = columns.iter().map(|(name, _, _)| name.as_str()).collect();

  let expected: BTreeSet<&str> = [
    "created_at",
    "disabled",
    "email",
    "email_enc",
    "email_index",
    "id",
    "is_admin",
    "must_change_password",
    "password_changed_at",
    "password_hash",
    "totp_enabled",
    "totp_recovery_code_hashes",
    "totp_secret_enc",
    "updated_at",
  ]
  .into_iter()
  .collect();
  assert_eq!(
    names, expected,
    "users has exactly the planned columns (no lockout/failed-login columns)"
  );

  // The only TOTP-secret column is the encrypted `bytea` one; no plaintext one.
  assert!(
    !names.contains("totp_secret"),
    "no plaintext totp_secret column"
  );
  let totp_type = columns
    .iter()
    .find(|(name, _, _)| name == "totp_secret_enc")
    .map(|(_, data_type, _)| data_type.as_str())
    .ok_or_else(|| io::Error::other("totp_secret_enc column missing"))?;
  assert_eq!(
    totp_type, "bytea",
    "TOTP secret is stored as encrypted bytea"
  );

  // `email` is the `citext` extension type (proves the extension was created).
  let email_type = columns
    .iter()
    .find(|(name, _, _)| name == "email")
    .map(|(_, _, udt_name)| udt_name.as_str())
    .ok_or_else(|| io::Error::other("email column missing"))?;
  assert_eq!(email_type, "citext", "email is case-insensitive citext");

  // The blind index is unique and partial: NULL email_index rows are unconstrained.
  assert_partial_unique_index(&pool, "ux_users_email_index", "users", "email_index").await?;

  for name in &names {
    assert!(!name.contains("lock"), "no lockout column: {name}");
    assert!(!name.contains("failed"), "no failed-login column: {name}");
    assert!(
      !name.contains("attempt"),
      "no failed-attempt column: {name}"
    );
  }
  Ok(())
}

/// Todo 8 expansion: the encrypted PII columns and blind indexes exist, the
/// plaintext columns the backfill blanks accept NULL, and the legacy unique
/// constraints survive (inert on NULL), so an encrypt-only row inserts.
#[tokio::test]
async fn expand_migration_adds_pii_columns() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  // The expansion version is compiled into the embedded set readiness reads.
  assert!(
    MIGRATOR.iter().any(|m| m.version == 1_791_417_600),
    "the PII expansion migration is embedded in MIGRATOR"
  );

  // users: email stays citext but becomes nullable; ciphertext + blind index add.
  let users = columns_of(&pool, "users").await?;
  assert_nullable(&users, "email")?;
  assert_udt(&users, "email_enc", "bytea")?;
  assert_udt(&users, "email_index", "text")?;
  assert_partial_unique_index(&pool, "ux_users_email_index", "users", "email_index").await?;
  assert_constraint_kept(&pool, "users", "ux_users_email").await?;

  // oauth_clients: every PII metadata column gains a ciphertext twin, the two
  // mTLS identities gain blind indexes, and client_name becomes nullable.
  let clients = columns_of(&pool, "oauth_clients").await?;
  assert_nullable(&clients, "client_name")?;
  for column in [
    "client_name_enc",
    "contacts_enc",
    "request_uris_enc",
    "jwks_uri_enc",
    "software_id_enc",
    "tls_client_auth_subject_dn_enc",
    "tls_client_auth_cert_thumbprint_enc",
  ] {
    assert_udt(&clients, column, "bytea")?;
  }
  assert_udt(&clients, "tls_client_auth_subject_dn_index", "text")?;
  assert_udt(&clients, "tls_client_auth_cert_thumbprint_index", "text")?;
  assert_partial_unique_index(
    &pool,
    "ux_oauth_clients_tls_subject_dn_index",
    "oauth_clients",
    "tls_client_auth_subject_dn_index",
  )
  .await?;
  assert_partial_unique_index(
    &pool,
    "ux_oauth_clients_tls_cert_thumbprint_index",
    "oauth_clients",
    "tls_client_auth_cert_thumbprint_index",
  )
  .await?;
  assert_index_exists(&pool, "oauth_clients", "ux_oauth_clients_tls_subject_dn").await?;
  assert_index_exists(
    &pool,
    "oauth_clients",
    "ux_oauth_clients_tls_cert_thumbprint",
  )
  .await?;

  // redirect_uris: uri becomes nullable; ciphertext + per-kind blind index add.
  let uris = columns_of(&pool, "redirect_uris").await?;
  assert_nullable(&uris, "uri")?;
  assert_udt(&uris, "uri_enc", "bytea")?;
  assert_udt(&uris, "uri_index", "text")?;
  assert_partial_unique_index(
    &pool,
    "ux_redirect_uris_uri_index_kind",
    "redirect_uris",
    "uri_index",
  )
  .await?;
  assert_constraint_kept(&pool, "redirect_uris", "ux_redirect_uris_uri_kind").await?;

  // Encrypt-only rows (plaintext NULL, ciphertext populated) insert cleanly.
  sqlx::query(
    "INSERT INTO users (id, email, email_enc, email_index, password_hash, created_at, updated_at) \
     VALUES ($1, NULL, $2, $3, $4, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(b"sealed-email".to_vec())
  .bind("blind-email-index")
  .bind("$argon2id$v=19$m=19456,t=2,p=1$placeholder")
  .execute(&pool)
  .await?;

  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, uri_enc, uri_index, created_at, updated_at) \
     VALUES ($1, NULL, $2, $3, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(b"sealed-uri".to_vec())
  .bind("blind-uri-index")
  .execute(&pool)
  .await?;

  sqlx::query(
    "INSERT INTO oauth_clients \
       (id, client_id, client_id_issued_at, client_name, client_name_enc, \
        grant_types, response_types, scope, token_endpoint_auth_method, \
        created_at, updated_at) \
     VALUES ($1, $2, now(), NULL, $3, $4, $5, $6, $7, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind("pii-expansion-client")
  .bind(b"sealed-name".to_vec())
  .bind(vec!["client_credentials".to_owned()])
  .bind(vec!["token".to_owned()])
  .bind("")
  .bind("client_secret_basic")
  .execute(&pool)
  .await?;

  // Re-running the migrator applies nothing new (a no-op).
  let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
    .fetch_one(&pool)
    .await?;
  MIGRATOR.run(&pool).await?;
  let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
    .fetch_one(&pool)
    .await?;
  assert_eq!(before, after, "re-running the migrator is a no-op");
  Ok(())
}

/// `is_admin`, `must_change_password`, `disabled`, and `totp_enabled` default
/// false, so a freshly provisioned user is never accidentally privileged.
#[tokio::test]
async fn migration_users_privilege_defaults_are_false() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  insert_user(&pool, "fresh@x.com").await?;
  let (is_admin, must_change, disabled, totp_enabled): (bool, bool, bool, bool) = sqlx::query_as(
    "SELECT is_admin, must_change_password, disabled, totp_enabled \
       FROM users WHERE email = 'fresh@x.com'",
  )
  .fetch_one(&pool)
  .await?;
  assert!(!is_admin, "is_admin defaults false");
  assert!(!must_change, "must_change_password defaults false");
  assert!(!disabled, "disabled defaults false");
  assert!(!totp_enabled, "totp_enabled defaults false");
  Ok(())
}

/// `redirect_uris.uri` is unique and a client URI attachment is unique.
#[tokio::test]
async fn migration_users_redirect_uri_and_attachment_are_unique() -> TestResult {
  let (_db, pool) = migrated_pool().await?;

  insert_client(&pool, "client-a").await?;
  let uri_id = uuid::Uuid::new_v4();
  insert_redirect_uri(&pool, uri_id, "https://app.example/cb").await?;

  // The same normalized-exact URI cannot be catalogued twice.
  let duplicate_uri =
    insert_redirect_uri(&pool, uuid::Uuid::new_v4(), "https://app.example/cb").await;
  assert_unique_violation(duplicate_uri)?;

  // The same URI cannot be attached to a client twice.
  attach(&pool, "client-a", uri_id).await?;
  let duplicate_attachment = attach(&pool, "client-a", uri_id).await;
  assert_unique_violation(duplicate_attachment)?;
  Ok(())
}

/// An already-applied migration whose content changed is rejected by the
/// checksum guard (`MigrateError::VersionMismatch`).
#[tokio::test]
async fn migration_users_rejects_a_tampered_applied_migration() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let tmp = copy_migrations_to_temp()?;

  // An untouched copy of the same migrations validates against the applied set.
  Migrator::new(tmp.as_path()).await?.run(&pool).await?;

  // Tamper an already-applied migration, then re-run: checksum mismatch.
  let victim = first_sql_file(&tmp)?;
  let mut sql = std::fs::read_to_string(&victim)?;
  sql.push_str("\n-- tampered after apply\n");
  std::fs::write(&victim, sql)?;

  let result = Migrator::new(tmp.as_path()).await?.run(&pool).await;
  let _ = std::fs::remove_dir_all(&tmp);

  match result {
    Err(MigrateError::VersionMismatch(_)) => Ok(()),
    other => {
      Err(format!("expected VersionMismatch for a tampered migration, got: {other:?}").into())
    }
  }
}

/// Copy every `*.sql` migration into a fresh temp directory.
fn copy_migrations_to_temp() -> Result<PathBuf, TestError> {
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  let tmp = std::env::temp_dir().join(format!(
    "d-oauth-migration-users-{}",
    uuid::Uuid::new_v4().simple()
  ));
  std::fs::create_dir_all(&tmp)?;
  for entry in std::fs::read_dir(&source)? {
    let entry = entry?;
    let path = entry.path();
    if path.extension().and_then(|ext| ext.to_str()) == Some("sql") {
      std::fs::copy(&path, tmp.join(entry.file_name()))?;
    }
  }
  Ok(tmp)
}

/// Return the first `*.sql` file in `dir` (deterministic enough: every SQL
/// migration in the directory has been applied by the time this is called).
fn first_sql_file(dir: &Path) -> Result<PathBuf, TestError> {
  for entry in std::fs::read_dir(dir)? {
    let entry = entry?;
    let path = entry.path();
    if path.extension().and_then(|ext| ext.to_str()) == Some("sql") {
      return Ok(path);
    }
  }
  Err(io::Error::other("no .sql migration files found").into())
}

//! Compose-first test scaffolding for the `src/**` unit-test suites.
//!
//! Unit tests under `src/` connect to the shared external services started by
//! `docker compose -f compose.test.yaml up -d` (Postgres on `127.0.0.1:5433`,
//! Redis on `127.0.0.1:6380`) instead of booting a per-test container. Per-test
//! isolation comes from a freshly created database per [`fresh_database_pool`]
//! call and from a distinct [`unique_prefixes`] pair per test, so parallel
//! tests never observe each other's rows or Redis keys.
//!
//! This module is context-agnostic on purpose: it references only external
//! crate types ([`sqlx`], [`redis`], [`uuid`]) plus URLs, DDL, and key
//! prefixes, never an internal module path, so the helper stays reachable
//! without a single-source dependency on `tests/common/mod.rs`. It imports no
//! container runtime either: the suites that genuinely need container control
//! (lifecycle, topology, a non-default server config) keep using the test
//! guard directly.
//!
//! Both URLs honour the same environment overrides as the integration suites
//! (`D_OAUTH_TEST_POSTGRES_URL`, `D_OAUTH_TEST_REDIS_URL`) through the internal
//! [`resolve_url`], so the override/default contract is testable without
//! `std::env::set_var` (which is `unsafe` under edition 2024 and forbidden by
//! the crate's `forbid(unsafe_code)`).

use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};

/// Hint shown when the shared test services are unreachable.
const COMPOSE_HINT: &str = "run `docker compose -f compose.test.yaml up -d`";

/// Default URL of the shared test Postgres server (the `postgres` maintenance
/// database), matching `compose.test.yaml` (`test-db`, port 5433).
const DEFAULT_POSTGRES_ADMIN_URL: &str =
  "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres?sslmode=disable";

/// Default URL of the shared test Redis server, matching `compose.test.yaml`
/// (`test-redis`, port 6380).
const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6380";

/// Aggregate error so test bodies use `?` instead of panicking.
///
/// `Send + Sync + 'static`, so a caller returning
/// `Box<dyn std::error::Error + Send + Sync>` can `?` a `Result<_, TestError>`.
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// The shared test service is unreachable or misconfigured.
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
pub fn test_postgres_admin_url() -> String {
  resolve_url(
    std::env::var("D_OAUTH_TEST_POSTGRES_URL").ok().as_deref(),
    DEFAULT_POSTGRES_ADMIN_URL,
  )
}

/// URL of the shared test Redis server.
///
/// Overridable via `D_OAUTH_TEST_REDIS_URL`; the default matches
/// `compose.test.yaml` (`test-redis`, port 6380).
pub fn test_redis_url() -> String {
  resolve_url(
    std::env::var("D_OAUTH_TEST_REDIS_URL").ok().as_deref(),
    DEFAULT_REDIS_URL,
  )
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
/// Returns both the fresh database URL and a pool to it. The database is empty
/// (no migrations are applied); callers apply exactly the migration SQL they
/// assert on. A connection failure names the compose file to start.
pub async fn fresh_database_pool() -> Result<(String, PgPool), TestError> {
  let server_url = test_postgres_admin_url();
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(&server_url)
    .await
    .map_err(|error| connect_hint(&server_url, &error))?;
  let name = format!("tst_{}", uuid::Uuid::new_v4().simple());
  // `CREATE DATABASE` cannot take a bind parameter, and `&Pool`'s `Executor`
  // requires a `'static` query, so leak this one tiny test-only string.
  let ddl: &'static str = Box::leak(format!("CREATE DATABASE \"{name}\"").into_boxed_str());
  let created = admin
    .execute(ddl)
    .await
    .map_err(|error| TestError::Setup(format!("failed to create test database {name}: {error}")));
  admin.close().await;
  created?;
  let target = with_database(&server_url, &name);
  let pool = PgPoolOptions::new()
    .max_connections(4)
    .connect(&target)
    .await
    .map_err(|error| connect_hint(&target, &error))?;
  Ok((target, pool))
}

/// A `ConnectionManager` to the shared test Redis server.
///
/// Uses the suite-wide timeout convention: a 10 s response timeout (a blocking
/// `WAITAOF` can wait a full fsync cycle) and a 5 s connection timeout. A
/// connection failure names the compose file to start.
pub async fn redis_manager() -> Result<ConnectionManager, TestError> {
  let url = test_redis_url();
  let client = redis::Client::open(url.as_str()).map_err(|error| {
    TestError::Setup(format!(
      "cannot open shared test Redis at {url}: {error}; {COMPOSE_HINT}"
    ))
  })?;
  let config = ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = ConnectionManager::new_with_config(client, config)
    .await
    .map_err(|error| {
      TestError::Setup(format!(
        "cannot reach shared test Redis at {url}: {error}; {COMPOSE_HINT}"
      ))
    })?;
  Ok(manager)
}

/// Resolve a URL from an optional override, falling back to the given default.
fn resolve_url(override_url: Option<&str>, default: &str) -> String {
  override_url.unwrap_or(default).to_owned()
}

/// Replace the database (path) component of `server_url` with `name`,
/// preserving any query string. Works with or without a `?`-query.
fn with_database(server_url: &str, name: &str) -> String {
  let (base, query) = match server_url.split_once('?') {
    Some((base, query)) => (base, Some(query)),
    None => (server_url, None),
  };
  let base = base.rsplit_once('/').map_or(base, |(prefix, _db)| prefix);
  match query {
    Some(query) => format!("{base}/{name}?{query}"),
    None => format!("{base}/{name}"),
  }
}

/// Helpful error for an unreachable shared Postgres (never a bare driver error).
fn connect_hint(url: &str, error: &sqlx::Error) -> TestError {
  TestError::Setup(format!(
    "cannot reach shared test Postgres at {url}: {error}; {COMPOSE_HINT}"
  ))
}

#[cfg(test)]
mod tests {
  use super::{
    DEFAULT_POSTGRES_ADMIN_URL, DEFAULT_REDIS_URL, resolve_url, unique_prefixes, with_database,
  };

  #[test]
  fn test_support_defaults_to_compose_ports() {
    assert_eq!(
      resolve_url(None, DEFAULT_POSTGRES_ADMIN_URL),
      "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres?sslmode=disable"
    );
    assert_eq!(
      resolve_url(Some("redis://example:9999"), DEFAULT_REDIS_URL),
      "redis://example:9999"
    );
  }

  #[test]
  fn fresh_db_url_replaces_database() {
    let name = "tst_abc123";
    assert_eq!(
      with_database(
        "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres?sslmode=disable",
        name
      ),
      "postgres://postgres:oauth-test-only@127.0.0.1:5433/tst_abc123?sslmode=disable"
    );
    assert_eq!(
      with_database(
        "postgres://postgres:oauth-test-only@127.0.0.1:5433/postgres",
        name
      ),
      "postgres://postgres:oauth-test-only@127.0.0.1:5433/tst_abc123"
    );
  }

  #[test]
  fn unique_prefixes_are_distinct() {
    let (state_a, rl_a) = unique_prefixes();
    let (state_b, rl_b) = unique_prefixes();
    assert!(state_a.starts_with("oauth:{state}:t"));
    assert!(rl_a.starts_with("oauth:{rl}:r"));
    assert!(state_b.starts_with("oauth:{state}:t"));
    assert!(rl_b.starts_with("oauth:{rl}:r"));
    let mut seen = vec![state_a, rl_a, state_b, rl_b];
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 4);
  }
}

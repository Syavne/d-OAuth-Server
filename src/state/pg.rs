//! Postgres pool construction.
//!
//! `PgPoolOptions` follow the plan exactly: `max_connections=15`,
//! `min_connections=2`, `acquire_timeout=3s`, `idle_timeout=300s`,
//! `max_lifetime=1800s`, `test_before_acquire=true`. The `after_connect` hook
//! applies the per-connection timeouts idempotently via `set_config` (bound
//! parameters, never string interpolation).
//!
//! The connect string carries `sslmode=verify-full` plus `sslrootcert`, an
//! `application_name` of `oauth21-<env>-<instance>`, and
//! `statement-cache-capacity=100`, connecting direct to Postgres (no pooler
//! transaction mode). An explicit `sslmode` in the URL is always honored
//! (tests pin `sslmode=disable` for plaintext containers); otherwise
//! `require_verify_full` selects `verify-full`, else `prefer`.

use std::str::FromStr;

use secrecy::ExposeSecret;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::StateError;
use crate::config::{DbConfig, types::Environment};

/// `application_name` identifying this binary to Postgres logs/locks.
fn application_name(environment: Environment) -> String {
  let env = match environment {
    Environment::Production => "production",
    Environment::Development => "development",
  };
  let instance = std::env::var("HOSTNAME")
    .ok()
    .filter(|name| !name.trim().is_empty())
    .unwrap_or_else(|| format!("pid-{}", std::process::id()));
  format!("oauth21-{env}-{instance}")
}

/// Whether the URL already pins an `sslmode` (in which case it wins).
fn has_explicit_sslmode(url: &str) -> bool {
  url
    .split(['?', '&'])
    .any(|part| part.starts_with("sslmode="))
}

/// Build `PgConnectOptions` from [`DbConfig`] without opening connections.
fn connect_options(
  db: &DbConfig,
  environment: Environment,
) -> Result<PgConnectOptions, StateError> {
  let mut url = db.url.expose_secret().to_owned();
  if !has_explicit_sslmode(&url) {
    url.push_str(if url.contains('?') {
      "&sslmode=verify-full"
    } else {
      "?sslmode=verify-full"
    });
    if !db.require_verify_full {
      // `verify-full` was just appended; relax it back to opportunistic TLS
      // for non-production configs (plaintext test containers).
      url = url.replace("sslmode=verify-full", "sslmode=prefer");
    }
  }
  let mut options = PgConnectOptions::from_str(&url).map_err(StateError::Database)?;
  if let Some(password) = db.password.as_ref() {
    options = options.password(password.expose_secret());
  }
  if let Some(root) = db.root_cert_path.as_ref() {
    options = options.ssl_root_cert(root);
  }
  options = options
    .application_name(&application_name(environment))
    .statement_cache_capacity(100);
  Ok(options)
}

/// Build the tuned `PgPoolOptions` (pool bounds + `after_connect` hook).
fn pool_options(db: &DbConfig, environment: Environment) -> PgPoolOptions {
  let statement_timeout = format!("{}s", db.statement_timeout.as_secs());
  let lock_timeout = format!("{}s", db.lock_timeout.as_secs());
  let idle_in_transaction = format!("{}s", db.idle_in_transaction_timeout.as_secs());
  let app_name = application_name(environment);
  PgPoolOptions::new()
    .max_connections(db.max_connections)
    .min_connections(db.min_connections)
    .acquire_timeout(db.acquire_timeout)
    .idle_timeout(db.idle_timeout)
    .max_lifetime(db.max_lifetime)
    .test_before_acquire(true)
    .after_connect(move |conn: &mut sqlx::PgConnection, _meta| {
      let statement_timeout = statement_timeout.clone();
      let lock_timeout = lock_timeout.clone();
      let idle_in_transaction = idle_in_transaction.clone();
      let app_name = app_name.clone();
      Box::pin(async move {
        sqlx::query(
          "SELECT set_config('application_name', $1, false), \
           set_config('statement_timeout', $2, false), \
           set_config('lock_timeout', $3, false), \
           set_config('idle_in_transaction_session_timeout', $4, false)",
        )
        .bind(app_name)
        .bind(statement_timeout)
        .bind(lock_timeout)
        .bind(idle_in_transaction)
        .execute(&mut *conn)
        .await
        .map(|_| ())
      })
    })
}

/// Open the Postgres pool, eagerly establishing `max(1, min_connections)`
/// (via `connect_with`) so a bad URL fails startup instead of first request.
pub async fn connect_postgres(
  db: &DbConfig,
  environment: Environment,
) -> Result<sqlx::PgPool, StateError> {
  let options = connect_options(db, environment)?;
  pool_options(db, environment)
    .connect_with(options)
    .await
    .map_err(StateError::Database)
}

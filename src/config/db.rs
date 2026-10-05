//! PostgreSQL connection and pool configuration.
//!
//! Production requires `sslmode=verify-full` in the URL. Timeouts form a
//! ladder validated at load time: `lock < statement <= acquire < request`.

use std::{fmt, path::PathBuf, time::Duration};

use secrecy::SecretString;
use serde::Deserialize;

use super::{ConfigError, read_secret_file, types::Environment};

/// Validated Postgres connection/pool configuration.
#[derive(Clone)]
pub struct DbConfig {
  /// Connection URL (may embed a password; never printed).
  pub url: SecretString,
  /// Optional password read from a mounted secret file.
  pub password: Option<SecretString>,
  /// Root certificate for `verify-full` (path to `sslrootcert`).
  pub root_cert_path: Option<PathBuf>,
  /// Maximum pool connections (default 15).
  pub max_connections: u32,
  /// Minimum idle pool connections (default 2).
  pub min_connections: u32,
  /// Acquire budget (default 3 s).
  pub acquire_timeout: Duration,
  /// Idle eviction timeout (default 300 s).
  pub idle_timeout: Duration,
  /// Connection max lifetime (default 1 800 s).
  pub max_lifetime: Duration,
  /// `statement_timeout` applied per connection (default 3 s).
  pub statement_timeout: Duration,
  /// `lock_timeout` applied per connection (default 1 s).
  pub lock_timeout: Duration,
  /// `idle_in_transaction_session_timeout` (default 30 s).
  pub idle_in_transaction_timeout: Duration,
  /// `application_name` (default `oauth21-server`).
  pub application_name: String,
  /// Whether the URL is required to carry `sslmode=verify-full`.
  pub require_verify_full: bool,
}

impl fmt::Debug for DbConfig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("DbConfig")
      .field("url", &"[REDACTED]")
      .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
      .field("root_cert_path", &self.root_cert_path)
      .field("max_connections", &self.max_connections)
      .field("min_connections", &self.min_connections)
      .field("acquire_timeout", &self.acquire_timeout)
      .field("idle_timeout", &self.idle_timeout)
      .field("max_lifetime", &self.max_lifetime)
      .field("statement_timeout", &self.statement_timeout)
      .field("lock_timeout", &self.lock_timeout)
      .field(
        "idle_in_transaction_timeout",
        &self.idle_in_transaction_timeout,
      )
      .field("application_name", &self.application_name)
      .field("require_verify_full", &self.require_verify_full)
      .finish()
  }
}

impl DbConfig {
  pub(crate) fn from_raw(raw: RawDbConfig, environment: Environment) -> Result<Self, ConfigError> {
    let url = match raw.url {
      Some(url) if !url.trim().is_empty() => url,
      _ => return Err(ConfigError::MissingDatabaseUrl),
    };
    if environment.is_production() && raw.require_verify_full && !has_verify_full(&url) {
      return Err(ConfigError::InsecureDatabaseTls);
    }
    if raw.max_connections == 0 || raw.min_connections > raw.max_connections {
      return Err(ConfigError::InvalidPoolBounds {
        min: raw.min_connections,
        max: raw.max_connections,
      });
    }
    let password = read_secret_file(raw.password_file.as_deref())?;
    Ok(Self {
      url: SecretString::from(url),
      password,
      root_cert_path: raw.root_cert_path,
      max_connections: raw.max_connections,
      min_connections: raw.min_connections,
      acquire_timeout: Duration::from_secs(raw.acquire_timeout_secs),
      idle_timeout: Duration::from_secs(raw.idle_timeout_secs),
      max_lifetime: Duration::from_secs(raw.max_lifetime_secs),
      statement_timeout: Duration::from_secs(raw.statement_timeout_secs),
      lock_timeout: Duration::from_secs(raw.lock_timeout_secs),
      idle_in_transaction_timeout: Duration::from_secs(raw.idle_in_transaction_timeout_secs),
      application_name: raw.application_name,
      require_verify_full: raw.require_verify_full,
    })
  }
}

/// Raw `database` block.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawDbConfig {
  pub url: Option<String>,
  pub password_file: Option<PathBuf>,
  pub root_cert_path: Option<PathBuf>,
  pub max_connections: u32,
  pub min_connections: u32,
  pub acquire_timeout_secs: u64,
  pub idle_timeout_secs: u64,
  pub max_lifetime_secs: u64,
  pub statement_timeout_secs: u64,
  pub lock_timeout_secs: u64,
  pub idle_in_transaction_timeout_secs: u64,
  pub application_name: String,
  pub require_verify_full: bool,
}

impl Default for RawDbConfig {
  fn default() -> Self {
    Self {
      url: None,
      password_file: None,
      root_cert_path: None,
      max_connections: 15,
      min_connections: 2,
      acquire_timeout_secs: 3,
      idle_timeout_secs: 300,
      max_lifetime_secs: 1_800,
      statement_timeout_secs: 3,
      lock_timeout_secs: 1,
      idle_in_transaction_timeout_secs: 30,
      application_name: "oauth21-server".to_owned(),
      require_verify_full: true,
    }
  }
}

fn has_verify_full(url: &str) -> bool {
  url
    .split(['?', '&'])
    .any(|part| part == "sslmode=verify-full")
}

//! Application state: pools, topology-aware Redis, clock, health.
//!
//! [`AppState`] is cloneable and holds the `sqlx::PgPool`, the [`RedisConn`]
//! enum (never a concrete connection type, so single/Sentinel/Cluster all
//! fit), `Arc<Config>`, `Arc<KeyRing>`, and a [`Clock`]. [`AppState::connect`]
//! fails closed at startup: an unreachable Postgres, an unreachable Redis, or
//! a Redis that violates the no-eviction/AOF durability contract is an error,
//! never a half-built state. Migrations are NOT run here (`serve` never
//! migrates; the `migrate` subcommand in todo 14 owns that); readiness
//! instead verifies the DB schema version matches [`MIGRATOR`].

mod health;
mod pg;
mod redis;
mod sentinel;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests_resilience;
#[cfg(test)]
mod tests_topology;

pub use health::health_router;
pub use redis::RedisConn;
pub use sentinel::SentinelConn;

use std::{fmt, sync::Arc, time::Duration};

use time::OffsetDateTime;

use crate::{
  config::{Config, ConfigError},
  keys::KeyRing,
};

/// Embedded migrations compiled from `./migrations` (currently empty; todos
/// 8/9 add the schema). Readiness requires every embedded migration to be
/// applied; `serve`/state never applies them.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Upper bound for the whole readiness probe (kubelet probes time out, so a
/// hung dependency must flip the probe to 503 instead of hanging it).
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Fail-closed startup/teardown failures for [`AppState`].
#[derive(Debug, thiserror::Error)]
pub enum StateError {
  /// The configuration or its startup durability assertions failed.
  #[error("invalid configuration: {0}")]
  Config(#[from] ConfigError),
  /// Postgres was unreachable or rejected the pool at startup.
  #[error("postgres unavailable")]
  Database(#[source] sqlx::Error),
  /// Redis was unreachable or a command failed at startup.
  #[error("redis unavailable")]
  Redis(#[source] ::redis::RedisError),
  /// An I/O failure outside the two data stores.
  #[error("i/o failure")]
  Io(#[from] std::io::Error),
}

/// Injectable clock; production uses [`Clock::system`], tests pin time with
/// [`Clock::fixed`].
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> OffsetDateTime + Send + Sync>);

impl Clock {
  /// Real wall-clock time.
  #[must_use]
  pub fn system() -> Self {
    Self(Arc::new(OffsetDateTime::now_utc))
  }

  /// A clock frozen at `when`, for deterministic tests.
  #[must_use]
  pub fn fixed(when: OffsetDateTime) -> Self {
    Self(Arc::new(move || when))
  }

  /// Read the current time.
  #[must_use]
  pub fn now(&self) -> OffsetDateTime {
    (self.0)()
  }
}

impl Default for Clock {
  fn default() -> Self {
    Self::system()
  }
}

impl fmt::Debug for Clock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("Clock").field(&self.now()).finish()
  }
}

/// Shared application state passed to every handler.
#[derive(Clone)]
pub struct AppState {
  /// Postgres pool (15/2, 3 s acquire budget, per-connection timeouts).
  pub pool: sqlx::PgPool,
  /// Topology-aware Redis (single/Sentinel/Cluster behind one enum).
  pub redis: RedisConn,
  /// Validated runtime configuration.
  pub config: Arc<Config>,
  /// Versioned token-pepper and TOTP-encryption keys.
  pub keys: Arc<KeyRing>,
  /// Injectable clock.
  pub clock: Clock,
}

impl AppState {
  /// Build live state: open the Postgres pool, connect Redis for the
  /// configured topology, and run the Redis durability/eviction startup
  /// assertions. Any failure is returned; no half-built state escapes.
  pub async fn connect(config: Arc<Config>) -> Result<Self, StateError> {
    let pool = pg::connect_postgres(&config.database, config.environment).await?;
    let redis = redis::connect_redis(&config.redis).await?;
    let keys = Arc::new(config.keys.clone());
    Ok(Self {
      pool,
      redis,
      config,
      keys,
      clock: Clock::system(),
    })
  }
}

impl fmt::Debug for AppState {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AppState")
      .field("pool_size", &self.pool.size())
      .field("redis", &self.redis.topology_name())
      .field("config", &self.config)
      .field("keys", &self.keys)
      .field("clock", &self.clock)
      .finish()
  }
}

//! Topology-aware Redis: one enum, all three topologies first-class.
//!
//! [`RedisConn`] is selected by `RedisConfig::topology` and implements
//! `redis::aio::ConnectionLike`, so every later store talks to one type:
//! - `Single` → `aio::ConnectionManager` (`retries=6`, `min_delay=100ms`,
//!   `exponent_base=2.0`, `max_delay=5s`, `response_timeout=2s`,
//!   `connection_timeout=3s`, taken from the config's retry knobs).
//! - `Sentinel` → retained [`SentinelClient`] + cached data connection with
//!   the hand-built failover resolver in [`super::sentinel`].
//! - `Cluster` → `ClusterClient::get_async_connection` (native slot refresh),
//!   with the config's response/connection timeouts.
//!
//! [`connect_redis`] fails startup closed: after connecting it pings the
//! deployment and runs the config's no-eviction/AOF assertion helpers, so a
//! wrong `maxmemory-policy` (or disabled AOF where required) is a startup
//! error, never a silent durability hole.

use std::fmt;

use redis::{
  AsyncConnectionConfig, Client, RedisFuture, Value,
  aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig},
  cluster::ClusterClientBuilder,
  cluster_async::ClusterConnection,
};
use secrecy::ExposeSecret;

use super::{StateError, sentinel::SentinelConn};
use crate::config::{RedisConfig, RedisTopology};

/// Topology-aware Redis connection (never a concrete connection type).
#[derive(Clone)]
pub enum RedisConn {
  /// Single node behind an auto-reconnecting manager.
  Single(ConnectionManager),
  /// Sentinel-managed replication with failover re-resolution.
  Sentinel(SentinelConn),
  /// Native cluster connection with slot refresh.
  Cluster(ClusterConnection),
}

impl fmt::Debug for RedisConn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("RedisConn")
      .field(&self.topology_name())
      .finish()
  }
}

impl RedisConn {
  /// Topology name for logs and health output (never a secret).
  #[must_use]
  pub fn topology_name(&self) -> &'static str {
    match self {
      Self::Single(_) => "single",
      Self::Sentinel(_) => "sentinel",
      Self::Cluster(_) => "cluster",
    }
  }
}

impl ConnectionLike for RedisConn {
  fn req_packed_command<'a>(&'a mut self, cmd: &'a redis::Cmd) -> RedisFuture<'a, Value> {
    match self {
      Self::Single(manager) => manager.req_packed_command(cmd),
      Self::Sentinel(sentinel) => Box::pin(sentinel.req_packed(cmd)),
      Self::Cluster(cluster) => cluster.req_packed_command(cmd),
    }
  }

  fn req_packed_commands<'a>(
    &'a mut self,
    pipeline: &'a redis::Pipeline,
    offset: usize,
    count: usize,
  ) -> RedisFuture<'a, Vec<Value>> {
    match self {
      Self::Single(manager) => manager.req_packed_commands(pipeline, offset, count),
      Self::Sentinel(sentinel) => Box::pin(sentinel.req_packed_pipeline(pipeline, offset, count)),
      Self::Cluster(cluster) => cluster.req_packed_commands(pipeline, offset, count),
    }
  }

  fn get_db(&self) -> i64 {
    match self {
      Self::Single(manager) => manager.get_db(),
      Self::Sentinel(_) => 0,
      Self::Cluster(cluster) => cluster.get_db(),
    }
  }
}

/// Inject `cfg.password` (mounted secret file) into a bare `redis://` URL.
///
/// Passwords containing URL-significant bytes must already be percent-encoded
/// in the URL itself; this only handles the common alphanumeric-secret case.
fn single_url(url: &secrecy::SecretString, password: Option<&secrecy::SecretString>) -> String {
  let url = url.expose_secret().to_owned();
  let Some(password) = password else {
    return url;
  };
  if url.contains('@') {
    return url;
  }
  match url.split_once("://") {
    Some((scheme, rest)) => format!("{scheme}://:{}@{rest}", password.expose_secret()),
    None => url,
  }
}

async fn connect_single(
  config: &RedisConfig,
  url: &secrecy::SecretString,
) -> Result<RedisConn, StateError> {
  let url = single_url(url, config.password.as_ref());
  let client = Client::open(url.as_str()).map_err(StateError::Redis)?;
  let manager_config = ConnectionManagerConfig::new()
    .set_number_of_retries(config.retry_budget as usize)
    .set_min_delay(config.retry_min_delay)
    .set_max_delay(config.retry_max_delay)
    .set_exponent_base(2.0)
    .set_response_timeout(Some(config.response_timeout))
    .set_connection_timeout(Some(config.connect_timeout));
  let manager = ConnectionManager::new_with_config(client, manager_config)
    .await
    .map_err(StateError::Redis)?;
  Ok(RedisConn::Single(manager))
}

async fn connect_cluster(config: &RedisConfig, seeds: &[String]) -> Result<RedisConn, StateError> {
  if seeds.is_empty() {
    return Err(StateError::Redis(redis::RedisError::from((
      redis::ErrorKind::InvalidClientConfig,
      "cluster topology requires seed nodes",
    ))));
  }
  let auth = match &config.topology {
    RedisTopology::Cluster { auth, .. } => auth.as_ref().or(config.password.as_ref()),
    _ => config.password.as_ref(),
  };
  let tls = match &config.topology {
    RedisTopology::Cluster { tls, .. } => *tls,
    _ => false,
  };
  let urls: Vec<String> = seeds
    .iter()
    .map(|seed| {
      if seed.contains("://") {
        seed.clone()
      } else {
        format!("redis://{seed}")
      }
    })
    .collect();
  let mut builder = ClusterClientBuilder::new(urls);
  if let Some(password) = auth {
    builder = builder.password(password.expose_secret());
  }
  if tls {
    builder = builder.tls(redis::TlsMode::Secure);
  }
  let client = builder
    .retries(config.retry_budget)
    .connection_timeout(config.connect_timeout)
    .response_timeout(config.response_timeout)
    .build()
    .map_err(StateError::Redis)?;
  let conn = client
    .get_async_connection()
    .await
    .map_err(StateError::Redis)?;
  Ok(RedisConn::Cluster(conn))
}

/// Read one `CONFIG GET <key>` value from the deployment.
async fn config_get(conn: &mut RedisConn, key: &str) -> Result<Option<String>, StateError> {
  let pair: Vec<String> = redis::cmd("CONFIG")
    .arg("GET")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(StateError::Redis)?;
  Ok(pair.into_iter().nth(1))
}

/// Run the config's Redis durability/eviction startup assertions.
async fn assert_contract(conn: &mut RedisConn, config: &RedisConfig) -> Result<(), StateError> {
  let observed = config_get(conn, "maxmemory-policy").await?;
  config
    .assert_noeviction_policy(observed.as_deref().unwrap_or("unknown"))
    .map_err(StateError::Config)?;
  let appendonly = config_get(conn, "appendonly").await?;
  config
    .assert_aof_persistence(appendonly.as_deref() == Some("yes"))
    .map_err(StateError::Config)?;
  Ok(())
}

/// Connect Redis for the configured topology, then prove the deployment is
/// reachable (PING) and contract-compliant (eviction/AOF assertions).
pub async fn connect_redis(config: &RedisConfig) -> Result<RedisConn, StateError> {
  let mut conn = match &config.topology {
    RedisTopology::Single { url } => connect_single(config, url).await?,
    RedisTopology::Sentinel { .. } => RedisConn::Sentinel(SentinelConn::connect(config).await?),
    RedisTopology::Cluster { seeds, .. } => connect_cluster(config, seeds).await?,
  };
  let pong: String = redis::cmd("PING")
    .query_async(&mut conn)
    .await
    .map_err(StateError::Redis)?;
  config
    .assert_topology_reachable(pong == "PONG")
    .map_err(StateError::Config)?;
  assert_contract(&mut conn, config).await?;
  Ok(conn)
}

/// Async-connection timeouts shared by the data paths.
pub fn data_timeouts(config: &RedisConfig) -> AsyncConnectionConfig {
  AsyncConnectionConfig::new()
    .set_connection_timeout(Some(config.connect_timeout))
    .set_response_timeout(Some(config.response_timeout))
}

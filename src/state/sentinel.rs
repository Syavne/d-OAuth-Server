//! Sentinel topology: retained client + cached data connection.
//!
//! redis-rs 1.7 ships no Sentinel connection manager, so [`SentinelConn`]
//! keeps a retained [`SentinelClient`] plus a cached `MultiplexedConnection`
//! and re-resolves the master on failover-class errors (`READONLY`, I/O,
//! `MasterNameNotFoundBySentinel`): the cached connection is dropped and the
//! master re-resolved under a singleflight guard (one concurrent
//! re-resolution; capped backoff from the config's retry knobs). Watchers for
//! `+switch-master` are intentionally NOT subscribed here (no `Stream`
//! combinator dependency in scope); invalidation is purely error-driven,
//! which todo 44 (resilience) may extend with a pro-active watcher.

use std::{fmt, sync::Arc, time::Duration};

use redis::{
  AsyncConnectionConfig, ErrorKind, RedisError, ServerErrorKind,
  aio::MultiplexedConnection,
  sentinel::{SentinelClient, SentinelClientBuilder, SentinelServerType},
};
use secrecy::ExposeSecret;
use tokio::sync::Mutex;

use super::StateError;
use crate::config::RedisConfig;

/// Errors that mean "the master moved": drop the cached connection and
/// re-resolve via Sentinel before retrying once.
pub(super) fn is_failover(error: &RedisError) -> bool {
  matches!(
    error.kind(),
    ErrorKind::Io | ErrorKind::MasterNameNotFoundBySentinel
  ) || matches!(error.kind(), ErrorKind::Server(ServerErrorKind::ReadOnly))
    || error.code() == Some("READONLY")
}

/// Split `host:port` (IPv4/hostname form used by [`RedisConfig`]).
fn split_host_port(node: &str) -> Result<(String, u16), RedisError> {
  let (host, port) = node.rsplit_once(':').unwrap_or(("", ""));
  let port = port.parse::<u16>().map_err(|_| {
    RedisError::from((
      ErrorKind::InvalidClientConfig,
      "invalid sentinel node address",
    ))
  })?;
  if host.trim().is_empty() {
    return Err(RedisError::from((
      ErrorKind::InvalidClientConfig,
      "invalid sentinel node address",
    )));
  }
  Ok((host.to_owned(), port))
}

/// Sentinel-backed data connection with hand-built failover re-resolution.
pub struct SentinelConn {
  /// Retained Sentinel client (guarded: resolution mutates its cursor).
  sentinel: Arc<Mutex<SentinelClient>>,
  /// Cached data connection to the current master.
  conn: Arc<Mutex<MultiplexedConnection>>,
  /// Singleflight guard: at most one concurrent master re-resolution.
  resolving: Arc<Mutex<()>>,
  async_config: AsyncConnectionConfig,
  max_attempts: u32,
  min_delay: Duration,
  max_delay: Duration,
}

impl Clone for SentinelConn {
  fn clone(&self) -> Self {
    Self {
      sentinel: Arc::clone(&self.sentinel),
      conn: Arc::clone(&self.conn),
      resolving: Arc::clone(&self.resolving),
      async_config: self.async_config.clone(),
      max_attempts: self.max_attempts,
      min_delay: self.min_delay,
      max_delay: self.max_delay,
    }
  }
}

impl fmt::Debug for SentinelConn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SentinelConn")
      .field("max_attempts", &self.max_attempts)
      .finish_non_exhaustive()
  }
}

impl SentinelConn {
  /// Resolve the current master via Sentinel and open a data connection.
  pub async fn connect(config: &RedisConfig) -> Result<Self, StateError> {
    let (nodes, master_name) = match &config.topology {
      crate::config::RedisTopology::Sentinel {
        nodes, master_name, ..
      } => (nodes, master_name),
      _ => {
        return Err(StateError::Redis(RedisError::from((
          ErrorKind::InvalidClientConfig,
          "sentinel connect requires the sentinel topology",
        ))));
      }
    };
    if nodes.is_empty() || master_name.trim().is_empty() {
      return Err(StateError::Redis(RedisError::from((
        ErrorKind::InvalidClientConfig,
        "sentinel topology requires nodes and a master name",
      ))));
    }
    let data_password = match &config.topology {
      crate::config::RedisTopology::Sentinel { data_auth, .. } => {
        data_auth.as_ref().or(config.password.as_ref())
      }
      _ => config.password.as_ref(),
    };
    let sentinel_password = match &config.topology {
      crate::config::RedisTopology::Sentinel { sentinel_auth, .. } => {
        sentinel_auth.as_ref().or(config.password.as_ref())
      }
      _ => config.password.as_ref(),
    };
    let tls = match &config.topology {
      crate::config::RedisTopology::Sentinel { tls, .. } => *tls,
      _ => false,
    };
    let mut addrs = Vec::with_capacity(nodes.len());
    for node in nodes {
      let (host, port) = split_host_port(node).map_err(StateError::Redis)?;
      addrs.push(redis::ConnectionAddr::Tcp(host, port));
    }
    let mut builder =
      SentinelClientBuilder::new(addrs, master_name.clone(), SentinelServerType::Master)
        .map_err(StateError::Redis)?;
    if tls {
      builder = builder
        .set_client_to_redis_tls_mode(redis::TlsMode::Secure)
        .set_client_to_sentinel_tls_mode(redis::TlsMode::Secure);
    }
    if let Some(password) = data_password {
      builder = builder.set_client_to_redis_password(password.expose_secret());
    }
    if let Some(password) = sentinel_password {
      builder = builder.set_client_to_sentinel_password(password.expose_secret());
    }
    let sentinel = builder.build().map_err(StateError::Redis)?;
    let async_config = super::redis::data_timeouts(config);
    let sentinel = Arc::new(Mutex::new(sentinel));
    let first = resolve(&sentinel, &async_config)
      .await
      .map_err(StateError::Redis)?;
    let this = Self {
      sentinel,
      conn: Arc::new(Mutex::new(first)),
      resolving: Arc::new(Mutex::new(())),
      async_config,
      max_attempts: config.retry_budget.max(1),
      min_delay: config.retry_min_delay,
      max_delay: config.retry_max_delay,
    };
    Ok(this)
  }

  /// Re-resolve the master under the singleflight guard with capped backoff.
  async fn refresh(&self) -> Result<(), RedisError> {
    let _guard = self.resolving.lock().await;
    let mut delay = self.min_delay;
    let mut attempt: u32 = 0;
    loop {
      match resolve(&self.sentinel, &self.async_config).await {
        Ok(fresh) => {
          *self.conn.lock().await = fresh;
          return Ok(());
        }
        Err(err) if attempt + 1 >= self.max_attempts => return Err(err),
        Err(_) => {
          tokio::time::sleep(delay).await;
          delay = delay
            .checked_mul(2)
            .unwrap_or(self.max_delay)
            .min(self.max_delay);
          attempt += 1;
        }
      }
    }
  }

  /// Run one packed command, refreshing once on a failover-class error.
  pub async fn req_packed(&self, cmd: &redis::Cmd) -> Result<redis::Value, RedisError> {
    use redis::aio::ConnectionLike as _;
    let first = self.conn.lock().await.req_packed_command(cmd).await;
    match first {
      Ok(value) => Ok(value),
      Err(err) if is_failover(&err) => {
        self.refresh().await?;
        self.conn.lock().await.req_packed_command(cmd).await
      }
      Err(err) => Err(err),
    }
  }

  /// Run one packed pipeline, refreshing once on a failover-class error.
  ///
  /// Callers must only send idempotent pipelines (the token-store scripts
  /// are idempotent by the rotation contract), since the retry re-sends.
  pub async fn req_packed_pipeline(
    &self,
    pipeline: &redis::Pipeline,
    offset: usize,
    count: usize,
  ) -> Result<Vec<redis::Value>, RedisError> {
    use redis::aio::ConnectionLike as _;
    let first = self
      .conn
      .lock()
      .await
      .req_packed_commands(pipeline, offset, count)
      .await;
    match first {
      Ok(values) => Ok(values),
      Err(err) if is_failover(&err) => {
        self.refresh().await?;
        self
          .conn
          .lock()
          .await
          .req_packed_commands(pipeline, offset, count)
          .await
      }
      Err(err) => Err(err),
    }
  }
}

/// Ask Sentinel for the current master and open a data connection to it.
async fn resolve(
  sentinel: &Arc<Mutex<SentinelClient>>,
  async_config: &AsyncConnectionConfig,
) -> Result<MultiplexedConnection, RedisError> {
  let master: redis::Client = sentinel.lock().await.async_get_client().await?;
  master
    .get_multiplexed_async_connection_with_config(async_config)
    .await
}

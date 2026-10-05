//! Topology-aware Redis configuration and startup durability assertions.
//!
//! Supports single-node, Sentinel, and Cluster from day one. The durability
//! contract is explicit and topology-consistent:
//!
//! - **Sentinel / Cluster (replicated):** `WAIT` barrier (`DurabilityMode::Wait`)
//!   after the rotation/replay write.
//! - **Single-node:** `WAIT AOF` (`DurabilityMode::WaitAof`) where Redis 7.2+
//!   is available, falling back to instance-wide `appendfsync always`
//!   (`DurabilityMode::AppendFsyncAlways`). `appendfsync` is process-global and
//!   is never applied selectively per write path.
//!
//! The assertion helpers validate observed server values; they never contact a
//! live Redis and so are safe to call during configuration parsing.

use std::{fmt, path::PathBuf, time::Duration};

use secrecy::SecretString;
use serde::Deserialize;

use super::{ConfigError, read_secret_file};

/// Default keyspace prefix for token/grant/code/session state (single-slot).
pub const DEFAULT_TOKEN_KEY_PREFIX: &str = "oauth:{state}:";
/// Default keyspace prefix for rate-limit counters (distributed).
pub const DEFAULT_RATELIMIT_KEY_PREFIX: &str = "oauth:{rl}:";

/// Redis durability mode for the token-state keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum DurabilityMode {
  /// Replicated topologies: AOF `everysec` + a synchronous `WAIT` barrier.
  #[serde(rename = "wait")]
  Wait,
  /// Single-node: local AOF fsync barrier via `WAITAOF`.
  #[serde(rename = "waitaof", alias = "wait_aof")]
  WaitAof,
  /// Single-node fallback: instance-wide `appendfsync always`.
  #[serde(rename = "appendfsync_always", alias = "appendfsync-always")]
  AppendFsyncAlways,
}

/// Redis topology selection.
#[derive(Clone)]
pub enum RedisTopology {
  /// One node addressed by URL.
  Single {
    /// Connection URL (`redis://` or `rediss://`).
    url: SecretString,
  },
  /// Sentinel-managed replication.
  Sentinel {
    /// Sentinel node addresses (`host:port`).
    nodes: Vec<String>,
    /// Monitored master name.
    master_name: String,
    /// Authentication for the Sentinel nodes.
    sentinel_auth: Option<SecretString>,
    /// Authentication for the data node.
    data_auth: Option<SecretString>,
    /// Whether the data connection uses TLS.
    tls: bool,
  },
  /// Native Redis Cluster.
  Cluster {
    /// Seed node addresses (`host:port`).
    seeds: Vec<String>,
    /// Authentication for cluster nodes.
    auth: Option<SecretString>,
    /// Whether cluster connections use TLS.
    tls: bool,
  },
}

impl fmt::Debug for RedisTopology {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Single { url: _ } => f
        .debug_struct("Single")
        .field("url", &"[REDACTED]")
        .finish(),
      Self::Sentinel {
        nodes,
        master_name,
        sentinel_auth,
        data_auth,
        tls,
      } => f
        .debug_struct("Sentinel")
        .field("nodes", nodes)
        .field("master_name", master_name)
        .field(
          "sentinel_auth",
          &sentinel_auth.as_ref().map(|_| "[REDACTED]"),
        )
        .field("data_auth", &data_auth.as_ref().map(|_| "[REDACTED]"))
        .field("tls", tls)
        .finish(),
      Self::Cluster { seeds, auth, tls } => f
        .debug_struct("Cluster")
        .field("seeds", seeds)
        .field("auth", &auth.as_ref().map(|_| "[REDACTED]"))
        .field("tls", tls)
        .finish(),
    }
  }
}

/// Validated Redis configuration.
#[derive(Clone)]
pub struct RedisConfig {
  /// Selected topology.
  pub topology: RedisTopology,
  /// Connection timeout (default 3 s).
  pub connect_timeout: Duration,
  /// Per-command response timeout (default 2 s).
  pub response_timeout: Duration,
  /// Reconnect/retry budget in attempts (default 6).
  pub retry_budget: u32,
  /// Minimum backoff between retries (default 100 ms).
  pub retry_min_delay: Duration,
  /// Maximum backoff between retries (default 5 s).
  pub retry_max_delay: Duration,
  /// Durability contract for the token-state keyspace.
  pub durability: DurabilityMode,
  /// Require `maxmemory-policy noeviction` (default true).
  pub noeviction_required: bool,
  /// Require AOF persistence (default true).
  pub aof_required: bool,
  /// Keyspace prefix for token/grant/code/session state.
  pub token_key_prefix: String,
  /// Keyspace prefix for rate-limit counters (must differ from token prefix).
  pub ratelimit_key_prefix: String,
  /// Root certificate for `rediss://` endpoints.
  pub root_cert_path: Option<PathBuf>,
  /// Optional auth password from a mounted secret file.
  pub password: Option<SecretString>,
}

impl fmt::Debug for RedisConfig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RedisConfig")
      .field("topology", &self.topology)
      .field("connect_timeout", &self.connect_timeout)
      .field("response_timeout", &self.response_timeout)
      .field("retry_budget", &self.retry_budget)
      .field("retry_min_delay", &self.retry_min_delay)
      .field("retry_max_delay", &self.retry_max_delay)
      .field("durability", &self.durability)
      .field("noeviction_required", &self.noeviction_required)
      .field("aof_required", &self.aof_required)
      .field("token_key_prefix", &self.token_key_prefix)
      .field("ratelimit_key_prefix", &self.ratelimit_key_prefix)
      .field("root_cert_path", &self.root_cert_path)
      .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
      .finish()
  }
}

impl RedisConfig {
  pub(crate) fn from_raw(raw: RawRedisConfig) -> Result<Self, ConfigError> {
    let url = raw.url.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let nodes = cleaned(raw.nodes);
    let seeds = cleaned(raw.seeds);
    let is_single = url.is_some() && nodes.is_empty() && seeds.is_empty();
    let is_sentinel = url.is_none() && !nodes.is_empty() && seeds.is_empty();
    let is_cluster = url.is_none() && nodes.is_empty() && !seeds.is_empty();

    let topology = if is_single {
      let url = match url {
        Some(url) => SecretString::from(url.to_owned()),
        None => return Err(ConfigError::RedisTopologyAmbiguous),
      };
      RedisTopology::Single { url }
    } else if is_sentinel {
      let master_name = match raw.master_name.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => return Err(ConfigError::RedisSentinelMissingMaster),
      };
      RedisTopology::Sentinel {
        nodes,
        master_name,
        sentinel_auth: raw.sentinel_auth.map(SecretString::from),
        data_auth: raw.data_auth.map(SecretString::from),
        tls: raw.tls,
      }
    } else if is_cluster {
      RedisTopology::Cluster {
        seeds,
        auth: raw.auth.map(SecretString::from),
        tls: raw.tls,
      }
    } else {
      return Err(ConfigError::RedisTopologyAmbiguous);
    };

    let durability = raw.durability.ok_or(ConfigError::RedisDurabilityContract)?;
    let topology_is_single = matches!(topology, RedisTopology::Single { .. });
    if topology_is_single && durability == DurabilityMode::Wait {
      return Err(ConfigError::RedisDurabilityContract);
    }
    if !topology_is_single && durability != DurabilityMode::Wait {
      return Err(ConfigError::RedisDurabilityContract);
    }

    let token_key_prefix = non_empty_or(raw.token_key_prefix, DEFAULT_TOKEN_KEY_PREFIX);
    let ratelimit_key_prefix = non_empty_or(raw.ratelimit_key_prefix, DEFAULT_RATELIMIT_KEY_PREFIX);
    if token_key_prefix == ratelimit_key_prefix {
      return Err(ConfigError::RedisKeyPrefixConflict);
    }
    if !token_key_prefix.contains("{state}") {
      return Err(ConfigError::RedisTokenPrefixHashTag);
    }
    if !ratelimit_key_prefix.contains("{rl}") {
      return Err(ConfigError::RedisRateLimitPrefixHashTag);
    }

    let password = read_secret_file(raw.password_file.as_deref())?;
    Ok(Self {
      topology,
      connect_timeout: Duration::from_secs(raw.connect_timeout_secs),
      response_timeout: Duration::from_secs(raw.response_timeout_secs),
      retry_budget: raw.retry_budget,
      retry_min_delay: Duration::from_millis(raw.retry_min_delay_ms),
      retry_max_delay: Duration::from_millis(raw.retry_max_delay_ms),
      durability,
      noeviction_required: raw.noeviction_required,
      aof_required: raw.aof_required,
      token_key_prefix,
      ratelimit_key_prefix,
      root_cert_path: raw.root_cert_path,
      password,
    })
  }

  /// Assert the observed `maxmemory-policy` satisfies the contract.
  ///
  /// Callable without a live Redis; invocation occurs at startup (todo 4).
  pub fn assert_noeviction_policy(&self, observed: &str) -> Result<(), ConfigError> {
    if self.noeviction_required && observed != "noeviction" {
      return Err(ConfigError::RedisEvictionPolicy {
        observed: observed.to_owned(),
      });
    }
    Ok(())
  }

  /// Assert AOF persistence is enabled when required.
  pub fn assert_aof_persistence(&self, aof_enabled: bool) -> Result<(), ConfigError> {
    if self.aof_required && !aof_enabled {
      return Err(ConfigError::RedisAofDisabled);
    }
    Ok(())
  }

  /// Assert the configured topology is reachable.
  pub fn assert_topology_reachable(&self, reachable: bool) -> Result<(), ConfigError> {
    if !reachable {
      return Err(ConfigError::RedisUnreachable);
    }
    Ok(())
  }
}

/// Raw `redis` block.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawRedisConfig {
  pub url: Option<String>,
  pub nodes: Vec<String>,
  pub master_name: Option<String>,
  pub sentinel_auth: Option<String>,
  pub data_auth: Option<String>,
  pub seeds: Vec<String>,
  pub auth: Option<String>,
  pub tls: bool,
  pub connect_timeout_secs: u64,
  pub response_timeout_secs: u64,
  pub retry_budget: u32,
  pub retry_min_delay_ms: u64,
  pub retry_max_delay_ms: u64,
  pub durability: Option<DurabilityMode>,
  pub noeviction_required: bool,
  pub aof_required: bool,
  pub token_key_prefix: Option<String>,
  pub ratelimit_key_prefix: Option<String>,
  pub root_cert_path: Option<PathBuf>,
  pub password_file: Option<PathBuf>,
}

impl Default for RawRedisConfig {
  fn default() -> Self {
    Self {
      url: None,
      nodes: Vec::new(),
      master_name: None,
      sentinel_auth: None,
      data_auth: None,
      seeds: Vec::new(),
      auth: None,
      tls: false,
      connect_timeout_secs: 3,
      response_timeout_secs: 2,
      retry_budget: 6,
      retry_min_delay_ms: 100,
      retry_max_delay_ms: 5_000,
      durability: None,
      noeviction_required: true,
      aof_required: true,
      token_key_prefix: None,
      ratelimit_key_prefix: None,
      root_cert_path: None,
      password_file: None,
    }
  }
}

fn cleaned(items: Vec<String>) -> Vec<String> {
  items
    .into_iter()
    .map(|s| s.trim().to_owned())
    .filter(|s| !s.is_empty())
    .collect()
}

fn non_empty_or(value: Option<String>, fallback: &str) -> String {
  match value {
    Some(value) if !value.trim().is_empty() => value,
    _ => fallback.to_owned(),
  }
}

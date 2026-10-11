//! Validated server configuration and optional scope registry.
//!
//! Loads env + optional YAML via the `config` crate: issuer, bind/health
//! addresses, TLS and CA paths, Postgres/Redis connection blocks, failure
//! policy, versioned key ids, TTLs, Argon2 params, cookie/CORS knobs,
//! rate-limit knobs, and the optional declarative `scope_registry`.
//!
//! Validation is fail-fast: an insecure issuer, a missing token pepper, a
//! Postgres URL without `sslmode=verify-full`, a Redis deployment without its
//! no-eviction/AOF durability contract, or an invalid timeout ladder is
//! rejected at load time ([`ConfigError`]). The [`Config`] `Debug` impl never
//! prints secret values.
//!
//! The `scope_registry` is an **optional declarative input** (default empty,
//! never required non-empty) applied only by `config sync`. The runtime source
//! of truth for `scopes_supported` remains the enabled `scopes` table.

use std::{
  fmt,
  net::SocketAddr,
  path::{Path, PathBuf},
};

use secrecy::SecretString;
use thiserror::Error;

use crate::keys::KeyRing;

mod build;
pub mod db;
pub mod policy;
mod raw;
pub mod redis;
pub mod scope;
#[cfg(test)]
mod tests;
pub mod types;

use raw::RawConfig;

pub use db::DbConfig;
pub use policy::{FailMode, FailurePolicy, RetryableClass};
pub use redis::{DurabilityMode, RedisConfig, RedisTopology};
pub use scope::{ClientClass, GrantKind, ScopeDefinition, TokenExchangeRule};
pub use types::{
  Argon2Params, DcrRedirectPolicy, Environment, RateLimitConfig, TrustedProxyNet, TtlConfig,
};

/// Environment-variable prefix for layered settings (`D_OAUTH_*`).
pub const ENV_PREFIX: &str = "D_OAUTH";
/// Environment variable naming an optional YAML/TOML config file.
pub const ENV_CONFIG_FILE: &str = "D_OAUTH_CONFIG";

/// TLS material paths (public listener) and the client-CA trust bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
  /// PEM certificate chain path.
  pub cert_path: PathBuf,
  /// PEM private-key path.
  pub key_path: PathBuf,
  /// Optional client-CA bundle used to verify mTLS peer chains.
  pub client_ca_path: Option<PathBuf>,
}

/// Fully validated runtime configuration.
pub struct Config {
  /// Public issuer URL (absolute `https`, no trailing slash).
  pub issuer: String,
  /// Public TLS listener address (default `0.0.0.0:8080`).
  pub bind_addr: SocketAddr,
  /// Plaintext pod-IP health listener address (default `0.0.0.0:8081`).
  pub health_addr: SocketAddr,
  /// Runtime environment.
  pub environment: Environment,
  /// TLS material and client-CA bundle.
  pub tls: TlsConfig,
  /// Postgres connection and pool settings.
  pub database: DbConfig,
  /// Redis topology and durability settings.
  pub redis: RedisConfig,
  /// Versioned token-pepper and TOTP-encryption keys.
  pub keys: KeyRing,
  /// Write PII plaintext alongside ciphertext during the rotation window
  /// (default false: encrypt-only).
  pub pii_dual_write: bool,
  /// Per-endpoint failure policy.
  pub failure_policy: FailurePolicy,
  /// Token/request lifetimes.
  pub ttl: TtlConfig,
  /// Argon2id parameters.
  pub argon2: Argon2Params,
  /// Rate-limit knobs.
  pub rate_limit: RateLimitConfig,
  /// Cookie domain (default: host-only).
  pub cookie_domain: Option<String>,
  /// Whether cookies carry the `Secure` attribute (default true).
  pub cookie_secure: bool,
  /// Whether unauthenticated dynamic registration is allowed (default false).
  pub allow_open_registration: bool,
  /// DCR redirect-URI policy (default [`DcrRedirectPolicy::Catalog`]).
  pub dcr_redirect_policy: DcrRedirectPolicy,
  /// Explicit CORS origin allowlist (default empty; no wildcard).
  pub cors_allowed_origins: Vec<String>,
  /// Optional declarative scope registry (default empty).
  pub scope_registry: Vec<ScopeDefinition>,
  /// Whether the token-exchange grant is enabled (default false).
  pub allow_token_exchange: bool,
  /// Explicit `(caller, subject, scopes)` allowlist for token exchange.
  pub token_exchange_allowlist: Vec<TokenExchangeRule>,
}

impl fmt::Debug for Config {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Config")
      .field("issuer", &self.issuer)
      .field("bind_addr", &self.bind_addr)
      .field("health_addr", &self.health_addr)
      .field("environment", &self.environment)
      .field("tls", &self.tls)
      .field("database", &self.database)
      .field("redis", &self.redis)
      .field("keys", &self.keys)
      .field("pii_dual_write", &self.pii_dual_write)
      .field("failure_policy", &self.failure_policy)
      .field("ttl", &self.ttl)
      .field("argon2", &self.argon2)
      .field("rate_limit", &self.rate_limit)
      .field("cookie_domain", &self.cookie_domain)
      .field("cookie_secure", &self.cookie_secure)
      .field("allow_open_registration", &self.allow_open_registration)
      .field("dcr_redirect_policy", &self.dcr_redirect_policy)
      .field("cors_allowed_origins", &self.cors_allowed_origins)
      .field("scope_registry_len", &self.scope_registry.len())
      .field("allow_token_exchange", &self.allow_token_exchange)
      .field(
        "token_exchange_allowlist_len",
        &self.token_exchange_allowlist.len(),
      )
      .finish_non_exhaustive()
  }
}

impl Config {
  /// Load configuration from `D_OAUTH_*` env vars plus an optional
  /// `D_OAUTH_CONFIG` file, then validate it.
  pub fn load() -> Result<Self, ConfigError> {
    let mut builder = ::config::Config::builder().add_source(env_source());
    if let Some(path) = std::env::var(ENV_CONFIG_FILE)
      .ok()
      .filter(|p| !p.is_empty())
    {
      builder = builder.add_source(::config::File::with_name(&path).required(false));
    }
    // Conventional mounted-secret env vars override file paths when present.
    for (env_var, key) in [
      ("DATABASE_PASSWORD_FILE", "database.password_file"),
      ("REDIS_PASSWORD_FILE", "redis.password_file"),
    ] {
      if let Some(path) = std::env::var(env_var).ok().filter(|p| !p.is_empty()) {
        builder = builder.set_override(key, path)?;
      }
    }
    Self::from_source(builder.build()?)
  }

  /// Alias for [`Config::load`].
  pub fn from_env() -> Result<Self, ConfigError> {
    Self::load()
  }

  /// Validate an already-assembled `config::Config` source.
  pub fn from_source(source: ::config::Config) -> Result<Self, ConfigError> {
    let raw: RawConfig = source.try_deserialize()?;
    Self::build(raw)
  }
}

/// Layered `D_OAUTH_*` environment source: `__` nests, single `_` stays
/// inside a snake_case key.
pub(crate) fn env_source() -> ::config::Environment {
  ::config::Environment::default()
    .prefix(ENV_PREFIX)
    .prefix_separator("_")
    .separator("__")
    .convert_case(::config::Case::Snake)
    .try_parsing(true)
}

/// Deserialize a string list that arrives as a real sequence from a file or
/// as a single string from `D_OAUTH_*` env vars (config-rs 0.15 keeps env
/// values as strings: only bool/int/float are coerced, never arrays). A
/// string starting with `[` parses as a JSON array (fail-closed on malformed
/// JSON); any other string splits on `,` with surrounding whitespace trimmed
/// and empty items dropped, so `10.0.0.5` and `a,b` both load. Blank strings
/// load as empty.
pub(crate) fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct StringOrVec;
  impl<'de> serde::de::Visitor<'de> for StringOrVec {
    type Value = Vec<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str("a string list or a JSON array string")
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Vec<String>, E> {
      Ok(Vec::new())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Vec<String>, E> {
      Ok(Vec::new())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
      let mut items = Vec::new();
      while let Some(item) = seq.next_element::<String>()? {
        items.push(item);
      }
      Ok(items)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Vec<String>, E> {
      parse_env_string_list(value).map_err(serde::de::Error::custom)
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Vec<String>, E> {
      parse_env_string_list(&value).map_err(serde::de::Error::custom)
    }
  }
  deserializer.deserialize_any(StringOrVec)
}

/// Split an env-provided string list: JSON array when it starts with `[`
/// (malformed JSON is an error, never a silent empty), otherwise
/// comma-separated with trimming.
fn parse_env_string_list(value: &str) -> Result<Vec<String>, String> {
  let trimmed = value.trim();
  if trimmed.is_empty() {
    return Ok(Vec::new());
  }
  if trimmed.starts_with('[') {
    return serde_json::from_str::<Vec<String>>(trimmed)
      .map_err(|err| format!("invalid string list {value:?}: {err}"));
  }
  Ok(
    trimmed
      .split(',')
      .map(str::trim)
      .filter(|item| !item.is_empty())
      .map(str::to_owned)
      .collect(),
  )
}

/// Configuration loading/validation failures.
#[derive(Debug, Error)]
pub enum ConfigError {
  /// The layered configuration source could not be read or deserialized.
  #[error("configuration source error: {0}")]
  Source(#[from] ::config::ConfigError),
  /// `issuer` was absent.
  #[error("issuer is required")]
  MissingIssuer,
  /// `issuer` was not an absolute `https` URL without a trailing slash.
  #[error("issuer must be absolute https without a trailing slash: {issuer}")]
  InsecureIssuer {
    /// The rejected value.
    issuer: String,
  },
  /// `bind_addr` was not a valid socket address.
  #[error("invalid bind address: {value}")]
  InvalidBindAddr {
    /// The rejected value.
    value: String,
  },
  /// `health_addr` was not a valid socket address.
  #[error("invalid health address: {value}")]
  InvalidHealthAddr {
    /// The rejected value.
    value: String,
  },
  /// The TLS certificate path was absent.
  #[error("tls cert_path is required")]
  MissingTlsCert,
  /// The TLS private-key path was absent.
  #[error("tls key_path is required")]
  MissingTlsKey,
  /// `database.url` was absent.
  #[error("database url is required")]
  MissingDatabaseUrl,
  /// A production Postgres URL lacked `sslmode=verify-full`.
  #[error("production database url must include sslmode=verify-full")]
  InsecureDatabaseTls,
  /// The pool min/max bounds were inconsistent.
  #[error("database pool min ({min}) must not exceed max ({max}) and max must be > 0")]
  InvalidPoolBounds {
    /// Configured minimum.
    min: u32,
    /// Configured maximum.
    max: u32,
  },
  /// The Redis no-eviction/AOF durability contract was absent or inconsistent.
  #[error("redis durability contract (noeviction + AOF) is required and must match the topology")]
  RedisDurabilityContract,
  /// The token and rate-limit key prefixes were identical.
  #[error("redis token and rate-limit key prefixes must differ")]
  RedisKeyPrefixConflict,
  /// The token key prefix lacked the `{state}` hash tag.
  #[error("redis token key prefix must contain the {{state}} hash tag")]
  RedisTokenPrefixHashTag,
  /// The rate-limit key prefix lacked the `{rl}` hash tag.
  #[error("redis rate-limit key prefix must contain the {{rl}} hash tag")]
  RedisRateLimitPrefixHashTag,
  /// The Redis topology could not be determined unambiguously.
  #[error("redis topology is ambiguous or missing (set exactly one of url/nodes/seeds)")]
  RedisTopologyAmbiguous,
  /// The Sentinel topology lacked a `master_name`.
  #[error("redis sentinel topology requires master_name")]
  RedisSentinelMissingMaster,
  /// The observed eviction policy violated the contract.
  #[error("redis maxmemory-policy must be noeviction (observed: {observed})")]
  RedisEvictionPolicy {
    /// The observed policy.
    observed: String,
  },
  /// AOF persistence was disabled while required.
  #[error("redis AOF persistence must be enabled")]
  RedisAofDisabled,
  /// The Redis topology was unreachable.
  #[error("redis topology is unreachable")]
  RedisUnreachable,
  /// The timeout ladder was invalid.
  #[error("invalid timeout ladder (require lock < statement <= acquire < request)")]
  InvalidTimeoutLadder,
  /// A scope name violated the scope-token grammar.
  #[error("invalid scope name: {name}")]
  InvalidScopeName {
    /// The rejected name.
    name: String,
  },
  /// The reserved `openid` scope was declared.
  #[error("reserved scope is not allowed: {name}")]
  ReservedScope {
    /// The reserved name.
    name: String,
  },
  /// A scope-registry or exchange rule was malformed.
  #[error("invalid scope-registry entry: {reason}")]
  InvalidScopeRegistry {
    /// Why the entry was rejected.
    reason: String,
  },
  /// A security endpoint was configured to fail open.
  #[error("fail-open is not permitted on security endpoint: {endpoint}")]
  FailOpenOnSecurityPath {
    /// The offending endpoint.
    endpoint: String,
  },
  /// A resolved master key was shorter than the required 32 bytes.
  #[error("key material for {key} must be at least 32 bytes")]
  WeakKeyMaterial {
    /// The configuration key that carried the weak material.
    key: &'static str,
  },
  /// Argon2 parameters were outside the safe range.
  #[error("invalid argon2 parameters")]
  InvalidArgon2Params,
  /// The rate-limit window was zero.
  #[error("invalid rate-limit window")]
  InvalidRateLimit,
  /// A `rate_limit.trusted_proxies` entry was not an exact IP or a valid
  /// CIDR, was a trust-everything `/0`, or the allowlist exceeded its bound.
  #[error("invalid trusted proxy entry: {value}")]
  InvalidTrustedProxy {
    /// The rejected value.
    value: String,
  },
  /// A TTL was zero.
  #[error("invalid token TTL: every lifetime must be non-zero")]
  InvalidTtl,
  /// The access-token lifetime exceeded the refresh-token lifetime.
  #[error("invalid token TTL: access lifetime must not exceed the refresh lifetime")]
  InvalidTtlLadder,
  /// A mounted secret file could not be read.
  #[error("failed to read secret file {path}: {source}")]
  SecretFile {
    /// The file path.
    path: PathBuf,
    /// The underlying I/O error.
    #[source]
    source: std::io::Error,
  },
  /// The key ring could not be constructed.
  #[error("key ring error: {0}")]
  KeyRing(#[from] crate::keys::KeyRingError),
  /// A retained (`*_previous_key`) key was provided without an explicit
  /// distinct previous key id.
  #[error("previous key requires an explicit distinct previous key id")]
  MissingPreviousKeyId,
  /// A key id contained characters outside `[A-Za-z0-9_-]`.
  #[error("invalid key id: {id}")]
  InvalidKeyId {
    /// The rejected value.
    id: String,
  },
  /// Production was configured without the `Secure` session-cookie
  /// attribute (`cookie_secure = false` is a development-only exception).
  #[error("production requires the Secure session-cookie attribute")]
  InsecureSessionCookie,
  /// `cookie_domain` was set: any non-blank value is rejected as
  /// incompatible with the `__Host-` session-cookie prefix (which forbids
  /// `Domain`; sessions stay host-only by design).
  #[error("invalid cookie domain: {value}")]
  InvalidCookieDomain {
    /// The rejected value.
    value: String,
  },
}

/// Read an optional secret from a mounted file, trimming trailing newlines.
pub(crate) fn read_secret_file(path: Option<&Path>) -> Result<Option<SecretString>, ConfigError> {
  match path {
    None => Ok(None),
    Some(path) => {
      let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::SecretFile {
        path: path.to_path_buf(),
        source,
      })?;
      Ok(Some(SecretString::from(
        contents.trim_end_matches(['\r', '\n']).to_owned(),
      )))
    }
  }
}

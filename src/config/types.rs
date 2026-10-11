//! Validated value types for TTLs, Argon2, rate limits, and scopes.
//!
//! Each type is produced from a permissive `Raw*` serde struct whose defaults
//! encode the plan's adopted defaults; conversion to the validated type
//! performs the fail-fast checks and returns [`ConfigError`](super::ConfigError).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

use super::ConfigError;

/// Runtime environment; production enables the strict validation paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
  /// Production: strict TLS and durability contracts are enforced.
  #[default]
  Production,
  /// Development: localhost conveniences (non-verify-full DB, plaintext) allowed.
  Development,
}

impl Environment {
  /// Whether this is the production environment.
  #[must_use]
  pub fn is_production(self) -> bool {
    matches!(self, Self::Production)
  }
}

/// Dynamic client registration redirect-URI policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrRedirectPolicy {
  /// Only URIs present in the runtime catalog may be registered (default).
  #[default]
  Catalog,
  /// Catalog URIs plus dynamic loopback URIs (RFC 8252).
  CatalogLoopback,
  /// Any URI may be registered (explicitly opted in; not the default).
  Open,
}

/// All token/request lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlConfig {
  /// Access-token lifetime (default 300 s).
  pub access: Duration,
  /// Refresh-token lifetime (default 2 592 000 s = 30 d).
  pub refresh: Duration,
  /// Authorization-code lifetime (default 60 s).
  pub code: Duration,
  /// PAR `request_uri` lifetime (default 90 s).
  pub par: Duration,
  /// Device-code lifetime (default 600 s).
  pub device: Duration,
  /// DCR initial-access-token lifetime (default 86 400 s = 24 h).
  pub dcr_initial_access: Duration,
  /// Server-side session lifetime (default 43 200 s = 12 h).
  pub session: Duration,
}

impl Default for TtlConfig {
  fn default() -> Self {
    Self {
      access: Duration::from_secs(300),
      refresh: Duration::from_secs(2_592_000),
      code: Duration::from_secs(60),
      par: Duration::from_secs(90),
      device: Duration::from_secs(600),
      dcr_initial_access: Duration::from_secs(86_400),
      session: Duration::from_secs(43_200),
    }
  }
}

impl TtlConfig {
  pub(crate) fn from_raw(raw: RawTtlConfig) -> Result<Self, ConfigError> {
    let ttl = Self {
      access: Duration::from_secs(raw.access_secs),
      refresh: Duration::from_secs(raw.refresh_secs),
      code: Duration::from_secs(raw.code_secs),
      par: Duration::from_secs(raw.par_secs),
      device: Duration::from_secs(raw.device_secs),
      dcr_initial_access: Duration::from_secs(raw.dcr_initial_access_secs),
      session: Duration::from_secs(raw.session_secs),
    };
    if [
      ttl.access,
      ttl.refresh,
      ttl.code,
      ttl.par,
      ttl.device,
      ttl.dcr_initial_access,
      ttl.session,
    ]
    .iter()
    .any(|d| d.is_zero())
    {
      return Err(ConfigError::InvalidTtl);
    }
    if ttl.access > ttl.refresh {
      return Err(ConfigError::InvalidTtlLadder);
    }
    Ok(ttl)
  }
}

/// Raw TTL durations in seconds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawTtlConfig {
  pub access_secs: u64,
  pub refresh_secs: u64,
  pub code_secs: u64,
  pub par_secs: u64,
  pub device_secs: u64,
  pub dcr_initial_access_secs: u64,
  pub session_secs: u64,
}

impl Default for RawTtlConfig {
  fn default() -> Self {
    let ttl = TtlConfig::default();
    Self {
      access_secs: ttl.access.as_secs(),
      refresh_secs: ttl.refresh.as_secs(),
      code_secs: ttl.code.as_secs(),
      par_secs: ttl.par.as_secs(),
      device_secs: ttl.device.as_secs(),
      dcr_initial_access_secs: ttl.dcr_initial_access.as_secs(),
      session_secs: ttl.session.as_secs(),
    }
  }
}

/// Argon2id parameters for password and client-secret hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
  /// Memory cost in KiB (default 19 456 = 19 MiB).
  pub memory_kib: u32,
  /// Iteration (time) cost (default 2).
  pub iterations: u32,
  /// Degree of parallelism (default 1).
  pub parallelism: u32,
}

impl Default for Argon2Params {
  fn default() -> Self {
    Self {
      memory_kib: 19_456,
      iterations: 2,
      parallelism: 1,
    }
  }
}

impl Argon2Params {
  pub(crate) fn from_raw(raw: RawArgon2) -> Result<Self, ConfigError> {
    let params = Self {
      memory_kib: raw.memory_kib,
      iterations: raw.iterations,
      parallelism: raw.parallelism,
    };
    if params.memory_kib < 8_192 || params.iterations == 0 || params.parallelism == 0 {
      return Err(ConfigError::InvalidArgon2Params);
    }
    Ok(params)
  }
}

/// Raw Argon2 parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawArgon2 {
  pub memory_kib: u32,
  pub iterations: u32,
  pub parallelism: u32,
}

impl Default for RawArgon2 {
  fn default() -> Self {
    let p = Argon2Params::default();
    Self {
      memory_kib: p.memory_kib,
      iterations: p.iterations,
      parallelism: p.parallelism,
    }
  }
}

/// Rate-limit knobs; counters live in Redis under the rate-limit key prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
  /// Whether rate limiting is enforced.
  pub enabled: bool,
  /// Window length for every counter.
  pub window: Duration,
  /// Per-client-IP request budget per window.
  pub per_ip: u32,
  /// Per-client request budget per window.
  pub per_client: u32,
  /// Per-client-IP login-attempt budget per window.
  pub login_per_ip: u32,
  /// Per-client token-request budget per window.
  pub token_per_client: u32,
  /// TCP peers whose `X-Forwarded-For` is honored for rate-limit IP
  /// attribution (default empty: headers are never honored). Each entry is an
  /// exact IP or a CIDR. This trust is narrowly scoped to rate-limit bucket
  /// selection only: it never authenticates a client and never carries a
  /// client certificate (mTLS still requires L4/TCP passthrough).
  pub trusted_proxies: Vec<TrustedProxyNet>,
}

impl Default for RateLimitConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      window: Duration::from_secs(60),
      per_ip: 120,
      per_client: 300,
      login_per_ip: 20,
      token_per_client: 60,
      trusted_proxies: Vec::new(),
    }
  }
}

impl RateLimitConfig {
  pub(crate) fn from_raw(raw: RawRateLimit) -> Result<Self, ConfigError> {
    if raw.window_secs == 0 {
      return Err(ConfigError::InvalidRateLimit);
    }
    if raw.trusted_proxies.len() > MAX_TRUSTED_PROXIES {
      return Err(ConfigError::InvalidTrustedProxy {
        value: format!("allowlist exceeds {MAX_TRUSTED_PROXIES} entries"),
      });
    }
    let trusted_proxies = raw
      .trusted_proxies
      .iter()
      .map(|entry| TrustedProxyNet::from_str(entry))
      .collect::<Result<Vec<_>, _>>()?;
    Ok(Self {
      enabled: raw.enabled,
      window: Duration::from_secs(raw.window_secs),
      per_ip: raw.per_ip,
      per_client: raw.per_client,
      login_per_ip: raw.login_per_ip,
      token_per_client: raw.token_per_client,
      trusted_proxies,
    })
  }
}

/// Raw rate-limit knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawRateLimit {
  pub enabled: bool,
  pub window_secs: u64,
  pub per_ip: u32,
  pub per_client: u32,
  pub login_per_ip: u32,
  pub token_per_client: u32,
  #[serde(default, deserialize_with = "crate::config::deserialize_string_or_vec")]
  pub trusted_proxies: Vec<String>,
}

impl Default for RawRateLimit {
  fn default() -> Self {
    let r = RateLimitConfig::default();
    Self {
      enabled: r.enabled,
      window_secs: r.window.as_secs(),
      per_ip: r.per_ip,
      per_client: r.per_client,
      login_per_ip: r.login_per_ip,
      token_per_client: r.token_per_client,
      trusted_proxies: Vec::new(),
    }
  }
}

/// Bound on the trusted-proxy allowlist: the limiter scans it once per
/// request, so an unbounded list would be a per-request cost the operator did
/// not intend.
const MAX_TRUSTED_PROXIES: usize = 64;

/// One trusted-proxy allowlist entry: an exact IP or a masked CIDR base.
///
/// Parsed with [`FromStr`] (`"10.0.0.1"`, `"10.0.0.0/8"`,
/// `"2001:db8::/32"`); a bare IP is a host route. A `/0` prefix would trust
/// every peer and is rejected, as is any malformed entry or out-of-range
/// prefix length — all fail the config load via
/// [`ConfigError::InvalidTrustedProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyNet {
  network: IpAddr,
  prefix_len: u8,
}

impl TrustedProxyNet {
  /// Whether `ip` falls inside this entry (family mismatch never matches).
  #[must_use]
  pub fn contains(self, ip: IpAddr) -> bool {
    match (self.network, ip) {
      (IpAddr::V4(net), IpAddr::V4(addr)) => {
        masked_v4(net, self.prefix_len) == masked_v4(addr, self.prefix_len)
      }
      (IpAddr::V6(net), IpAddr::V6(addr)) => {
        masked_v6(net, self.prefix_len) == masked_v6(addr, self.prefix_len)
      }
      _ => false,
    }
  }
}

impl FromStr for TrustedProxyNet {
  type Err = ConfigError;

  fn from_str(raw: &str) -> Result<Self, Self::Err> {
    let invalid = |value: &str| ConfigError::InvalidTrustedProxy {
      value: value.to_owned(),
    };
    let entry = raw.trim();
    if entry.is_empty() {
      return Err(invalid(raw));
    }
    let (addr_text, prefix_len) = match entry.split_once('/') {
      Some((addr_text, prefix_text)) => {
        let max = if addr_text.contains(':') { 128 } else { 32 };
        let prefix_len: u8 = prefix_text.trim().parse().map_err(|_| invalid(raw))?;
        if prefix_len == 0 || prefix_len > max {
          return Err(invalid(raw));
        }
        (addr_text.trim(), prefix_len)
      }
      None => {
        let max = if entry.contains(':') { 128 } else { 32 };
        (entry, max)
      }
    };
    let addr: IpAddr = addr_text.parse().map_err(|_| invalid(raw))?;
    let network = match addr {
      IpAddr::V4(base) => IpAddr::V4(masked_v4(base, prefix_len)),
      IpAddr::V6(base) => IpAddr::V6(masked_v6(base, prefix_len)),
    };
    Ok(Self {
      network,
      prefix_len,
    })
  }
}

/// The network base with the host bits beyond `prefix_len` cleared.
/// `prefix_len` is at most 32 here (enforced by [`FromStr`]).
fn masked_v4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
  let bits = u32::from(addr);
  let mask = u32::MAX
    .checked_shl(32 - u32::from(prefix_len))
    .unwrap_or(0);
  Ipv4Addr::from(bits & mask)
}

/// The network base with the host bits beyond `prefix_len` cleared.
/// `prefix_len` is at most 128 here (enforced by [`FromStr`]).
fn masked_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
  let bits = u128::from(addr);
  let mask = u128::MAX
    .checked_shl(128 - u32::from(prefix_len))
    .unwrap_or(0);
  Ipv6Addr::from(bits & mask)
}

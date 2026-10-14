//! Construction and cross-field validation of [`Config`] from raw input.
//!
//! Kept in a submodule so the root `config.rs` stays focused on the public
//! types and loader surface.

use std::{net::SocketAddr, path::Path, str::FromStr};

use secrecy::{ExposeSecret, SecretString};

use super::{
  Config, ConfigError, TlsConfig,
  db::DbConfig,
  policy::FailurePolicy,
  raw::{RawConfig, RawTls},
  read_secret_file,
  redis::RedisConfig,
  scope::{ScopeDefinition, TokenExchangeRule},
  types::{Argon2Params, RateLimitConfig, TtlConfig},
};
use crate::keys::{KeyId, KeyRing, KeyRingError};

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:8081";
const DEFAULT_KEY_ID: &str = "v1";

impl Config {
  pub(crate) fn build(raw: RawConfig) -> Result<Self, ConfigError> {
    let environment = raw.environment;
    let issuer = parse_issuer(raw.issuer.as_deref())?;
    let bind_addr = parse_socket_addr(raw.bind_addr.as_deref(), DEFAULT_BIND_ADDR, |value| {
      ConfigError::InvalidBindAddr { value }
    })?;
    let health_addr =
      parse_socket_addr(raw.health_addr.as_deref(), DEFAULT_HEALTH_ADDR, |value| {
        ConfigError::InvalidHealthAddr { value }
      })?;
    let tls = TlsConfig::from_raw(&raw.tls)?;
    let keys = build_key_ring(&raw)?;
    let database = DbConfig::from_raw(raw.database, environment)?;
    let redis = RedisConfig::from_raw(raw.redis)?;
    let failure_policy = FailurePolicy::from_raw(raw.failure_policy)?;
    validate_timeout_ladder(&database, &failure_policy)?;
    let ttl = TtlConfig::from_raw(raw.ttl)?;
    let argon2 = Argon2Params::from_raw(raw.argon2)?;
    let rate_limit = RateLimitConfig::from_raw(raw.rate_limit)?;
    let scope_registry = raw
      .scope_registry
      .into_iter()
      .map(ScopeDefinition::from_raw)
      .collect::<Result<Vec<_>, _>>()?;
    let cookie_secure = raw.cookie_secure.unwrap_or(true);
    if environment.is_production() && !cookie_secure {
      return Err(ConfigError::InsecureSessionCookie);
    }
    let cookie_domain = validate_cookie_domain(raw.cookie_domain)?;
    let token_exchange_allowlist = raw
      .token_exchange_allowlist
      .into_iter()
      .map(TokenExchangeRule::from_raw)
      .collect::<Result<Vec<_>, _>>()?;

    Ok(Self {
      issuer,
      bind_addr,
      health_addr,
      environment,
      tls,
      database,
      redis,
      keys,
      failure_policy,
      ttl,
      argon2,
      rate_limit,
      cookie_domain,
      cookie_secure,
      allow_open_registration: raw.allow_open_registration,
      pii_dual_write: raw.pii_dual_write,
      dcr_redirect_policy: raw.dcr_redirect_policy,
      cors_allowed_origins: raw.cors_allowed_origins,
      scope_registry,
      allow_token_exchange: raw.allow_token_exchange,
      token_exchange_allowlist,
    })
  }
}

impl TlsConfig {
  fn from_raw(raw: &RawTls) -> Result<Self, ConfigError> {
    Ok(Self {
      cert_path: raw.cert_path.clone().ok_or(ConfigError::MissingTlsCert)?,
      key_path: raw.key_path.clone().ok_or(ConfigError::MissingTlsKey)?,
      client_ca_path: raw.client_ca_path.clone(),
    })
  }
}

fn parse_issuer(raw: Option<&str>) -> Result<String, ConfigError> {
  let issuer = raw
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .ok_or(ConfigError::MissingIssuer)?;
  if !issuer.starts_with("https://") || issuer.ends_with('/') {
    return Err(ConfigError::InsecureIssuer {
      issuer: issuer.to_owned(),
    });
  }
  let authority = issuer.get("https://".len()..).unwrap_or_default();
  if authority.is_empty() || authority.contains(char::is_whitespace) {
    return Err(ConfigError::InsecureIssuer {
      issuer: issuer.to_owned(),
    });
  }
  Ok(issuer.to_owned())
}

fn parse_socket_addr<F>(
  raw: Option<&str>,
  default: &str,
  invalid: F,
) -> Result<SocketAddr, ConfigError>
where
  F: FnOnce(String) -> ConfigError,
{
  let value = raw
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .unwrap_or(default);
  SocketAddr::from_str(value).map_err(|_| invalid(value.to_owned()))
}

/// Master keys must carry at least 256 bits of material.
const MIN_KEY_BYTES: usize = 32;

/// Reject a resolved key shorter than [`MIN_KEY_BYTES`]. `None` (no key
/// configured) passes through: the key-ring chain builder reports a missing
/// active key as its own error.
fn require_min_key_bytes(
  secret: Option<SecretString>,
  key: &'static str,
) -> Result<Option<SecretString>, ConfigError> {
  match secret {
    Some(secret) if secret.expose_secret().len() < MIN_KEY_BYTES => {
      Err(ConfigError::WeakKeyMaterial { key })
    }
    other => Ok(other),
  }
}

fn build_key_ring(raw: &RawConfig) -> Result<KeyRing, ConfigError> {
  let pepper = require_min_key_bytes(
    resolve_secret(
      raw.token_pepper.as_deref(),
      raw.token_pepper_file.as_deref(),
    )?,
    "token_pepper",
  )?;
  let totp = require_min_key_bytes(
    resolve_secret(
      raw.totp_encryption_key.as_deref(),
      raw.totp_encryption_key_file.as_deref(),
    )?,
    "totp_encryption_key",
  )?;
  let pii = require_min_key_bytes(
    non_blank(resolve_secret(
      raw.pii_encryption_key.as_deref(),
      raw.pii_encryption_key_file.as_deref(),
    )?),
    "pii_encryption_key",
  )?;
  let totp_previous = require_min_key_bytes(
    non_blank(resolve_secret(
      raw.totp_previous_key.as_deref(),
      raw.totp_previous_key_file.as_deref(),
    )?),
    "totp_previous_key",
  )?;
  let pii_previous = require_min_key_bytes(
    non_blank(resolve_secret(
      raw.pii_previous_key.as_deref(),
      raw.pii_previous_key_file.as_deref(),
    )?),
    "pii_previous_key",
  )?;
  let pepper_previous = require_min_key_bytes(
    non_blank(resolve_secret(
      raw.token_pepper_previous_key.as_deref(),
      raw.token_pepper_previous_key_file.as_deref(),
    )?),
    "token_pepper_previous_key",
  )?;
  let pepper_id = key_id_or_default(raw.token_pepper_id.as_deref())?;
  let totp_id = key_id_or_default(raw.totp_key_id.as_deref())?;
  let pii_id = key_id_or_default(raw.pii_key_id.as_deref())?;
  let peppers = active_first_chain(
    pepper.map(|secret| (pepper_id, secret)),
    raw.token_pepper_previous_key_id.as_deref(),
    pepper_previous,
    KeyRingError::MissingTokenPepper,
  )?;
  let totp_keys = active_first_chain(
    totp.map(|secret| (totp_id, secret)),
    raw.totp_previous_key_id.as_deref(),
    totp_previous,
    KeyRingError::MissingTotpKey,
  )?;
  let pii_keys = active_first_chain(
    pii.map(|secret| (pii_id, secret)),
    raw.pii_previous_key_id.as_deref(),
    pii_previous,
    KeyRingError::MissingPiiKey,
  )?;
  KeyRing::from_parts(peppers, totp_keys, pii_keys).map_err(ConfigError::from)
}

/// Build an active-first chain from the active key plus its retained previous
/// key. A missing active key with no previous key yields an empty chain (the
/// caller maps it to `missing_active`); a previous key without its active key
/// (R2) or without an explicit distinct id (R1) is rejected here so a retained
/// key can never silently become active.
fn active_first_chain(
  active: Option<(KeyId, SecretString)>,
  previous_id_raw: Option<&str>,
  previous: Option<SecretString>,
  missing_active: KeyRingError,
) -> Result<Vec<(KeyId, SecretString)>, ConfigError> {
  match (active, previous) {
    (None, None) => Ok(Vec::new()),
    (Some(pair), None) => Ok(vec![pair]),
    (None, Some(_)) => Err(ConfigError::KeyRing(missing_active)),
    (Some(active_pair), Some(previous_secret)) => {
      let id_raw = previous_id_raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::MissingPreviousKeyId)?;
      let id = validate_key_id(id_raw)?;
      if id == active_pair.0 {
        return Err(ConfigError::MissingPreviousKeyId);
      }
      Ok(vec![active_pair, (id, previous_secret)])
    }
  }
}

/// Treat empty/whitespace-only resolved material as absent. The inline path in
/// `resolve_secret` already drops blanks, but a mounted file can be zero-byte
/// or whitespace-only; such a value must not become a chain element.
fn non_blank(secret: Option<SecretString>) -> Option<SecretString> {
  secret.filter(|value| !value.expose_secret().trim().is_empty())
}

fn resolve_secret(
  inline: Option<&str>,
  file: Option<&Path>,
) -> Result<Option<SecretString>, ConfigError> {
  match inline.map(str::trim).filter(|value| !value.is_empty()) {
    Some(value) => Ok(Some(SecretString::from(value.to_owned()))),
    None => read_secret_file(file),
  }
}

fn key_id_or_default(raw: Option<&str>) -> Result<KeyId, ConfigError> {
  match raw.map(str::trim).filter(|value| !value.is_empty()) {
    Some(value) => validate_key_id(value),
    None => Ok(KeyId::new(DEFAULT_KEY_ID)),
  }
}

/// Reject a configured key id outside `[A-Za-z0-9_-]+`: `.` would collide
/// with the `<kid>.<digest>` storage format, and empty/whitespace values are
/// never valid ids (absent ids fall back to the default above).
fn validate_key_id(value: &str) -> Result<KeyId, ConfigError> {
  if crate::keys::is_valid_key_id(value) {
    Ok(KeyId::new(value))
  } else {
    Err(ConfigError::InvalidKeyId {
      id: value.to_owned(),
    })
  }
}

fn validate_timeout_ladder(db: &DbConfig, policy: &FailurePolicy) -> Result<(), ConfigError> {
  let lock = db.lock_timeout;
  let statement = db.statement_timeout;
  let acquire = db.acquire_timeout;
  let request = policy.request_timeout;
  if lock < statement && statement <= acquire && acquire < request {
    Ok(())
  } else {
    Err(ConfigError::InvalidTimeoutLadder)
  }
}

/// Validate `cookie_domain` against the issuer host (T3-D2).
///
/// Every non-blank value is rejected: the `__Host-` session-cookie prefix
/// forbids `Domain`, so sessions stay host-only by design and the key remains
/// reserved. Blank values are treated as absent, matching the other optional
/// keys.
fn validate_cookie_domain(raw: Option<String>) -> Result<Option<String>, ConfigError> {
  let Some(domain) = raw else {
    return Ok(None);
  };
  let normalized = domain.trim().trim_start_matches('.').to_ascii_lowercase();
  if normalized.is_empty() {
    return Ok(None);
  }
  Err(ConfigError::InvalidCookieDomain { value: domain })
}

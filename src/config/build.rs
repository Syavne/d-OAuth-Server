//! Construction and cross-field validation of [`Config`] from raw input.
//!
//! Kept in a submodule so the root `config.rs` stays focused on the public
//! types and loader surface.

use std::{
  net::{IpAddr, SocketAddr},
  path::Path,
  str::FromStr,
};

use secrecy::SecretString;

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
use crate::keys::{KeyId, KeyRing};

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
    let trusted_proxy = parse_trusted_proxy(raw.trusted_proxy.as_deref())?;
    let scope_registry = raw
      .scope_registry
      .into_iter()
      .map(ScopeDefinition::from_raw)
      .collect::<Result<Vec<_>, _>>()?;
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
      cookie_domain: raw.cookie_domain,
      cookie_secure: raw.cookie_secure.unwrap_or(true),
      trusted_proxy,
      allow_open_registration: raw.allow_open_registration,
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

fn parse_trusted_proxy(raw: Option<&str>) -> Result<Option<IpAddr>, ConfigError> {
  match raw.map(str::trim).filter(|value| !value.is_empty()) {
    None => Ok(None),
    Some(value) => {
      IpAddr::from_str(value)
        .map(Some)
        .map_err(|_| ConfigError::InvalidTrustedProxy {
          value: value.to_owned(),
        })
    }
  }
}

fn build_key_ring(raw: &RawConfig) -> Result<KeyRing, ConfigError> {
  let pepper = resolve_secret(
    raw.token_pepper.as_deref(),
    raw.token_pepper_file.as_deref(),
  )?;
  let totp = resolve_secret(
    raw.totp_encryption_key.as_deref(),
    raw.totp_encryption_key_file.as_deref(),
  )?;
  let pepper_id = key_id_or_default(raw.token_pepper_id.as_deref());
  let totp_id = key_id_or_default(raw.totp_key_id.as_deref());
  let peppers = pepper
    .map(|secret| vec![(pepper_id, secret)])
    .unwrap_or_default();
  let totp_keys = totp
    .map(|secret| vec![(totp_id, secret)])
    .unwrap_or_default();
  KeyRing::from_parts(peppers, totp_keys).map_err(ConfigError::from)
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

fn key_id_or_default(raw: Option<&str>) -> KeyId {
  match raw.map(str::trim).filter(|value| !value.is_empty()) {
    Some(value) => KeyId::new(value),
    None => KeyId::new(DEFAULT_KEY_ID),
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

//! Construction and cross-field validation of [`Config`] from raw input.
//!
//! Kept in a submodule so the root `config.rs` stays focused on the public
//! types and loader surface.

use std::{collections::HashSet, net::SocketAddr, path::Path, str::FromStr, time::Duration};

use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};

use super::{
  Config, ConfigError, TlsConfig,
  db::DbConfig,
  jwt::{JWT_KEY_BYTES, JwtSigningKey},
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
    validate_protected_resources(&raw)?;
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
    let (jwt_signing_key, jwt_signing_previous_keys) = build_jwt_signing(&raw)?;
    let cimd_fetch_timeout = validate_cimd_fetch_timeout(raw.cimd_fetch_timeout_secs)?;
    let cimd_max_bytes = validate_cimd_max_bytes(raw.cimd_max_bytes)?;
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
      resource_indicators_enabled: raw.resource_indicators_enabled,
      cimd_enabled: raw.cimd_enabled,
      protected_resources_enabled: raw.protected_resources_enabled,
      protected_resource_ids: raw.protected_resource_ids,
      allow_localhost_redirect: raw.allow_localhost_redirect,
      jwt_access_tokens_enabled: raw.jwt_access_tokens_enabled,
      jwt_signing_key,
      jwt_signing_previous_keys,
      jwt_access_token_signing_alg: raw.jwt_access_token_signing_alg,
      cimd_fetch_timeout,
      cimd_max_bytes,
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

/// Require the JWT signing key to be exactly [`JWT_KEY_BYTES`] bytes: short
/// material cannot form a key and over-long material is refused (the pepper/
/// TOTP/PII chains enforce only a minimum).
fn require_exact_jwt_key_bytes(
  secret: &SecretString,
  key: &'static str,
) -> Result<(), ConfigError> {
  if secret.expose_secret().len() == JWT_KEY_BYTES {
    Ok(())
  } else {
    Err(ConfigError::WeakKeyMaterial { key })
  }
}

/// Build the optional active JWT signing key and its previous (verify-only)
/// keys, validating length, kid uniqueness, and JOSE construction at load.
fn build_jwt_signing(
  raw: &RawConfig,
) -> Result<(Option<JwtSigningKey>, Vec<JwtSigningKey>), ConfigError> {
  let alg = raw.jwt_access_token_signing_alg;
  let current = match non_blank(resolve_secret(
    raw.jwt_signing_key.as_deref(),
    raw.jwt_signing_key_file.as_deref(),
  )?) {
    Some(secret) => {
      require_exact_jwt_key_bytes(&secret, "jwt_signing_key")?;
      let kid = key_id_or_default(raw.jwt_signing_kid.as_deref())?;
      Some(JwtSigningKey::from_raw(
        kid,
        alg,
        &secret,
        "jwt_signing_key",
      )?)
    }
    None => None,
  };
  let mut previous = Vec::with_capacity(raw.jwt_signing_previous_keys.len());
  for entry in &raw.jwt_signing_previous_keys {
    let id_raw = entry
      .kid
      .as_deref()
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .ok_or(ConfigError::MissingPreviousKeyId)?;
    let kid = validate_key_id(id_raw)?;
    let secret = entry
      .key
      .as_deref()
      .map(str::trim)
      .filter(|value| !value.is_empty())
      .ok_or(ConfigError::InvalidJwtSigningKey {
        key: "jwt_signing_previous_keys",
      })?;
    let secret = SecretString::from(secret.to_owned());
    require_exact_jwt_key_bytes(&secret, "jwt_signing_previous_keys")?;
    previous.push(JwtSigningKey::from_raw(
      kid,
      alg,
      &secret,
      "jwt_signing_previous_keys",
    )?);
  }
  if (raw.jwt_access_tokens_enabled || !previous.is_empty()) && current.is_none() {
    return Err(ConfigError::MissingJwtSigningKey);
  }
  let active_kid = current.as_ref().map(|key| key.kid().clone());
  for (index, key) in previous.iter().enumerate() {
    let clashes_active = active_kid.as_ref().is_some_and(|id| id == key.kid());
    let clashes_previous = previous[..index].iter().any(|seen| seen.kid() == key.kid());
    if clashes_active || clashes_previous {
      return Err(ConfigError::DuplicateJwtSigningKid {
        kid: key.kid().as_str().to_owned(),
      });
    }
  }
  Ok((current, previous))
}

/// RFC 9728 `protected_resources` is advertised only from a validated,
/// non-empty, duplicate-free identifier set, and only when the RFC 8707
/// indicator gate is also on. With the flag off the identifiers are inert.
fn validate_protected_resources(raw: &RawConfig) -> Result<(), ConfigError> {
  if !raw.protected_resources_enabled {
    return Ok(());
  }
  if !raw.resource_indicators_enabled {
    return Err(ConfigError::InvalidProtectedResources {
      reason: "resource_indicators_enabled must be true".to_owned(),
    });
  }
  if raw.protected_resource_ids.is_empty() {
    return Err(ConfigError::InvalidProtectedResources {
      reason: "protected_resource_ids must not be empty".to_owned(),
    });
  }
  let mut seen = HashSet::new();
  for value in &raw.protected_resource_ids {
    let url = validate_protected_resource_id(value)?;
    if !seen.insert(url) {
      return Err(ConfigError::InvalidProtectedResources {
        reason: format!("duplicate protected resource id: {value}"),
      });
    }
  }
  Ok(())
}

/// One advertised identifier must be an absolute `https` URI with a host and
/// no wildcard, userinfo, fragment, or query. The parsed record is returned so
/// duplicates are detected after URL normalization.
fn validate_protected_resource_id(value: &str) -> Result<Url, ConfigError> {
  let invalid = |reason: &str| ConfigError::InvalidProtectedResources {
    reason: format!("{reason}: {value}"),
  };
  if value.contains('*') {
    return Err(invalid("wildcards are not allowed"));
  }
  let url = Url::parse(value).map_err(|_| invalid("must be an absolute URI"))?;
  if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
    return Err(invalid("must be an absolute https URI with a host"));
  }
  if !url.username().is_empty() || url.password().is_some() {
    return Err(invalid("userinfo is not allowed"));
  }
  if url.fragment().is_some() {
    return Err(invalid("a fragment is not allowed"));
  }
  if url.query().is_some() {
    return Err(invalid("a query is not allowed"));
  }
  Ok(url)
}

/// CIMD fetch timeout must sit inside the 1-10 second window.
fn validate_cimd_fetch_timeout(secs: u64) -> Result<Duration, ConfigError> {
  if (1..=10).contains(&secs) {
    Ok(Duration::from_secs(secs))
  } else {
    Err(ConfigError::InvalidCimdFetchTimeout)
  }
}

/// CIMD document byte cap must be positive and at most 5120 bytes.
fn validate_cimd_max_bytes(bytes: usize) -> Result<usize, ConfigError> {
  if (1..=5_120).contains(&bytes) {
    Ok(bytes)
  } else {
    Err(ConfigError::InvalidCimdMaxBytes)
  }
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

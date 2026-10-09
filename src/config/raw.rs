//! Raw serde shapes for the layered configuration sources.
//!
//! These types are permissive (every field defaults) and are converted to the
//! validated types in the parent module. They are never part of the public API.

use std::path::PathBuf;

use serde::Deserialize;

use super::{
  db::RawDbConfig,
  policy::RawFailurePolicy,
  redis::RawRedisConfig,
  scope::{RawScopeDefinition, RawTokenExchangeRule},
  types::{DcrRedirectPolicy, Environment, RawArgon2, RawRateLimit, RawTtlConfig},
};

/// Raw `tls` block.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawTls {
  pub cert_path: Option<PathBuf>,
  pub key_path: Option<PathBuf>,
  pub client_ca_path: Option<PathBuf>,
}

/// Raw top-level configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawConfig {
  pub issuer: Option<String>,
  pub bind_addr: Option<String>,
  pub health_addr: Option<String>,
  pub environment: Environment,
  pub tls: RawTls,
  pub database: RawDbConfig,
  pub redis: RawRedisConfig,
  pub token_pepper: Option<String>,
  pub token_pepper_file: Option<PathBuf>,
  pub token_pepper_id: Option<String>,
  pub totp_encryption_key: Option<String>,
  pub totp_encryption_key_file: Option<PathBuf>,
  pub totp_key_id: Option<String>,
  pub totp_previous_key: Option<String>,
  pub totp_previous_key_file: Option<PathBuf>,
  pub totp_previous_key_id: Option<String>,
  pub pii_encryption_key: Option<String>,
  pub pii_encryption_key_file: Option<PathBuf>,
  pub pii_key_id: Option<String>,
  pub pii_previous_key: Option<String>,
  pub pii_previous_key_file: Option<PathBuf>,
  pub pii_previous_key_id: Option<String>,
  pub pii_dual_write: bool,
  pub failure_policy: RawFailurePolicy,
  pub ttl: RawTtlConfig,
  pub argon2: RawArgon2,
  pub rate_limit: RawRateLimit,
  pub cookie_domain: Option<String>,
  pub cookie_secure: Option<bool>,
  pub allow_open_registration: bool,
  pub dcr_redirect_policy: DcrRedirectPolicy,
  pub cors_allowed_origins: Vec<String>,
  pub scope_registry: Vec<RawScopeDefinition>,
  pub allow_token_exchange: bool,
  pub token_exchange_allowlist: Vec<RawTokenExchangeRule>,
}

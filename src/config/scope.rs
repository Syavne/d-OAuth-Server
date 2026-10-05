//! Optional declarative scope registry and token-exchange allowlist entries.
//!
//! The scope registry is an OPTIONAL input applied only by `config sync`; it is
//! empty by default and never required non-empty. Scope names are exact-match
//! and namespaced (`<resource>:<action>`, e.g. `api:read`). `openid` is always
//! reserved; `offline_access` is off unless explicitly declared here.

use serde::Deserialize;

use super::ConfigError;

/// A grant kind a scope may be attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
  /// Authorization-code grant.
  AuthorizationCode,
  /// Refresh-token grant.
  RefreshToken,
  /// Client-credentials grant.
  ClientCredentials,
  /// Device-code grant.
  DeviceCode,
  /// Token-exchange grant.
  TokenExchange,
}

/// A client class a scope may be attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientClass {
  /// Public client (`token_endpoint_auth_method = none`).
  Public,
  /// Confidential client (secret, private-key JWT, or mTLS).
  Confidential,
}

/// An optional declarative scope entry applied only by `config sync`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDefinition {
  /// Namespaced exact-match scope name, e.g. `api:read`.
  pub name: String,
  /// Optional human description.
  pub description: Option<String>,
  /// Grants this scope may be requested under (empty = unrestrained).
  pub allowed_grants: Vec<GrantKind>,
  /// Client classes this scope may be issued to (empty = unrestrained).
  pub allowed_client_classes: Vec<ClientClass>,
}

impl ScopeDefinition {
  pub(crate) fn from_raw(raw: RawScopeDefinition) -> Result<Self, ConfigError> {
    let scope = Self {
      name: raw.name,
      description: raw.description,
      allowed_grants: raw.allowed_grants,
      allowed_client_classes: raw.allowed_client_classes,
    };
    validate_scope_name(&scope.name)?;
    Ok(scope)
  }
}

/// Raw scope-registry entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawScopeDefinition {
  pub name: String,
  pub description: Option<String>,
  pub allowed_grants: Vec<GrantKind>,
  pub allowed_client_classes: Vec<ClientClass>,
}

/// A `(caller, subject, scopes)` rule for token exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangeRule {
  /// Client id permitted to perform the exchange.
  pub caller: String,
  /// Subject token type/client the caller may exchange.
  pub subject: String,
  /// Scopes the caller may request for the subject.
  pub scopes: Vec<String>,
}

impl TokenExchangeRule {
  pub(crate) fn from_raw(raw: RawTokenExchangeRule) -> Result<Self, ConfigError> {
    if raw.caller.trim().is_empty() || raw.subject.trim().is_empty() {
      return Err(ConfigError::InvalidScopeRegistry {
        reason: "token-exchange rule requires a non-empty caller and subject".to_owned(),
      });
    }
    for scope in &raw.scopes {
      validate_scope_name(scope)?;
    }
    Ok(Self {
      caller: raw.caller,
      subject: raw.subject,
      scopes: raw.scopes,
    })
  }
}

/// Raw token-exchange rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawTokenExchangeRule {
  pub caller: String,
  pub subject: String,
  pub scopes: Vec<String>,
}

/// Validate a scope name against the RFC 6749 scope-token grammar (bounded).
pub(crate) fn validate_scope_name(name: &str) -> Result<(), ConfigError> {
  if name.is_empty() || name.len() > 128 {
    return Err(ConfigError::InvalidScopeName {
      name: name.to_owned(),
    });
  }
  if name == "openid" {
    return Err(ConfigError::ReservedScope {
      name: name.to_owned(),
    });
  }
  let is_scope_char = |c: char| {
    let code = u32::from(c);
    code == 0x21 || (0x23..=0x5B).contains(&code) || (0x5D..=0x7E).contains(&code)
  };
  if !name.chars().all(is_scope_char) {
    return Err(ConfigError::InvalidScopeName {
      name: name.to_owned(),
    });
  }
  Ok(())
}

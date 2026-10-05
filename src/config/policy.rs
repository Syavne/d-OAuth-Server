//! Per-endpoint failure policy: fail-closed vs fail-open, retry classes, budget.
//!
//! Security endpoints (authorize, token, introspect, revoke, PAR, device, DCR)
//! are always fail-closed: dependency outage yields `503 temporarily_unavailable`
//! rather than a silent success on a security path.

use std::{collections::BTreeMap, time::Duration};

use serde::Deserialize;

use super::ConfigError;

/// Whether a dependency outage fails the request closed or (explicitly) open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
  /// Fail closed: return `503 temporarily_unavailable` (default, mandatory on
  /// security paths).
  #[default]
  Closed,
  /// Fail open: proceed without the dependency (never allowed on security paths).
  Open,
}

/// A class of transient error that may be retried for idempotent operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryableClass {
  /// I/O error on the socket.
  Io,
  /// Operation exceeded its response timeout.
  Timeout,
  /// Connection reset by the peer.
  ConnectionReset,
  /// Upstream reported temporary unavailability.
  TemporarilyUnavailable,
  /// A pool acquire timed out.
  PoolTimedOut,
}

/// Endpoints that must never fail open.
pub const SECURITY_ENDPOINTS: [&str; 7] = [
  "authorize",
  "token",
  "introspect",
  "revoke",
  "par",
  "device_authorization",
  "register",
];

/// Failure policy applied across the request surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailurePolicy {
  /// Mode applied to endpoints not named in [`Self::endpoints`].
  pub default_mode: FailMode,
  /// Per-endpoint override (security endpoints pre-populated as closed).
  pub endpoints: BTreeMap<String, FailMode>,
  /// Error classes eligible for bounded retry.
  pub retryable: Vec<RetryableClass>,
  /// Maximum retry attempts within the budget.
  pub retry_budget: u32,
  /// End-to-end request timeout (the `request` rung of the timeout ladder).
  pub request_timeout: Duration,
}

impl Default for FailurePolicy {
  fn default() -> Self {
    Self {
      default_mode: FailMode::Closed,
      endpoints: default_endpoints(),
      retryable: default_retryable(),
      retry_budget: 3,
      request_timeout: Duration::from_secs(10),
    }
  }
}

impl FailurePolicy {
  pub(crate) fn from_raw(raw: RawFailurePolicy) -> Result<Self, ConfigError> {
    let mut endpoints = default_endpoints();
    for (endpoint, mode) in raw.endpoints {
      if mode == FailMode::Open && SECURITY_ENDPOINTS.contains(&endpoint.as_str()) {
        return Err(ConfigError::FailOpenOnSecurityPath { endpoint });
      }
      endpoints.insert(endpoint, mode);
    }
    Ok(Self {
      default_mode: raw.default_mode,
      endpoints,
      retryable: raw.retryable,
      retry_budget: raw.retry_budget,
      request_timeout: Duration::from_secs(raw.request_timeout_secs),
    })
  }
}

/// Raw failure-policy block.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub(crate) struct RawFailurePolicy {
  pub default_mode: FailMode,
  pub endpoints: BTreeMap<String, FailMode>,
  pub retryable: Vec<RetryableClass>,
  pub retry_budget: u32,
  pub request_timeout_secs: u64,
}

impl Default for RawFailurePolicy {
  fn default() -> Self {
    Self {
      default_mode: FailMode::Closed,
      endpoints: BTreeMap::new(),
      retryable: default_retryable(),
      retry_budget: 3,
      request_timeout_secs: 10,
    }
  }
}

fn default_endpoints() -> BTreeMap<String, FailMode> {
  SECURITY_ENDPOINTS
    .iter()
    .map(|e| ((*e).to_owned(), FailMode::Closed))
    .collect()
}

fn default_retryable() -> Vec<RetryableClass> {
  vec![
    RetryableClass::Io,
    RetryableClass::Timeout,
    RetryableClass::ConnectionReset,
    RetryableClass::TemporarilyUnavailable,
    RetryableClass::PoolTimedOut,
  ]
}

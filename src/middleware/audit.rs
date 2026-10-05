//! Structured audit events on the dedicated `audit` tracing target.
//!
//! Every event carries a stable machine-readable name plus non-secret
//! identifiers (request id, subject, client id, grant type). Sensitive values
//! are never part of the payload; [`super::redaction`] covers anything that
//! reaches the generic HTTP log path.

use tracing::info;

/// An audited security-relevant outcome.
///
/// The variants are exhaustive by design: adding a new outcome forces the
/// `emit` match to be updated, so no event silently goes unaudited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent<'a> {
  /// Password / passkey login succeeded.
  LoginSuccess {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// Authenticated subject identifier.
    subject: &'a str,
  },
  /// Login attempt rejected.
  LoginFailure {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// Subject identifier when known; omitted for unknown accounts.
    subject: Option<&'a str>,
    /// Short, non-sensitive rejection reason.
    reason: &'a str,
  },
  /// Consent screen granted or denied.
  Consent {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// OAuth client identifier.
    client_id: &'a str,
    /// Resource owner.
    subject: &'a str,
    /// Whether consent was granted.
    granted: bool,
  },
  /// Access/refresh token minted.
  TokenIssue {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// OAuth client identifier.
    client_id: &'a str,
    /// Grant type used.
    grant_type: &'a str,
  },
  /// Token explicitly revoked.
  TokenRevoke {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// OAuth client identifier.
    client_id: &'a str,
  },
  /// A refresh token was replayed after rotation (reuse detection).
  RefreshReuseDetected {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// OAuth client identifier.
    client_id: &'a str,
  },
  /// Dynamic client registration completed.
  DynamicClientRegistered {
    /// Correlating request id, when one is in scope.
    request_id: Option<&'a str>,
    /// Newly registered client identifier.
    client_id: &'a str,
  },
}

impl AuditEvent<'_> {
  /// Stable, machine-readable event name.
  #[must_use]
  pub const fn name(&self) -> &'static str {
    match self {
      Self::LoginSuccess { .. } => "login.success",
      Self::LoginFailure { .. } => "login.failure",
      Self::Consent { .. } => "consent",
      Self::TokenIssue { .. } => "token.issue",
      Self::TokenRevoke { .. } => "token.revoke",
      Self::RefreshReuseDetected { .. } => "token.refresh_reuse_detected",
      Self::DynamicClientRegistered { .. } => "dcr.register",
    }
  }

  /// Emit this event as one structured log line.
  pub fn emit(&self) {
    match self {
      Self::LoginSuccess {
        request_id,
        subject,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        subject = %subject,
        outcome = "success",
        "login succeeded"
      ),
      Self::LoginFailure {
        request_id,
        subject,
        reason,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        subject = ?subject,
        reason = %reason,
        outcome = "failure",
        "login failed"
      ),
      Self::Consent {
        request_id,
        client_id,
        subject,
        granted,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        client_id = %client_id,
        subject = %subject,
        granted = %granted,
        "consent decision"
      ),
      Self::TokenIssue {
        request_id,
        client_id,
        grant_type,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        client_id = %client_id,
        grant_type = %grant_type,
        "token issued"
      ),
      Self::TokenRevoke {
        request_id,
        client_id,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        client_id = %client_id,
        "token revoked"
      ),
      Self::RefreshReuseDetected {
        request_id,
        client_id,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        client_id = %client_id,
        "refresh token reuse detected"
      ),
      Self::DynamicClientRegistered {
        request_id,
        client_id,
      } => info!(
        target: "audit",
        event = self.name(),
        request_id = ?request_id,
        client_id = %client_id,
        "dynamic client registered"
      ),
    }
  }
}

#[cfg(test)]
mod audit_tests {
  use super::*;

  #[test]
  fn audit_event_names_are_stable() {
    assert_eq!(
      AuditEvent::LoginSuccess {
        request_id: None,
        subject: "s"
      }
      .name(),
      "login.success"
    );
    assert_eq!(
      AuditEvent::LoginFailure {
        request_id: None,
        subject: None,
        reason: "bad_credentials"
      }
      .name(),
      "login.failure"
    );
    assert_eq!(
      AuditEvent::Consent {
        request_id: None,
        client_id: "c",
        subject: "s",
        granted: true
      }
      .name(),
      "consent"
    );
    assert_eq!(
      AuditEvent::TokenIssue {
        request_id: None,
        client_id: "c",
        grant_type: "authorization_code"
      }
      .name(),
      "token.issue"
    );
    assert_eq!(
      AuditEvent::TokenRevoke {
        request_id: None,
        client_id: "c"
      }
      .name(),
      "token.revoke"
    );
    assert_eq!(
      AuditEvent::RefreshReuseDetected {
        request_id: None,
        client_id: "c"
      }
      .name(),
      "token.refresh_reuse_detected"
    );
    assert_eq!(
      AuditEvent::DynamicClientRegistered {
        request_id: None,
        client_id: "c"
      }
      .name(),
      "dcr.register"
    );
  }
}

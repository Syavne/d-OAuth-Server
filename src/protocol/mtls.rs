//! mTLS client matching (`tls_client_auth`, RFC 8705 §2-§3).
//!
//! Two modes, two verifiers: `self_signed_tls_client_auth` (primary,
//! §2.2 — chain-skipping, thumbprint pinning) and `tls_client_auth`
//! (PKI / subject-DN over the client-CA bundle). Both verifiers offer but
//! never require a certificate at the TLS layer; [`select::authenticate`]
//! decides per registered client. The leaf arrives via
//! [`crate::tls::PeerCertificates`], injected per request by the custom
//! accept loop.

mod cert;
mod select;
mod verifier;

pub use cert::{subject_dn, thumbprint_b64url};
pub use select::{authenticate, authenticate_by_id, select_by_subject_dn, select_by_thumbprint};
pub use verifier::{
  TLS_PROTOCOL_VERSIONS, pki_verifier, pki_verifier_from_file, self_signed_verifier, server_config,
};

use crate::error::{AppError, OAuthErrorCode};

/// mTLS client-authentication failures.
///
/// Every variant except [`MtlsError::Database`], [`MtlsError::App`], and
/// [`MtlsError::TrustBundle`] maps to `invalid_client`
/// (see [`MtlsError::into_app_error`]); no certificate bytes, subject
/// details, or database text are exposed to the client.
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
  /// No client certificate was presented but the client requires mTLS.
  #[error("no client certificate was presented")]
  MissingCertificate,
  /// The presented certificate is not registered to this client.
  #[error("client certificate is not registered to this client")]
  UnknownCertificate,
  /// The subject DN matches more than one registered client.
  #[error("client certificate subject matches more than one client")]
  AmbiguousSubjectDn,
  /// The presented bytes are not a parseable X.509 certificate.
  #[error("client certificate could not be parsed")]
  MalformedCertificate,
  /// The presented certificate is outside its validity window.
  #[error("client certificate is outside its validity period")]
  ExpiredCertificate,
  /// No active client has this `client_id`.
  #[error("unknown client")]
  UnknownClient,
  /// The client is not registered for either mTLS method.
  #[error("client is not registered for mTLS authentication")]
  UnexpectedMethod,
  /// The client-CA trust bundle (or server identity) could not be loaded.
  #[error("mTLS trust bundle error: {0}")]
  TrustBundle(String),
  /// A client lookup failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An encrypted client lookup failed (fail-closed PII or store error).
  #[error("client lookup failed")]
  App(#[from] AppError),
}

impl MtlsError {
  /// Map this failure onto the RFC error model.
  #[must_use]
  pub fn into_app_error(self) -> AppError {
    match self {
      Self::Database(source) => AppError::from(source),
      Self::App(error) => error,
      Self::TrustBundle(_) => AppError::from_code(OAuthErrorCode::ServerError),
      Self::MissingCertificate
      | Self::UnknownCertificate
      | Self::AmbiguousSubjectDn
      | Self::MalformedCertificate
      | Self::ExpiredCertificate
      | Self::UnknownClient
      | Self::UnexpectedMethod => AppError::invalid_client_non_basic(),
    }
  }
}

/// The confirmation claim bound into issued tokens (RFC 8705 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsCnf {
  /// Base64url SHA-256 of the leaf DER (the `x5t#S256` value).
  pub x5t_s256: String,
}

impl MtlsCnf {
  /// Render the `cnf` object attached to access tokens.
  #[must_use]
  pub fn claim(&self) -> serde_json::Value {
    serde_json::json!({ "x5t#S256": self.x5t_s256 })
  }
}

//! Leaf-certificate identity: `x5t#S256` thumbprints and subject DNs.
//!
//! Registration stores the base64url SHA-256 rendering of [`thumbprint_b64url`]
//! (the `x5t#S256` value, RFC 8705 §2.1) and the RFC 4514 rendering of
//! [`subject_dn`] (certificate attribute order, e.g.
//! `CN=mtls-test-client, O=Example`).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::MtlsError;

/// Compute the `x5t#S256` value: base64url (no pad) of SHA-256 over the
/// leaf DER (RFC 8705 §2.1).
#[must_use]
pub fn thumbprint_b64url(der: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// Render the leaf subject DN in RFC 4514 order (certificate attribute
/// order). Registration must store exactly this rendering.
pub fn subject_dn(der: &[u8]) -> Result<String, MtlsError> {
  let (_, cert) = X509Certificate::from_der(der).map_err(|_| MtlsError::MalformedCertificate)?;
  Ok(cert.subject().to_string())
}

/// Reject a leaf outside its validity window (RFC 5280 §6.3.3 path
/// validation): an expired or not-yet-valid certificate must never bind a
/// `cnf`, whichever method matched its identity.
pub fn ensure_within_validity(der: &[u8]) -> Result<(), MtlsError> {
  let (_, cert) = X509Certificate::from_der(der).map_err(|_| MtlsError::MalformedCertificate)?;
  if !cert.validity().is_valid() {
    return Err(MtlsError::ExpiredCertificate);
  }
  Ok(())
}

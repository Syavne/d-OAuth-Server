//! `test(mtls)` certificate fixtures.
//!
//! Short-lived RSA-2048 fixtures minted with `openssl` for task 21 only:
//! a TLS server identity, a self-signed client, a client CA plus a
//! CA-signed client, and an unregistered rogue client. They expire days
//! after minting; if a fixture expires, re-mint with the same subjects and
//! update the pinned `x5t#S256` vectors in `tests/mtls.rs`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// TLS server certificate (`CN=localhost`, SAN `localhost`/127.0.0.1).
pub const SERVER_CERT_PEM: &str = include_str!("certs/server-cert.pem");
/// TLS server private key (PKCS#8).
pub const SERVER_KEY_PEM: &str = include_str!("certs/server-key.pem");
/// Self-signed client certificate (`CN=mtls-test-client, O=Example`).
pub const CLIENT_SELF_CERT_PEM: &str = include_str!("certs/client-self-cert.pem");
/// Self-signed client private key (PKCS#8).
pub const CLIENT_SELF_KEY_PEM: &str = include_str!("certs/client-self-key.pem");
/// Client CA bundle (single self-signed CA, `CN=mtls-test-ca`).
pub const CA_CERT_PEM: &str = include_str!("certs/ca-cert.pem");
/// CA-signed client certificate (`CN=mtls-pki-client, O=Example`).
pub const CLIENT_PKI_CERT_PEM: &str = include_str!("certs/client-pki-cert.pem");
/// CA-signed client private key (PKCS#8).
pub const CLIENT_PKI_KEY_PEM: &str = include_str!("certs/client-pki-key.pem");
/// Unregistered self-signed client certificate (`CN=rogue, O=Example`).
pub const CLIENT_ROGUE_CERT_PEM: &str = include_str!("certs/client-rogue-cert.pem");

/// Fixture errors.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
  /// A PEM block did not decode.
  #[error("fixture PEM error: {0}")]
  Pem(#[from] rustls_pki_types::pem::Error),
}

/// Decode the first certificate from a PEM fixture.
pub fn cert_der(pem: &str) -> Result<CertificateDer<'static>, FixtureError> {
  Ok(CertificateDer::from_pem_slice(pem.as_bytes())?)
}

/// Decode the first private key from a PEM fixture.
pub fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>, FixtureError> {
  Ok(PrivateKeyDer::from_pem_slice(pem.as_bytes())?)
}

/// Standard-base64 DER of the first certificate in a PEM fixture (the
/// trusted-proxy header encoding).
pub fn der_b64(pem: &str) -> Result<String, FixtureError> {
  Ok(STANDARD.encode(cert_der(pem)?.as_ref()))
}

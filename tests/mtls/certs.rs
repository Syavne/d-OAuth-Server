//! `test(mtls)` certificate fixtures.
//!
//! RSA-2048 fixtures minted with `openssl` for task 21 only: a TLS server
//! identity, a self-signed client, a client CA plus a CA-signed client, an
//! unregistered rogue client, and an already-expired client. The live
//! fixtures expire years after minting; if one expires, re-mint with the
//! same subjects and update the pinned `x5t#S256` vectors in
//! `tests/mtls.rs`. The expired fixture is deliberately outside its
//! validity window and must stay that way.

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
/// Expired self-signed client certificate (`CN=mtls-expired-client,
/// O=Example`; valid 2020-01-01 to 2020-12-31 only).
pub const CLIENT_EXPIRED_CERT_PEM: &str = include_str!("certs/client-expired-cert.pem");

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

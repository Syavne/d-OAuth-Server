//! The two TLS client-cert verifiers.
//!
//! [`self_signed_verifier`] skips chain validation (RFC 8705 §2.2 forbids
//! requiring it in this mode) but still verifies the `CertificateVerify`
//! signature against the presented leaf, so only the holder of the private
//! key completes the handshake; identity is pinned at the application layer
//! by thumbprint. [`pki_verifier`] is the standard `WebPkiClientVerifier`
//! over the client-CA bundle for `tls_client_auth`.

use std::{path::Path, sync::Arc};

// `HandshakeSignatureValid` is only re-exported through `client::danger`;
use rustls::{
  DigitallySignedStruct, DistinguishedName, Error as RustlsError, RootCertStore, ServerConfig,
  SignatureScheme, SupportedProtocolVersion,
  client::danger::HandshakeSignatureValid,
  crypto::{
    WebPkiSupportedAlgorithms, ring::default_provider, verify_tls12_signature,
    verify_tls13_signature,
  },
  pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
  server::{
    ParsedCertificate, WebPkiClientVerifier,
    danger::{ClientCertVerified, ClientCertVerifier},
  },
  version::{TLS12, TLS13},
};

use super::MtlsError;

/// Chain-skipping client-cert verifier for `self_signed_tls_client_auth`.
#[derive(Debug)]
struct SelfSignedClientVerifier {
  /// Signature algorithms of the process crypto provider.
  algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for SelfSignedClientVerifier {
  fn client_auth_mandatory(&self) -> bool {
    false
  }

  fn root_hint_subjects(&self) -> &[DistinguishedName] {
    &[]
  }

  fn verify_client_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    _now: UnixTime,
  ) -> Result<ClientCertVerified, RustlsError> {
    let _parsed = ParsedCertificate::try_from(end_entity)?;
    Ok(ClientCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    verify_tls12_signature(message, cert, dss, &self.algs)
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, RustlsError> {
    verify_tls13_signature(message, cert, dss, &self.algs)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.algs.supported_schemes()
  }
}

/// Build the primary `self_signed_tls_client_auth` verifier: no chain
/// validation, possession proven by the handshake signature, identity
/// pinned at the application layer.
#[must_use]
pub fn self_signed_verifier() -> Arc<dyn ClientCertVerifier> {
  Arc::new(SelfSignedClientVerifier {
    algs: default_provider().signature_verification_algorithms,
  })
}

/// Build the optional `tls_client_auth` verifier: `WebPkiClientVerifier`
/// over the client-CA bundle, accepting but not requiring a certificate at
/// the TLS layer (absence rejects only mTLS-registered clients, in
/// [`super::select::authenticate`]).
pub fn pki_verifier(ca_pem: &[u8]) -> Result<Arc<dyn ClientCertVerifier>, MtlsError> {
  const NO_CA: &str = "client-CA bundle holds no parseable certificate";
  let mut roots = RootCertStore::empty();
  let mut count = 0;
  for cert in CertificateDer::pem_slice_iter(ca_pem) {
    let cert = cert.map_err(|_| MtlsError::TrustBundle(NO_CA.to_owned()))?;
    roots
      .add(cert)
      .map_err(|_| MtlsError::TrustBundle(NO_CA.to_owned()))?;
    count += 1;
  }
  if count == 0 {
    return Err(MtlsError::TrustBundle(NO_CA.to_owned()));
  }
  WebPkiClientVerifier::builder(Arc::new(roots))
    .allow_unauthenticated()
    .build()
    .map_err(|err| MtlsError::TrustBundle(err.to_string()))
}

/// Load the client-CA bundle from `tls.client_ca_path` and build the
/// `tls_client_auth` verifier.
pub fn pki_verifier_from_file(path: &Path) -> Result<Arc<dyn ClientCertVerifier>, MtlsError> {
  pki_verifier(&std::fs::read(path).map_err(|err| MtlsError::TrustBundle(err.to_string()))?)
}

/// Explicit TLS floor for the public listener: TLS 1.2 minimum, per
/// draft-ietf-oauth-v2-1-16 §1.5 and §7.14.
///
/// Pinned explicitly instead of relying on rustls defaults, so a future
/// default change cannot silently re-enable an older protocol version.
pub static TLS_PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];

/// Build a TLS server config pairing the server identity with either mTLS
/// verifier. Wired into the accept loop by the TLS listener task.
pub fn server_config(
  cert_chain_pem: &[u8],
  key_pem: &[u8],
  client_verifier: Arc<dyn ClientCertVerifier>,
) -> Result<ServerConfig, MtlsError> {
  const BAD_CHAIN: &str = "server certificate chain is not valid PEM";
  let chain = CertificateDer::pem_slice_iter(cert_chain_pem)
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()
    .map_err(|_| MtlsError::TrustBundle(BAD_CHAIN.to_owned()))?;
  if chain.is_empty() {
    return Err(MtlsError::TrustBundle(
      "server certificate chain is empty".to_owned(),
    ));
  }
  let key = PrivateKeyDer::from_pem_slice(key_pem)
    .map_err(|_| MtlsError::TrustBundle("server private key is not valid PEM".to_owned()))?;
  ServerConfig::builder_with_protocol_versions(TLS_PROTOCOL_VERSIONS)
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(chain, key)
    .map_err(|_| MtlsError::TrustBundle("server certificate and key do not match".to_owned()))
}

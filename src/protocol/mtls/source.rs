//! Where the leaf comes from: direct TLS evidence or proxy assertion.
//!
//! The direct-TLS certificate ([`crate::tls::PeerCertificates`], injected
//! per request by the custom accept loop) always wins. The proxy headers
//! are a fallback honored only when `trusted_proxy` is set and the proxy
//! signals `SUCCESS`; without the signal the headers are ignored, and a
//! `SUCCESS`-signed header that does not decode to an X.509 leaf fails
//! closed. The direct listener calls [`strip_proxy_headers`] on inbound
//! requests so a forged header can never reach this module.

use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::MtlsError;
use crate::tls::PeerCertificates;

/// Proxy header carrying the base64 (standard alphabet) DER of the leaf the
/// terminating proxy verified.
pub const PROXY_CERT_HEADER: &str = "x-forwarded-tls-client-cert";
/// Proxy header carrying the proxy's verification verdict.
pub const PROXY_VERIFY_HEADER: &str = "x-forwarded-tls-client-verify";
/// The only [`PROXY_VERIFY_HEADER`] value that authorizes trusting
/// [`PROXY_CERT_HEADER`].
pub const PROXY_VERIFY_SUCCESS: &str = "SUCCESS";

/// Resolve the presented leaf for this request: the direct-TLS certificate
/// first, the trusted-proxy headers only as a fallback.
pub fn presented_leaf(
  parts: &axum::http::request::Parts,
  trusted_proxy: Option<IpAddr>,
) -> Result<Option<CertificateDer<'static>>, MtlsError> {
  if let Some(peer) = parts.extensions.get::<PeerCertificates>() {
    let leaf = peer.chain().first().ok_or(MtlsError::MissingCertificate)?;
    return Ok(Some(leaf.clone()));
  }
  proxy_leaf(&parts.headers, trusted_proxy)
}

/// Remove inbound proxy client-cert headers. The direct listener applies
/// this before routing so a forged header can never be mistaken for proxy
/// evidence downstream.
pub fn strip_proxy_headers(headers: &mut axum::http::HeaderMap) {
  headers.remove(PROXY_CERT_HEADER);
  headers.remove(PROXY_VERIFY_HEADER);
}

/// Read the proxy-asserted leaf. Returns `None` unless `trusted_proxy` is
/// set *and* the proxy signals `SUCCESS` *and* a header is present; a
/// `SUCCESS`-signed header that does not decode to an X.509 leaf fails
/// closed.
fn proxy_leaf(
  headers: &axum::http::HeaderMap,
  trusted_proxy: Option<IpAddr>,
) -> Result<Option<CertificateDer<'static>>, MtlsError> {
  if trusted_proxy.is_none() {
    return Ok(None);
  }
  let verified = headers
    .get(PROXY_VERIFY_HEADER)
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value == PROXY_VERIFY_SUCCESS);
  if !verified {
    return Ok(None);
  }
  let Some(raw) = headers
    .get(PROXY_CERT_HEADER)
    .and_then(|value| value.to_str().ok())
  else {
    return Ok(None);
  };
  let der = STANDARD
    .decode(raw.trim())
    .map_err(|_| MtlsError::MalformedCertificate)?;
  X509Certificate::from_der(&der).map_err(|_| MtlsError::MalformedCertificate)?;
  Ok(Some(CertificateDer::from(der)))
}

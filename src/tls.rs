//! mTLS accept loop: `tokio-rustls` + `hyper-util` with peer-chain injection.
//!
//! The public TLS listener is driven by [`serve_tls`], a hand-rolled accept
//! loop (NOT `axum::serve`, which cannot carry a per-connection acceptor, and
//! NOT `axum-server`, whose `RustlsAcceptor` discards the TLS session and
//! exposes no `peer_certificates()`). After the handshake, the verified peer
//! certificate chain is inserted into every request's extensions as
//! [`PeerCertificates`], which `mtls.rs` (todo 21) reads. The `trusted_proxy`
//! header mode is the documented alternative for deployments that terminate
//! TLS at a reverse proxy.

use std::{io, sync::Arc};

use hyper::body::Incoming;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Verified peer certificate chain for one mTLS connection.
///
/// Inserted into request extensions by [`serve_tls`]; `None` (no chain) is
/// represented by the extension being absent, so handlers distinguish
/// "no client certificate presented" from "empty chain" without ambiguity.
#[derive(Clone, Debug)]
pub struct PeerCertificates(pub Arc<Vec<CertificateDer<'static>>>);

impl PeerCertificates {
  /// Borrow the DER chain.
  #[must_use]
  pub fn chain(&self) -> &[CertificateDer<'static>] {
    &self.0
  }
}

/// Drive the public TLS listener with per-connection peer-chain injection.
///
/// For every accepted TCP stream: run the `rustls` server handshake, snapshot
/// the verified peer chain, then serve the connection with `hyper-util`'s
/// auto (HTTP/1 + HTTP/2 version-sniffing) builder. Each request is mapped
/// through an injector that inserts [`PeerCertificates`] into its extensions
/// before the inner `service` sees it.
///
/// Handshake and connection errors are traced and skipped; the loop itself
/// only ends on an accept failure, which is returned so the caller can decide
/// whether to restart the listener.
pub async fn serve_tls<S>(
  listener: TcpListener,
  acceptor: TlsAcceptor,
  service: S,
) -> io::Result<()>
where
  S: tower::Service<axum::http::Request<Incoming>, Response = axum::response::Response>
    + Clone
    + Send
    + 'static,
  S::Future: Send + 'static,
  S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  loop {
    let (stream, peer) = listener.accept().await?;
    let acceptor = acceptor.clone();
    let service = service.clone();
    tokio::spawn(async move {
      let tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(err) => {
          tracing::warn!(error = %err, "tls handshake failed");
          return;
        }
      };
      let certs: Option<Arc<Vec<CertificateDer<'static>>>> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|chain| Arc::new(chain.to_vec()));
      let injector = tower::ServiceBuilder::new()
        .map_request(move |mut req: axum::http::Request<Incoming>| {
          if let Some(certs) = certs.clone() {
            req.extensions_mut().insert(PeerCertificates(certs));
          }
          req
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
          req
        })
        .service(service);
      let adapted = hyper_util::service::TowerToHyperService::new(injector);
      let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
      if let Err(err) = builder
        .serve_connection(hyper_util::rt::TokioIo::new(tls), adapted)
        .await
      {
        tracing::debug!(error = %err, "tls connection closed with error");
      }
    });
  }
}

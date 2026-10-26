//! Peer-certificate request helper for mTLS router tests (plan todo 7).
//!
//! Drives the REAL production router ([`d_oauth::routes::build_router`],
//! unmodified) in-process via `oneshot`, injecting the verified peer chain
//! the TLS accept loop would insert ([`d_oauth::tls::PeerCertificates`]).
//! Both peer-identity extensions the stack reads are ALWAYS inserted
//! (`ConnectInfo` for the limiter, `MockConnectInfo` for the `ConnectInfo`
//! extractor; fixed `127.0.0.1:40001`, mirroring `src/routes.rs` `drive`),
//! so the rate-limit layer never fails closed. No TLS listener is needed.
//!
//! Included by the mTLS grant suite as `#[path = "e2e/peer.rs"] mod peer;`
//! alongside `#[path = "e2e/harness.rs"] mod harness;` (the happy-path
//! check below reaches `World` as `crate::harness::World`, the same shape
//! every existing e2e suite uses).

use std::{net::SocketAddr, sync::Arc};

use axum::{
  body::Body,
  extract::{ConnectInfo, connect_info::MockConnectInfo},
  http::Request,
  response::Response,
};
use d_oauth::{routes::build_router, state::AppState, tls::PeerCertificates};
use rustls::pki_types::CertificateDer;
use tower::ServiceExt as _;

// PEM fixtures live in `tests/mtls/certs.rs`, one directory up from here.
#[path = "../mtls/certs.rs"]
mod certs;

pub use certs::FixtureError;

/// `x5t#S256` of the CA-signed fixture (copied from `tests/mtls.rs`).
pub const PKI_THUMBPRINT: &str = "VSFBS4-7neqMcHVsx-dcc28rEEemzFvmeqtZSE3xbK8";
/// Subject of the CA-signed fixture in `mtls::subject_dn` rendering
/// (copied from `tests/mtls.rs`).
pub const PKI_DN: &str = "CN=mtls-pki-client, O=Example";

/// Build the `PEER_CHAIN`: the CA-signed client leaf
/// ([`CLIENT_PKI_CERT_PEM`](certs::CLIENT_PKI_CERT_PEM)) chained to the
/// client CA bundle ([`CA_CERT_PEM`](certs::CA_CERT_PEM)), the same chain
/// the TLS accept loop would hand the router for the PKI fixture.
pub fn peer_chain() -> Result<Vec<CertificateDer<'static>>, FixtureError> {
  Ok(vec![
    certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?,
    certs::cert_der(certs::CA_CERT_PEM)?,
  ])
}

/// Drive one request through the production router with peer extensions.
///
/// When `peer` is `Some`, its chain is inserted as [`PeerCertificates`];
/// when `None`, the extension is absent (the "no client certificate"
/// shape). Both `ConnectInfo` and `MockConnectInfo` are always inserted so
/// the rate-limit layer attributes the fixed loopback peer instead of
/// failing closed with 503.
pub async fn oneshot_with_peer(
  state: AppState,
  mut request: Request<Body>,
  peer: Option<Vec<CertificateDer<'static>>>,
) -> Response {
  let addr = SocketAddr::from(([127, 0, 0, 1], 40_001));
  if let Some(chain) = peer {
    request
      .extensions_mut()
      .insert(PeerCertificates(Arc::new(chain)));
  }
  request.extensions_mut().insert(ConnectInfo(addr));
  request.extensions_mut().insert(MockConnectInfo(addr));
  match build_router(state).oneshot(request).await {
    Ok(response) => response,
    Err(error) => match error {},
  }
}

/// Happy-path check for the helper. Files under `tests/e2e/` are included
/// via `#[path]` (never standalone targets), so this module only compiles
/// when a test target includes `peer.rs` — exactly how todo 14 will use it
/// (`#[path = "e2e/peer.rs"] mod peer;` next to `mod harness;`).
#[cfg(test)]
mod tests {
  use axum::http::{Request, StatusCode};
  use d_oauth::protocol::mtls;

  use super::{PKI_DN, PKI_THUMBPRINT, oneshot_with_peer, peer_chain};

  /// Test-body result (no `unwrap`/`expect` under the deny lints).
  type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

  /// `GET /jwks.json` through the helper with the given peer evidence.
  async fn get_jwks(
    peer: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
  ) -> TestResult<StatusCode> {
    let world = crate::harness::World::start(crate::harness::open_rate_limit()).await?;
    let request = Request::builder()
      .uri("/jwks.json")
      .body(axum::body::Body::empty())?;
    Ok(
      oneshot_with_peer(world.state.clone(), request, peer)
        .await
        .status(),
    )
  }

  /// The helper serves `GET /jwks.json` with 200 both with and without a
  /// peer chain (the chain only matters to mTLS-authenticated grants), and
  /// the built chain matches the pinned PKI constants.
  #[tokio::test]
  async fn peer_helper_serves_jwks_with_and_without_chain() -> TestResult {
    let chain = peer_chain()?;
    if mtls::thumbprint_b64url(chain[0].as_ref()) != PKI_THUMBPRINT {
      return Err("peer leaf thumbprint must match PKI_THUMBPRINT".into());
    }
    if mtls::subject_dn(chain[0].as_ref())? != PKI_DN {
      return Err("peer leaf subject must match PKI_DN".into());
    }
    if get_jwks(None).await? != StatusCode::OK {
      return Err("GET /jwks.json without a peer must be 200".into());
    }
    if get_jwks(Some(chain)).await? != StatusCode::OK {
      return Err("GET /jwks.json with a peer chain must be 200".into());
    }
    Ok(())
  }
}

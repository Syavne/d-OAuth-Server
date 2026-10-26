//! `test(e2e_)` mTLS `tls_client_auth` token-endpoint mint and rejection
//! matrix (plan todo 14).
//!
//! Every case drives the REAL production router
//! ([`d_oauth::routes::build_router`]) in process through
//! [`peer::oneshot_with_peer`], which injects the verified peer chain the TLS
//! accept loop would hand the router. No listener is bound: certificate-chain
//! trust stays covered by the real-handshake `tests/bootstrap.rs` suite, while
//! this suite proves what the router does with an already-verified chain —
//! subject-DN matching, `cnf.x5t#S256` derivation, and the rejection rows.
//!
//! Test names contain `e2e_mtls` so
//! `cargo nextest run -E 'binary(e2e_mtls_grant)'` selects exactly them.

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

#[allow(dead_code)]
#[path = "e2e/peer.rs"]
mod peer;

#[allow(dead_code)]
#[allow(clippy::duplicate_mod)]
#[path = "mtls/certs.rs"]
mod certs;

use axum::{
  body::Body,
  http::{Method, Request, StatusCode, header},
  response::Response,
};
use harness::{
  TestError, World, ensure, fail, json_body, open_rate_limit, seed_mtls_client, seed_scope,
};
use peer::{PKI_DN, PKI_THUMBPRINT, oneshot_with_peer, peer_chain};
use rustls::pki_types::CertificateDer;

/// Registered `tls_client_auth` client id.
const CLIENT_ID: &str = "e2e-mtls-pki-client";

/// Drive one form-encoded `POST` through the production router with the given
/// peer evidence and return the status plus the body text.
async fn post_with_peer(
  world: &World,
  uri: &str,
  form: String,
  peer: Option<Vec<CertificateDer<'static>>>,
) -> Result<(StatusCode, String), TestError> {
  let request = Request::builder()
    .method(Method::POST)
    .uri(uri)
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    .body(Body::from(form))
    .map_err(|error| fail(format!("request build failed: {error}")))?;
  let response: Response = oneshot_with_peer(world.state.clone(), request, peer).await;
  let status = response.status();
  let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
    .await
    .map_err(|error| fail(format!("response body read failed: {error}")))?;
  let text = String::from_utf8(bytes.to_vec())
    .map_err(|error| fail(format!("response body is not UTF-8: {error}")))?;
  Ok((status, text))
}

/// Assert a token-endpoint rejection is `invalid_client` and mints nothing.
fn ensure_invalid_client(status: StatusCode, body: &str) -> Result<(), TestError> {
  ensure(
    status == StatusCode::BAD_REQUEST,
    format!("must be 400 invalid_client, got {status}: {body}"),
  )?;
  ensure(
    json_body(body)?["error"] == "invalid_client",
    format!("failure must be invalid_client: {body}"),
  )?;
  ensure(
    !body.contains("access_token"),
    "a rejected request must not mint a token",
  )?;
  Ok(())
}

/// A registered CA-signed subject DN mints a `Bearer` token whose `cnf`
/// carries the leaf thumbprint, and introspection reports that binding.
#[tokio::test]
async fn e2e_mtls_client_credentials_mints_cnf_bound_token() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_mtls_client(&world, CLIENT_ID, PKI_DN, PKI_THUMBPRINT).await?;
  seed_scope(&world.pool, "api:read").await?;

  let (status, body) = post_with_peer(
    &world,
    "/token",
    format!("grant_type=client_credentials&client_id={CLIENT_ID}"),
    Some(peer_chain().map_err(|error| fail(format!("peer chain fixture: {error}")))?),
  )
  .await?;
  ensure(
    status == StatusCode::OK,
    format!("mTLS client_credentials must mint, got {status}: {body}"),
  )?;
  let token = json_body(&body)?;
  ensure(
    token["token_type"] == "Bearer",
    format!("an mTLS-only issuance stays Bearer: {token}"),
  )?;
  let access_token = token["access_token"]
    .as_str()
    .filter(|value| !value.is_empty())
    .ok_or_else(|| fail("token response must carry an access_token"))?;

  let (status, body) = post_with_peer(
    &world,
    "/introspect",
    format!("token={access_token}&client_id={CLIENT_ID}"),
    Some(peer_chain().map_err(|error| fail(format!("peer chain fixture: {error}")))?),
  )
  .await?;
  ensure(
    status == StatusCode::OK,
    format!("introspection must 200, got {status}: {body}"),
  )?;
  let introspected = json_body(&body)?;
  ensure(
    introspected["active"] == true,
    format!("minted token must introspect active: {introspected}"),
  )?;
  ensure(
    introspected["cnf"]["x5t#S256"] == PKI_THUMBPRINT,
    format!("introspection must report the leaf thumbprint: {introspected}"),
  )?;
  Ok(())
}

/// A verified chain whose leaf matches neither the registered subject DN nor
/// thumbprint is rejected.
#[tokio::test]
async fn e2e_mtls_unknown_leaf_rejected() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_mtls_client(&world, CLIENT_ID, PKI_DN, PKI_THUMBPRINT).await?;
  seed_scope(&world.pool, "api:read").await?;
  let unknown = vec![
    certs::cert_der(certs::CLIENT_ROGUE_CERT_PEM)
      .map_err(|error| fail(format!("rogue cert fixture: {error}")))?,
  ];

  let (status, body) = post_with_peer(
    &world,
    "/token",
    format!("grant_type=client_credentials&client_id={CLIENT_ID}"),
    Some(unknown),
  )
  .await?;
  ensure_invalid_client(status, &body)
}

/// No peer certificate is `invalid_client` for an mTLS-enrolled client.
#[tokio::test]
async fn e2e_mtls_missing_cert_rejected() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_mtls_client(&world, CLIENT_ID, PKI_DN, PKI_THUMBPRINT).await?;
  seed_scope(&world.pool, "api:read").await?;

  let (status, body) = post_with_peer(
    &world,
    "/token",
    format!("grant_type=client_credentials&client_id={CLIENT_ID}"),
    None,
  )
  .await?;
  ensure_invalid_client(status, &body)
}

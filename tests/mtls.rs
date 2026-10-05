//! `test(mtls)` — mTLS client authentication (plan todo 21).
//!
//! Covers the two RFC 8705 verifiers (chain-skipping `self_signed` vs
//! `WebPkiClientVerifier` + client-CA bundle), thumbprint/DN matching,
//! rejection of unknown/missing/ambiguous identities, the trusted-proxy
//! header mode, and the request-extension injection over a real TLS
//! handshake through [`d_oauth::tls::serve_tls`].
//!
//! Test names contain `mtls` so
//! `cargo nextest run -E 'test(mtls)'` selects exactly them. Bodies use
//! `Result` + `?` (`unwrap`/`expect`/`panic` are denied workspace-wide).

#[path = "mtls/certs.rs"]
mod certs;

use std::{
  net::{IpAddr, SocketAddr},
  sync::Arc,
};

use certs::FixtureError;
use d_oauth::{
  db::client_repo::{self, Client},
  error::{AppError, OAuthErrorCode},
  protocol::mtls::{
    self, MtlsCnf, MtlsError, PROXY_CERT_HEADER, PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS,
  },
};
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use test_guard::ContainerGuard;

/// The `oauth_clients` migration, embedded byte-for-byte from the repo.
const OAUTH_CLIENTS_SQL: &str = include_str!("../migrations/1791072000_oauth_clients.sql");

/// The forward-only client column additions the repository queries need.
const CLIENT_DPOP_BOUND_SQL: &str = include_str!("../migrations/1791244800_client_dpop_bound.sql");

/// Throwaway Postgres superuser password.
const PG_PASSWORD: &str = "mtls-test-secret";

/// Start a fresh Postgres and connect a pool to it. The returned guard
/// must stay alive for the duration of the test; dropping it removes the
/// container synchronously.
async fn mtls_postgres() -> Result<(ContainerGuard, sqlx::PgPool), TestError> {
  let container = GenericImage::new("postgres", "latest")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  let pool = sqlx::PgPool::connect(&url).await?;
  Ok((guarded, pool))
}

/// Apply the embedded migration script exactly as the migrator would.
async fn mtls_migrate(pool: &sqlx::PgPool) -> Result<(), TestError> {
  sqlx::raw_sql(OAUTH_CLIENTS_SQL).execute(pool).await?;
  sqlx::raw_sql(CLIENT_DPOP_BOUND_SQL).execute(pool).await?;
  Ok(())
}

/// `x5t#S256` of the self-signed fixture (minted 2026-10-04; see
/// `tests/mtls/certs.rs` if fixtures are re-minted).
const SELF_THUMBPRINT: &str = "9qdr8V8zS6_ay9l9KkxIDqDtLK_JpWmWVeDLEm89VX0";
/// `x5t#S256` of the CA-signed fixture.
const PKI_THUMBPRINT: &str = "PC8ir71uIdRIdw1XFkMmoFvGC8Ud4CANxkk4x3BWqAc";
/// Subject of the self-signed fixture in [`mtls::subject_dn`] rendering.
const SELF_DN: &str = "CN=mtls-test-client, O=Example";
/// Subject of the CA-signed fixture in [`mtls::subject_dn`] rendering.
const PKI_DN: &str = "CN=mtls-pki-client, O=Example";

/// Test-body error.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An mTLS operation failed.
  #[error("mtls error: {0}")]
  Mtls(#[from] MtlsError),
  /// A fixture did not decode.
  #[error("fixture error: {0}")]
  Fixture(#[from] FixtureError),
  /// A rustls operation failed.
  #[error("tls error: {0}")]
  Tls(#[from] rustls::Error),
  /// An I/O operation failed.
  #[error("io error: {0}")]
  Io(#[from] std::io::Error),
  /// An HTTP value was invalid.
  #[error("http error: {0}")]
  Http(#[from] axum::http::Error),
  /// A spawned task failed.
  #[error("task error: {0}")]
  Task(#[from] tokio::task::JoinError),
  /// An address did not parse.
  #[error("address error: {0}")]
  Addr(#[from] std::net::AddrParseError),
  /// A DNS name was invalid.
  #[error("dns error: {0}")]
  Dns(#[from] rustls::pki_types::InvalidDnsNameError),
  /// A response was not UTF-8.
  #[error("encoding error: {0}")]
  Encoding(#[from] std::string::FromUtf8Error),
}

type TestResult = Result<(), TestError>;

/// Insert one mTLS client row with a runtime query (no sqlx macros, so the
/// offline query cache is untouched).
async fn insert_mtls_client(
  pool: &sqlx::PgPool,
  client_id: &str,
  method: &str,
  dn: Option<&str>,
  thumbprint: Option<&str>,
) -> TestResult {
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name,
       grant_types, response_types, scope, token_endpoint_auth_method,
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint,
       created_at, updated_at)
     VALUES ($1, $2, now(), 'mTLS Test',
       ARRAY['client_credentials'], ARRAY['token'], 'api:read', $3, $4, $5,
       now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(client_id)
  .bind(method)
  .bind(dn)
  .bind(thumbprint)
  .execute(pool)
  .await?;
  Ok(())
}

/// Minimal in-memory client for the pure (DB-free) selector tests.
fn fixture_client(method: &str, dn: Option<&str>, thumbprint: Option<&str>) -> Client {
  Client {
    id: uuid::Uuid::nil(),
    client_id: "mtls-fixture".to_owned(),
    client_secret_expires_at: None,
    client_id_issued_at: time::OffsetDateTime::UNIX_EPOCH,
    client_name: "mTLS Fixture".to_owned(),
    grant_types: Vec::new(),
    response_types: Vec::new(),
    scope: String::new(),
    token_endpoint_auth_method: method.to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: dn.map(str::to_owned),
    tls_client_auth_cert_thumbprint: thumbprint.map(str::to_owned),
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    active: true,
    created_at: time::OffsetDateTime::UNIX_EPOCH,
    updated_at: time::OffsetDateTime::UNIX_EPOCH,
  }
}

fn is_invalid_client(result: Result<MtlsCnf, MtlsError>) -> bool {
  matches!(
    result.map(|_| ()).map_err(MtlsError::into_app_error),
    Err(AppError::OAuth {
      code: OAuthErrorCode::InvalidClient,
      ..
    })
  )
}

/// The thumbprint matches the `openssl`-computed vector (RFC 8705 §2.1).
#[test]
fn mtls_thumbprint_matches_openssl_vector() -> TestResult {
  let der = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  assert_eq!(mtls::thumbprint_b64url(der.as_ref()), SELF_THUMBPRINT);
  let pki = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  assert_eq!(mtls::thumbprint_b64url(pki.as_ref()), PKI_THUMBPRINT);
  Ok(())
}

/// The subject DN renders in RFC 4514 certificate-attribute order.
#[test]
fn mtls_subject_dn_renders_rfc4514() -> TestResult {
  let der = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  assert_eq!(mtls::subject_dn(der.as_ref())?, SELF_DN);
  let pki = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  assert_eq!(mtls::subject_dn(pki.as_ref())?, PKI_DN);
  Ok(())
}

/// A registered self-signed certificate binds `cnf.x5t#S256`.
#[tokio::test]
async fn mtls_registered_thumbprint_binds_cnf() -> TestResult {
  let (_container, pool) = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(
    &pool,
    "mtls-self",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  let client = client_repo::find_active_by_client_id(&pool, "mtls-self")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let leaf = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  let cnf = mtls::authenticate(&pool, &client, Some(&leaf)).await?;
  assert_eq!(cnf.x5t_s256, SELF_THUMBPRINT);
  assert_eq!(cnf.claim()["x5t#S256"], SELF_THUMBPRINT);
  Ok(())
}

/// A CA-issued certificate binds via subject DN under `tls_client_auth`.
#[tokio::test]
async fn mtls_pki_subject_dn_binds_cnf() -> TestResult {
  let (_container, pool) = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(&pool, "mtls-pki", "tls_client_auth", Some(PKI_DN), None).await?;
  let client = client_repo::find_active_by_client_id(&pool, "mtls-pki")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let leaf = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  let cnf = mtls::authenticate(&pool, &client, Some(&leaf)).await?;
  assert_eq!(cnf.x5t_s256, PKI_THUMBPRINT);
  Ok(())
}

/// An unregistered certificate is rejected as `invalid_client`.
#[tokio::test]
async fn mtls_unregistered_thumbprint_rejected_as_invalid_client() -> TestResult {
  let (_container, pool) = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(
    &pool,
    "mtls-self",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  let client = client_repo::find_active_by_client_id(&pool, "mtls-self")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let rogue = certs::cert_der(certs::CLIENT_ROGUE_CERT_PEM)?;
  let result = mtls::authenticate(&pool, &client, Some(&rogue)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));
  Ok(())
}

/// A missing certificate rejects every mTLS-registered client.
#[tokio::test]
async fn mtls_missing_cert_rejects_mtls_clients() -> TestResult {
  let (_container, pool) = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let pinned = fixture_client("self_signed_tls_client_auth", None, Some(SELF_THUMBPRINT));
  let result = mtls::authenticate(&pool, &pinned, None).await;
  assert!(matches!(result, Err(MtlsError::MissingCertificate)));
  assert!(is_invalid_client(result));
  let pki = fixture_client("tls_client_auth", Some(PKI_DN), None);
  let result = mtls::authenticate(&pool, &pki, None).await;
  assert!(matches!(result, Err(MtlsError::MissingCertificate)));
  assert!(is_invalid_client(result));
  Ok(())
}

/// A subject DN shared by two clients is rejected as ambiguous.
#[test]
fn mtls_subject_dn_ambiguity_rejected() -> TestResult {
  let first = fixture_client("tls_client_auth", Some(PKI_DN), None);
  let second = fixture_client("tls_client_auth", Some(PKI_DN), None);
  let clients = [first, second];
  let result = mtls::select_by_subject_dn(&clients, PKI_DN);
  assert!(matches!(result, Err(MtlsError::AmbiguousSubjectDn)));
  assert!(is_invalid_client(result.map(|_| MtlsCnf {
    x5t_s256: String::new()
  })));
  let lone = fixture_client("tls_client_auth", Some(PKI_DN), None);
  let clients = [lone];
  assert_eq!(
    mtls::select_by_subject_dn(&clients, PKI_DN)?.client_id,
    "mtls-fixture"
  );
  assert!(matches!(
    mtls::select_by_subject_dn(&clients, "CN=nobody, O=Example"),
    Err(MtlsError::UnknownCertificate)
  ));
  Ok(())
}

/// Build request parts carrying the given proxy headers.
fn mtls_proxy_parts(pairs: &[(&str, &str)]) -> Result<axum::http::request::Parts, TestError> {
  let mut builder = axum::http::Request::builder().uri("/token");
  for (name, value) in pairs {
    builder = builder.header(*name, *value);
  }
  Ok(builder.body(())?.into_parts().0)
}

/// A forged proxy header is ignored without a valid verification signal,
/// and always ignored when no proxy is trusted.
#[test]
fn mtls_forged_proxy_header_ignored_without_success_signal() -> TestResult {
  let der_b64 = certs::der_b64(certs::CLIENT_SELF_CERT_PEM)?;
  let proxy: Option<IpAddr> = Some("127.0.0.1".parse()?);
  // No trusted proxy: even a SUCCESS-signed header is ignored.
  let parts = mtls_proxy_parts(&[
    (PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS),
    (PROXY_CERT_HEADER, &der_b64),
  ])?;
  assert!(mtls::presented_leaf(&parts, None)?.is_none());
  // Trusted proxy but no signal: ignored.
  let parts = mtls_proxy_parts(&[(PROXY_CERT_HEADER, &der_b64)])?;
  assert!(mtls::presented_leaf(&parts, proxy)?.is_none());
  // Trusted proxy with a failed signal: ignored.
  let parts = mtls_proxy_parts(&[
    (PROXY_VERIFY_HEADER, "FAILED"),
    (PROXY_CERT_HEADER, &der_b64),
  ])?;
  assert!(mtls::presented_leaf(&parts, proxy)?.is_none());
  // SUCCESS signal but no certificate: nothing to trust.
  let parts = mtls_proxy_parts(&[(PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS)])?;
  assert!(mtls::presented_leaf(&parts, proxy)?.is_none());
  Ok(())
}

/// A SUCCESS-signed header is honored only with `trusted_proxy`, and the
/// direct listener strips inbound headers before routing.
#[test]
fn mtls_proxy_success_signal_accepted_and_stripped() -> TestResult {
  let der_b64 = certs::der_b64(certs::CLIENT_SELF_CERT_PEM)?;
  let proxy: Option<IpAddr> = Some("127.0.0.1".parse()?);
  let parts = mtls_proxy_parts(&[
    (PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS),
    (PROXY_CERT_HEADER, &der_b64),
  ])?;
  let leaf = mtls::presented_leaf(&parts, proxy)?.ok_or(MtlsError::MissingCertificate)?;
  assert_eq!(mtls::thumbprint_b64url(leaf.as_ref()), SELF_THUMBPRINT);
  // A SUCCESS-signed garbage header fails closed instead of binding.
  let parts = mtls_proxy_parts(&[
    (PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS),
    (PROXY_CERT_HEADER, "!!!"),
  ])?;
  assert!(matches!(
    mtls::presented_leaf(&parts, proxy),
    Err(MtlsError::MalformedCertificate)
  ));
  // Stripping removes both headers, so downstream sees no certificate.
  let mut parts = mtls_proxy_parts(&[
    (PROXY_VERIFY_HEADER, PROXY_VERIFY_SUCCESS),
    (PROXY_CERT_HEADER, &der_b64),
  ])?;
  mtls::strip_proxy_headers(&mut parts.headers);
  assert!(!parts.headers.contains_key(PROXY_CERT_HEADER));
  assert!(!parts.headers.contains_key(PROXY_VERIFY_HEADER));
  assert!(mtls::presented_leaf(&parts, proxy)?.is_none());
  Ok(())
}

/// Handler echo for the handshake test: the bound thumbprint, or `no-cert`.
async fn mtls_thumbprint_handler(req: axum::http::Request<axum::body::Body>) -> String {
  match req.extensions().get::<d_oauth::tls::PeerCertificates>() {
    Some(peer) => peer.chain().first().map_or_else(
      || "empty".to_owned(),
      |der| mtls::thumbprint_b64url(der.as_ref()),
    ),
    None => "no-cert".to_owned(),
  }
}

/// Raw HTTPS GET over a rustls client config, returning the response body.
async fn mtls_get(
  addr: SocketAddr,
  client_cert: Option<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
  )>,
) -> Result<String, TestError> {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  let mut roots = rustls::RootCertStore::empty();
  roots.add(certs::cert_der(certs::SERVER_CERT_PEM)?)?;
  let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
  let config = match client_cert {
    Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
    None => builder.with_no_client_auth(),
  };
  let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
  let stream = tokio::net::TcpStream::connect(addr).await?;
  let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
  let mut tls = connector.connect(server_name, stream).await?;
  tls
    .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
    .await?;
  let mut raw = Vec::new();
  tls.read_to_end(&mut raw).await?;
  let text = String::from_utf8(raw)?;
  Ok(text.split("\r\n\r\n").last().unwrap_or("").to_owned())
}

/// The extension-injection mechanism works over a real TLS handshake: a
/// self-signed client (no CA involved) binds, and a cert-less connection on
/// the same listener is served with no extension.
#[tokio::test]
async fn mtls_real_tls_handshake_injects_peer_extension() -> TestResult {
  let app = axum::Router::new().route("/", axum::routing::get(mtls_thumbprint_handler));
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
  let addr = listener.local_addr()?;
  let config = mtls::server_config(
    certs::SERVER_CERT_PEM.as_bytes(),
    certs::SERVER_KEY_PEM.as_bytes(),
    mtls::self_signed_verifier(),
  )?;
  let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
  let server = tokio::spawn(async move { d_oauth::tls::serve_tls(listener, acceptor, app).await });

  let chain = vec![certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?];
  let key = certs::private_key(certs::CLIENT_SELF_KEY_PEM)?;
  assert_eq!(mtls_get(addr, Some((chain, key))).await?, SELF_THUMBPRINT);
  assert_eq!(mtls_get(addr, None).await?, "no-cert");

  server.abort();
  Ok(())
}

/// One TLS byte-roundtrip with the given client identity.
async fn mtls_roundtrip(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<u8, TestError> {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  let mut roots = rustls::RootCertStore::empty();
  roots.add(certs::cert_der(certs::SERVER_CERT_PEM)?)?;
  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_client_auth_cert(
      vec![certs::cert_der(cert_pem)?],
      certs::private_key(key_pem)?,
    )?;
  let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
  let stream = tokio::net::TcpStream::connect(addr).await?;
  let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
  let mut tls = connector.connect(server_name, stream).await?;
  tls.write_all(b"Z").await?;
  let mut byte = [0_u8; 1];
  tls.read_exact(&mut byte).await?;
  Ok(byte[0])
}

/// The PKI verifier chains to the client CA: a CA-signed client completes
/// the handshake while a self-signed impostor is rejected mid-handshake.
#[tokio::test]
async fn mtls_pki_verifier_accepts_ca_signed_rejects_self_signed() -> TestResult {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  let verifier = mtls::pki_verifier(certs::CA_CERT_PEM.as_bytes())?;
  let config = mtls::server_config(
    certs::SERVER_CERT_PEM.as_bytes(),
    certs::SERVER_KEY_PEM.as_bytes(),
    verifier,
  )?;
  let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
  let addr = listener.local_addr()?;
  let server = tokio::spawn(async move {
    let mut completed = 0;
    for _ in 0..2 {
      let (stream, _) = listener.accept().await?;
      let mut tls = acceptor.accept(stream).await?;
      let mut byte = [0_u8; 1];
      tls.read_exact(&mut byte).await?;
      tls.write_all(&byte).await?;
      completed += 1;
    }
    Ok::<u32, TestError>(completed)
  });

  assert_eq!(
    mtls_roundtrip(addr, certs::CLIENT_PKI_CERT_PEM, certs::CLIENT_PKI_KEY_PEM).await?,
    b'Z'
  );
  assert!(
    mtls_roundtrip(
      addr,
      certs::CLIENT_SELF_CERT_PEM,
      certs::CLIENT_SELF_KEY_PEM
    )
    .await
    .is_err()
  );
  assert!(server.await?.is_err());
  Ok(())
}

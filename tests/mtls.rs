//! `test(mtls)` — mTLS client authentication (plan todo 21).
//!
//! Covers the two RFC 8705 verifiers (chain-skipping `self_signed` vs
//! `WebPkiClientVerifier` + client-CA bundle), thumbprint/DN matching,
//! rejection of unknown/missing/ambiguous/cross-wired/expired identities,
//! and the request-extension injection over a real TLS handshake through
//! [`d_oauth::tls::serve_tls`].
//!
//! Test names contain `mtls` so
//! `cargo nextest run -E 'test(mtls)'` selects exactly them. Bodies use
//! `Result` + `?` (`unwrap`/`expect`/`panic` are denied workspace-wide).

#[path = "mtls/certs.rs"]
mod certs;

use std::{net::SocketAddr, sync::Arc};

use certs::FixtureError;
use d_oauth::{
  db::client_repo::{self, Client, NewClient},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  protocol::mtls::{self, MtlsCnf, MtlsError},
};
use secrecy::SecretString;
mod common;

/// The `oauth_clients` migration, embedded byte-for-byte from the repo.
const OAUTH_CLIENTS_SQL: &str = include_str!("../migrations/1791072000_oauth_clients.sql");

/// The forward-only client column additions the repository queries need.
const CLIENT_DPOP_BOUND_SQL: &str = include_str!("../migrations/1791244800_client_dpop_bound.sql");

/// The resource-server catalog plus the `oauth_clients.access_token_format`
/// column the repository SELECT/INSERT needs.
const RESOURCE_SERVERS_SQL: &str = include_str!("../migrations/1791504000_resource_servers.sql");

/// Start a fresh database on the shared test Postgres and connect a pool
/// to it (see `tests/common/mod.rs`). Each test migrates its own database,
/// so parallel tests never share state.
async fn mtls_postgres() -> Result<sqlx::PgPool, TestError> {
  common::postgres()
    .await
    .map_err(|error| TestError::Setup(error.to_string()))
}

/// Apply the embedded forward-only client migrations exactly as the migrator
/// would, including the resource-server/JWT-format migration, so the harness
/// schema cannot silently diverge when a column is added.
async fn mtls_migrate(pool: &sqlx::PgPool) -> Result<(), TestError> {
  sqlx::raw_sql(OAUTH_CLIENTS_SQL).execute(pool).await?;
  sqlx::raw_sql(CLIENT_DPOP_BOUND_SQL).execute(pool).await?;
  sqlx::raw_sql(RESOURCE_SERVERS_SQL).execute(pool).await?;
  sqlx::raw_sql(
    "ALTER TABLE oauth_clients ALTER COLUMN client_name DROP NOT NULL;
     ALTER TABLE oauth_clients
       ADD COLUMN client_name_enc bytea NULL,
       ADD COLUMN contacts_enc bytea NULL,
       ADD COLUMN request_uris_enc bytea NULL,
       ADD COLUMN jwks_uri_enc bytea NULL,
       ADD COLUMN software_id_enc bytea NULL,
       ADD COLUMN tls_client_auth_subject_dn_enc bytea NULL,
       ADD COLUMN tls_client_auth_cert_thumbprint_enc bytea NULL,
       ADD COLUMN tls_client_auth_subject_dn_index text NULL,
       ADD COLUMN tls_client_auth_cert_thumbprint_index text NULL;
     CREATE UNIQUE INDEX ux_oauth_clients_tls_subject_dn_index
       ON oauth_clients (tls_client_auth_subject_dn_index)
       WHERE tls_client_auth_subject_dn_index IS NOT NULL;
     CREATE UNIQUE INDEX ux_oauth_clients_tls_cert_thumbprint_index
       ON oauth_clients (tls_client_auth_cert_thumbprint_index)
       WHERE tls_client_auth_cert_thumbprint_index IS NOT NULL;",
  )
  .execute(pool)
  .await?;
  Ok(())
}

/// Test PII key ring for the encrypted client projection.
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("mtls-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("mtls-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("mtls-test-pii"))],
  )?)
}

/// `x5t#S256` of the self-signed fixture (re-minted 2026-10-06, valid to
/// 2036-10-03; see `tests/mtls/certs.rs` if fixtures are re-minted).
const SELF_THUMBPRINT: &str = "UoFOLf7P9QP8478uT1qx-2pZyBJQDdNlbbLyopxl8cA";
/// `x5t#S256` of the CA-signed fixture (re-minted 2026-10-06).
const PKI_THUMBPRINT: &str = "VSFBS4-7neqMcHVsx-dcc28rEEemzFvmeqtZSE3xbK8";
/// Subject of the self-signed fixture in [`mtls::subject_dn`] rendering.
const SELF_DN: &str = "CN=mtls-test-client, O=Example";
/// Subject of the CA-signed fixture in [`mtls::subject_dn`] rendering.
const PKI_DN: &str = "CN=mtls-pki-client, O=Example";

/// Test-body error.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// The shared test service is unreachable (usually: compose not started).
  #[error("test setup: {0}")]
  Setup(String),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An mTLS operation failed.
  #[error("mtls error: {0}")]
  Mtls(#[from] MtlsError),
  /// An application error escaped where success was required.
  #[error("app error: {0}")]
  App(#[from] AppError),
  /// A test key ring was rejected.
  #[error("key error: {0}")]
  Keys(#[from] d_oauth::keys::KeyRingError),
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
    access_token_format: "opaque".to_owned(),
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
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(
    &pool,
    "mtls-self",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  let client = client_repo::find_active_by_client_id(&pool, &test_keys()?, "mtls-self")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let leaf = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  let cnf = mtls::authenticate(&pool, &test_keys()?, &client, Some(&leaf)).await?;
  assert_eq!(cnf.x5t_s256, SELF_THUMBPRINT);
  assert_eq!(cnf.claim()["x5t#S256"], SELF_THUMBPRINT);
  Ok(())
}

/// A CA-issued certificate binds via subject DN under `tls_client_auth`.
#[tokio::test]
async fn mtls_pki_subject_dn_binds_cnf() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(&pool, "mtls-pki", "tls_client_auth", Some(PKI_DN), None).await?;
  let client = client_repo::find_active_by_client_id(&pool, &test_keys()?, "mtls-pki")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let leaf = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  let cnf = mtls::authenticate(&pool, &test_keys()?, &client, Some(&leaf)).await?;
  assert_eq!(cnf.x5t_s256, PKI_THUMBPRINT);
  Ok(())
}

/// An unregistered certificate is rejected as `invalid_client`.
#[tokio::test]
async fn mtls_unregistered_thumbprint_rejected_as_invalid_client() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  insert_mtls_client(
    &pool,
    "mtls-self",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  let client = client_repo::find_active_by_client_id(&pool, &test_keys()?, "mtls-self")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  let rogue = certs::cert_der(certs::CLIENT_ROGUE_CERT_PEM)?;
  let result = mtls::authenticate(&pool, &test_keys()?, &client, Some(&rogue)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));
  Ok(())
}

/// A missing certificate rejects every mTLS-registered client.
#[tokio::test]
async fn mtls_missing_cert_rejects_mtls_clients() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let pinned = fixture_client("self_signed_tls_client_auth", None, Some(SELF_THUMBPRINT));
  let result = mtls::authenticate(&pool, &test_keys()?, &pinned, None).await;
  assert!(matches!(result, Err(MtlsError::MissingCertificate)));
  assert!(is_invalid_client(result));
  let pki = fixture_client("tls_client_auth", Some(PKI_DN), None);
  let result = mtls::authenticate(&pool, &test_keys()?, &pki, None).await;
  assert!(matches!(result, Err(MtlsError::MissingCertificate)));
  assert!(is_invalid_client(result));
  Ok(())
}

/// RFC 8705 §2: the presented certificate must match the identity registered
/// for the requesting `client_id`. A certificate enrolled for one client must
/// not authenticate another, in either direction, and no `cnf` may be bound.
#[tokio::test]
async fn mtls_cross_wire_certificate_rejected_for_other_client() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let keys = test_keys()?;
  insert_mtls_client(
    &pool,
    "mtls-xwire-a",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  insert_mtls_client(
    &pool,
    "mtls-xwire-b",
    "self_signed_tls_client_auth",
    None,
    Some(PKI_THUMBPRINT),
  )
  .await?;
  insert_mtls_client(&pool, "mtls-xwire-c", "tls_client_auth", Some(PKI_DN), None).await?;
  let leaf_a = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  let leaf_b = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;

  // A's certificate while authenticating as B: B's thumbprint pin differs.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-b", Some(&leaf_a)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));
  // B's certificate while authenticating as A: A's thumbprint pin differs.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-a", Some(&leaf_b)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));
  // A's certificate while authenticating as the subject-DN client C.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-c", Some(&leaf_a)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));

  // Controls: each client still binds with its own certificate, so the
  // rejections above are the cross-wire and not an over-broad guard.
  assert_eq!(
    mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-a", Some(&leaf_a))
      .await?
      .x5t_s256,
    SELF_THUMBPRINT
  );
  assert_eq!(
    mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-b", Some(&leaf_b))
      .await?
      .x5t_s256,
    PKI_THUMBPRINT
  );
  assert_eq!(
    mtls::authenticate_by_id(&pool, &keys, "mtls-xwire-c", Some(&leaf_b))
      .await?
      .x5t_s256,
    PKI_THUMBPRINT
  );
  Ok(())
}

/// The registered method is part of the credential: `tls_client_auth` is
/// matched by subject DN, `self_signed_tls_client_auth` by exact thumbprint,
/// and neither accepts the other method's identity.
#[tokio::test]
async fn mtls_auth_methods_not_interchangeable() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let keys = test_keys()?;
  insert_mtls_client(
    &pool,
    "mtls-method-pinned",
    "self_signed_tls_client_auth",
    None,
    Some(SELF_THUMBPRINT),
  )
  .await?;
  insert_mtls_client(
    &pool,
    "mtls-method-dn",
    "tls_client_auth",
    Some(PKI_DN),
    None,
  )
  .await?;
  let self_leaf = certs::cert_der(certs::CLIENT_SELF_CERT_PEM)?;
  let pki_leaf = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;

  // A self-signed certificate is not the identity registered for the
  // tls_client_auth client.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-method-dn", Some(&self_leaf)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));
  // A CA-issued certificate is not the thumbprint pinned for the
  // self_signed_tls_client_auth client.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-method-pinned", Some(&pki_leaf)).await;
  assert!(matches!(result, Err(MtlsError::UnknownCertificate)));
  assert!(is_invalid_client(result));

  // Controls: each method accepts exactly its own registered identity.
  assert_eq!(
    mtls::authenticate_by_id(&pool, &keys, "mtls-method-pinned", Some(&self_leaf))
      .await?
      .x5t_s256,
    SELF_THUMBPRINT
  );
  assert_eq!(
    mtls::authenticate_by_id(&pool, &keys, "mtls-method-dn", Some(&pki_leaf))
      .await?
      .x5t_s256,
    PKI_THUMBPRINT
  );
  Ok(())
}

/// RFC 8705 §2 and RFC 5280 §6.3.3: a certificate outside its validity
/// window authenticates nobody, even when its thumbprint or subject DN is
/// registered byte-for-byte; it must never bind a `cnf`.
#[tokio::test]
async fn mtls_expired_certificate_never_binds_cnf() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let keys = test_keys()?;
  let expired = certs::cert_der(certs::CLIENT_EXPIRED_CERT_PEM)?;
  let expired_thumbprint = mtls::thumbprint_b64url(expired.as_ref());
  let expired_dn = mtls::subject_dn(expired.as_ref())?;
  insert_mtls_client(
    &pool,
    "mtls-expired-pinned",
    "self_signed_tls_client_auth",
    None,
    Some(&expired_thumbprint),
  )
  .await?;
  insert_mtls_client(
    &pool,
    "mtls-expired-dn",
    "tls_client_auth",
    Some(&expired_dn),
    None,
  )
  .await?;

  let pinned = client_repo::find_active_by_client_id(&pool, &keys, "mtls-expired-pinned")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  assert_eq!(
    pinned.tls_client_auth_cert_thumbprint.as_deref(),
    Some(expired_thumbprint.as_str())
  );
  let by_dn = client_repo::find_active_by_client_id(&pool, &keys, "mtls-expired-dn")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  assert_eq!(
    by_dn.tls_client_auth_subject_dn.as_deref(),
    Some(expired_dn.as_str())
  );

  // The registered identity matches; only the validity window rejects, and
  // no `cnf` may be produced for either method.
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-expired-pinned", Some(&expired)).await;
  assert!(matches!(result, Err(MtlsError::ExpiredCertificate)));
  assert!(is_invalid_client(result));
  let result = mtls::authenticate_by_id(&pool, &keys, "mtls-expired-dn", Some(&expired)).await;
  assert!(matches!(result, Err(MtlsError::ExpiredCertificate)));
  assert!(is_invalid_client(result));
  Ok(())
}

/// An encrypted subject-DN row matches after decryption; an unknown DN
/// fails closed; a corrupt `tls_client_auth_subject_dn_enc` surfaces as
/// 503 `temporarily_unavailable`, never a flattened `invalid_client`.
#[tokio::test]
async fn mtls_subject_dn_select() -> TestResult {
  let pool = mtls_postgres().await?;
  mtls_migrate(&pool).await?;
  let keys = test_keys()?;
  client_repo::insert(
    &pool,
    &keys,
    false,
    &NewClient {
      id: uuid::Uuid::new_v4(),
      client_id: "mtls-enc-dn".to_owned(),
      client_secret_hash: None,
      client_secret_expires_at: None,
      client_name: "mTLS Encrypted DN".to_owned(),
      grant_types: vec!["client_credentials".to_owned()],
      response_types: vec!["token".to_owned()],
      scope: "api:read".to_owned(),
      token_endpoint_auth_method: "tls_client_auth".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: Some(PKI_DN.to_owned()),
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      access_token_format: "opaque".to_owned(),
      registration_access_token_hash: None,
    },
  )
  .await?;
  let client = client_repo::find_active_by_client_id(&pool, &keys, "mtls-enc-dn")
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  assert_eq!(client.tls_client_auth_subject_dn.as_deref(), Some(PKI_DN));
  let clients = [client.clone()];
  assert_eq!(
    mtls::select_by_subject_dn(&clients, PKI_DN)?.client_id,
    "mtls-enc-dn"
  );
  assert!(matches!(
    mtls::select_by_subject_dn(&clients, "CN=nobody, O=Example"),
    Err(MtlsError::UnknownCertificate)
  ));
  let leaf = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  let cnf = mtls::authenticate(&pool, &keys, &client, Some(&leaf)).await?;
  assert_eq!(cnf.x5t_s256, PKI_THUMBPRINT);

  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE oauth_clients SET tls_client_auth_subject_dn_enc = $1 WHERE client_id = $2")
    .bind(corrupt)
    .bind("mtls-enc-dn")
    .execute(&pool)
    .await?;
  match client_repo::find_active_by_client_id(&pool, &keys, "mtls-enc-dn").await {
    Ok(_) => {
      return Err(TestError::Setup(
        "corrupt subject_dn_enc decrypted".to_owned(),
      ));
    }
    Err(error) => {
      assert!(matches!(error, AppError::PiiDecrypt));
      let app = MtlsError::from(error).into_app_error();
      assert_eq!(app.code(), OAuthErrorCode::TemporarilyUnavailable);
      assert_eq!(app.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
  }
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

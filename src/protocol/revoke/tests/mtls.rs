//! mTLS revocation: a registered certificate self-revokes over the verified
//! peer chain; an unknown certificate fails closed as `invalid_client`.

use std::sync::{Arc, atomic::AtomicBool};

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::post,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tower::ServiceExt as _;
use uuid::Uuid;

use super::{
  TestError, TestResult, mint_request, now_unix, service, test_keys, test_redis, unique,
};
use crate::{
  db::client_repo::{self, NewClient},
  protocol::{mtls, revoke::revoke_handler},
  state::{AppState, Clock, RedisConn},
  tls::PeerCertificates,
};

/// Self-signed client fixture (`CN=mtls-test-client, O=Example`).
const CLIENT_SELF_PEM: &str = include_str!("../../../../tests/mtls/certs/client-self-cert.pem");
/// Unregistered self-signed client (`CN=rogue, O=Example`).
const CLIENT_ROGUE_PEM: &str = include_str!("../../../../tests/mtls/certs/client-rogue-cert.pem");

/// Decode the first certificate from a PEM fixture.
fn cert_der(pem: &str) -> Result<CertificateDer<'static>, TestError> {
  CertificateDer::from_pem_slice(pem.as_bytes())
    .map_err(|error| TestError::Unexpected(format!("fixture PEM: {error}")))
}

/// Register a `self_signed_tls_client_auth` client pinned to `thumbprint`.
async fn insert_mtls_client(pool: &sqlx::PgPool, client_id: &str, thumbprint: &str) -> TestResult {
  let keys = test_keys()?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: "self_signed_tls_client_auth".to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: Some(thumbprint.to_owned()),
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, &keys, false, &new).await?;
  Ok(())
}

/// Handler-level [`AppState`] over a real pool and Redis handle, with the
/// per-test `{state}`/`{rl}` prefixes threaded into the config so the handler's
/// own store resolves the same keyspace the test minted into.
fn app_state(
  pool: sqlx::PgPool,
  redis: RedisConn,
  token_prefix: String,
  ratelimit_prefix: String,
) -> Result<AppState, TestError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/revoke-test-cert.pem", "key_path": "/tmp/revoke-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/revoke"},
    "redis": {
      "url": "redis://127.0.0.1:1",
      "durability": "waitaof",
      "token_key_prefix": token_prefix,
      "ratelimit_key_prefix": ratelimit_prefix,
    },
    "token_pepper": "revoke-test-pepper-0123456789abcdef",
    "totp_encryption_key": "revoke-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "revoke-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  let config = crate::config::Config::from_source(source)
    .map_err(|error| TestError::Unexpected(format!("config fixture: {error:?}")))?;
  Ok(AppState {
    pool,
    redis,
    config: Arc::new(config),
    keys: Arc::new(test_keys()?),
    transition_unsafe: Arc::new(AtomicBool::new(false)),
    clock: Clock::system(),
    cimd_fetcher: crate::protocol::cimd::ssrf_fetcher(),
  })
}

/// A `POST /revoke` carrying `token` + `client_id` with `certs` injected as
/// the verified peer chain, exactly as the TLS accept loop provides it.
async fn revoke_with_certs(
  state: AppState,
  token: &str,
  client_id: &str,
  certs: PeerCertificates,
) -> Result<StatusCode, TestError> {
  let app = Router::new()
    .route("/revoke", post(revoke_handler))
    .with_state(state);
  let body = format!("token={token}&client_id={client_id}&token_type_hint=access_token");
  let mut request = Request::post("/revoke")
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    .body(Body::from(body))
    .map_err(|error| TestError::Unexpected(format!("request build: {error}")))?;
  request.extensions_mut().insert(certs);
  let response = match app.oneshot(request).await {
    Ok(response) => response,
    Err(never) => match never {},
  };
  Ok(response.status())
}

/// A `POST /revoke` carrying `token` + `client_id` with `certs` injected as
/// the verified peer chain, returning the status plus the parsed JSON body
/// (empty object when the body is not JSON, e.g. the `200` empty response).
async fn revoke_with_certs_full(
  state: AppState,
  token: &str,
  client_id: &str,
  certs: PeerCertificates,
) -> Result<(StatusCode, serde_json::Value), TestError> {
  let app = Router::new()
    .route("/revoke", post(revoke_handler))
    .with_state(state);
  let body = format!("token={token}&client_id={client_id}&token_type_hint=access_token");
  let mut request = Request::post("/revoke")
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    .body(Body::from(body))
    .map_err(|error| TestError::Unexpected(format!("request build: {error}")))?;
  request.extensions_mut().insert(certs);
  let response = match app.oneshot(request).await {
    Ok(response) => response,
    Err(never) => match never {},
  };
  let status = response.status();
  let bytes = http_body_util::BodyExt::collect(response.into_body())
    .await
    .map_err(|error| TestError::Unexpected(format!("body read: {error}")))?
    .to_bytes();
  let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
  Ok((status, json))
}

/// A registered-but-foreign chain fails closed as `invalid_client` and leaves
/// the victim token live: the attacker presents its own valid certificate
/// while claiming the victim `client_id`, so the thumbprint pin does not
/// match the claimed client.
#[tokio::test]
async fn revoke_mtls_chain_does_not_match_claimed_client() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("postgres: {error}")))?;
  let (mut conn, store_handle, (token_prefix, ratelimit_prefix)) = test_redis().await?;
  let service = service()?;
  let victim_leaf = cert_der(CLIENT_SELF_PEM)?;
  let victim_thumbprint = mtls::thumbprint_b64url(victim_leaf.as_ref());
  let victim_id = unique("mtls-victim");
  insert_mtls_client(&pool, &victim_id, &victim_thumbprint).await?;
  let attacker_leaf = cert_der(CLIENT_ROGUE_PEM)?;
  let attacker_thumbprint = mtls::thumbprint_b64url(attacker_leaf.as_ref());
  let attacker_id = unique("mtls-attacker");
  insert_mtls_client(&pool, &attacker_id, &attacker_thumbprint).await?;
  let minted = service
    .mint(
      &mut conn,
      &store_handle,
      &mint_request(&victim_id, &unique("grant")),
      now_unix(),
    )
    .await?;
  let access = minted.access_token.clone();
  let peer = PeerCertificates(Arc::new(vec![attacker_leaf]));
  let mut verify_conn = conn.clone();
  let state = app_state(pool, conn, token_prefix, ratelimit_prefix)?;
  let (status, body) = revoke_with_certs_full(state, &access, &victim_id, peer).await?;
  if status != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(format!(
      "foreign mTLS chain must be invalid_client (400), got {status}"
    )));
  }
  if body.get("error").and_then(|value| value.as_str()) != Some("invalid_client") {
    return Err(TestError::Unexpected(
      "foreign mTLS chain must render invalid_client".to_owned(),
    ));
  }
  if service
    .find_access(&mut verify_conn, &store_handle, &access)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "rejected mTLS revocation must leave the victim token live".to_owned(),
    ));
  }
  Ok(())
}

/// A disabled mTLS client fails closed as `invalid_client`, even over its
/// previously valid chain, and the token stays live.
#[tokio::test]
async fn revoke_mtls_disabled_client_rejected() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("postgres: {error}")))?;
  let (mut conn, store_handle, (token_prefix, ratelimit_prefix)) = test_redis().await?;
  let service = service()?;
  let leaf = cert_der(CLIENT_SELF_PEM)?;
  let thumbprint = mtls::thumbprint_b64url(leaf.as_ref());
  let client_id = unique("mtls-disabled");
  insert_mtls_client(&pool, &client_id, &thumbprint).await?;
  let minted = service
    .mint(
      &mut conn,
      &store_handle,
      &mint_request(&client_id, &unique("grant")),
      now_unix(),
    )
    .await?;
  let access = minted.access_token.clone();
  if !crate::db::client_repo::deactivate(&pool, &client_id).await? {
    return Err(TestError::Unexpected(
      "deactivate must update a row".to_owned(),
    ));
  }
  let peer = PeerCertificates(Arc::new(vec![leaf]));
  let mut verify_conn = conn.clone();
  let state = app_state(pool, conn, token_prefix, ratelimit_prefix)?;
  let (status, body) = revoke_with_certs_full(state, &access, &client_id, peer).await?;
  if status != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(format!(
      "disabled mTLS client must be invalid_client (400), got {status}"
    )));
  }
  if body.get("error").and_then(|value| value.as_str()) != Some("invalid_client") {
    return Err(TestError::Unexpected(
      "disabled mTLS client must render invalid_client".to_owned(),
    ));
  }
  if service
    .find_access(&mut verify_conn, &store_handle, &access)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "rejected mTLS revocation must leave the token live".to_owned(),
    ));
  }
  Ok(())
}

/// An mTLS-registered client self-revokes its own access token over the
/// verified peer chain.
#[tokio::test]
async fn revoke_mtls_client_self_revokes() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("postgres: {error}")))?;
  let (mut conn, store_handle, (token_prefix, ratelimit_prefix)) = test_redis().await?;
  let service = service()?;
  let leaf = cert_der(CLIENT_SELF_PEM)?;
  let thumbprint = mtls::thumbprint_b64url(leaf.as_ref());
  let client_id = unique("mtls-client");
  insert_mtls_client(&pool, &client_id, &thumbprint).await?;
  let minted = service
    .mint(
      &mut conn,
      &store_handle,
      &mint_request(&client_id, &unique("grant")),
      now_unix(),
    )
    .await?;
  let access = minted.access_token.clone();
  let peer = PeerCertificates(Arc::new(vec![leaf]));
  let mut verify_conn = conn.clone();
  let state = app_state(pool, conn, token_prefix, ratelimit_prefix)?;
  let status = revoke_with_certs(state, &access, &client_id, peer).await?;
  if status != StatusCode::OK {
    return Err(TestError::Unexpected(format!(
      "mTLS self-revoke must be 200, got {status}"
    )));
  }
  if service
    .find_access(&mut verify_conn, &store_handle, &access)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "mTLS self-revoke must delete the access token".to_owned(),
    ));
  }
  Ok(())
}

/// An unregistered certificate fails closed as `invalid_client` and leaves
/// the token live.
#[tokio::test]
async fn revoke_mtls_unknown_certificate_rejected() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("postgres: {error}")))?;
  let (mut conn, store_handle, (token_prefix, ratelimit_prefix)) = test_redis().await?;
  let service = service()?;
  let leaf = cert_der(CLIENT_SELF_PEM)?;
  let thumbprint = mtls::thumbprint_b64url(leaf.as_ref());
  let client_id = unique("mtls-client");
  insert_mtls_client(&pool, &client_id, &thumbprint).await?;
  let minted = service
    .mint(
      &mut conn,
      &store_handle,
      &mint_request(&client_id, &unique("grant")),
      now_unix(),
    )
    .await?;
  let access = minted.access_token.clone();
  let rogue = cert_der(CLIENT_ROGUE_PEM)?;
  let peer = PeerCertificates(Arc::new(vec![rogue]));
  let mut verify_conn = conn.clone();
  let state = app_state(pool, conn, token_prefix, ratelimit_prefix)?;
  let status = revoke_with_certs(state, &access, &client_id, peer).await?;
  if status != StatusCode::UNAUTHORIZED && status != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(format!(
      "unknown mTLS certificate must be invalid_client (401/400), got {status}"
    )));
  }
  if service
    .find_access(&mut verify_conn, &store_handle, &access)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "rejected mTLS revocation must leave the token live".to_owned(),
    ));
  }
  Ok(())
}

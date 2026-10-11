//! `test(dcr_register)` container suite: `POST /register` against real
//! Postgres and Redis (IAT enforcement, metadata validation, the
//! confidential sender-constraint rule, and hash-only persistence).

use std::time::Duration;

use sqlx::PgPool;
use testcontainers::{
  GenericImage,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
  RegisterContext, RegisterRequest, RegisterStores, is_loopback_uri, is_open_redirect_uri,
  register_client,
};
use crate::{
  config::{Config, DurabilityMode},
  crypto::{secret as secret_crypto, tokens as tokens_crypto},
  db::{client_repo, redirect_repo, scope_repo, test_support::Db},
  error::{AppError, OAuthErrorCode},
  state::RedisConn,
  store::{Store, dcr as dcr_store},
  test_guard::{ContainerGuard, Lease},
};

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// Layered config source construction failed.
  #[error("config source error: {0}")]
  Source(#[from] ::config::ConfigError),
  /// Validated config construction failed.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// An application error from a repository helper.
  #[error("app error: {0}")]
  App(#[from] crate::error::AppError),
  /// A crypto or encoding operation failed.
  #[error("test crypto error: {0}")]
  Crypto(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Live handles for one registration test.
struct Harness {
  _db: Lease<Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  config: Config,
}

/// Fresh Postgres database plus a throwaway Redis for one test.
///
/// The guard removes the Redis container synchronously when the test drops
/// it; the Postgres container is owned by the shared `db` lease.
async fn harness(open: bool, policy: &str) -> Result<(ContainerGuard, Harness), TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let redis_url = format!("redis://127.0.0.1:{port}");
  let client = redis::Client::open(redis_url.as_str())?;
  let manager = redis::aio::ConnectionManager::new(client).await?;
  // The config fixture is never connected through: the pool and Redis
  // connection above are used directly, so its URLs only need to pass
  // syntactic validation.
  let config = test_config(
    "postgres://postgres:dummy@127.0.0.1:1/postgres?sslmode=disable",
    "redis://127.0.0.1:1",
    open,
    policy,
  )?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((
    guarded,
    Harness {
      _db,
      pool,
      conn: RedisConn::Single(manager),
      store,
      config,
    },
  ))
}

/// Build a validated [`Config`] over fixture URLs.
fn test_config(
  pg_url: &str,
  redis_url: &str,
  open: bool,
  policy: &str,
) -> Result<Config, TestError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/dcr-test-cert.pem", "key_path": "/tmp/dcr-test-key.pem"},
    "database": {"url": pg_url},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "dcr-test-pepper-0123456789abcdef",
    "totp_encryption_key": "dcr-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "dcr-test-pii-key-0123456789abcdef",
    "argon2": {"memory_kib": 8192, "iterations": 1, "parallelism": 1},
    "allow_open_registration": open,
    "dcr_redirect_policy": policy,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Ok(Config::from_source(source)?)
}

/// Split one harness into the datastore handles and the request context.
///
/// The borrows are disjoint fields of the same harness, so the immutable
/// config borrow and the mutable connection borrow coexist.
fn parts_of(harness: &mut Harness) -> (RegisterStores<'_>, RegisterContext<'_>) {
  let stores = RegisterStores {
    pool: &harness.pool,
    conn: &mut harness.conn,
    store: &harness.store,
  };
  let ctx = RegisterContext {
    config: &harness.config,
    now: OffsetDateTime::now_utc(),
  };
  (stores, ctx)
}

/// Seed one enabled catalog redirect URI.
async fn seed_redirect(pool: &PgPool, keys: &crate::keys::KeyRing, uri: &str) -> TestResult {
  redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::Authorize,
      description: "dcr test",
      created_by: None,
    },
  )
  .await?;
  Ok(())
}

/// Seed one enabled catalog scope.
async fn seed_scope(pool: &PgPool, name: &str) -> TestResult {
  scope_repo::upsert(pool, name, "dcr test scope").await?;
  Ok(())
}

/// Issue an initial access token through the same path as the CLI and return
/// the raw token (only its keyed hash is stored).
async fn issue_iat(harness: &mut Harness, uses: u64) -> Result<String, TestError> {
  let token = tokens_crypto::mint_token().map_err(|error| TestError::Crypto(format!("{error}")))?;
  let hash = super::keyed_hash(&harness.config, &token)
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  dcr_store::issue(
    &mut harness.conn,
    &harness.store,
    &hash,
    &dcr_store::InitialAccessRecord {
      uses_remaining: uses,
      label: "dcr test".to_owned(),
    },
    Duration::from_secs(600),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  Ok(token)
}

/// A registration request against `redirect_uri` with DPoP binding.
fn dpop_request(redirect_uri: &str, scope: Option<&str>) -> RegisterRequest {
  RegisterRequest {
    redirect_uris: Some(vec![redirect_uri.to_owned()]),
    client_name: Some("dcr test client".to_owned()),
    token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: scope.map(str::to_owned),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    dpop_bound_access_tokens: Some(true),
    contacts: None,
    request_uris: None,
    software_id: None,
  }
}

/// Assert an error renders the expected wire code and HTTP status.
fn expect_error(error: AppError, code: OAuthErrorCode, status: u16) -> TestResult {
  if error.code() != code {
    return Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    )));
  }
  if error.status().as_u16() != status {
    return Err(TestError::Unexpected(format!(
      "wrong status: {}",
      error.status()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_valid_201() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  seed_scope(&harness.pool, "read").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("https://app.example.test/cb", Some("read"));

  let response = {
    let (mut stores, stores_ctx) = parts_of(&mut harness);
    register_client(&mut stores, &stores_ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("register failed: {error}")))?
  };

  if response.client_id.is_empty() {
    return Err(TestError::Unexpected("empty client_id".to_owned()));
  }
  let secret = response
    .client_secret
    .clone()
    .ok_or_else(|| TestError::Unexpected("missing client_secret".to_owned()))?;
  if response.registration_access_token.is_empty() {
    return Err(TestError::Unexpected(
      "missing registration_access_token".to_owned(),
    ));
  }
  if response.redirect_uris != vec!["https://app.example.test/cb".to_owned()] {
    return Err(TestError::Unexpected(format!(
      "wrong redirects: {:?}",
      response.redirect_uris
    )));
  }
  if !response.dpop_bound_access_tokens {
    return Err(TestError::Unexpected("dpop flag not echoed".to_owned()));
  }
  let stored_bound: bool =
    sqlx::query_scalar("SELECT dpop_bound_access_tokens FROM oauth_clients WHERE client_id = $1")
      .bind(&response.client_id)
      .fetch_one(&harness.pool)
      .await?;
  if !stored_bound {
    return Err(TestError::Unexpected(
      "dpop_bound_access_tokens flag not persisted".to_owned(),
    ));
  }

  let secret_hash: Option<String> =
    sqlx::query_scalar("SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1")
      .bind(&response.client_id)
      .fetch_optional(&harness.pool)
      .await?
      .flatten();
  let secret_hash =
    secret_hash.ok_or_else(|| TestError::Unexpected("no secret hash stored".to_owned()))?;
  if !secret_hash.starts_with("$argon2id$") || secret_hash == secret {
    return Err(TestError::Unexpected(
      "client secret not stored as Argon2id hash".to_owned(),
    ));
  }
  let verified = secret_crypto::verify_secret(&secret, &secret_hash)
    .map_err(|error| TestError::Crypto(format!("{error}")))?;
  if !verified {
    return Err(TestError::Unexpected(
      "stored secret hash does not verify".to_owned(),
    ));
  }

  let reg_hash: Option<String> = sqlx::query_scalar(
    "SELECT registration_access_token_hash FROM oauth_clients WHERE client_id = $1",
  )
  .bind(&response.client_id)
  .fetch_optional(&harness.pool)
  .await?
  .flatten();
  let reg_hash =
    reg_hash.ok_or_else(|| TestError::Unexpected("no registration hash stored".to_owned()))?;
  if reg_hash == response.registration_access_token {
    return Err(TestError::Unexpected(
      "registration token stored in plaintext".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_round_trip() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let contacts = serde_json::json!(["admin@example.test"]);
  let request_uris = serde_json::json!(["https://app.example.test/request.jwt"]);
  let mut request = dpop_request("https://app.example.test/cb", None);
  request.client_name = Some("round trip client".to_owned());
  request.contacts = Some(contacts.clone());
  request.request_uris = Some(request_uris.clone());

  let response = {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("register failed: {error}")))?
  };

  let row =
    client_repo::find_active_by_client_id(&harness.pool, &harness.config.keys, &response.client_id)
      .await?
      .ok_or_else(|| TestError::Unexpected("registered row missing".to_owned()))?;
  if row.client_name != "round trip client" {
    return Err(TestError::Unexpected(format!(
      "client_name not round-tripped: {}",
      row.client_name
    )));
  }
  if row.contacts.as_ref() != Some(&contacts) {
    return Err(TestError::Unexpected(format!(
      "contacts not round-tripped: {:?}",
      row.contacts
    )));
  }
  if row.request_uris.as_ref() != Some(&request_uris) {
    return Err(TestError::Unexpected(format!(
      "request_uris not round-tripped: {:?}",
      row.request_uris
    )));
  }
  if response.client_name != "round trip client" {
    return Err(TestError::Unexpected(format!(
      "response lost the name: {}",
      response.client_name
    )));
  }

  let name_enc_present: bool = sqlx::query_scalar(
    "SELECT client_name_enc IS NOT NULL FROM oauth_clients WHERE client_id = $1",
  )
  .bind(&response.client_id)
  .fetch_one(&harness.pool)
  .await?;
  let name_plain_present: bool =
    sqlx::query_scalar("SELECT client_name IS NOT NULL FROM oauth_clients WHERE client_id = $1")
      .bind(&response.client_id)
      .fetch_one(&harness.pool)
      .await?;
  let uris_enc_present: bool = sqlx::query_scalar(
    "SELECT request_uris_enc IS NOT NULL FROM oauth_clients WHERE client_id = $1",
  )
  .bind(&response.client_id)
  .fetch_one(&harness.pool)
  .await?;
  let uris_plain_present: bool =
    sqlx::query_scalar("SELECT request_uris IS NOT NULL FROM oauth_clients WHERE client_id = $1")
      .bind(&response.client_id)
      .fetch_one(&harness.pool)
      .await?;
  if !name_enc_present || name_plain_present {
    return Err(TestError::Unexpected(
      "client_name was not sealed with encrypt-only mode".to_owned(),
    ));
  }
  if !uris_enc_present || uris_plain_present {
    return Err(TestError::Unexpected(
      "request_uris was not sealed with encrypt-only mode".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_duplicate_mtls_identity_is_400() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 5).await?;
  let mut request = dpop_request("https://app.example.test/cb", None);
  request.token_endpoint_auth_method = Some("tls_client_auth".to_owned());
  request.dpop_bound_access_tokens = None;
  request.tls_client_auth_subject_dn = Some("CN=duplicate-client, O=Example".to_owned());

  {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("first register failed: {error}")))?;
  }

  let error = {
    let (mut stores, ctx) = parts_of(&mut harness);
    match register_client(&mut stores, &ctx, Some(&iat), &request).await {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "duplicate mTLS identity accepted".to_owned(),
        ));
      }
      Err(error) => error,
    }
  };

  if error.code() != OAuthErrorCode::InvalidClientMetadata {
    return Err(TestError::Unexpected(format!(
      "wrong duplicate code: {}",
      error.code()
    )));
  }
  if error.status().as_u16() != 400 {
    return Err(TestError::Unexpected(format!(
      "wrong duplicate status: {}",
      error.status()
    )));
  }
  let description = error.description().to_owned();
  if description.contains("CN=") || description.contains("duplicate-client") {
    return Err(TestError::Unexpected(format!(
      "duplicate description leaks the identity: {description}"
    )));
  }
  if description != OAuthErrorCode::InvalidClientMetadata.default_description() {
    return Err(TestError::Unexpected(format!(
      "duplicate description is not the static default: {description}"
    )));
  }

  use axum::response::IntoResponse as _;
  use http_body_util::BodyExt as _;
  let rendered = error.into_response();
  let body = match rendered.into_body().collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(_) => axum::body::Bytes::new(),
  };
  let body = String::from_utf8_lossy(&body);
  if body.contains("CN=") || body.contains("duplicate-client") || body.contains("Example") {
    return Err(TestError::Unexpected(format!(
      "400 body leaks the identity: {body}"
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_missing_iat_401() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  let request = dpop_request("https://app.example.test/cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, None, &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "anonymous registration succeeded while closed".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClient, 401),
  }
}

#[tokio::test]
async fn dcr_register_invalid_iat_401() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  let request = dpop_request("https://app.example.test/cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some("no-such-token"), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "bogus IAT registration succeeded".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClient, 401),
  }
}

#[tokio::test]
async fn dcr_register_bad_redirect_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("https://evil.example.test/cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "non-catalog redirect accepted".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidRedirectUri, 400),
  }
}

#[tokio::test]
async fn dcr_register_bad_auth_method_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let mut request = dpop_request("https://app.example.test/cb", None);
  request.token_endpoint_auth_method = Some("magic_auth".to_owned());
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "unknown auth method accepted".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400),
  }
}

#[tokio::test]
async fn dcr_register_bad_grant_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let mut request = dpop_request("https://app.example.test/cb", None);
  request.grant_types = Some(vec!["client_credentials".to_owned()]);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "unsupported grant accepted".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400),
  }
}

#[tokio::test]
async fn dcr_register_bad_scope_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  seed_scope(&harness.pool, "read").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("https://app.example.test/cb", Some("admin"));
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected("unknown scope accepted".to_owned())),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400),
  }
}

#[tokio::test]
async fn dcr_register_confidential_without_binding_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 5).await?;

  let mut bare_secret = dpop_request("https://app.example.test/cb", None);
  bare_secret.dpop_bound_access_tokens = None;
  {
    let (mut stores, ctx) = parts_of(&mut harness);
    match register_client(&mut stores, &ctx, Some(&iat), &bare_secret).await {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "unbound client_secret_basic accepted".to_owned(),
        ));
      }
      Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400)?,
    }
  }

  let mut bare_jwt = dpop_request("https://app.example.test/cb", None);
  bare_jwt.token_endpoint_auth_method = Some("private_key_jwt".to_owned());
  bare_jwt.dpop_bound_access_tokens = None;
  bare_jwt.jwks = Some(serde_json::json!({
    "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k1" }]
  }));
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &bare_jwt).await {
    Ok(_) => Err(TestError::Unexpected(
      "unbound private_key_jwt accepted".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400),
  }
}

#[tokio::test]
async fn dcr_register_open_anonymous_201() -> TestResult {
  let (_guard, mut harness) = harness(true, "catalog_loopback").await?;
  let request = RegisterRequest {
    redirect_uris: Some(vec!["http://127.0.0.1:6420/cb".to_owned()]),
    client_name: Some("native app".to_owned()),
    token_endpoint_auth_method: Some("none".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    dpop_bound_access_tokens: None,
    contacts: None,
    request_uris: None,
    software_id: None,
  };
  let response = {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, None, &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("anonymous register failed: {error}")))?
  };

  if response.client_secret.is_some() {
    return Err(TestError::Unexpected(
      "public client was issued a secret".to_owned(),
    ));
  }
  let effective =
    redirect_repo::effective_for_client(&harness.pool, &harness.config.keys, &response.client_id)
      .await?;
  if effective.len() != 1 || effective[0].uri != "http://127.0.0.1:6420/cb" {
    return Err(TestError::Unexpected(format!(
      "loopback URI not attached: {:?}",
      effective.iter().map(|row| &row.uri).collect::<Vec<_>>()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_open_policy_rejects_plaintext_non_loopback() -> TestResult {
  let (_guard, mut harness) = harness(false, "open").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("http://evil.example.com/cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "plaintext non-loopback redirect accepted under open".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidRedirectUri, 400),
  }
}

#[tokio::test]
async fn dcr_register_open_policy_rejects_custom_scheme() -> TestResult {
  let (_guard, mut harness) = harness(false, "open").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("myapp://cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "custom-scheme redirect accepted under open".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidRedirectUri, 400),
  }
}

#[tokio::test]
async fn dcr_catalog_policy_private_scheme_dot_rule() -> TestResult {
  // Isolated catalog-policy cover for the private-use dot rule in
  // `validate_metadata` (draft-ietf-oauth-v2-1-16 §2.3.1): the dotted scheme
  // registers via its catalog hit, while the dotless scheme is rejected by
  // `is_valid_redirect_scheme` even though it is also seeded in the catalog
  // (so the failure cannot be a catalog miss).
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(&harness.pool, &harness.config.keys, "com.example.app:/cb").await?;
  seed_redirect(&harness.pool, &harness.config.keys, "myapp:/cb").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let dotted = dpop_request("com.example.app:/cb", None);
  {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &dotted)
      .await
      .map_err(|error| TestError::Unexpected(format!("dotted scheme failed: {error}")))?;
  }
  let dotless = dpop_request("myapp:/cb", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &dotless).await {
    Ok(_) => Err(TestError::Unexpected(
      "dotless private-use scheme accepted under catalog".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidRedirectUri, 400),
  }
}

#[tokio::test]
async fn dcr_register_open_policy_rejects_fragment() -> TestResult {
  let (_guard, mut harness) = harness(false, "open").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("https://app.example.com/cb?x=1#frag", None);
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected(
      "fragment redirect accepted under open".to_owned(),
    )),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidRedirectUri, 400),
  }
}

#[tokio::test]
async fn dcr_register_open_policy_accepts_https() -> TestResult {
  let (_guard, mut harness) = harness(false, "open").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("https://app.example.com/cb", None);
  let response = {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("https register failed: {error}")))?
  };
  let effective =
    redirect_repo::effective_for_client(&harness.pool, &harness.config.keys, &response.client_id)
      .await?;
  if effective.len() != 1 || effective[0].uri != "https://app.example.com/cb" {
    return Err(TestError::Unexpected(format!(
      "https URI not attached: {:?}",
      effective.iter().map(|row| &row.uri).collect::<Vec<_>>()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_open_policy_accepts_loopback() -> TestResult {
  let (_guard, mut harness) = harness(false, "open").await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = dpop_request("http://127.0.0.1:1234/cb", None);
  let response = {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("loopback register failed: {error}")))?
  };
  let effective =
    redirect_repo::effective_for_client(&harness.pool, &harness.config.keys, &response.client_id)
      .await?;
  if effective.len() != 1 || effective[0].uri != "http://127.0.0.1:1234/cb" {
    return Err(TestError::Unexpected(format!(
      "loopback URI not attached: {:?}",
      effective.iter().map(|row| &row.uri).collect::<Vec<_>>()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_mtls_client_201() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let request = RegisterRequest {
    redirect_uris: Some(vec!["https://app.example.test/cb".to_owned()]),
    client_name: Some("mtls client".to_owned()),
    token_endpoint_auth_method: Some("tls_client_auth".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: Some("CN=mtls-client, O=Example".to_owned()),
    dpop_bound_access_tokens: None,
    contacts: None,
    request_uris: None,
    software_id: None,
  };
  let response = {
    let (mut stores, ctx) = parts_of(&mut harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("mtls register failed: {error}")))?
  };

  if response.client_secret.is_some() {
    return Err(TestError::Unexpected(
      "mTLS client was issued a secret".to_owned(),
    ));
  }
  let row =
    client_repo::find_active_by_client_id(&harness.pool, &harness.config.keys, &response.client_id)
      .await?
      .ok_or_else(|| TestError::Unexpected("mtls client row missing".to_owned()))?;
  if row.tls_client_auth_subject_dn.as_deref() != Some("CN=mtls-client, O=Example") {
    return Err(TestError::Unexpected(format!(
      "subject DN not persisted: {:?}",
      row.tls_client_auth_subject_dn
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_register_jwks_xor_rejected() -> TestResult {
  let (_guard, mut harness) = harness(false, "catalog").await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/cb",
  )
  .await?;
  let iat = issue_iat(&mut harness, 3).await?;
  let mut request = dpop_request("https://app.example.test/cb", None);
  request.jwks = Some(serde_json::json!({"keys": []}));
  request.jwks_uri = Some("https://jwks.example.test/keys".to_owned());
  let (mut stores, ctx) = parts_of(&mut harness);
  match register_client(&mut stores, &ctx, Some(&iat), &request).await {
    Ok(_) => Err(TestError::Unexpected("jwks+jwks_uri accepted".to_owned())),
    Err(error) => expect_error(error, OAuthErrorCode::InvalidClientMetadata, 400),
  }
}

#[test]
fn dcr_register_loopback_shapes() {
  assert!(is_loopback_uri("http://127.0.0.1/cb"));
  assert!(is_loopback_uri("http://127.0.0.1:6420/cb"));
  assert!(is_loopback_uri("http://[::1]/cb"));
  assert!(is_loopback_uri("http://[::1]:8080/cb"));
  assert!(!is_loopback_uri("https://127.0.0.1/cb"));
  assert!(!is_loopback_uri("http://localhost/cb"));
  assert!(!is_loopback_uri("http://127.0.0.1/cb?x=1"));
  assert!(!is_loopback_uri("http://127.0.0.1/cb#frag"));
  assert!(!is_loopback_uri("http://user@127.0.0.1/cb"));
  assert!(!is_loopback_uri("http://192.168.1.1/cb"));
  assert!(!is_loopback_uri("not a uri"));
}

#[test]
fn dcr_register_open_redirect_shapes() {
  assert!(is_open_redirect_uri("https://app.example.com/cb"));
  assert!(is_open_redirect_uri("https://app.example.com/cb?x=1"));
  assert!(is_open_redirect_uri("https://app.example.com:8443/cb"));
  assert!(is_open_redirect_uri("HTTPS://APP.EXAMPLE.COM/cb"));
  assert!(is_open_redirect_uri("https://[2001:db8::1]/cb"));
  assert!(is_open_redirect_uri("http://127.0.0.1:1234/cb"));
  assert!(is_open_redirect_uri("http://[::1]:1234/cb"));
  assert!(!is_open_redirect_uri("http://evil.example.com/cb"));
  assert!(!is_open_redirect_uri("myapp://cb"));
  assert!(!is_open_redirect_uri("//app.example.com/cb"));
  assert!(!is_open_redirect_uri("https://app.example.com/cb?x=1#frag"));
  assert!(!is_open_redirect_uri("https://app.example.com/cb#frag"));
  assert!(!is_open_redirect_uri("https://user@app.example.com/cb"));
  assert!(!is_open_redirect_uri("https:///cb"));
  assert!(!is_open_redirect_uri("https://"));
  assert!(!is_open_redirect_uri("https:app.example.com/cb"));
  assert!(!is_open_redirect_uri("https://[]/cb"));
  assert!(!is_open_redirect_uri("https://app.example.com/cb "));
  assert!(!is_open_redirect_uri("not a uri"));
}

#[test]
fn dcr_register_bearer_exposes_nothing_secret() {
  let exposed = format!("{:?}", AppError::invalid_client_bearer());
  assert!(!exposed.to_ascii_lowercase().contains("pepper"));
}

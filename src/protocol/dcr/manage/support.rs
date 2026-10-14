//! Shared harness for the `dcr_manage` suites.
//!
//! Real Postgres plus the shared compose Redis per test; clients are created
//! through the production [`register_client`](super::super::register_client)
//! path so every management test starts from a genuinely registered client.

use std::time::Duration;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
  RegisterContext, RegisterRequest, RegisterResponse, RegisterStores, register_client,
};
use super::{ManageContext, ManageError, ManageStores};
use crate::{
  config::{Config, DurabilityMode},
  crypto::tokens as tokens_crypto,
  db::{redirect_repo, scope_repo, test_support::Db},
  error::{AppError, OAuthErrorCode},
  state::RedisConn,
  store::{Store, dcr as dcr_store},
  test_guard::Lease,
};

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
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

/// The suite result alias.
pub(super) type TestResult = Result<(), TestError>;

/// Live handles for one management test.
pub(super) struct Harness {
  _db: Lease<Db>,
  pub(super) pool: PgPool,
  pub(super) conn: RedisConn,
  pub(super) store: Store,
  pub(super) config: Config,
}

/// One registered client's credentials (raw values, shown once).
pub(super) struct Registered {
  /// The minted public client identifier.
  pub(super) client_id: String,
  /// The minted secret (secret-method clients only).
  pub(super) secret: Option<String>,
  /// The minted registration access token.
  pub(super) reg_token: String,
}

/// Fresh Postgres database plus the shared compose Redis for one test.
///
/// Postgres comes from the shared `db` lease; Redis comes from the shared
/// compose service, isolated per test by a unique prefix pair.
pub(super) async fn harness(policy: &str) -> Result<Harness, TestError> {
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  finish_harness(policy, manager).await
}

/// Fresh Postgres database plus the Redis at `redis_url` for one test.
///
/// Container-free: the caller owns whatever backs `redis_url`. The suite's
/// Redis-loss test (`tests_delete.rs`, keep-listed) builds a private
/// container inline, keeps its guard alive for the test, and passes the
/// container's URL here so its full wipe never touches the shared service.
/// Every other test uses [`harness`].
pub(super) async fn harness_with_redis(
  redis_url: &str,
  policy: &str,
) -> Result<Harness, TestError> {
  let client = redis::Client::open(redis_url)?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  finish_harness(policy, manager).await
}

/// Shared tail of [`harness`] and [`harness_with_redis`]: fresh Postgres,
/// per-test unique prefixes, and the fixture config over dummy URLs.
async fn finish_harness(
  policy: &str,
  manager: redis::aio::ConnectionManager,
) -> Result<Harness, TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  let config = test_config(
    "postgres://postgres:dummy@127.0.0.1:1/postgres?sslmode=disable",
    "redis://127.0.0.1:1",
    policy,
  )?;
  let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, rl_prefix, DurabilityMode::WaitAof);
  Ok(Harness {
    _db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    config,
  })
}

/// Build a validated [`Config`] over fixture URLs.
fn test_config(pg_url: &str, redis_url: &str, policy: &str) -> Result<Config, TestError> {
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
    "allow_open_registration": false,
    "dcr_redirect_policy": policy,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Ok(Config::from_source(source)?)
}

/// Split one harness into the registration datastore handles and context.
fn register_parts(harness: &mut Harness) -> (RegisterStores<'_>, RegisterContext<'_>) {
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

/// Split one harness into the management datastore handles and context.
pub(super) fn manage_parts(harness: &mut Harness) -> (ManageStores<'_>, ManageContext<'_>) {
  let stores = ManageStores {
    pool: &harness.pool,
    conn: &mut harness.conn,
    store: &harness.store,
  };
  let ctx = ManageContext {
    config: &harness.config,
    now: OffsetDateTime::now_utc(),
  };
  (stores, ctx)
}

/// Seed one enabled catalog redirect URI.
pub(super) async fn seed_redirect(
  pool: &PgPool,
  keys: &crate::keys::KeyRing,
  uri: &str,
) -> TestResult {
  redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::Authorize,
      description: "dcr manage test",
      created_by: None,
    },
  )
  .await?;
  Ok(())
}

/// Seed one enabled catalog scope.
pub(super) async fn seed_scope(pool: &PgPool, name: &str) -> TestResult {
  scope_repo::upsert(pool, name, "dcr manage test scope").await?;
  Ok(())
}

/// Issue an initial access token through the same path as the CLI.
async fn issue_iat(harness: &mut Harness, uses: u64) -> Result<String, TestError> {
  let token = tokens_crypto::mint_token().map_err(|error| TestError::Crypto(format!("{error}")))?;
  let hash = super::super::keyed_hash(&harness.config, &token)
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  dcr_store::issue(
    &mut harness.conn,
    &harness.store,
    &hash,
    &dcr_store::InitialAccessRecord {
      uses_remaining: uses,
      label: "dcr manage test".to_owned(),
    },
    Duration::from_secs(600),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  Ok(token)
}

/// A registration request against `redirect_uri` with DPoP binding.
pub(super) fn dpop_request(redirect_uri: &str, scope: Option<&str>) -> RegisterRequest {
  RegisterRequest {
    redirect_uris: Some(vec![redirect_uri.to_owned()]),
    client_name: Some("dcr manage client".to_owned()),
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

/// Register one confidential client through the production path.
pub(super) async fn register(
  harness: &mut Harness,
  redirect_uri: &str,
  scope: Option<&str>,
) -> Result<Registered, TestError> {
  seed_redirect(&harness.pool, &harness.config.keys, redirect_uri).await?;
  if let Some(name) = scope {
    seed_scope(&harness.pool, name).await?;
  }
  let iat = issue_iat(harness, 3).await?;
  let request = dpop_request(redirect_uri, scope);
  let response = {
    let (mut stores, ctx) = register_parts(harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("register failed: {error}")))?
  };
  Ok(Registered {
    client_id: response.client_id,
    secret: response.client_secret,
    reg_token: response.registration_access_token,
  })
}

/// Build an mTLS (`tls_client_auth`) registration body for `subject_dn`.
pub(super) fn mtls_request(redirect_uri: &str, subject_dn: &str) -> RegisterRequest {
  RegisterRequest {
    redirect_uris: Some(vec![redirect_uri.to_owned()]),
    client_name: Some("dcr manage mtls client".to_owned()),
    token_endpoint_auth_method: Some("tls_client_auth".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: Some(subject_dn.to_owned()),
    dpop_bound_access_tokens: None,
    contacts: None,
    request_uris: None,
    software_id: None,
  }
}

/// Register one mTLS client through the production path.
pub(super) async fn register_mtls(
  harness: &mut Harness,
  redirect_uri: &str,
  subject_dn: &str,
) -> Result<Registered, TestError> {
  seed_redirect(&harness.pool, &harness.config.keys, redirect_uri).await?;
  let iat = issue_iat(harness, 3).await?;
  let request = mtls_request(redirect_uri, subject_dn);
  let response = {
    let (mut stores, ctx) = register_parts(harness);
    register_client(&mut stores, &ctx, Some(&iat), &request)
      .await
      .map_err(|error| TestError::Unexpected(format!("mtls register failed: {error}")))?
  };
  Ok(Registered {
    client_id: response.client_id,
    secret: response.client_secret,
    reg_token: response.registration_access_token,
  })
}

/// Register one client through the production path with an explicit body,
/// returning the raw application outcome so tests can assert typed errors.
///
/// The caller seeds any catalog redirect URI or scope first.
pub(super) async fn try_register(
  harness: &mut Harness,
  request: &RegisterRequest,
) -> Result<Result<RegisterResponse, AppError>, TestError> {
  let iat = issue_iat(harness, 3).await?;
  let outcome = {
    let (mut stores, ctx) = register_parts(harness);
    register_client(&mut stores, &ctx, Some(&iat), request).await
  };
  Ok(outcome)
}

/// Assert an application error is exactly the typed `code`/`status` contract.
pub(super) fn expect_app_error(error: AppError, code: OAuthErrorCode, status: u16) -> TestResult {
  if error.code() != code || error.status().as_u16() != status {
    return Err(TestError::Unexpected(format!(
      "wrong error: {} {} (expected {code} {status})",
      error.code(),
      error.status()
    )));
  }
  Ok(())
}

/// Assert the SSRF guard denies `uri` per the documented fetch policy:
/// `https` only, and never a private/loopback/link-local literal
/// (docs/OAUTH.md "JAR and PAR", docs/SECURITY.md "PAR and JAR"). A URL
/// that fails the scheme or IP-literal check is denied before any socket
/// is opened, so this never performs network I/O for the fixture URLs.
pub(super) async fn expect_ssrf_denied(uri: &str) -> TestResult {
  use crate::protocol::ssrf::{SsrfError, fetch_guarded_bytes};

  match fetch_guarded_bytes(uri).await {
    Err(SsrfError::NonHttps | SsrfError::BlockedTarget) => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "unexpected guard failure for {uri}: {error}"
    ))),
    Ok(_) => Err(TestError::Unexpected(format!(
      "guard fetched a forbidden request_uri: {uri}"
    ))),
  }
}

/// Assert a management failure is `401 invalid_client`.
pub(super) fn expect_unauthorized(error: ManageError) -> TestResult {
  match error {
    ManageError::Protocol(app) => {
      if app.code() != OAuthErrorCode::InvalidClient || app.status().as_u16() != 401 {
        return Err(TestError::Unexpected(format!(
          "wrong denial: {} {}",
          app.code(),
          app.status()
        )));
      }
      Ok(())
    }
    ManageError::Forbidden => Err(TestError::Unexpected(
      "expected 401 invalid_client, got 403".to_owned(),
    )),
  }
}

/// Assert a management failure is the `403` cross-client denial.
pub(super) fn expect_forbidden(error: ManageError) -> TestResult {
  match error {
    ManageError::Forbidden => Ok(()),
    ManageError::Protocol(app) => Err(TestError::Unexpected(format!(
      "expected 403, got {} {}",
      app.code(),
      app.status()
    ))),
  }
}

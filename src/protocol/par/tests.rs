//! `test(par)` suite: PAR push, one-time client-bound consume,
//! cross-client/replay/expiry rejection, and auth/rule enforcement.

mod consume;
mod rules;

use std::{collections::HashMap, time::Duration};

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ParContext, ParStores};
use crate::{
  config::DurabilityMode,
  crypto::secret::{Argon2Params, hash_secret},
  db::{NewClient, TokenEndpointAuthMethod, client_repo, redirect_repo, test_support::Db},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  protocol::client_auth::ClientAuthRequest,
  state::RedisConn,
  store::Store,
  test_guard::Lease,
};
use secrecy::SecretString;

/// Test scaffolding failures (no `unwrap`/`expect` under the deny lints).
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An application error from a repository helper.
  #[error("app error: {0}")]
  App(#[from] AppError),
  /// A crypto operation failed.
  #[error("test crypto error: {0}")]
  Crypto(String),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Live handles for one PAR test.
struct Harness {
  _db: Lease<Db>,
  pool: PgPool,
  conn: RedisConn,
  store: Store,
  endpoint: String,
  keys: KeyRing,
}

/// Fresh Postgres database plus the shared compose Redis for one test.
///
/// The Redis keyspace is isolated by a per-test unique `{state}`/`{rl}` prefix
/// pair, so parallel tests never observe each other's keys.
async fn harness() -> Result<Harness, TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  let url = crate::test_support::test_redis_url();
  let client = redis::Client::open(url.as_str())?;
  let manager = redis::aio::ConnectionManager::new(client).await?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  let h = Harness {
    _db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    endpoint: "https://auth.example.test/token".to_owned(),
    keys: KeyRing::from_parts(
      vec![(KeyId::new("v1"), SecretString::from("par-test-pepper"))],
      vec![(KeyId::new("v1"), SecretString::from("par-test-totp"))],
      vec![(KeyId::new("v1"), SecretString::from("par-test-pii"))],
    )
    .map_err(|error| TestError::Crypto(format!("{error:?}")))?,
  };
  Ok(h)
}

/// Borrow datastore handles out of a harness.
fn stores_of(h: &mut Harness) -> ParStores<'_> {
  ParStores {
    pool: &h.pool,
    keys: &h.keys,
    conn: &mut h.conn,
    store: &h.store,
  }
}

/// Request context for the harness endpoint with the plan PAR TTL.
fn ctx_of(endpoint: &str) -> ParContext<'_> {
  ParContext {
    token_endpoint: endpoint,
    now: OffsetDateTime::now_utc(),
    par_ttl: Duration::from_secs(90),
  }
}

/// Register a client row for PAR tests.
async fn insert_client(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
) -> Result<(), TestError> {
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Crypto(format!("{error}")))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()
    .map_err(|error| TestError::Crypto(format!("{error}")))?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: method.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, keys, false, &new).await?;
  Ok(())
}

/// Register a redirect URI in the catalog and attach it to the client.
async fn attach_redirect(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
  uri: &str,
) -> Result<(), TestError> {
  let (row, _) = redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::Authorize,
      description: "par test",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(pool, client_id, row.id, None).await?;
  Ok(())
}

/// Authorize-time parameters for a PAR push.
fn push_params(client_id: &str, redirect_uri: &str) -> HashMap<String, String> {
  HashMap::from([
    ("client_id".to_owned(), client_id.to_owned()),
    ("response_type".to_owned(), "code".to_owned()),
    ("redirect_uri".to_owned(), redirect_uri.to_owned()),
    ("scope".to_owned(), "orders:read".to_owned()),
    ("state".to_owned(), "par-state".to_owned()),
    (
      "code_challenge".to_owned(),
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    ),
    ("code_challenge_method".to_owned(), "S256".to_owned()),
  ])
}

/// Credential-free auth naming `client_id` (public clients).
fn bare_auth(client_id: &str) -> ClientAuthRequest<'_> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

/// Assert an error renders a given OAuth code.
fn expect_code(error: &AppError, code: OAuthErrorCode) -> Result<(), TestError> {
  if error.code() != code {
    return Err(TestError::Unexpected(format!(
      "wrong code: {}",
      error.code()
    )));
  }
  Ok(())
}

//! Postgres fixtures for `test(grant_device)`: clients, scopes, users.

use sqlx::PgPool;
use uuid::Uuid;

use super::{TestError, TestResult, unique};
use crate::{
  config::Config,
  crypto::secret::{Argon2Params, hash_secret},
  db::{NewClient, TokenEndpointAuthMethod, client_repo, scope_repo, user_repo},
  protocol::device::DEVICE_GRANT,
};

pub(super) async fn insert_client(
  pool: &PgPool,
  config: &Config,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
  scope: &str,
) -> TestResult {
  insert_client_bound(pool, config, client_id, method, secret, scope, false).await
}

/// Insert a client with an explicit `dpop_bound_access_tokens` registration.
pub(super) async fn insert_client_bound(
  pool: &PgPool,
  config: &Config,
  client_id: &str,
  method: TokenEndpointAuthMethod,
  secret: Option<&str>,
  scope: &str,
  dpop_bound: bool,
) -> TestResult {
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()
    .map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} name"),
    grant_types: vec![DEVICE_GRANT.to_owned()],
    response_types: Vec::new(),
    scope: scope.to_owned(),
    token_endpoint_auth_method: method.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: dpop_bound,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, &config.keys, config.pii_dual_write, &new).await?;
  Ok(())
}

/// Enable catalog scopes for issuance-time narrowing.
pub(super) async fn enable_scopes(pool: &PgPool, names: &[&str]) -> TestResult {
  for name in names {
    scope_repo::upsert(pool, name, "grant-device test scope").await?;
  }
  Ok(())
}

/// Provision a user and entitle it to the given scopes, returning the record.
pub(super) async fn entitled_user_record(
  pool: &PgPool,
  config: &Config,
  scopes: &[&str],
) -> Result<user_repo::UserRecord, TestError> {
  let email = format!("{}@example.test", unique("user"));
  let record = user_repo::create_user(
    pool,
    &config.keys,
    config.pii_dual_write,
    &user_repo::NewUser {
      email,
      password_hash: "grant-device-dummy-hash".to_owned(),
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  for scope in scopes {
    crate::db::user_scope_repo::entitle(pool, record.id, scope, None).await?;
  }
  Ok(record)
}

/// Provision a user and entitle it to the given scopes.
pub(super) async fn entitled_user(
  pool: &PgPool,
  config: &Config,
  scopes: &[&str],
) -> Result<Uuid, TestError> {
  Ok(entitled_user_record(pool, config, scopes).await?.id)
}

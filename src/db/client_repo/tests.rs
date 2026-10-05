//! `test(client_repo)` — real-Postgres tests for `db::client_repo`.
//!
//! Covers CRUD round-trips, secret verification, the active/deactivated
//! projection rules, the metadata allowlist, the redirect/scope rules, and
//! registration-token hash storage. Every test gets a fresh migrated database
//! from [`crate::db::test_support`].

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::{Client, ClientMetadata, NewClient, TokenEndpointAuthMethod};
use super::{deactivate, find_active_by_client_id, find_by_id, insert, list};
use super::{redirect_uri_allowed, registration_token_hash, rotate_secret_hash, scope_allowed};
use super::{set_registration_token_hash, update_metadata, verify_secret};
use crate::crypto::secret::{Argon2Params, hash_secret};
use crate::db::redirect_repo;
use crate::db::test_support::{TestError, migrated_pool};

/// Low-cost Argon2id parameters keep the tests fast.
fn params() -> Result<Argon2Params, TestError> {
  Ok(Argon2Params::new(8, 1, 1, 32)?)
}

/// A minimal confidential-client fixture with a hashed secret.
fn confidential(client_id: &str) -> NewClient {
  NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: "Test Client".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: "api:read api:write".to_owned(),
    token_endpoint_auth_method: "client_secret_basic".to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    registration_access_token_hash: None,
  }
}

/// Hash a secret with the fast test parameters.
fn hashed(secret: &str) -> Result<String, TestError> {
  Ok(hash_secret(secret, &params()?)?)
}

/// Insert a scope catalog row.
async fn insert_scope(pool: &PgPool, name: &str, enabled: bool) -> Result<(), sqlx::Error> {
  sqlx::query(
    "INSERT INTO scopes (name, description, enabled, created_at, updated_at) \
     VALUES ($1, '', $2, now(), now())",
  )
  .bind(name)
  .bind(enabled)
  .execute(pool)
  .await
  .map(|_| ())
}

/// Insert + find by both keys round-trips the full metadata projection.
#[tokio::test]
async fn client_repo_insert_and_find_round_trip() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let mut new = confidential("client-round-trip");
  new.client_secret_hash = Some(hashed("s3cret")?);
  new.jwks = Some(json!({"keys": []}));
  new.contacts = Some(json!(["ops@example.test"]));
  new.software_id = Some("sw-1".to_owned());
  new.request_uris = Some(json!(["https://app.example.test/request"]));

  let created = insert(&pool, &new).await?;
  assert_eq!(created.client_id, "client-round-trip");
  assert_eq!(created.client_name, "Test Client");
  assert!(created.active);
  assert_eq!(created.grant_types, vec!["authorization_code".to_owned()]);
  assert_eq!(created.scope, "api:read api:write");
  assert_eq!(created.jwks, Some(json!({"keys": []})));

  let by_client_id = find_active_by_client_id(&pool, "client-round-trip").await?;
  assert_eq!(by_client_id, Some(created.clone()));
  let by_id = find_by_id(&pool, created.id).await?;
  assert_eq!(by_id, Some(created.clone()));

  let listed = list(&pool, false).await?;
  assert!(listed.iter().any(|client| client.id == created.id));

  // Unknown keys resolve to None, not an error.
  assert_eq!(find_active_by_client_id(&pool, "nope").await?, None);
  assert_eq!(find_by_id(&pool, Uuid::new_v4()).await?, None);
  Ok(())
}

/// A deactivated client is hidden from active lookups and the active list but
/// still visible by id / with `include_inactive`.
#[tokio::test]
async fn client_repo_deactivated_client_is_hidden() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let created = insert(&pool, &confidential("client-gone")).await?;

  assert!(deactivate(&pool, "client-gone").await?);
  // A second deactivate changes nothing.
  assert!(!deactivate(&pool, "client-gone").await?);

  assert_eq!(find_active_by_client_id(&pool, "client-gone").await?, None);
  let by_id = find_by_id(&pool, created.id).await?;
  assert!(matches!(&by_id, Some(client) if !client.active));
  assert!(
    !list(&pool, false)
      .await?
      .iter()
      .any(|client| client.client_id == "client-gone")
  );
  assert!(
    list(&pool, true)
      .await?
      .iter()
      .any(|client| client.client_id == "client-gone")
  );
  Ok(())
}

/// Secret verification: correct true, wrong false, unknown/public None.
#[tokio::test]
async fn client_repo_verify_secret() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let mut client = confidential("client-secret");
  client.client_secret_hash = Some(hashed("correct-horse")?);
  insert(&pool, &client).await?;

  assert_eq!(
    verify_secret(&pool, "client-secret", "correct-horse").await?,
    Some(true)
  );
  assert_eq!(
    verify_secret(&pool, "client-secret", "wrong").await?,
    Some(false)
  );
  assert_eq!(verify_secret(&pool, "unknown", "whatever").await?, None);

  // A public client has no stored hash, so it cannot be secret-authenticated.
  let mut public = confidential("client-public");
  public.token_endpoint_auth_method = "none".to_owned();
  insert(&pool, &public).await?;
  assert_eq!(
    verify_secret(&pool, "client-public", "anything").await?,
    None
  );

  // Rotation invalidates the old secret and accepts the new one.
  assert!(rotate_secret_hash(&pool, "client-secret", &hashed("rotated")?, None).await?);
  assert_eq!(
    verify_secret(&pool, "client-secret", "correct-horse").await?,
    Some(false)
  );
  assert_eq!(
    verify_secret(&pool, "client-secret", "rotated").await?,
    Some(true)
  );

  // A deactivated client is no longer verifiable.
  assert!(deactivate(&pool, "client-secret").await?);
  assert_eq!(
    verify_secret(&pool, "client-secret", "rotated").await?,
    None
  );
  Ok(())
}

/// Metadata updates only touch the allowlist and preserve identity/secret.
#[tokio::test]
async fn client_repo_update_metadata_allowlist() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let mut new = confidential("client-update");
  new.client_secret_hash = Some(hashed("keep-me")?);
  let created = insert(&pool, &new).await?;

  let meta = ClientMetadata {
    client_name: "Renamed".to_owned(),
    grant_types: vec!["client_credentials".to_owned()],
    response_types: vec!["token".to_owned()],
    scope: "api:admin".to_owned(),
    token_endpoint_auth_method: "private_key_jwt".to_owned(),
    jwks: Some(json!({"keys": [{"kty": "EC"}]})),
    jwks_uri: Some("https://app.example.test/jwks".to_owned()),
    tls_client_auth_subject_dn: Some("CN=client-update".to_owned()),
    tls_client_auth_cert_thumbprint: Some("abc123".to_owned()),
    request_uris: Some(json!(["https://app.example.test/r"])),
    contacts: Some(json!(["soc@example.test"])),
    software_id: Some("sw-2".to_owned()),
    dpop_bound_access_tokens: true,
  };
  let updated = update_metadata(&pool, "client-update", &meta).await?;
  let updated = updated.ok_or("update returned None")?;
  assert_eq!(updated.id, created.id);
  assert_eq!(updated.client_name, "Renamed");
  assert_eq!(updated.scope, "api:admin");
  assert_eq!(
    updated.jwks_uri.as_deref(),
    Some("https://app.example.test/jwks")
  );
  assert_eq!(
    updated.auth_method()?,
    TokenEndpointAuthMethod::PrivateKeyJwt
  );

  // Identity and secret survived the metadata write.
  assert_eq!(
    verify_secret(&pool, "client-update", "keep-me").await?,
    Some(true)
  );
  assert!(update_metadata(&pool, "missing", &meta).await?.is_none());
  Ok(())
}

/// Attached+enabled redirect URIs and registered+enabled scopes are allowed.
#[tokio::test]
async fn client_repo_redirect_and_scope_rules() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  insert(&pool, &confidential("client-rules")).await?;
  insert_scope(&pool, "api:read", true).await?;
  insert_scope(&pool, "api:disabled", false).await?;

  let uri = redirect_repo::upsert(
    &pool,
    Uuid::new_v4(),
    "https://app.example.test/cb",
    redirect_repo::RedirectKind::Authorize,
    "",
    None,
  )
  .await?;
  redirect_repo::attach(&pool, "client-rules", uri.id, None).await?;

  assert!(redirect_uri_allowed(&pool, "client-rules", "https://app.example.test/cb").await?);
  assert!(!redirect_uri_allowed(&pool, "client-rules", "https://evil.example.test/cb").await?);

  // Disabling the catalog entry removes it from the effective set.
  redirect_repo::disable(&pool, uri.id).await?;
  assert!(!redirect_uri_allowed(&pool, "client-rules", "https://app.example.test/cb").await?);

  // Scope must be registered by the client AND enabled in the catalog.
  assert!(scope_allowed(&pool, "client-rules", "api:read").await?);
  assert!(!scope_allowed(&pool, "client-rules", "api:write").await?);
  assert!(!scope_allowed(&pool, "client-rules", "api:disabled").await?);
  assert!(!scope_allowed(&pool, "client-rules", "unknown").await?);
  assert!(!scope_allowed(&pool, "client-absent", "api:read").await?);
  Ok(())
}

/// The registration-access-token hash is stored and rotated, never returned by
/// the metadata projection.
#[tokio::test]
async fn client_repo_registration_token_hash() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let mut new = confidential("client-reg");
  new.registration_access_token_hash = Some("v1.initial".to_owned());
  let created = insert(&pool, &new).await?;

  assert_eq!(
    registration_token_hash(&pool, "client-reg")
      .await?
      .as_deref(),
    Some("v1.initial")
  );
  assert!(set_registration_token_hash(&pool, "client-reg", "v2.rotated").await?);
  assert_eq!(
    registration_token_hash(&pool, "client-reg")
      .await?
      .as_deref(),
    Some("v2.rotated")
  );
  assert_eq!(registration_token_hash(&pool, "nope").await?, None);

  // The projection type carries no hash field at all; this is compile-time.
  let _: &Client = &created;
  Ok(())
}

//! `test(client_repo)` — real-Postgres tests for `db::client_repo`.
//!
//! Covers encrypted CRUD round-trips, secret verification, the active/deactivated
//! projection rules, the metadata allowlist, the redirect/scope rules, and
//! registration-token hash storage. Every test gets a fresh migrated database
//! from [`crate::db::test_support`].

use secrecy::SecretString;
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
use crate::error::{AppError, OAuthErrorCode};
use crate::keys::{KeyId, KeyRing};

/// Test PII key ring for the encrypted client projection.
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("client-repo-test-pepper"),
    )],
    vec![(
      KeyId::new("v1"),
      SecretString::from("client-repo-test-totp"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("client-repo-test-pii"))],
  )?)
}

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

/// Insert a legacy plaintext row: all `_enc`/`_index` NULL, PII in clear.
async fn insert_legacy(
  pool: &PgPool,
  client_id: &str,
  dn: Option<&str>,
  thumbprint: Option<&str>,
) -> Result<Uuid, TestError> {
  let id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name, grant_types, \
       response_types, scope, token_endpoint_auth_method, jwks_uri, tls_client_auth_subject_dn, \
       tls_client_auth_cert_thumbprint, software_id, created_at, updated_at) \
     VALUES ($1, $2, now(), 'Legacy Client', ARRAY['authorization_code'], ARRAY['code'], \
       'api:read', 'tls_client_auth', 'https://legacy.example.test/jwks', $3, $4, 'sw-legacy', \
       now(), now())",
  )
  .bind(id)
  .bind(client_id)
  .bind(dn)
  .bind(thumbprint)
  .execute(pool)
  .await?;
  Ok(id)
}

/// Insert + find by both keys round-trips the full metadata projection.
#[tokio::test]
async fn client_repo_insert_and_find_round_trip() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let mut new = confidential("client-round-trip");
  new.client_secret_hash = Some(hashed("s3cret")?);
  new.jwks = Some(json!({"keys": []}));
  new.jwks_uri = Some("https://app.example.test/jwks".to_owned());
  new.contacts = Some(json!(["ops@example.test"]));
  new.software_id = Some("sw-1".to_owned());
  new.request_uris = Some(json!(["https://app.example.test/request"]));
  new.tls_client_auth_subject_dn = Some("CN=round-trip, O=Example".to_owned());
  new.tls_client_auth_cert_thumbprint = Some("round-trip-thumb".to_owned());

  let created = insert(&pool, &keys, false, &new).await?;
  assert_eq!(created.client_id, "client-round-trip");
  assert_eq!(created.client_name, "Test Client");
  assert!(created.active);
  assert_eq!(created.grant_types, vec!["authorization_code".to_owned()]);
  assert_eq!(created.scope, "api:read api:write");
  assert_eq!(created.jwks, Some(json!({"keys": []})));
  assert_eq!(
    created.jwks_uri.as_deref(),
    Some("https://app.example.test/jwks")
  );
  assert_eq!(created.contacts, Some(json!(["ops@example.test"])));
  assert_eq!(
    created.request_uris,
    Some(json!(["https://app.example.test/request"]))
  );
  assert_eq!(created.software_id.as_deref(), Some("sw-1"));
  assert_eq!(
    created.tls_client_auth_subject_dn.as_deref(),
    Some("CN=round-trip, O=Example")
  );
  assert_eq!(
    created.tls_client_auth_cert_thumbprint.as_deref(),
    Some("round-trip-thumb")
  );

  // Encrypt-only: no PII plaintext at rest, ciphertext + blind indexes set.
  let at_rest = sqlx::query(
    "SELECT client_name, client_name_enc, contacts, contacts_enc, jwks_uri, jwks_uri_enc, \
       tls_client_auth_subject_dn, tls_client_auth_subject_dn_enc, \
       tls_client_auth_subject_dn_index, tls_client_auth_cert_thumbprint, \
       tls_client_auth_cert_thumbprint_enc, tls_client_auth_cert_thumbprint_index \
     FROM oauth_clients WHERE client_id = 'client-round-trip'",
  )
  .fetch_one(&pool)
  .await?;
  use sqlx::Row as _;
  let name_plain: Option<String> = at_rest.try_get("client_name")?;
  let name_enc: Option<Vec<u8>> = at_rest.try_get("client_name_enc")?;
  let contacts_plain: Option<serde_json::Value> = at_rest.try_get("contacts")?;
  let contacts_enc: Option<Vec<u8>> = at_rest.try_get("contacts_enc")?;
  let jwks_uri_plain: Option<String> = at_rest.try_get("jwks_uri")?;
  let jwks_uri_enc: Option<Vec<u8>> = at_rest.try_get("jwks_uri_enc")?;
  let dn_plain: Option<String> = at_rest.try_get("tls_client_auth_subject_dn")?;
  let dn_enc: Option<Vec<u8>> = at_rest.try_get("tls_client_auth_subject_dn_enc")?;
  let dn_index: Option<String> = at_rest.try_get("tls_client_auth_subject_dn_index")?;
  let thumb_plain: Option<String> = at_rest.try_get("tls_client_auth_cert_thumbprint")?;
  let thumb_enc: Option<Vec<u8>> = at_rest.try_get("tls_client_auth_cert_thumbprint_enc")?;
  let thumb_index: Option<String> = at_rest.try_get("tls_client_auth_cert_thumbprint_index")?;
  assert_eq!(name_plain, None);
  assert!(name_enc.is_some());
  assert_eq!(contacts_plain, None);
  assert!(contacts_enc.is_some());
  assert_eq!(jwks_uri_plain, None);
  assert!(jwks_uri_enc.is_some());
  assert_eq!(dn_plain, None);
  assert!(dn_enc.is_some());
  assert!(dn_index.is_some());
  assert_eq!(thumb_plain, None);
  assert!(thumb_enc.is_some());
  assert!(thumb_index.is_some());
  // Ciphertext never embeds the cleartext.
  let enc = name_enc.ok_or("missing client_name_enc")?;
  assert!(
    !enc
      .windows("Test Client".len())
      .any(|window| window == b"Test Client")
  );

  let by_client_id = find_active_by_client_id(&pool, &keys, "client-round-trip").await?;
  assert_eq!(by_client_id, Some(created.clone()));
  let by_id = find_by_id(&pool, &keys, created.id).await?;
  assert_eq!(by_id, Some(created.clone()));

  let listed = list(&pool, &keys, false).await?;
  assert!(listed.iter().any(|client| client.id == created.id));

  // Unknown keys resolve to None, not an error.
  assert_eq!(find_active_by_client_id(&pool, &keys, "nope").await?, None);
  assert_eq!(find_by_id(&pool, &keys, Uuid::new_v4()).await?, None);
  Ok(())
}

/// A deactivated client is hidden from active lookups and the active list but
/// still visible by id / with `include_inactive`.
#[tokio::test]
async fn client_repo_deactivated_client_is_hidden() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let created = insert(&pool, &keys, false, &confidential("client-gone")).await?;

  assert!(deactivate(&pool, "client-gone").await?);
  // A second deactivate changes nothing.
  assert!(!deactivate(&pool, "client-gone").await?);

  assert_eq!(
    find_active_by_client_id(&pool, &keys, "client-gone").await?,
    None
  );
  let by_id = find_by_id(&pool, &keys, created.id).await?;
  assert!(matches!(&by_id, Some(client) if !client.active));
  assert!(
    !list(&pool, &keys, false)
      .await?
      .iter()
      .any(|client| client.client_id == "client-gone")
  );
  assert!(
    list(&pool, &keys, true)
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
  let keys = test_keys()?;
  let mut client = confidential("client-secret");
  client.client_secret_hash = Some(hashed("correct-horse")?);
  insert(&pool, &keys, false, &client).await?;

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
  insert(&pool, &keys, false, &public).await?;
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
  let keys = test_keys()?;
  let mut new = confidential("client-update");
  new.client_secret_hash = Some(hashed("keep-me")?);
  let created = insert(&pool, &keys, false, &new).await?;

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
  let updated = update_metadata(&pool, &keys, false, "client-update", &meta).await?;
  let updated = updated.ok_or("update returned None")?;
  assert_eq!(updated.id, created.id);
  assert_eq!(updated.client_name, "Renamed");
  assert_eq!(updated.scope, "api:admin");
  assert_eq!(updated.contacts, Some(json!(["soc@example.test"])));
  assert_eq!(
    updated.request_uris,
    Some(json!(["https://app.example.test/r"]))
  );
  assert_eq!(updated.software_id.as_deref(), Some("sw-2"));
  assert_eq!(
    updated.tls_client_auth_subject_dn.as_deref(),
    Some("CN=client-update")
  );
  assert_eq!(
    updated.tls_client_auth_cert_thumbprint.as_deref(),
    Some("abc123")
  );
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
  assert!(
    update_metadata(&pool, &keys, false, "missing", &meta)
      .await?
      .is_none()
  );
  Ok(())
}

/// Attached+enabled redirect URIs (sealed or legacy plaintext) and registered+
/// enabled scopes are allowed.
#[tokio::test]
async fn client_repo_redirect_and_scope_rules() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert(&pool, &keys, false, &confidential("client-rules")).await?;
  insert_scope(&pool, "api:read", true).await?;
  insert_scope(&pool, "api:disabled", false).await?;

  // Encrypt-only catalog row: `uri_enc` + `uri_index`, plaintext `uri` blanked.
  let (sealed, _) = redirect_repo::upsert(
    &pool,
    &keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri: "https://app.example.test/cb",
      kind: redirect_repo::RedirectKind::Authorize,
      description: "",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(&pool, "client-rules", sealed.id, None).await?;

  // Legacy NULL-index row: plaintext only, no ciphertext and no index.
  let legacy_id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, description, created_by, created_at, updated_at) \
     VALUES ($1, $2, 'authorize', '', NULL, now(), now())",
  )
  .bind(legacy_id)
  .bind("https://legacy.example.test/cb")
  .execute(&pool)
  .await?;
  redirect_repo::attach(&pool, "client-rules", legacy_id, None).await?;

  // Both the sealed row and the legacy plaintext row match.
  assert!(redirect_uri_allowed(&pool, &keys, "client-rules", "https://app.example.test/cb").await?);
  assert!(
    redirect_uri_allowed(
      &pool,
      &keys,
      "client-rules",
      "https://legacy.example.test/cb"
    )
    .await?
  );

  // An unknown URI, and an enabled-but-unattached catalog URI, do not match.
  let _ = redirect_repo::upsert(
    &pool,
    &keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri: "https://unattached.example.test/cb",
      kind: redirect_repo::RedirectKind::Authorize,
      description: "",
      created_by: None,
    },
  )
  .await?;
  assert!(
    !redirect_uri_allowed(&pool, &keys, "client-rules", "https://evil.example.test/cb").await?
  );
  assert!(
    !redirect_uri_allowed(
      &pool,
      &keys,
      "client-rules",
      "https://unattached.example.test/cb"
    )
    .await?
  );

  // Disabling the sealed catalog entry removes it from the effective set.
  redirect_repo::disable(&pool, &keys, sealed.id).await?;
  assert!(
    !redirect_uri_allowed(&pool, &keys, "client-rules", "https://app.example.test/cb").await?
  );

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
  let keys = test_keys()?;
  let mut new = confidential("client-reg");
  new.registration_access_token_hash = Some("v1.initial".to_owned());
  let created = insert(&pool, &keys, false, &new).await?;

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

/// A duplicate mTLS identity is rejected with the payload-free typed error,
/// which renders `invalid_client_metadata` (400) — never a 500.
#[tokio::test]
async fn client_repo_tls_identity_index_unique() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let mut first = confidential("client-tls-a");
  first.tls_client_auth_subject_dn = Some("CN=alpha, O=Example".to_owned());
  first.tls_client_auth_cert_thumbprint = Some("thumb-alpha".to_owned());
  insert(&pool, &keys, false, &first).await?;

  // A distinct identity inserts cleanly.
  let mut other = confidential("client-tls-b");
  other.tls_client_auth_subject_dn = Some("CN=beta, O=Example".to_owned());
  other.tls_client_auth_cert_thumbprint = Some("thumb-beta".to_owned());
  insert(&pool, &keys, false, &other).await?;

  // A duplicate subject DN is rejected without any identity payload.
  let mut dupe_dn = confidential("client-tls-dupe-dn");
  dupe_dn.tls_client_auth_subject_dn = Some("CN=alpha, O=Example".to_owned());
  let error = match insert(&pool, &keys, false, &dupe_dn).await {
    Ok(_) => return Err("duplicate subject DN accepted".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::DuplicateClientIdentity));
  assert_eq!(error.code(), OAuthErrorCode::InvalidClientMetadata);
  assert_eq!(error.status(), axum::http::StatusCode::BAD_REQUEST);
  assert!(!format!("{error:?}").contains("CN=alpha"));

  // A duplicate thumbprint is rejected the same way.
  let mut dupe_thumb = confidential("client-tls-dupe-thumb");
  dupe_thumb.tls_client_auth_cert_thumbprint = Some("thumb-alpha".to_owned());
  let error = match insert(&pool, &keys, false, &dupe_thumb).await {
    Ok(_) => return Err("duplicate thumbprint accepted".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::DuplicateClientIdentity));
  assert_eq!(error.code(), OAuthErrorCode::InvalidClientMetadata);
  Ok(())
}

/// A row with NULL `_enc` (simulated N-1) still reads via the plaintext.
#[tokio::test]
async fn client_repo_decrypts_legacy_plaintext_row() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_legacy(
    &pool,
    "client-legacy",
    Some("CN=legacy, O=Example"),
    Some("thumb-legacy"),
  )
  .await?;

  let found = find_active_by_client_id(&pool, &keys, "client-legacy")
    .await?
    .ok_or("legacy row missing")?;
  assert_eq!(found.client_name, "Legacy Client");
  assert_eq!(
    found.tls_client_auth_subject_dn.as_deref(),
    Some("CN=legacy, O=Example")
  );
  assert_eq!(
    found.tls_client_auth_cert_thumbprint.as_deref(),
    Some("thumb-legacy")
  );
  assert_eq!(
    found.jwks_uri.as_deref(),
    Some("https://legacy.example.test/jwks")
  );
  assert_eq!(found.software_id.as_deref(), Some("sw-legacy"));

  let listed = list(&pool, &keys, false).await?;
  assert!(
    listed
      .iter()
      .any(|client| client.client_id == "client-legacy")
  );
  Ok(())
}

/// A duplicate identity against a legacy NULL-index row is rejected: the
/// partial unique index alone would miss it, the dual-predicate pre-check
/// catches it.
#[tokio::test]
async fn client_repo_rejects_duplicate_vs_legacy_identity() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_legacy(&pool, "client-legacy-dn", Some("CN=taken, O=Example"), None).await?;
  insert_legacy(&pool, "client-legacy-thumb", None, Some("thumb-taken")).await?;

  let mut dupe_dn = confidential("client-new-dn");
  dupe_dn.tls_client_auth_subject_dn = Some("CN=taken, O=Example".to_owned());
  let error = match insert(&pool, &keys, false, &dupe_dn).await {
    Ok(_) => return Err("duplicate legacy DN accepted".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::DuplicateClientIdentity));

  let mut dupe_thumb = confidential("client-new-thumb");
  dupe_thumb.tls_client_auth_cert_thumbprint = Some("thumb-taken".to_owned());
  let error = match insert(&pool, &keys, false, &dupe_thumb).await {
    Ok(_) => return Err("duplicate legacy thumbprint accepted".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::DuplicateClientIdentity));
  Ok(())
}

/// `update_metadata` rejects an identity taken by a legacy NULL-index row
/// (excluding the row itself), yet accepts a rewrite of the client's own
/// unchanged DN.
#[tokio::test]
async fn client_repo_update_metadata_rejects_duplicate_vs_legacy_identity() -> Result<(), TestError>
{
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert_legacy(
    &pool,
    "client-legacy-holder",
    Some("CN=held, O=Example"),
    None,
  )
  .await?;

  let mut new = confidential("client-owned");
  new.tls_client_auth_subject_dn = Some("CN=owned, O=Example".to_owned());
  insert(&pool, &keys, false, &new).await?;

  // Rewriting the client's OWN unchanged DN succeeds (self-exclusion).
  let mut same = ClientMetadata {
    client_name: "Owned".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: "api:read".to_owned(),
    token_endpoint_auth_method: "tls_client_auth".to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: Some("CN=owned, O=Example".to_owned()),
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
  };
  let kept = update_metadata(&pool, &keys, false, "client-owned", &same)
    .await?
    .ok_or("self-update returned None")?;
  assert_eq!(
    kept.tls_client_auth_subject_dn.as_deref(),
    Some("CN=owned, O=Example")
  );

  // Claiming the legacy row's DN is rejected.
  same.tls_client_auth_subject_dn = Some("CN=held, O=Example".to_owned());
  let error = match update_metadata(&pool, &keys, false, "client-owned", &same).await {
    Ok(_) => return Err("duplicate legacy DN update accepted".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::DuplicateClientIdentity));
  Ok(())
}

/// A corrupt `client_name_enc` fails closed with `PiiDecrypt` (503), never
/// a 500 and never a plaintext fallback.
#[tokio::test]
async fn client_repo_corrupt_ciphertext_fails_closed() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  insert(&pool, &keys, false, &confidential("client-corrupt")).await?;

  sqlx::query("UPDATE oauth_clients SET client_name_enc = decode('00', 'hex') WHERE client_id = 'client-corrupt'")
    .execute(&pool)
    .await?;
  let error = match find_active_by_client_id(&pool, &keys, "client-corrupt").await {
    Ok(_) => return Err("corrupt ciphertext read succeeded".into()),
    Err(error) => error,
  };
  assert!(matches!(error, AppError::PiiDecrypt));
  assert_eq!(error.code(), OAuthErrorCode::TemporarilyUnavailable);
  assert_eq!(error.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
  Ok(())
}

/// `Debug` of a populated projection exposes no PII.
#[tokio::test]
async fn client_repo_debug_redacts_pii() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let mut new = confidential("client-debug");
  new.client_name = "Ada Lovelace".to_owned();
  new.jwks_uri = Some("https://app.example.test/jwks".to_owned());
  new.contacts = Some(json!(["ada@example.test"]));
  new.request_uris = Some(json!(["https://app.example.test/r"]));
  new.software_id = Some("sw-debug".to_owned());
  new.tls_client_auth_subject_dn = Some("CN=debug, O=Example".to_owned());
  new.tls_client_auth_cert_thumbprint = Some("debug-thumb".to_owned());
  let created = insert(&pool, &keys, false, &new).await?;

  let rendered = format!("{created:?}");
  for secret in [
    "Ada Lovelace",
    "https://app.example.test/jwks",
    "ada@example.test",
    "https://app.example.test/r",
    "sw-debug",
    "CN=debug, O=Example",
    "debug-thumb",
  ] {
    assert!(!rendered.contains(secret), "Debug leaked PII: {secret}");
  }

  let meta = ClientMetadata {
    client_name: "Ada Lovelace".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: "none".to_owned(),
    jwks: None,
    jwks_uri: Some("https://app.example.test/jwks".to_owned()),
    tls_client_auth_subject_dn: Some("CN=debug, O=Example".to_owned()),
    tls_client_auth_cert_thumbprint: Some("debug-thumb".to_owned()),
    request_uris: Some(json!(["https://app.example.test/r"])),
    contacts: Some(json!(["ada@example.test"])),
    software_id: Some("sw-debug".to_owned()),
    dpop_bound_access_tokens: false,
  };
  let rendered = format!("{meta:?}");
  for secret in [
    "Ada Lovelace",
    "https://app.example.test/jwks",
    "ada@example.test",
    "CN=debug, O=Example",
    "debug-thumb",
  ] {
    assert!(!rendered.contains(secret), "Debug leaked PII: {secret}");
  }
  Ok(())
}

//! `test(cli)` suite: config validation, user provisioning, token issuance,
//! TOTP encryption, scope grants, idempotent config sync, and audit emission.

use std::{net::IpAddr, sync::Arc};

use base64::Engine as _;
use clap::Parser as _;
use ring::{
  aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
  hkdf,
  rand::{SecureRandom as _, SystemRandom},
};
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::Row as _;
use time::OffsetDateTime;

use super::{
  Cli, CliError, ClientCommand, Command, RedirectUriCommand, ResourceServerCommand, ScopeCommand,
  UserCommand, admin, ops, redirect, resource, scope, secret,
  sync::{ClientTokenFormatEntry, RedirectEntry, ResourceServerEntry, ScopeEntry, SyncFile},
  test_support::{self, TestError},
  user,
};
use crate::{
  config::Config,
  crypto::totp,
  db::{client_repo, redirect_repo, resource_repo, user_repo},
  keys::{KeyId, KeyRing},
  state::{AppState, RedisConn},
  ui::login::{
    CHANGE_PASSWORD_PATH, ConfirmOutcome, LoginAttempt, LoginDeps, LoginOutcome, PasswordOutcome,
    attempt_login, change_password, confirm_totp, ensure_presession, load_session,
    login_csrf_token, provision_totp, restricted_allows_path,
  },
};

/// Fresh migrated database plus a fast-argon2 config for bootstrap tests.
///
/// Each test owns its database (via the shared Postgres server), so parallel
/// bootstrap tests stay isolated and every test starts with zero admins.
/// The config's database URL is a dummy: bootstrap and login cores take the
/// pool directly and only read hashing/key/TTL settings from the config.
async fn bootstrap_setup(
  redis_url: &str,
) -> Result<
  (
    crate::test_guard::Lease<crate::db::test_support::Db>,
    sqlx::PgPool,
    Arc<Config>,
  ),
  TestError,
> {
  let (db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/bootstrap-test-cert.pem", "key_path": "/tmp/bootstrap-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/bootstrap"},
    "redis": {
      "url": redis_url,
      "durability": "waitaof",
      "token_key_prefix": state_prefix,
      "ratelimit_key_prefix": rl_prefix,
    },
    "token_pepper": "bootstrap-test-pepper-0123456789abcdef",
    "totp_encryption_key": "bootstrap-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "bootstrap-test-pii-key-0123456789abcdef",
    "argon2": {"memory_kib": 8192, "iterations": 1, "parallelism": 1},
  });
  let source = ::config::Config::try_from(&fixture)?;
  let config = Arc::new(Config::from_source(source)?);
  Ok((db, pool, config))
}

const PASSWORD: &str = "correct-horse-battery-staple";

#[test]
fn cli_config_check_exits_nonzero_on_bad_config() {
  let result = ops::ensure_config(Err(crate::config::ConfigError::MissingIssuer));
  assert!(result.is_err());
}

#[tokio::test]
async fn cli_user_create_inserts_user() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("create");
  user::create(&context, &email, true, PASSWORD).await?;

  let found = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("created user"))?;
  assert!(found.is_admin);
  assert!(found.must_change_password);
  let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
    .bind(found.id)
    .fetch_one(context.pool())
    .await?;
  assert!(hash.starts_with("$argon2id$"));
  assert!(!hash.contains(PASSWORD));
  Ok(())
}

#[tokio::test]
async fn cli_user_create_duplicate_email_fails() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("duplicate");
  user::create(&context, &email, false, PASSWORD).await?;
  let upper = email.to_uppercase();
  let second = user::create(&context, &upper, false, PASSWORD).await;
  assert!(matches!(
    second,
    Err(super::context::CliError::AlreadyExists(_))
  ));
  Ok(())
}

#[tokio::test]
async fn cli_user_create_and_lookup() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("create-lookup");
  user::create(&context, &email, false, PASSWORD).await?;

  // The lookup resolves through the encrypted repository (blind index); the
  // plaintext `email` column may be NULL, so only the sealed row proves it.
  let id = user::find_user_id(&context, &email).await?;
  let record = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("created user"))?;
  assert_eq!(record.id, id);
  assert_eq!(record.email, email.to_lowercase());

  // Case-insensitive lookup through the same encrypted path.
  let upper_id = user::find_user_id(&context, &email.to_uppercase()).await?;
  assert_eq!(upper_id, id);

  // A duplicate create maps to `AlreadyExists` with a payload-free message:
  // the CLI error must never carry the email address.
  match user::create(&context, &email, false, PASSWORD).await {
    Err(super::context::CliError::AlreadyExists(message)) => {
      assert!(
        !message.contains(&email) && !message.contains(&email.to_lowercase()),
        "duplicate error leaked the email: {message}"
      );
    }
    Err(other) => return Err(TestError::Harness(format!("unexpected error: {other:?}"))),
    Ok(()) => return Err(TestError::Missing("duplicate create must fail")),
  }

  // A missing user is a clean, payload-free not-found.
  let missing = test_support::unique_email("create-lookup-missing");
  match user::find_user_id(&context, &missing).await {
    Err(super::context::CliError::NotFound(message)) => {
      assert!(
        !message.contains('@') && !message.contains(&missing),
        "not-found error leaked the email: {message}"
      );
    }
    Err(other) => return Err(TestError::Harness(format!("unexpected error: {other:?}"))),
    Ok(_) => return Err(TestError::Missing("missing user must be NotFound")),
  }
  Ok(())
}

#[tokio::test]
async fn cli_initial_access_token_stores_only_hash() -> Result<(), TestError> {
  let harness = test_support::harness().await?;
  let token = ops::issue_with(harness.config.clone(), 3, 600, "cli-test").await?;
  let hash = secret::token_hash(&harness.config, token.as_str())?;
  assert_ne!(hash.as_str(), token.as_str());

  let store = crate::store::Store::from_config(&harness.config.redis);
  let mut conn = AppState::connect(harness.config.clone())
    .await?
    .redis
    .clone();

  let key = store.dcr_iat_key(&hash);
  let present: i64 = redis::cmd("EXISTS")
    .arg(&key)
    .query_async(&mut conn)
    .await?;
  assert_eq!(present, 1);

  let raw_key = store.dcr_iat_key(token.as_str());
  let raw_present: i64 = redis::cmd("EXISTS")
    .arg(&raw_key)
    .query_async(&mut conn)
    .await?;
  assert_eq!(raw_present, 0);

  let fields: Vec<String> = redis::cmd("HGETALL")
    .arg(&key)
    .query_async(&mut conn)
    .await?;
  assert!(fields.iter().all(|field| !field.contains(token.as_str())));
  Ok(())
}

#[tokio::test]
async fn cli_user_enroll_totp_stores_encrypted_secret() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("totp");
  user::create(&context, &email, false, PASSWORD).await?;

  let enrollment = user::enroll_totp(&context, &email).await?;
  let user = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("created user"))?;
  let (blob, enabled): (Option<Vec<u8>>, bool) =
    sqlx::query_as("SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1")
      .bind(user.id)
      .fetch_one(context.pool())
      .await?;

  let blob = blob.ok_or(TestError::Missing("totp_secret_enc"))?;
  assert!(enabled);
  assert!(!blob.is_empty());
  assert!(
    !blob
      .windows(enrollment.secret.len())
      .any(|window| window == enrollment.secret.as_bytes()),
    "plaintext TOTP secret found in stored blob"
  );
  let decrypted = secret::decrypt_totp(context.config(), &blob)?;
  assert_eq!(decrypted.as_str(), enrollment.secret.as_str());
  assert!(enrollment.uri.starts_with("otpauth://totp/"));
  Ok(())
}

#[tokio::test]
async fn cli_totp_v3_cross_decrypts() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let config = context.config();
  let plaintext = secret::generate_totp_secret()?;

  // CLI -> crypto: a v3 envelope the CLI wrote opens under crypto::totp.
  let cli_blob = secret::encrypt_totp(config, plaintext.as_str(), true)?;
  assert_eq!(
    cli_blob.first().copied(),
    Some(3),
    "CLI envelope write must be v3"
  );
  assert_eq!(
    totp::decrypt_secret(&config.keys, &cli_blob)?.as_str(),
    plaintext.as_str()
  );

  // CLI round-trips through its own reader.
  assert_eq!(
    secret::decrypt_totp(config, &cli_blob)?.as_str(),
    plaintext.as_str()
  );

  // crypto -> CLI: a v3 envelope crypto wrote opens under the CLI.
  let crypto_blob = totp::encrypt_secret(&config.keys, plaintext.as_str(), true)?;
  assert_eq!(crypto_blob.first().copied(), Some(3));
  assert_eq!(
    secret::decrypt_totp(config, &crypto_blob)?.as_str(),
    plaintext.as_str()
  );

  // The version gate keeps the legacy v2 write cross-compatible too.
  let legacy = secret::encrypt_totp(config, plaintext.as_str(), false)?;
  assert_eq!(
    legacy.first().copied(),
    Some(2),
    "gated CLI write must stay v2"
  );
  assert_eq!(
    totp::decrypt_secret(&config.keys, &legacy)?.as_str(),
    plaintext.as_str()
  );
  assert_eq!(
    secret::decrypt_totp(config, &legacy)?.as_str(),
    plaintext.as_str()
  );

  // Data AAD excludes the kid: re-wrap the DEK under a different kid (same key
  // material) leaving the data nonce and ciphertext byte-identical, and the
  // crypto reader still opens it — which holds only if the data seal never
  // bound the wrapping kid. This is what `totp rewrap` relies on.
  let (kid, material) = config
    .keys
    .active_totp_key()
    .ok_or(TestError::Missing("active TOTP key"))?;
  let target = KeyId::new("v99");
  let rewrapped = rewrap_v3(&cli_blob, kid.as_str(), material, target.as_str())?;
  let ring = key_ring_with_totp(&config.keys, target, material)?;
  assert_eq!(
    totp::decrypt_secret(&ring, &rewrapped)?.as_str(),
    plaintext.as_str()
  );

  // A truncated blob fails closed without leaking plaintext.
  let truncated = &cli_blob[..12];
  assert!(secret::decrypt_totp(config, truncated).is_err());
  assert!(
    !truncated
      .windows(plaintext.len())
      .any(|window| window == plaintext.as_bytes())
  );
  Ok(())
}

/// Re-wrap a v3 envelope's DEK under `target_kid`, keeping the data nonce and
/// ciphertext untouched. Mirrors `crypto::totp::wrap_aad` / `derive_labeled`.
fn rewrap_v3(
  blob: &[u8],
  source_kid: &str,
  material: &SecretString,
  target_kid: &str,
) -> Result<Vec<u8>, TestError> {
  const NONCE_LEN: usize = 12;
  const WRAPPED_DEK_LEN: usize = 48;

  let header = 2 + usize::from(blob[1]);
  let wrap_nonce = &blob[header..header + NONCE_LEN];
  let wrapped_dek = &blob[header + NONCE_LEN..header + NONCE_LEN + WRAPPED_DEK_LEN];
  let data_start = header + NONCE_LEN + WRAPPED_DEK_LEN;
  let data_nonce = &blob[data_start..data_start + NONCE_LEN];
  let data_ct = &blob[data_start + NONCE_LEN..];

  let kek = totp_derive_kek(material.expose_secret().as_bytes())?;
  let dek = totp_open(
    &kek,
    wrap_nonce,
    &totp_wrap_aad(source_kid.as_bytes(), data_nonce),
    wrapped_dek,
  )?;

  let mut new_wrap_nonce = [0u8; NONCE_LEN];
  SystemRandom::new()
    .fill(&mut new_wrap_nonce)
    .map_err(|_| TestError::Harness("operating-system randomness unavailable".to_owned()))?;
  let mut new_wrapped = dek;
  totp_seal(
    &kek,
    &new_wrap_nonce,
    &totp_wrap_aad(target_kid.as_bytes(), data_nonce),
    &mut new_wrapped,
  )?;

  if target_kid.len() > usize::from(u8::MAX) {
    return Err(TestError::Harness("target kid too long".to_owned()));
  }
  let mut out = Vec::new();
  out.push(3u8);
  out.push(target_kid.len() as u8);
  out.extend_from_slice(target_kid.as_bytes());
  out.extend_from_slice(&new_wrap_nonce);
  out.extend_from_slice(&new_wrapped);
  out.extend_from_slice(data_nonce);
  out.extend_from_slice(data_ct);
  Ok(out)
}

/// Build a ring whose only TOTP key is `id` -> `material`, reusing the source
/// ring's pepper and PII chains.
fn key_ring_with_totp(
  source: &KeyRing,
  id: KeyId,
  material: &SecretString,
) -> Result<KeyRing, TestError> {
  let peppers = source
    .peppers_newest_first()
    .map(|(id, secret)| (id.clone(), secret.clone()))
    .collect();
  let pii_keys = source
    .pii_keys_newest_first()
    .map(|(id, secret)| (id.clone(), secret.clone()))
    .collect();
  KeyRing::from_parts(peppers, vec![(id, material.clone())], pii_keys)
    .map_err(|error| TestError::Harness(error.to_string()))
}

/// `wrap_aad = b"totp-v3\x03" || [kid_len] || kid || data_nonce`.
fn totp_wrap_aad(kid: &[u8], data_nonce: &[u8]) -> Vec<u8> {
  let mut aad = Vec::with_capacity(9 + kid.len() + data_nonce.len());
  aad.extend_from_slice(b"totp-v3\x03");
  aad.push(kid.len() as u8);
  aad.extend_from_slice(kid);
  aad.extend_from_slice(data_nonce);
  aad
}

/// HKDF-SHA256(ikm, info `totp-kek-v1`), matching `crypto::totp`.
fn totp_derive_kek(ikm: &[u8]) -> Result<[u8; 32], TestError> {
  let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(ikm);
  let info_labels = [b"totp-kek-v1".as_slice()];
  let okm = prk
    .expand(&info_labels, TotpHkdfKey)
    .map_err(|_| TestError::Harness("TOTP KEK derivation failed".to_owned()))?;
  let mut key = [0u8; 32];
  okm
    .fill(&mut key)
    .map_err(|_| TestError::Harness("TOTP KEK derivation failed".to_owned()))?;
  Ok(key)
}

fn totp_open(
  key: &[u8; 32],
  nonce: &[u8],
  aad: &[u8],
  ciphertext: &[u8],
) -> Result<Vec<u8>, TestError> {
  let mut nonce_bytes = [0u8; 12];
  nonce_bytes.copy_from_slice(nonce);
  let mut in_out = ciphertext.to_vec();
  let opening = LessSafeKey::new(
    UnboundKey::new(&AES_256_GCM, key)
      .map_err(|_| TestError::Harness("TOTP key rejected by AEAD".to_owned()))?,
  );
  let plaintext = opening
    .open_in_place(
      Nonce::assume_unique_for_key(nonce_bytes),
      Aad::from(aad),
      &mut in_out,
    )
    .map_err(|_| TestError::Harness("TOTP DEK unwrap failed".to_owned()))?;
  Ok(plaintext.to_vec())
}

fn totp_seal(
  key: &[u8; 32],
  nonce: &[u8; 12],
  aad: &[u8],
  in_out: &mut Vec<u8>,
) -> Result<(), TestError> {
  let sealing = LessSafeKey::new(
    UnboundKey::new(&AES_256_GCM, key)
      .map_err(|_| TestError::Harness("TOTP key rejected by AEAD".to_owned()))?,
  );
  sealing
    .seal_in_place_append_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), in_out)
    .map_err(|_| TestError::Harness("TOTP DEK wrap failed".to_owned()))
}

/// `ring::hkdf` output-length marker for a 256-bit AES key.
struct TotpHkdfKey;

impl hkdf::KeyType for TotpHkdfKey {
  fn len(&self) -> usize {
    32
  }
}

#[tokio::test]
async fn cli_scope_create_and_grant_take_effect() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("grant");
  let scope_name = test_support::unique_name("orders:read");
  user::create(&context, &email, false, PASSWORD).await?;

  scope::run(
    &context,
    ScopeCommand::Create {
      name: scope_name.clone(),
      description: Some("read orders".to_owned()),
    },
  )
  .await?;
  user::grant_scope(&context, &email, &scope_name).await?;

  let scopes = user::list_scopes(&context, &email).await?;
  assert_eq!(scopes, vec![scope_name.clone()]);

  user::revoke_scope(&context, &email, &scope_name).await?;
  assert!(user::list_scopes(&context, &email).await?.is_empty());
  Ok(())
}

#[tokio::test]
async fn cli_config_sync_is_idempotent() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let scope_name = test_support::unique_name("sync");
  let uri = format!("https://{}.example.test/cb", uuid::Uuid::new_v4());
  let file = SyncFile {
    scopes: vec![ScopeEntry {
      name: scope_name.clone(),
      description: Some("synced".to_owned()),
      enabled: true,
    }],
    redirect_uris: vec![RedirectEntry {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
      description: None,
      enabled: true,
    }],
    user_scopes: Vec::new(),
    client_redirect_uris: Vec::new(),
    resource_servers: Vec::new(),
    client_access_token_formats: Vec::new(),
  };

  let first = super::sync::apply(&context, &file).await?;
  assert_eq!(first.scopes_created, 1);
  assert_eq!(first.redirects_created, 1);

  let before: OffsetDateTime = sqlx::query_scalar("SELECT updated_at FROM scopes WHERE name = $1")
    .bind(&scope_name)
    .fetch_one(context.pool())
    .await?;

  let second = super::sync::apply(&context, &file).await?;
  assert!(second.is_noop(), "second sync changed rows: {second}");

  let after: OffsetDateTime = sqlx::query_scalar("SELECT updated_at FROM scopes WHERE name = $1")
    .bind(&scope_name)
    .fetch_one(context.pool())
    .await?;
  assert_eq!(before, after, "idempotent sync must not touch updated_at");
  Ok(())
}

/// Insert a minimal client so redirect attachments satisfy their FKs.
async fn insert_redirect_client(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<(), TestError> {
  client_repo::insert(
    pool,
    keys,
    false,
    &client_repo::NewClient {
      id: uuid::Uuid::new_v4(),
      client_id: client_id.to_owned(),
      client_secret_hash: None,
      client_secret_expires_at: None,
      client_name: "CLI Redirect Client".to_owned(),
      grant_types: vec!["authorization_code".to_owned()],
      response_types: vec!["code".to_owned()],
      scope: String::new(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
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
  Ok(())
}

/// `config sync` writes redirect URIs through the encrypted repository:
/// created-vs-updated is preserved, a second identical apply is a true no-op,
/// and an existing row's description/enabled are never overwritten.
#[tokio::test]
async fn config_sync_redirects() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let keys = &context.config().keys;
  let uri = format!("https://{}.example.test/synced", uuid::Uuid::new_v4());
  let file = SyncFile {
    scopes: Vec::new(),
    redirect_uris: vec![RedirectEntry {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
      description: Some("synced".to_owned()),
      enabled: true,
    }],
    user_scopes: Vec::new(),
    client_redirect_uris: Vec::new(),
    resource_servers: Vec::new(),
    client_access_token_formats: Vec::new(),
  };

  let first = super::sync::apply(&context, &file).await?;
  assert_eq!(first.redirects_created, 1);
  assert_eq!(first.redirects_updated, 0);

  // Encrypt-only at rest: plaintext blank, ciphertext + blind index present.
  let id = redirect::find_redirect_id(&context, &uri, "authorize").await?;
  let stored = sqlx::query(
    "SELECT uri, uri_enc, uri_index, description, enabled FROM redirect_uris WHERE id = $1",
  )
  .bind(id)
  .fetch_one(context.pool())
  .await?;
  assert!(stored.try_get::<Option<String>, _>("uri")?.is_none());
  assert!(stored.try_get::<Option<Vec<u8>>, _>("uri_enc")?.is_some());
  assert!(stored.try_get::<Option<String>, _>("uri_index")?.is_some());
  assert_eq!(stored.try_get::<String, _>("description")?, "synced");
  assert!(stored.try_get::<bool, _>("enabled")?);

  // A second identical apply changes nothing.
  let second = super::sync::apply(&context, &file).await?;
  assert!(second.is_noop(), "second sync must be a no-op: {second}");

  // A legacy NULL-index row is adopted as Updated (not Created) and keeps its
  // original description and disabled state.
  let legacy_uri = format!("https://legacy-{}.example.test/cb", uuid::Uuid::new_v4());
  let legacy_id = uuid::Uuid::new_v4();
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, description, enabled, created_at, updated_at) \
     VALUES ($1, $2, 'authorize', 'legacy', false, now(), now())",
  )
  .bind(legacy_id)
  .bind(&legacy_uri)
  .execute(context.pool())
  .await?;
  let adopt = SyncFile {
    redirect_uris: vec![RedirectEntry {
      uri: legacy_uri.clone(),
      kind: "authorize".to_owned(),
      description: Some("declared".to_owned()),
      enabled: true,
    }],
    ..SyncFile::default()
  };
  let third = super::sync::apply(&context, &adopt).await?;
  assert_eq!(third.redirects_created, 0);
  assert_eq!(third.redirects_updated, 1);

  let adopted = redirect_repo::list(context.pool(), keys, true)
    .await?
    .into_iter()
    .find(|entry| entry.id == legacy_id)
    .ok_or(TestError::Missing("adopted legacy redirect"))?;
  assert_eq!(adopted.uri, legacy_uri);
  assert_eq!(
    adopted.description, "legacy",
    "sync must not overwrite description"
  );
  assert!(!adopted.enabled, "sync must not re-enable an existing row");
  let sealed: Option<Vec<u8>> =
    sqlx::query_scalar("SELECT uri_enc FROM redirect_uris WHERE id = $1")
      .bind(legacy_id)
      .fetch_one(context.pool())
      .await?;
  assert!(sealed.is_some(), "legacy row must be sealed after adoption");
  Ok(())
}

/// The CLI upsert/list/enable/disable/attach/detach round-trip through
/// ciphertext: a sealed row is idempotent, a legacy NULL-index row is adopted,
/// deleting an attached URI disables instead of deleting, and an unknown URI is
/// a clean not-found.
#[tokio::test]
async fn cli_redirect_upsert_and_attach() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let keys = &context.config().keys;
  let uri = format!("https://{}.example.test/cb", uuid::Uuid::new_v4());

  redirect::run_uri(
    &context,
    RedirectUriCommand::Create {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
      description: Some("initial".to_owned()),
    },
  )
  .await?;
  let id = redirect::find_redirect_id(&context, &uri, "authorize").await?;
  let stored = sqlx::query(
    "SELECT uri, uri_enc, uri_index, description, enabled FROM redirect_uris WHERE id = $1",
  )
  .bind(id)
  .fetch_one(context.pool())
  .await?;
  assert!(stored.try_get::<Option<String>, _>("uri")?.is_none());
  assert!(stored.try_get::<Option<Vec<u8>>, _>("uri_enc")?.is_some());
  assert!(stored.try_get::<Option<String>, _>("uri_index")?.is_some());

  // Disable the row, then re-create the same URI with a different description:
  // it must stay disabled and keep its original description.
  redirect::run_uri(
    &context,
    RedirectUriCommand::Disable {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;
  redirect::run_uri(
    &context,
    RedirectUriCommand::Create {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
      description: Some("changed".to_owned()),
    },
  )
  .await?;
  let preserved = sqlx::query("SELECT description, enabled FROM redirect_uris WHERE id = $1")
    .bind(id)
    .fetch_one(context.pool())
    .await?;
  assert_eq!(preserved.try_get::<String, _>("description")?, "initial");
  assert!(!preserved.try_get::<bool, _>("enabled")?);

  // Re-enable so the attachment is effective.
  redirect::run_uri(
    &context,
    RedirectUriCommand::Enable {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;

  // A legacy NULL-index row resolves through the plaintext fallback and is
  // adopted in place on the next create.
  let legacy_uri = format!("https://legacy-{}.example.test/cb", uuid::Uuid::new_v4());
  let legacy_id = uuid::Uuid::new_v4();
  sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, description, created_at, updated_at) \
     VALUES ($1, $2, 'authorize', 'legacy', now(), now())",
  )
  .bind(legacy_id)
  .bind(&legacy_uri)
  .execute(context.pool())
  .await?;
  assert_eq!(
    redirect::find_redirect_id(&context, &legacy_uri, "authorize").await?,
    legacy_id
  );
  redirect::run_uri(
    &context,
    RedirectUriCommand::Create {
      uri: legacy_uri.clone(),
      kind: "authorize".to_owned(),
      description: Some("adopted".to_owned()),
    },
  )
  .await?;
  let legacy_sealed: Option<Vec<u8>> =
    sqlx::query_scalar("SELECT uri_enc FROM redirect_uris WHERE id = $1")
      .bind(legacy_id)
      .fetch_one(context.pool())
      .await?;
  assert!(legacy_sealed.is_some(), "legacy row must gain ciphertext");

  // Attach through the CLI; then delete disables instead of deleting.
  let client_id = format!("client-{}", uuid::Uuid::new_v4().simple());
  insert_redirect_client(context.pool(), keys, &client_id).await?;
  redirect::run_client(
    &context,
    ClientCommand::AttachRedirectUri {
      client_id: client_id.clone(),
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;
  let attached = redirect_repo::list_for_client(context.pool(), keys, &client_id).await?;
  assert_eq!(attached.len(), 1);
  assert_eq!(attached[0].uri, uri);

  redirect::run_uri(
    &context,
    RedirectUriCommand::Delete {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;
  let disabled = sqlx::query("SELECT enabled FROM redirect_uris WHERE id = $1")
    .bind(id)
    .fetch_one(context.pool())
    .await?;
  assert!(
    !disabled.try_get::<bool, _>("enabled")?,
    "an attached URI must be disabled, not deleted"
  );
  assert!(
    redirect::find_redirect_id(&context, &uri, "authorize")
      .await
      .is_ok()
  );

  // Detach, then delete removes the row.
  redirect::run_client(
    &context,
    ClientCommand::DetachRedirectUri {
      client_id: client_id.clone(),
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;
  redirect::run_uri(
    &context,
    RedirectUriCommand::Delete {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
    },
  )
  .await?;
  assert!(
    redirect::find_redirect_id(&context, &uri, "authorize")
      .await
      .is_err()
  );

  // Draft-ietf-oauth-v2-1-16 §2.3.1: a dotless private-use scheme must be
  // rejected with `CliError::Input`, while reverse-DNS dotted schemes upsert.
  let dotless = redirect::run_uri(
    &context,
    RedirectUriCommand::Create {
      uri: "myapp:/cb".to_owned(),
      kind: "authorize".to_owned(),
      description: None,
    },
  )
  .await;
  assert!(
    matches!(dotless, Err(super::context::CliError::Input(_))),
    "dotless private-use scheme must be rejected"
  );
  if let Err(super::context::CliError::Input(message)) = dotless {
    assert!(
      message.contains("§2.3.1"),
      "rejection must cite §2.3.1, got: {message}"
    );
  }
  redirect::run_uri(
    &context,
    RedirectUriCommand::Create {
      uri: "com.example.app:/cb".to_owned(),
      kind: "authorize".to_owned(),
      description: None,
    },
  )
  .await?;
  assert!(
    redirect::find_redirect_id(&context, "com.example.app:/cb", "authorize")
      .await
      .is_ok(),
    "dotted reverse-DNS scheme must still upsert"
  );

  // An unknown URI is a clean not-found, not a database error.
  let missing =
    redirect::find_redirect_id(&context, "https://unknown.example.test/x", "authorize").await;
  assert!(matches!(
    missing,
    Err(super::context::CliError::NotFound(_))
  ));
  Ok(())
}

#[tokio::test]
async fn cli_mutations_emit_audit_events() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let scope_name = test_support::unique_name("audit");
  let capture = test_support::install_capture()?;

  scope::run(
    &context,
    ScopeCommand::Create {
      name: scope_name.clone(),
      description: None,
    },
  )
  .await?;
  drop(capture.guard);

  let log = test_support::captured(&capture.buffer);
  assert!(log.contains("cli.mutation"), "missing audit event: {log}");
  assert!(log.contains("scope.create"), "missing operation: {log}");
  assert!(log.contains(&scope_name), "missing subject: {log}");
  Ok(())
}

#[test]
fn cli_keygen_es256_emits_pem() -> Result<(), TestError> {
  let keypair = secret::generate_es256()?;
  assert!(keypair.private_key_pem.contains("BEGIN PRIVATE KEY"));
  let jwk: serde_json::Value = serde_json::from_str(&keypair.public_jwk)?;
  assert_eq!(jwk["kty"], "EC");
  assert_eq!(jwk["crv"], "P-256");
  assert_eq!(jwk["alg"], "ES256");
  Ok(())
}

#[tokio::test]
async fn cli_healthcheck_exits_one_when_unreachable() -> Result<(), TestError> {
  let code = ops::healthcheck("http://127.0.0.1:1/health/live").await?;
  assert_eq!(code, 1);
  Ok(())
}

// ---------------------------------------------------------------------------
// `test(admin_bootstrap)` suite (task 47)
// ---------------------------------------------------------------------------

const BOOTSTRAP_PASSWORD: &str = "bootstrap-correct-horse-01";

#[tokio::test]
async fn admin_bootstrap_creates_first_admin_must_change() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let email = test_support::unique_email("bootstrap");
  let capture = test_support::install_capture()?;

  let outcome = admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
    false,
  )
  .await?;
  drop(capture.guard);

  assert_eq!(outcome.email, email.to_lowercase());
  assert!(outcome.generated_password.is_none());

  let row: (bool, bool, bool, Option<OffsetDateTime>) = sqlx::query_as(
    "SELECT is_admin, must_change_password, totp_enabled, password_changed_at
       FROM users WHERE id = $1",
  )
  .bind(outcome.id)
  .fetch_one(&pool)
  .await?;
  assert!(row.0, "bootstrap must create an admin");
  assert!(row.1, "bootstrap must force a password change");
  assert!(!row.2, "bootstrap must not enable TOTP");
  assert!(
    row.3.is_none(),
    "password_changed_at stays NULL until rotation"
  );

  let verdict = user_repo::verify_password(&pool, &config.keys, &email, BOOTSTRAP_PASSWORD).await?;
  assert_eq!(verdict, user_repo::PasswordVerdict::Matched);
  assert!(user_repo::has_any_admin(&pool).await?);

  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.created"),
    "missing audit: {log}"
  );
  assert!(log.contains("admin.count.changed"), "missing audit: {log}");
  assert!(
    !log.contains(BOOTSTRAP_PASSWORD),
    "password leaked into logs"
  );
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_concurrent_creates_exactly_one() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let prefix = uuid::Uuid::new_v4().simple().to_string();

  let mut handles = Vec::new();
  for index in 0..8 {
    let pool = pool.clone();
    let config = config.clone();
    let email = format!("racer-{index}-{prefix}@example.test");
    handles.push(tokio::spawn(async move {
      admin::bootstrap(
        &config,
        &pool,
        &email,
        admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
        false,
      )
      .await
      .map(|outcome| outcome.email)
    }));
  }
  let mut created = 0;
  let mut refused = 0;
  for handle in handles {
    match handle
      .await
      .map_err(|error| TestError::Harness(error.to_string()))?
    {
      Ok(_) => created += 1,
      Err(super::context::CliError::AlreadyExists(_)) => refused += 1,
      Err(error) => return Err(TestError::Cli(error)),
    }
  }
  assert_eq!(created, 1, "exactly one racer must win");
  assert_eq!(refused, 7, "every loser must refuse");

  let admins: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
      .fetch_one(&pool)
      .await?;
  assert_eq!(admins, 1, "the advisory lock must serialize bootstrap");
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_second_refuses_and_force_is_audited() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let first = test_support::unique_email("bootstrap-first");
  let second = test_support::unique_email("bootstrap-second");

  admin::bootstrap(
    &config,
    &pool,
    &first,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
    false,
  )
  .await?;

  let capture = test_support::install_capture()?;
  let refused = admin::bootstrap(
    &config,
    &pool,
    &second,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
    false,
  )
  .await;
  drop(capture.guard);
  assert!(
    matches!(refused, Err(super::context::CliError::AlreadyExists(_))),
    "a second bootstrap must refuse"
  );
  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.refused"),
    "missing audit: {log}"
  );
  assert!(
    !log.contains(BOOTSTRAP_PASSWORD),
    "password leaked into logs"
  );

  let capture = test_support::install_capture()?;
  admin::bootstrap(
    &config,
    &pool,
    &second,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
    true,
  )
  .await?;
  drop(capture.guard);
  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.force"),
    "missing audit: {log}"
  );

  let admins: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
      .fetch_one(&pool)
      .await?;
  assert_eq!(admins, 2, "--force creates the second admin explicitly");
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_generated_password_is_256_bit_and_unlogged() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let email = test_support::unique_email("bootstrap-gen");
  let capture = test_support::install_capture()?;
  let outcome = admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Generate,
    false,
  )
  .await?;
  drop(capture.guard);

  let generated = outcome
    .generated_password
    .ok_or(TestError::Missing("generated password"))?;
  let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(generated.as_str())
    .map_err(|_| TestError::Missing("generated password must be base64"))?;
  assert_eq!(raw.len(), 32, "generated passwords are 256-bit");

  let verdict = user_repo::verify_password(&pool, &config.keys, &email, generated.as_str()).await?;
  assert_eq!(verdict, user_repo::PasswordVerdict::Matched);

  let log = test_support::captured(&capture.buffer);
  assert!(
    !log.contains(generated.as_str()),
    "generated password leaked into logs"
  );
  assert!(
    log.contains("admin.bootstrap.created"),
    "missing audit: {log}"
  );
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_first_login_restricted_until_rotation() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup(&crate::test_support::test_redis_url()).await?;
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Harness(format!("shared redis: {error}")))?;
  let mut conn = RedisConn::Single(manager);
  let store = crate::store::Store::from_config(&config.redis);

  let email = test_support::unique_email("bootstrap-login");
  admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned().into()),
    false,
  )
  .await?;

  let wall = OffsetDateTime::now_utc().unix_timestamp().max(0);
  let wall = u64::try_from(wall).map_err(|_| TestError::Missing("clock"))?;
  let counter = wall / totp::TOTP_STEP_SECS;
  let now = OffsetDateTime::from_unix_timestamp(
    counter
      .saturating_mul(totp::TOTP_STEP_SECS)
      .saturating_add(totp::TOTP_STEP_SECS / 2) as i64,
  )
  .map_err(|_| TestError::Missing("clock"))?;
  macro_rules! deps {
    () => {
      LoginDeps {
        pool: &pool,
        conn: &mut conn,
        store: &store,
        keys: &config.keys,
        config: &config,
        now,
      }
    };
  }

  let (presession_id, _fresh) = ensure_presession(&mut deps!(), None).await?;
  let csrf = login_csrf_token(&config.keys, &presession_id)?;
  let restricted = match attempt_login(
    &mut deps!(),
    LoginAttempt {
      presession_id,
      email: email.clone(),
      password: BOOTSTRAP_PASSWORD.to_owned(),
      code: String::new(),
      csrf,
      peer_ip: None,
    },
  )
  .await?
  {
    LoginOutcome::Restricted {
      session_id,
      redirect_to,
    } => {
      assert_eq!(redirect_to, CHANGE_PASSWORD_PATH);
      session_id
    }
    LoginOutcome::Authenticated { .. } => {
      return Err(TestError::Missing("login must be restricted"));
    }
    LoginOutcome::Rejected => return Err(TestError::Missing("login must succeed")),
  };

  for denied in [
    "/authorize",
    "/oauth/token",
    "/oauth/introspect",
    "/admin/users",
  ] {
    assert!(
      !restricted_allows_path(denied),
      "{denied} must deny restricted sessions"
    );
  }
  for allowed in ["/login/change-password", "/login/totp/setup", "/logout"] {
    assert!(
      restricted_allows_path(allowed),
      "{allowed} must stay reachable"
    );
  }

  match change_password(
    &mut deps!(),
    &restricted,
    "new-strong-password-77",
    "new-strong-password-77",
  )
  .await?
  {
    PasswordOutcome::StillRestricted { .. } => {}
    PasswordOutcome::Promoted { .. } => {
      return Err(TestError::Missing("promotion needs TOTP enrollment first"));
    }
  }
  let user = user_repo::find_by_email(&pool, &config.keys, &email)
    .await?
    .ok_or(TestError::Missing("bootstrap admin"))?;
  assert!(!user.must_change_password);
  assert!(user.password_changed_at.is_some());

  let offer = provision_totp(&mut deps!(), &restricted).await?;
  let code = totp::build_totp(&offer.secret)?
    .generate(counter * totp::TOTP_STEP_SECS)
    .to_string();
  let full = match confirm_totp(&mut deps!(), &restricted, &code, None).await? {
    ConfirmOutcome::Completed { session_id, .. } => session_id,
    _ => {
      return Err(TestError::Missing(
        "correct confirmation must complete bootstrap",
      ));
    }
  };
  assert_ne!(full, restricted);
  let live = load_session(&mut conn, &store, &full)
    .await?
    .ok_or(TestError::Missing("re-issued session"))?;
  assert!(
    !live.record.restricted,
    "completion re-issues a full session"
  );
  assert!(live.record.mfa_verified);
  Ok(())
}

#[test]
fn admin_bootstrap_has_no_password_argv_and_migrate_seeds_no_admin() {
  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "admin",
    "bootstrap",
    "--email",
    "ops@example.test",
    "--password-file",
    "/run/secrets/bootstrap-password",
    "--force",
  ]);
  assert!(parsed.is_ok(), "documented flags must parse");

  let rejected = Cli::try_parse_from([
    "d-oauth-server",
    "admin",
    "bootstrap",
    "--email",
    "ops@example.test",
    "--password",
    "hunter2",
  ]);
  assert!(rejected.is_err(), "passwords must never travel via argv");
}

#[test]
fn user_unlock_parses_with_email() {
  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "user",
    "unlock",
    "--email",
    "ops@example.test",
  ]);
  assert!(parsed.is_ok(), "documented unlock flags must parse");
  if let Ok(cli) = parsed {
    assert!(
      matches!(
        cli.command,
        Command::User {
          command: UserCommand::Unlock { .. },
        }
      ),
      "user unlock must parse to the unlock command"
    );
  }
}

/// `user unlock` clears the account counter and every composite bucket for
/// the user, emits `user.unlock`, and leaves the label-less unknown buckets
/// untouched.
#[tokio::test]
async fn user_unlock_clears_lockout_and_emits_audit() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("unlock");
  user::create(&context, &email, false, PASSWORD).await?;

  let store = crate::store::Store::from_config(&context.config().redis);
  let mut conn = AppState::connect(context.config().clone())
    .await?
    .redis
    .clone();
  let policy = user_repo::LockoutPolicy::new(5, 20, std::time::Duration::from_secs(900))
    .ok_or(TestError::Missing("lockout policy"))?;
  let attacker: IpAddr = "192.0.2.77"
    .parse()
    .map_err(|_| TestError::Missing("attacker ip"))?;
  for _ in 0..5 {
    user_repo::register_login_failure(&mut conn, &store, policy, &email, Some(attacker)).await?;
  }
  user_repo::register_unknown_failure(&mut conn, &store, policy, Some(attacker)).await?;
  if !user_repo::is_locked_out(&mut conn, &store, policy, &email, Some(attacker)).await? {
    return Err(TestError::Missing("account must lock before unlock"));
  }

  let capture = test_support::install_capture()?;
  let removed = user::unlock(&context, &email).await?;
  drop(capture.guard);
  if removed < 2 {
    return Err(TestError::Harness(format!(
      "unlock must remove the account and composite keys, removed {removed}"
    )));
  }
  if user_repo::is_locked_out(&mut conn, &store, policy, &email, Some(attacker)).await? {
    return Err(TestError::Harness(
      "unlock must release the lockout".to_owned(),
    ));
  }
  if user_repo::unknown_failure_count(&mut conn, &store, Some(attacker)).await? != 1 {
    return Err(TestError::Harness(
      "unlock must leave unknown buckets untouched".to_owned(),
    ));
  }
  let log = test_support::captured(&capture.buffer);
  if !log.contains("cli.mutation") {
    return Err(TestError::Harness(format!("missing audit event: {log}")));
  }
  if !log.contains("user.unlock") {
    return Err(TestError::Harness(format!("missing operation: {log}")));
  }
  Ok(())
}

/// `user unlock` on an absent address is a clean, payload-free not-found.
#[tokio::test]
async fn user_unlock_unknown_user_is_not_found() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let missing = test_support::unique_email("unlock-missing");
  match user::unlock(&context, &missing).await {
    Err(super::context::CliError::NotFound(message)) => {
      if message.contains(&missing) || message.contains('@') {
        return Err(TestError::Harness(format!(
          "not-found error leaked the email: {message}"
        )));
      }
      Ok(())
    }
    Err(other) => Err(TestError::Harness(format!("unexpected error: {other:?}"))),
    Ok(_) => Err(TestError::Missing("missing user must be NotFound")),
  }
}

/// `user unlock` fails closed when Redis is unreachable: the command errors
/// without an audit event and the account row stays exactly as it was.
#[tokio::test]
async fn user_unlock_redis_outage_fails_closed() -> Result<(), TestError> {
  let (pg_url, setup) = crate::test_support::fresh_database_pool()
    .await
    .map_err(|error| TestError::Harness(format!("shared postgres: {error}")))?;
  crate::state::MIGRATOR.run(&setup).await?;
  setup.close().await;
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/cli-test-cert.pem", "key_path": "/tmp/cli-test-key.pem"},
    "database": {"url": pg_url},
    "redis": {"url": "redis://127.0.0.1:1", "durability": "waitaof"},
    "token_pepper": "cli-test-pepper-0123456789abcdef",
    "totp_encryption_key": "cli-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "cli-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  let config = Arc::new(Config::from_source(source)?);
  let context = super::context::Context::from_config(config).await?;
  let email = test_support::unique_email("unlock-outage");
  user::create(&context, &email, false, PASSWORD).await?;

  let capture = test_support::install_capture()?;
  let outcome = user::unlock(&context, &email).await;
  drop(capture.guard);
  match outcome {
    Err(super::context::CliError::NotFound(_)) => {
      return Err(TestError::Harness(
        "a live user must not be NotFound".to_owned(),
      ));
    }
    Err(_) => {}
    Ok(_) => return Err(TestError::Missing("unlock over a dead Redis must fail")),
  }
  if test_support::captured(&capture.buffer).contains("user.unlock") {
    return Err(TestError::Harness(
      "a failed unlock must not emit user.unlock".to_owned(),
    ));
  }
  let record = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("created user"))?;
  if record.disabled {
    return Err(TestError::Harness(
      "a failed unlock must not touch the account".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_migrate_seeds_no_admin() -> Result<(), TestError> {
  let (_db, pool, _config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  assert!(
    !user_repo::has_any_admin(&pool).await?,
    "migrations must seed zero users"
  );
  let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
    .fetch_one(&pool)
    .await?;
  assert_eq!(users, 0, "nothing auto-creates an admin");
  Ok(())
}

#[test]
fn admin_bootstrap_runbook_matches_cli() -> Result<(), TestError> {
  let runbook =
    std::fs::read_to_string("RUNBOOK.md").map_err(|_| TestError::Missing("RUNBOOK.md"))?;
  for command in [
    "admin bootstrap --email",
    "--password-file",
    "--force",
    "user create --admin",
    "user disable",
  ] {
    assert!(
      runbook.contains(command),
      "runbook must document `{command}`"
    );
  }
  Ok(())
}

/// `open_pool` must honor the mounted database password: a passwordless DSN
/// plus `password_file` connects (the cluster migrate-Job contract).
#[tokio::test]
async fn open_pool_uses_mounted_database_password() -> Result<(), TestError> {
  let (pg_url, setup) = crate::test_support::fresh_database_pool()
    .await
    .map_err(|error| TestError::Harness(format!("shared postgres: {error}")))?;
  crate::state::MIGRATOR.run(&setup).await?;
  setup.close().await;
  let user_prefix = "postgres://postgres";
  let user_end = user_prefix.len();
  assert!(pg_url.starts_with(&format!("{user_prefix}:")));
  let at = pg_url
    .find('@')
    .ok_or(TestError::Missing("container url carries userinfo"))?;
  let password = pg_url[user_end + 1..at].to_owned();
  let passwordless = format!("{}{}", &pg_url[..user_end], &pg_url[at..]);
  let pw_path = std::env::temp_dir().join(format!(
    "d-oauth-cli-open-pool-pw-{}.txt",
    uuid::Uuid::new_v4()
  ));
  std::fs::write(&pw_path, format!("{password}\n"))?;
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/cli-test-cert.pem", "key_path": "/tmp/cli-test-key.pem"},
    "database": {"url": passwordless, "password_file": pw_path.to_string_lossy()},
    "redis": {"url": "redis://127.0.0.1:6379", "durability": "waitaof"},
    "token_pepper": "cli-test-pepper-0123456789abcdef",
    "totp_encryption_key": "cli-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "cli-test-pii-key-0123456789abcdef",
  });
  let source = ::config::Config::try_from(&fixture)?;
  let config = Config::from_source(source)?;
  let pool = super::context::open_pool(&config).await?;
  sqlx::query("SELECT 1").execute(&pool).await?;
  let _ = std::fs::remove_file(&pw_path);
  Ok(())
}

/// `user disable` purges the user's Redis ephemeral state before flipping the
/// Postgres `disabled` flag; unrelated subjects' keys survive.
#[tokio::test]
async fn user_disable_purges_ephemeral_state() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("disable-purge");
  user::create(&context, &email, false, PASSWORD).await?;
  let record = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("created user"))?;
  let canonical = record.email.clone();
  let user_id = record.id.to_string();
  let tag = uuid::Uuid::new_v4().to_string();

  let store = crate::store::Store::from_config(&context.config().redis);
  let mut conn = AppState::connect(context.config().clone())
    .await?
    .redis
    .clone();

  async fn hset(conn: &mut RedisConn, key: &str, pairs: &[(&str, &str)]) -> Result<(), TestError> {
    let mut cmd = redis::cmd("HSET");
    cmd.arg(key);
    for (field, value) in pairs {
      cmd.arg(field).arg(value);
    }
    cmd.query_async::<()>(conn).await?;
    redis::cmd("PEXPIRE")
      .arg(key)
      .arg(60_000)
      .query_async::<()>(conn)
      .await?;
    Ok(())
  }

  let session_key = store.session_key(&format!("disable-purge-session-{tag}"));
  hset(
    &mut conn,
    &session_key,
    &[
      ("subject", &canonical),
      ("mfa_verified", "true"),
      ("restricted", "false"),
    ],
  )
  .await?;
  let session_meta = format!("{session_key}:meta");
  hset(
    &mut conn,
    &session_meta,
    &[("auth_time", "1700000000"), ("csrf", "csrf-secret")],
  )
  .await?;

  let code_key = store.code_key(&format!("disable-purge-code-{tag}"));
  hset(
    &mut conn,
    &code_key,
    &[
      ("client_id", "client-a"),
      ("redirect_uri", "https://client.example.test/cb"),
      ("scope", "orders:read"),
      (
        "code_challenge",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      ),
      ("subject", &canonical),
      ("grant_id", "grant-code"),
      ("cnf", ""),
    ],
  )
  .await?;

  let grant_id = format!("disable-purge-grant-{tag}");
  let grant_key = store.grant_key(&grant_id);
  hset(
    &mut conn,
    &grant_key,
    &[
      ("grant_id", &grant_id),
      ("client_id", "client-a"),
      ("subject", &canonical),
      ("scope", "orders:read"),
    ],
  )
  .await?;
  let access_hash = format!("disable-purge-access-{tag}");
  let refresh_hash = format!("disable-purge-refresh-{tag}");
  let access_key = store.access_key(&access_hash);
  let refresh_key = store.refresh_key(&refresh_hash);
  for (key, hash) in [(&access_key, &access_hash), (&refresh_key, &refresh_hash)] {
    hset(
      &mut conn,
      key,
      &[
        ("client_id", "client-a"),
        ("grant_id", &grant_id),
        ("scope", "orders:read"),
        ("subject", &canonical),
        ("cnf", ""),
      ],
    )
    .await?;
    redis::cmd("SADD")
      .arg(store.grant_tokens_key(&grant_id))
      .arg(hash)
      .query_async::<()>(&mut conn)
      .await?;
  }
  let access_act = format!("{access_key}:act");
  redis::cmd("SET")
    .arg(&access_act)
    .arg("jkt")
    .arg("PX")
    .arg(60_000)
    .query_async::<()>(&mut conn)
    .await?;

  let device_hash = format!("disable-purge-device-{tag}");
  let device_key = store.device_key(&device_hash);
  hset(
    &mut conn,
    &device_key,
    &[
      ("client_id", "client-a"),
      ("scope", "orders:read"),
      ("status", "approved"),
      ("subject", &user_id),
      ("grant_id", ""),
    ],
  )
  .await?;
  let device_cnf = format!("{device_key}:cnf");
  let device_poll = format!("{device_key}:poll");
  for key in [&device_cnf, &device_poll] {
    redis::cmd("SET")
      .arg(key)
      .arg("sidecar")
      .arg("PX")
      .arg(60_000)
      .query_async::<()>(&mut conn)
      .await?;
  }
  let user_code_key = store.user_code_key(&format!("disable-purge-usercode-{tag}"));
  redis::cmd("SET")
    .arg(&user_code_key)
    .arg(&device_hash)
    .arg("PX")
    .arg(60_000)
    .query_async::<()>(&mut conn)
    .await?;

  let fail_key = store.login_fail_key(&crate::store::sha256_hex(
    crate::db::user_repo::normalize_email(&canonical).as_bytes(),
  ));
  redis::cmd("INCR")
    .arg(&fail_key)
    .query_async::<()>(&mut conn)
    .await?;

  let decoy_email = test_support::unique_email("disable-purge-decoy");
  let decoy_session_key = store.session_key(&format!("disable-purge-decoy-{tag}"));
  hset(
    &mut conn,
    &decoy_session_key,
    &[
      ("subject", &decoy_email),
      ("mfa_verified", "true"),
      ("restricted", "false"),
    ],
  )
  .await?;

  user::disable(&context, &email).await?;

  let after = user_repo::find_by_email(context.pool(), &context.config().keys, &email)
    .await?
    .ok_or(TestError::Missing("disabled user"))?;
  assert!(after.disabled, "user disable must set the disabled flag");

  for key in [
    session_key,
    session_meta,
    code_key,
    grant_key,
    store.grant_tokens_key(&grant_id),
    access_key,
    access_act,
    refresh_key,
    device_key,
    device_cnf,
    device_poll,
    user_code_key,
    fail_key,
  ] {
    let present: i64 = redis::cmd("EXISTS")
      .arg(&key)
      .query_async(&mut conn)
      .await?;
    assert_eq!(present, 0, "disable must purge {key}");
  }
  let decoy_present: i64 = redis::cmd("EXISTS")
    .arg(&decoy_session_key)
    .query_async(&mut conn)
    .await?;
  assert_eq!(decoy_present, 1, "disable must keep unrelated subjects");
  Ok(())
}

// ---------------------------------------------------------------------------
// `test(cli_secret_hygiene)` suite (T3-D1, red-first)
// ---------------------------------------------------------------------------

#[test]
#[cfg(unix)]
fn cli_password_file_world_readable_rejected() -> Result<(), TestError> {
  use std::os::unix::fs::PermissionsExt as _;
  let path = std::env::temp_dir().join(format!(
    "d-oauth-cli-secret-hygiene-{}",
    uuid::Uuid::new_v4()
  ));
  std::fs::write(&path, "placeholder-secret-value\n")?;
  std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
  let result = super::context::read_secret(false, Some(&path));
  let _ = std::fs::remove_file(&path);
  assert!(
    result.is_err(),
    "a world-readable password file must be rejected"
  );
  Ok(())
}

#[test]
fn cli_enroll_totp_accepts_show_secret_flag() {
  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "user",
    "enroll-totp",
    "--email",
    "ops@example.test",
    "--show-secret",
  ]);
  assert!(
    parsed.is_ok(),
    "enroll-totp must accept an explicit --show-secret flag"
  );
}

#[test]
fn cli_iat_issue_accepts_show_secret_flag() {
  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "initial-access-token",
    "issue",
    "--uses",
    "3",
    "--ttl",
    "600",
    "--show-secret",
  ]);
  assert!(
    parsed.is_ok(),
    "initial-access-token issue must accept an explicit --show-secret flag"
  );
}

#[test]
fn cli_bootstrap_debug_redacts_with_length() {
  let debug = format!(
    "{:?}",
    admin::BootstrapPassword::Provided("placeholder-secret-value".to_owned().into())
  );
  assert!(
    !debug.contains("placeholder-secret-value"),
    "Debug must never carry the password: {debug}"
  );
  assert!(
    debug.contains("[REDACTED]"),
    "Debug must mark the password redacted: {debug}"
  );
  let outcome = admin::BootstrapOutcome {
    id: uuid::Uuid::new_v4(),
    email: "ops@example.test".to_owned(),
    generated_password: Some("placeholder-secret-value".to_owned().into()),
  };
  let debug = format!("{outcome:?}");
  assert!(
    !debug.contains("placeholder-secret-value"),
    "Debug must never carry the generated password: {debug}"
  );
  assert!(
    debug.contains("[REDACTED]"),
    "Debug must mark the generated password redacted: {debug}"
  );
}

#[test]
fn cli_secret_output_guard_refuses_without_flag() {
  assert!(
    super::check_secret_output(false, false).is_err(),
    "one-time secret output to a non-TTY stdout without --show-secret must refuse"
  );
  assert!(
    super::check_secret_output(false, true).is_ok(),
    "one-time secret output to a TTY without --show-secret must allow"
  );
  assert!(
    super::require_secret_output(true).is_ok(),
    "an explicit --show-secret flag must allow the one-time print"
  );
  assert!(
    super::check_secret_output(true, false).is_ok(),
    "an explicit --show-secret flag must allow a non-TTY print"
  );
  assert!(
    super::check_secret_output(true, true).is_ok(),
    "an explicit --show-secret flag must allow a TTY print"
  );
}

#[test]
#[cfg(unix)]
fn cli_password_file_group_readable_accepted() -> Result<(), TestError> {
  use std::os::unix::fs::PermissionsExt as _;
  let path =
    std::env::temp_dir().join(format!("d-oauth-cli-secret-group-{}", uuid::Uuid::new_v4()));
  std::fs::write(&path, "placeholder-secret-value\n")?;
  std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
  let result = super::context::read_secret(false, Some(&path));
  let _ = std::fs::remove_file(&path);
  assert!(
    result.is_ok(),
    "a group-readable (non-world-readable) password file must be accepted"
  );
  Ok(())
}

#[test]
#[cfg(unix)]
fn cli_password_file_non_utf8_rejected() -> Result<(), TestError> {
  use std::os::unix::fs::PermissionsExt as _;
  let path = std::env::temp_dir().join(format!(
    "d-oauth-cli-secret-nonutf8-{}",
    uuid::Uuid::new_v4()
  ));
  std::fs::write(&path, [0xff, 0xfe, b'\n'])?; // invalid UTF-8, no secret material
  std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
  let result = super::context::read_secret(false, Some(&path));
  let _ = std::fs::remove_file(&path);
  assert!(
    result.is_err(),
    "a non-UTF-8 password file must be rejected"
  );
  Ok(())
}

#[test]
#[cfg(unix)]
fn cli_password_file_trims_trailing_newline() -> Result<(), TestError> {
  use std::os::unix::fs::PermissionsExt as _;
  let path = std::env::temp_dir().join(format!("d-oauth-cli-secret-trim-{}", uuid::Uuid::new_v4()));
  std::fs::write(&path, "placeholder-secret-value\r\n")?;
  std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
  let secret = super::context::read_secret(false, Some(&path))?;
  let _ = std::fs::remove_file(&path);
  assert_eq!(
    secret.as_str(),
    "placeholder-secret-value",
    "a trailing CR/LF must be trimmed in place"
  );
  Ok(())
}

/// `resource-server` create/list/enable/disable/delete round-trips, rejects a
/// wildcard identifier, and re-applies a `config sync` `resource_servers`
/// array idempotently.
#[tokio::test]
async fn cli_resource_server_create() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let identifier = format!("https://api-{}.example.test", uuid::Uuid::new_v4());

  resource::run(
    &context,
    ResourceServerCommand::Create {
      identifier: identifier.clone(),
      description: Some("orders API".to_owned()),
    },
  )
  .await?;
  assert!(
    resource_repo::find_enabled(context.pool(), &identifier)
      .await?
      .is_some(),
    "a created resource server is enabled"
  );

  let wildcard = resource::run(
    &context,
    ResourceServerCommand::Create {
      identifier: "https://*.example.test".to_owned(),
      description: None,
    },
  )
  .await;
  assert!(
    matches!(wildcard, Err(CliError::Input(_))),
    "a wildcard identifier must be rejected"
  );

  resource::run(
    &context,
    ResourceServerCommand::Disable {
      identifier: identifier.clone(),
    },
  )
  .await?;
  assert!(
    resource_repo::find_enabled(context.pool(), &identifier)
      .await?
      .is_none(),
    "a disabled resource server is not enabled"
  );
  resource::run(
    &context,
    ResourceServerCommand::Enable {
      identifier: identifier.clone(),
    },
  )
  .await?;

  let synced = format!("https://synced-{}.example.test", uuid::Uuid::new_v4());
  let file = SyncFile {
    resource_servers: vec![ResourceServerEntry {
      identifier: synced.clone(),
      description: Some("synced".to_owned()),
      enabled: true,
    }],
    ..SyncFile::default()
  };
  let first = super::sync::apply(&context, &file).await?;
  assert_eq!(first.resource_servers_created, 1);
  let second = super::sync::apply(&context, &file).await?;
  assert!(second.is_noop(), "second sync must be a no-op: {second}");

  resource::run(
    &context,
    ResourceServerCommand::Delete {
      identifier: identifier.clone(),
    },
  )
  .await?;
  assert!(
    resource_repo::find_enabled(context.pool(), &identifier)
      .await?
      .is_none(),
    "a deleted resource server is gone"
  );
  Ok(())
}

/// `client set-access-token-format` writes `jwt` (operator opt-in), reads it
/// back through the repository projection, rejects an unknown client, and
/// refuses an invalid `--format` value at parse time.
#[tokio::test]
async fn cli_client_set_access_token_format() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let client_id = format!("fmt-client-{}", uuid::Uuid::new_v4());
  insert_redirect_client(context.pool(), &context.config().keys, &client_id).await?;

  let initial: String =
    sqlx::query_scalar("SELECT access_token_format FROM oauth_clients WHERE client_id = $1")
      .bind(&client_id)
      .fetch_one(context.pool())
      .await?;
  assert_eq!(initial, "opaque", "a new client defaults to opaque");

  redirect::run_client(
    &context,
    ClientCommand::SetAccessTokenFormat {
      client_id: client_id.clone(),
      format: "jwt".to_owned(),
    },
  )
  .await?;

  let stored: String =
    sqlx::query_scalar("SELECT access_token_format FROM oauth_clients WHERE client_id = $1")
      .bind(&client_id)
      .fetch_one(context.pool())
      .await?;
  assert_eq!(stored, "jwt");

  let client =
    client_repo::find_active_by_client_id(context.pool(), &context.config().keys, &client_id)
      .await?
      .ok_or(TestError::Missing("client after format change"))?;
  assert_eq!(client.access_token_format, "jwt", "read-back must be jwt");

  let second = format!("fmt-sync-{}", uuid::Uuid::new_v4());
  insert_redirect_client(context.pool(), &context.config().keys, &second).await?;
  let file = SyncFile {
    client_access_token_formats: vec![ClientTokenFormatEntry {
      client_id: second.clone(),
      access_token_format: "jwt".to_owned(),
    }],
    ..SyncFile::default()
  };
  let first = super::sync::apply(&context, &file).await?;
  assert_eq!(first.client_formats_set, 1);
  let reapply = super::sync::apply(&context, &file).await?;
  assert!(reapply.is_noop(), "second sync must be a no-op: {reapply}");
  let synced: String =
    sqlx::query_scalar("SELECT access_token_format FROM oauth_clients WHERE client_id = $1")
      .bind(&second)
      .fetch_one(context.pool())
      .await?;
  assert_eq!(synced, "jwt", "sync must apply the declared format");

  let unknown = redirect::run_client(
    &context,
    ClientCommand::SetAccessTokenFormat {
      client_id: "no-such-client".to_owned(),
      format: "opaque".to_owned(),
    },
  )
  .await;
  assert!(
    matches!(unknown, Err(CliError::NotFound(_))),
    "an unknown client is not found"
  );

  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "client",
    "set-access-token-format",
    "--client-id",
    &client_id,
    "--format",
    "bogus",
  ]);
  assert!(
    parsed.is_err(),
    "an invalid --format value must be rejected"
  );
  Ok(())
}

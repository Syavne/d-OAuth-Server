//! `test(consent)` suite: effective scope, approve/deny, CSRF, and binding.
//!
//! Uses the same live Postgres + Redis harness as the login suite. The session
//! and its sidecar (`auth_time`, `csrf_secret`, `pending_request_id`) are
//! written directly with the documented task-25 wire format, so the tests
//! exercise consent without paying for a real password+TOTP login. Approval
//! drives task 27's real [`CodeIssuer`](crate::protocol::code::CodeIssuer), so
//! the stored code record proves the effective scope that was issued.

use std::time::Duration;

use axum::http::StatusCode;
use secrecy::SecretString;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::{
  ConsentDecision, ConsentDeps, ConsentOutcome, ConsentSubmission, consent_action,
  load_consent_view, submit_consent,
};
use crate::{
  config::{DurabilityMode, TtlConfig},
  crypto::{
    secret::{Argon2Params, hash_secret},
    tokens::mint_token,
  },
  db::{
    client_repo::{self, NewClient},
    scope_repo,
    test_support::Db,
    user_repo::{self, NewUser},
    user_scope_repo,
  },
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  protocol::code,
  state::RedisConn,
  store::{
    self, Store, codes,
    pending::{self, PendingAuth},
    sessions,
  },
  test_guard::Lease,
  ui::login::form_token,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;
/// Boxed scaffolding/assertion failure.
type TestError = Box<dyn std::error::Error + Send + Sync>;

/// Live handles for one consent test.
struct Harness {
  /// Lease on the shared Postgres server (keeps its container alive).
  _db: Lease<Db>,
  /// Fresh migrated database for this test.
  pool: PgPool,
  /// Live Redis connection.
  conn: RedisConn,
  /// Store handle over the test keyspaces.
  store: Store,
  /// PII key ring for the encrypted user-email lookup (strict encrypt-only).
  keys: KeyRing,
}

/// Start Postgres (fresh DB) + Redis for one test.
async fn harness() -> Result<Harness, TestError> {
  let (db, pool) = crate::db::test_support::migrated_pool().await?;
  let manager = crate::test_support::redis_manager().await?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  Ok(Harness {
    _db: db,
    pool,
    conn: RedisConn::Single(manager),
    store,
    keys: test_ring()?,
  })
}

/// Borrow the harness into consent dependencies.
fn deps_of(h: &mut Harness) -> ConsentDeps<'_> {
  ConsentDeps {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.keys,
  }
}

/// A key ring with one pepper generation plus the mandatory TOTP chain.
fn test_ring() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("consent-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("consent-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("consent-test-pii"))],
  )?)
}

/// Build a real code issuer over a fresh test key ring.
fn test_issuer() -> Result<code::CodeIssuer, TestError> {
  Ok(code::CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?)
}

/// A provisioned client, user, pending request, and bound full session.
struct Fixture {
  /// Pending-auth id the session is bound to.
  request_id: String,
  /// Full authenticated session id.
  session_id: String,
  /// Session CSRF secret (for minting valid form tokens).
  csrf_secret: String,
  /// Canonical email of the authenticated user.
  user_email: String,
}

/// Provision a client + scopes + entitled user, a pending request, and a
/// full session bound to it.
async fn provision(h: &mut Harness) -> Result<Fixture, TestError> {
  let client = client_repo::insert(
    &h.pool,
    &h.keys,
    false,
    &NewClient {
      id: Uuid::new_v4(),
      client_id: "consent-client".to_owned(),
      client_secret_hash: None,
      client_secret_expires_at: None,
      client_name: "Consent Test App".to_owned(),
      grant_types: vec!["authorization_code".to_owned()],
      response_types: vec!["code".to_owned()],
      scope: "orders:read orders:write".to_owned(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      registration_access_token_hash: None,
    },
  )
  .await?;
  for name in ["orders:read", "orders:write", "admin:all"] {
    scope_repo::upsert(&h.pool, name, "").await?;
  }
  let params = Argon2Params::new(8192, 1, 1, 32)?;
  let user = user_repo::create_user(
    &h.pool,
    &h.keys,
    false,
    &NewUser {
      email: "consent-user@example.test".to_owned(),
      password_hash: hash_secret("consent-password-01", &params)?,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  // Entitled to ONE of the two requested scopes.
  user_scope_repo::entitle(&h.pool, user.id, "orders:read", None).await?;

  let request_id = pending::new_request_id()?;
  let record = PendingAuth {
    client_id: client.client_id.clone(),
    redirect_uri: "https://client.example.test/cb".to_owned(),
    scope: "orders:read orders:write".to_owned(),
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    state: Some("state-xyz".to_owned()),
    // A public client must carry a verified DPoP `jkt` to issue (task 27).
    dpop_jkt: Some("test-jkt".to_owned()),
    iss: "https://auth.example.test".to_owned(),
    post_logout_uri: None,
  };
  pending::put(
    &mut h.conn,
    &h.store,
    &request_id,
    &record,
    Duration::from_secs(300),
  )
  .await?;

  let session_id = mint_token()?;
  let session = sessions::SessionRecord {
    subject: user.email.clone(),
    mfa_verified: true,
    restricted: false,
  };
  sessions::put(
    &mut h.conn,
    &h.store,
    &session_id,
    &session,
    Duration::from_secs(3600),
  )
  .await?;
  let csrf_secret = mint_token()?;
  let session_key = h.store.session_key(&session_id);
  let meta_key = format!("{session_key}:meta");
  let pairs = vec![
    ("auth_time".to_owned(), "0".to_owned()),
    ("csrf_secret".to_owned(), csrf_secret.clone()),
    ("pending_request_id".to_owned(), request_id.clone()),
  ];
  store::hset_record(&mut h.conn, &meta_key, &pairs, Duration::from_secs(3600)).await?;

  Ok(Fixture {
    request_id,
    session_id,
    csrf_secret,
    user_email: user.email,
  })
}

/// Number of authorization-code records in Redis.
async fn code_key_count(h: &mut Harness) -> Result<usize, TestError> {
  let pattern = format!("{}*", h.store.code_key(""));
  let keys: Vec<String> = redis::cmd("KEYS")
    .arg(pattern)
    .query_async(&mut h.conn)
    .await?;
  Ok(keys.len())
}

/// Approve issues a code whose stored record carries the effective scope
/// (the unentitled `orders:write` is dropped before issuance).
#[tokio::test]
async fn consent_approve_issues_code() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let view = {
    let mut deps = deps_of(&mut h);
    load_consent_view(&mut deps, &fx.session_id).await?
  };
  let Some(view) = view else {
    return Err("a bound full session must render consent".into());
  };
  let issuer = test_issuer()?;
  let outcome = {
    let mut deps = deps_of(&mut h);
    submit_consent(
      &mut deps,
      ConsentSubmission {
        session_id: &fx.session_id,
        request_id: &view.request_id,
        csrf: &view.csrf,
        decision: ConsentDecision::Approve,
      },
      &issuer,
    )
    .await?
  };
  let issued = match outcome {
    ConsentOutcome::Approved { issued } => issued,
    _ => return Err("approval must issue a code".into()),
  };
  for needle in ["code=", "state=state-xyz", "iss="] {
    if !issued.location.contains(needle) {
      return Err(format!("success redirect missing {needle}: {}", issued.location).into());
    }
  }
  let record = codes::consume(&mut h.conn, &h.store, &issued.code_hash)
    .await?
    .ok_or_else(|| -> TestError { "the issued code must be stored".into() })?;
  if record.scope != "orders:read" {
    return Err(format!("code must store the effective scope, got: {}", record.scope).into());
  }
  if record.client_id != "consent-client" || record.subject != fx.user_email {
    return Err("code must carry the client and authenticated subject".into());
  }
  if record.cnf != "test-jkt" {
    return Err("public-client code must carry the DPoP binding".into());
  }
  Ok(())
}

/// A requested scope the user is not entitled to is dropped from the view.
#[tokio::test]
async fn consent_unentitled_scope_dropped() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let view = {
    let mut deps = deps_of(&mut h);
    load_consent_view(&mut deps, &fx.session_id).await?
  };
  let Some(view) = view else {
    return Err("a bound full session must render consent".into());
  };
  if view.scopes != vec!["orders:read".to_owned()] {
    return Err(format!("unentitled scope must not be shown: {:?}", view.scopes).into());
  }
  if view.client_name != "Consent Test App" {
    return Err(format!("client name must render: {}", view.client_name).into());
  }
  Ok(())
}

/// Denial redirects to the validated URI with `access_denied` and issues none.
#[tokio::test]
async fn consent_deny_redirects_access_denied() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let view = {
    let mut deps = deps_of(&mut h);
    load_consent_view(&mut deps, &fx.session_id).await?
  };
  let Some(view) = view else {
    return Err("a bound full session must render consent".into());
  };
  let issuer = test_issuer()?;
  let outcome = {
    let mut deps = deps_of(&mut h);
    submit_consent(
      &mut deps,
      ConsentSubmission {
        session_id: &fx.session_id,
        request_id: &view.request_id,
        csrf: &view.csrf,
        decision: ConsentDecision::Deny,
      },
      &issuer,
    )
    .await?
  };
  match outcome {
    ConsentOutcome::Denied { redirect_to } => {
      for needle in ["error=access_denied", "state=state-xyz", "iss="] {
        if !redirect_to.contains(needle) {
          return Err(format!("denial redirect missing {needle}: {redirect_to}").into());
        }
      }
    }
    _ => return Err("denial must redirect with access_denied".into()),
  }
  if code_key_count(&mut h).await? != 0 {
    return Err("denial must never issue a code".into());
  }
  Ok(())
}

/// A missing or tampered CSRF token is rejected and issues no code.
#[tokio::test]
async fn consent_missing_csrf_rejected() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let issuer = test_issuer()?;
  for csrf in ["", "tampered-token"] {
    let result = {
      let mut deps = deps_of(&mut h);
      submit_consent(
        &mut deps,
        ConsentSubmission {
          session_id: &fx.session_id,
          request_id: &fx.request_id,
          csrf,
          decision: ConsentDecision::Approve,
        },
        &issuer,
      )
      .await
    };
    match result {
      Err(error) if error.code() == OAuthErrorCode::InvalidRequest => {}
      Err(_) => return Err("a bad CSRF token must be invalid_request".into()),
      Ok(_) => return Err("a bad CSRF token must never approve".into()),
    }
  }
  if code_key_count(&mut h).await? != 0 {
    return Err("a bad CSRF token must never issue a code".into());
  }
  Ok(())
}

/// A submission for a different request than the session's binding is refused,
/// even with a CSRF token minted for that other request.
#[tokio::test]
async fn consent_session_request_mismatch_rejected() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let other_id = pending::new_request_id()?;
  let other = PendingAuth {
    client_id: "consent-client".to_owned(),
    redirect_uri: "https://client.example.test/cb".to_owned(),
    scope: "orders:read".to_owned(),
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    state: None,
    dpop_jkt: Some("other-jkt".to_owned()),
    iss: "https://auth.example.test".to_owned(),
    post_logout_uri: None,
  };
  pending::put(
    &mut h.conn,
    &h.store,
    &other_id,
    &other,
    Duration::from_secs(300),
  )
  .await?;
  let csrf = form_token(&fx.csrf_secret, &consent_action(&other_id));
  let issuer = test_issuer()?;
  let result = {
    let mut deps = deps_of(&mut h);
    submit_consent(
      &mut deps,
      ConsentSubmission {
        session_id: &fx.session_id,
        request_id: &other_id,
        csrf: &csrf,
        decision: ConsentDecision::Approve,
      },
      &issuer,
    )
    .await
  };
  match result {
    Err(error) if error.code() == OAuthErrorCode::InvalidRequest => {}
    Err(_) => return Err("a mismatched pair must be invalid_request".into()),
    Ok(_) => return Err("a mismatched session/request pair must not proceed".into()),
  }
  if code_key_count(&mut h).await? != 0 {
    return Err("a mismatched pair must never issue a code".into());
  }
  Ok(())
}

/// Consent cannot proceed without an authenticated session.
#[tokio::test]
async fn consent_requires_authenticated_session() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let view = {
    let mut deps = deps_of(&mut h);
    load_consent_view(&mut deps, "not-a-session").await?
  };
  if view.is_some() {
    return Err("an unknown session must not render consent".into());
  }
  let issuer = test_issuer()?;
  let outcome = {
    let mut deps = deps_of(&mut h);
    submit_consent(
      &mut deps,
      ConsentSubmission {
        session_id: "not-a-session",
        request_id: &fx.request_id,
        csrf: "whatever",
        decision: ConsentDecision::Approve,
      },
      &issuer,
    )
    .await?
  };
  match outcome {
    ConsentOutcome::NeedsLogin => {}
    _ => return Err("an unknown session must be sent to login".into()),
  }
  if code_key_count(&mut h).await? != 0 {
    return Err("no code may be issued without a session".into());
  }
  Ok(())
}

/// The consent screen renders the DECRYPTED client name: the stored row is
/// encrypt-only (plaintext blanked), and a corrupt ciphertext fails closed
/// as `PiiDecrypt` (503) with no plaintext in the error.
#[tokio::test]
async fn consent_renders_client_name() -> TestResult {
  let mut h = harness().await?;
  let fx = provision(&mut h).await?;
  let at_rest = sqlx::query(
    "SELECT client_name, client_name_enc FROM oauth_clients WHERE client_id = 'consent-client'",
  )
  .fetch_one(&h.pool)
  .await?;
  let plain: Option<String> = at_rest.try_get("client_name")?;
  let sealed: Option<Vec<u8>> = at_rest.try_get("client_name_enc")?;
  if plain.is_some() {
    return Err("encrypt-only must blank the client name".into());
  }
  if sealed.is_none() {
    return Err("the sealed client name must be stored".into());
  }
  let view = {
    let mut deps = deps_of(&mut h);
    load_consent_view(&mut deps, &fx.session_id).await?
  };
  let Some(view) = view else {
    return Err("a bound full session must render consent".into());
  };
  if view.client_name != "Consent Test App" {
    return Err(
      format!(
        "consent must render the decrypted client name, got: {}",
        view.client_name
      )
      .into(),
    );
  }
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE oauth_clients SET client_name_enc = $1 WHERE client_id = 'consent-client'")
    .bind(corrupt)
    .execute(&h.pool)
    .await?;
  let mut deps = deps_of(&mut h);
  match load_consent_view(&mut deps, &fx.session_id).await {
    Err(error) => {
      if !matches!(error, AppError::PiiDecrypt) {
        return Err("a corrupt client_name_enc must be PiiDecrypt".into());
      }
      if error.status() != StatusCode::SERVICE_UNAVAILABLE {
        return Err("a decrypt failure must be 503, never 500".into());
      }
      if format!("{error:?}").contains("Consent Test App") {
        return Err("a decrypt error must not leak plaintext".into());
      }
    }
    Ok(_) => return Err("a corrupt client row must never render".into()),
  }
  Ok(())
}

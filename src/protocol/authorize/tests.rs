//! `test(authorize_validate)` suite: validation order + error-delivery matrix.

use std::{collections::HashMap, time::Duration};

use axum::http::{StatusCode, header};
use uuid::Uuid;

use super::{AuthorizeFailure, AuthorizeInput, validate};
use crate::{
  config::DurabilityMode,
  crypto::pkce::challenge_from_verifier,
  db::{client_repo::NewClient, redirect_repo, scope_repo, test_support::migrated_pool},
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  state::RedisConn,
  store::Store,
};
use secrecy::SecretString;

/// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const ISSUER: &str = "https://auth.example.test";
const REDIRECT: &str = "https://app.example.test/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Build a query map from pairs.
fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
  pairs
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect()
}

/// A minimal client fixture; `public` selects `token_endpoint_auth_method`.
fn fixture(client_id: &str, public: bool) -> NewClient {
  NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: "Authorize Test Client".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: "api:read".to_owned(),
    token_endpoint_auth_method: if public {
      "none".to_owned()
    } else {
      "client_secret_basic".to_owned()
    },
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

/// Register a client, one redirect URI, and the `api:read` catalog scope.
async fn provision(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  client_id: &str,
  public: bool,
) -> TestResult {
  provision_at(pool, keys, client_id, public, REDIRECT).await
}

/// Register a client with an explicit redirect URI (encrypt-only at rest).
async fn provision_at(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  client_id: &str,
  public: bool,
  uri: &str,
) -> TestResult {
  crate::db::client_repo::insert(pool, keys, false, &fixture(client_id, public)).await?;
  let (row, _) = redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::Authorize,
      description: "authorize test",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(pool, client_id, row.id, None).await?;
  scope_repo::upsert(pool, "api:read", "read api").await?;
  Ok(())
}

/// A never-dialed Redis connection: plain-query validation never touches PAR.
fn offline_redis() -> TestResult<RedisConn> {
  let client = redis::Client::open("redis://127.0.0.1:1")?;
  let manager = redis::aio::ConnectionManager::new_lazy_with_config(
    client,
    redis::aio::ConnectionManagerConfig::new()
      .set_number_of_retries(0)
      .set_response_timeout(Some(Duration::from_millis(200)))
      .set_connection_timeout(Some(Duration::from_millis(200))),
  )?;
  Ok(RedisConn::Single(manager))
}

/// Store handle for the PAR lookup (unused on the plain-query path).
fn test_store() -> Store {
  Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  )
}

/// Test PII key ring for the encrypted client projection.
fn test_keys() -> TestResult<KeyRing> {
  Ok(KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("authorize-test-pepper"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("authorize-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("authorize-test-pii"))],
  )?)
}

/// A valid plain-query authorize map for the provisioned client.
fn valid_query(client_id: &str, challenge: &str) -> HashMap<String, String> {
  query(&[
    ("client_id", client_id),
    ("redirect_uri", REDIRECT),
    ("response_type", "code"),
    ("scope", "api:read"),
    ("code_challenge", challenge),
    ("code_challenge_method", "S256"),
    ("state", "xyz-state"),
  ])
}

/// A public client with plain query + PKCE proceeds with every field carried.
#[tokio::test]
async fn authorize_validate_public_client_plain_query_proceeds() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-public", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = valid_query("authz-public", &challenge);
  let mut conn = offline_redis()?;
  let store = test_store();

  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  .map_err(|failure| format!("valid request rejected: {}", failure.code()))?;

  assert_eq!(validated.client_id, "authz-public");
  assert_eq!(validated.redirect_uri, REDIRECT);
  assert_eq!(validated.scope.render(), "api:read");
  assert_eq!(validated.code_challenge, challenge);
  assert_eq!(validated.state.as_deref(), Some("xyz-state"));
  Ok(())
}

/// An unknown `client_id` shows the error page: 400, no `Location`.
#[tokio::test]
async fn authorize_validate_unknown_client_shows_page() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let mut params = valid_query("authz-ghost", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  params.remove("scope");
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("unknown client was accepted".into()),
    Err(failure) => {
      let response = failure.into_response();
      assert_eq!(response.status(), StatusCode::BAD_REQUEST);
      assert!(response.headers().get(header::LOCATION).is_none());
      Ok(())
    }
  }
}

/// An unregistered `redirect_uri` shows the error page: 400, no `Location`.
#[tokio::test]
async fn authorize_validate_unregistered_redirect_shows_page() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-redirect", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut params = valid_query("authz-redirect", &challenge);
  params.insert(
    "redirect_uri".to_owned(),
    "https://evil.example.test/cb".to_owned(),
  );
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("unregistered redirect was accepted".into()),
    Err(failure) => {
      assert_eq!(failure.code(), OAuthErrorCode::InvalidRequest);
      let response = failure.into_response();
      assert_eq!(response.status(), StatusCode::BAD_REQUEST);
      assert!(response.headers().get(header::LOCATION).is_none());
      Ok(())
    }
  }
}

/// `response_type=token` redirects with `unsupported_response_type` + `state`.
#[tokio::test]
async fn authorize_validate_token_response_type_redirects() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-rt", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut params = valid_query("authz-rt", &challenge);
  params.insert("response_type".to_owned(), "token".to_owned());
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("response_type=token was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::UnsupportedResponseType);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state,
      }
      .into_response();
      assert_eq!(response.status(), StatusCode::FOUND);
      let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
      assert!(location.contains("error=unsupported_response_type"));
      assert!(location.contains("state=xyz-state"));
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}

/// An unknown scope redirects with `invalid_scope` + `state` (no page).
#[tokio::test]
async fn authorize_validate_unknown_scope_redirects() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-scope", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut params = valid_query("authz-scope", &challenge);
  params.insert("scope".to_owned(), "admin:all".to_owned());
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("unknown scope was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidScope);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state,
      }
      .into_response();
      assert_eq!(response.status(), StatusCode::FOUND);
      let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
      assert!(location.contains("error=invalid_scope"));
      assert!(location.contains("state=xyz-state"));
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}

/// A confidential client with only plain query params is rejected with
/// `invalid_request` (no PAR `request_uri`, no signed `request` object).
#[tokio::test]
async fn authorize_validate_confidential_plain_query_rejected() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-conf", false).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = valid_query("authz-conf", &challenge);
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("confidential plain-query request was accepted".into()),
    Err(failure) => {
      assert_eq!(failure.code(), OAuthErrorCode::InvalidRequest);
      let response = failure.into_response();
      assert_eq!(response.status(), StatusCode::BAD_REQUEST);
      assert!(response.headers().get(header::LOCATION).is_none());
      Ok(())
    }
  }
}

/// An exact registered redirect matches after decryption; a prefix/evil
/// URI still fails closed; a corrupt `uri_enc` fails as 503 `PiiDecrypt`.
#[tokio::test]
async fn authorize_redirect_exact_match() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-exact", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut conn = offline_redis()?;
  let store = test_store();

  let params = valid_query("authz-exact", &challenge);
  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  .map_err(|failure| format!("exact redirect rejected: {}", failure.code()))?;
  assert_eq!(validated.redirect_uri, REDIRECT);

  for hostile in [
    "https://evil.example.test/cb",
    "https://app.example.test/cb/extra",
  ] {
    let mut params = valid_query("authz-exact", &challenge);
    params.insert("redirect_uri".to_owned(), hostile.to_owned());
    match validate(AuthorizeInput {
      pool: &pool,
      keys: &keys,
      conn: &mut conn,
      store: &store,
      issuer: ISSUER,
      query: &params,
    })
    .await
    {
      Ok(_) => return Err(format!("hostile redirect accepted: {hostile}").into()),
      Err(failure) => {
        assert_eq!(failure.code(), OAuthErrorCode::InvalidRequest);
        let response = failure.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
      }
    }
  }

  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE redirect_uris SET uri_enc = $1")
    .bind(corrupt)
    .execute(&pool)
    .await
    .map_err(|error| format!("corrupt fixture failed: {error}"))?;
  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("corrupt uri_enc accepted".into()),
    Err(AuthorizeFailure::Page(error)) => {
      assert!(matches!(error, AppError::PiiDecrypt));
      assert_eq!(error.code(), OAuthErrorCode::TemporarilyUnavailable);
      assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
      Ok(())
    }
    Err(other) => Err(format!("expected a PiiDecrypt page, got {}", other.code()).into()),
  }
}

/// A loopback registration matches a request with a random port (RFC 8252
/// §7.3) after decryption; a different path still fails closed.
#[tokio::test]
async fn authorize_loopback_allows_port() -> TestResult {
  const LOOPBACK: &str = "http://127.0.0.1:8080/cb";
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision_at(&pool, &keys, "authz-loop", true, LOOPBACK).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut conn = offline_redis()?;
  let store = test_store();

  let mut params = valid_query("authz-loop", &challenge);
  params.insert(
    "redirect_uri".to_owned(),
    "http://127.0.0.1:59231/cb".to_owned(),
  );
  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  .map_err(|failure| format!("loopback port rejected: {}", failure.code()))?;
  assert_eq!(validated.redirect_uri, "http://127.0.0.1:59231/cb");

  params.insert(
    "redirect_uri".to_owned(),
    "http://127.0.0.1:59231/other".to_owned(),
  );
  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("loopback wrong-path accepted".into()),
    Err(failure) => {
      assert_eq!(failure.code(), OAuthErrorCode::InvalidRequest);
      Ok(())
    }
  }
}

/// A missing PKCE challenge redirects with `invalid_request` (+ `state`).
#[tokio::test]
async fn authorize_validate_missing_challenge_redirects() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-pkce", true).await?;
  let mut params = valid_query("authz-pkce", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  params.remove("code_challenge");
  params.remove("code_challenge_method");
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    query: &params,
  })
  .await
  {
    Ok(_) => Err("challengeless request was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidRequest);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}

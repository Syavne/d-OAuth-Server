//! `test(authorize_validate)` suite: validation order + error-delivery matrix.

use std::{collections::HashMap, time::Duration};

use axum::http::{StatusCode, header};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use secrecy::SecretString;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AuthorizeFailure, AuthorizeInput, validate};
use crate::{
  config::DurabilityMode,
  crypto::pkce::challenge_from_verifier,
  db::{
    client_repo, client_repo::NewClient, redirect_repo, resource_repo, scope_repo,
    test_support::migrated_pool,
  },
  error::{AppError, OAuthErrorCode},
  keys::{KeyId, KeyRing},
  protocol::{
    cimd,
    client_auth::ClientAuthRequest,
    par::{ParContext, ParStores, push_authorization_request},
  },
  state::RedisConn,
  store::Store,
  test_support,
};

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
    access_token_format: "opaque".to_owned(),
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

/// An Ed25519 signer plus the matching inline JWKS for a JAR regression.
struct TestSigner {
  encoding: EncodingKey,
  jwks: serde_json::Value,
}

impl TestSigner {
  /// Generate a fresh Ed25519 keypair and its one-key inline JWKS.
  fn generate(kid: &str) -> TestResult<Self> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "ed25519 keygen failed")?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "ed25519 reload failed")?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    Ok(Self {
      encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
      jwks: serde_json::json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid }]
      }),
    })
  }

  /// Sign a request object bound to `client_id` and the test issuer.
  fn request_object(
    &self,
    kid: &str,
    client_id: &str,
    extra: serde_json::Value,
  ) -> TestResult<String> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = serde_json::json!({
      "iss": client_id,
      "aud": ISSUER,
      "exp": now + 300,
      "iat": now,
    });
    let object = claims
      .as_object_mut()
      .ok_or("request object claims must be an object")?;
    let extra = extra
      .as_object()
      .ok_or("request object extra claims must be an object")?;
    for (name, value) in extra {
      object.insert(name.clone(), value.clone());
    }
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    Ok(encode(&header, &claims, &self.encoding)?)
  }
}

/// Register a client whose inline JWKS verifies signed request objects.
async fn provision_signing(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  client_id: &str,
  jwks: serde_json::Value,
) -> TestResult {
  let mut new = fixture(client_id, true);
  new.jwks = Some(jwks);
  client_repo::insert(pool, keys, false, &new).await?;
  let (row, _) = redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri: REDIRECT,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("response_type=token was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
      iss,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::UnsupportedResponseType);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      assert_eq!(iss, ISSUER);
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state,
        iss,
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
      assert!(
        location.contains("iss=https%3A%2F%2Fauth.example.test"),
        "error redirect missing iss: {location}"
      );
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("unknown scope was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
      iss,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidScope);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      assert_eq!(iss, ISSUER);
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state,
        iss,
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
      assert!(
        location.contains("iss=https%3A%2F%2Fauth.example.test"),
        "error redirect missing iss: {location}"
      );
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
      allow_localhost_redirect: false,
      cimd: None,
      query: &params,
      resources: Vec::new(),
      resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
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
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("challengeless request was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
      iss,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidRequest);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      assert_eq!(iss, ISSUER);
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}

/// A direct `Page(temporarily_unavailable)` renders 503 + `Retry-After`
/// (fail-closed Postgres/PII outage pre-validation); `Page(server_error)`
/// renders 500. Client-error pages stay 400.
#[tokio::test]
async fn authorize_page_outage_renders_503_with_retry_after() -> TestResult {
  let response = AuthorizeFailure::Page(AppError::temporarily_unavailable()).into_response();
  assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
  assert_eq!(
    response
      .headers()
      .get(header::RETRY_AFTER)
      .and_then(|value| value.to_str().ok()),
    Some("1")
  );
  assert!(response.headers().get(header::LOCATION).is_none());

  let response = AuthorizeFailure::Page(AppError::server_error()).into_response();
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  assert!(response.headers().get(header::LOCATION).is_none());

  let response = AuthorizeFailure::Page(AppError::invalid_request("bad")).into_response();
  assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  assert!(response.headers().get(header::LOCATION).is_none());
  Ok(())
}

/// A `post_logout` catalog outage after `redirect_uri` validation redirects
/// (302) with `temporarily_unavailable`, per the error-delivery matrix.
#[tokio::test]
async fn authorize_post_logout_outage_redirects() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-post-logout", true).await?;
  let (row, _) = redirect_repo::upsert(
    &pool,
    &keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: Uuid::new_v4(),
      uri: "https://app.example.test/signed-out",
      kind: redirect_repo::RedirectKind::PostLogout,
      description: "post-logout test",
      created_by: None,
    },
  )
  .await
  .map_err(|error| format!("post-logout fixture failed: {error}"))?;
  redirect_repo::attach(&pool, "authz-post-logout", row.id, None)
    .await
    .map_err(|error| format!("post-logout attach failed: {error}"))?;
  sqlx::query("UPDATE redirect_uris SET uri_enc = $1 WHERE kind = 'post_logout'")
    .bind(b"corrupt-blob".as_slice())
    .execute(&pool)
    .await
    .map_err(|error| format!("corrupt fixture failed: {error}"))?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = valid_query("authz-post-logout", &challenge);
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("post-logout outage was accepted".into()),
    Err(AuthorizeFailure::Redirect { target, error, .. }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::TemporarilyUnavailable);
      assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state: None,
        iss: ISSUER.to_owned(),
      }
      .into_response();
      assert_eq!(response.status(), StatusCode::FOUND);
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}
/// draft-ietf-oauth-v2-1-16 §4.1.2.1 and §7.15.1.
#[tokio::test]
async fn authorize_error_iss() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-err-iss", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut params = valid_query("authz-err-iss", &challenge);
  params.insert("response_type".to_owned(), "token".to_owned());
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("response_type=token was accepted".into()),
    Err(AuthorizeFailure::Redirect {
      target,
      error,
      state,
      iss,
    }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::UnsupportedResponseType);
      assert_eq!(state.as_deref(), Some("xyz-state"));
      assert_eq!(iss, ISSUER);
      let response = AuthorizeFailure::Redirect {
        target,
        error,
        state,
        iss,
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
      assert!(
        location.contains("iss=https%3A%2F%2Fauth.example.test"),
        "error redirect missing iss: {location}"
      );
      Ok(())
    }
    Err(other) => Err(format!("expected a redirect, got {}", other.code()).into()),
  }
}
/// A missing `response_type` redirects with `invalid_request` (+ `state`):
/// `client_id` and `redirect_uri` are already validated here, so per
/// draft-ietf-oauth-v2-1-16 §4.1.1 and §4.1.2.1 the error rides the redirect.
#[tokio::test]
async fn authorize_validate_missing_response_type_redirects() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-missing-rt", true).await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let mut conn = offline_redis()?;
  let store = test_store();

  for params in [
    {
      let mut q = valid_query("authz-missing-rt", &challenge);
      q.remove("response_type");
      q
    },
    {
      let mut q = valid_query("authz-missing-rt", &challenge);
      q.insert("response_type".to_owned(), String::new());
      q
    },
  ] {
    match validate(AuthorizeInput {
      pool: &pool,
      keys: &keys,
      conn: &mut conn,
      store: &store,
      issuer: ISSUER,
      allow_localhost_redirect: false,
      cimd: None,
      query: &params,
      resources: Vec::new(),
      resource_indicators_enabled: false,
    })
    .await
    {
      Ok(_) => return Err("missing response_type was accepted".into()),
      Err(AuthorizeFailure::Redirect {
        target,
        error,
        state,
        iss,
      }) => {
        assert_eq!(target, REDIRECT);
        assert_eq!(error.code(), OAuthErrorCode::InvalidRequest);
        assert_eq!(state.as_deref(), Some("xyz-state"));
        assert_eq!(iss, ISSUER);
        let response = AuthorizeFailure::Redirect {
          target,
          error,
          state,
          iss,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
          .headers()
          .get(header::LOCATION)
          .and_then(|value| value.to_str().ok())
          .unwrap_or_default()
          .to_owned();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("error_description="));
        assert!(location.contains("state=xyz-state"));
        assert!(
          location.contains("iss=https%3A%2F%2Fauth.example.test"),
          "error redirect missing iss: {location}"
        );
      }
      Err(other) => {
        return Err(format!("expected a redirect, got {}", other.code()).into());
      }
    }
  }
  Ok(())
}

/// Seed the CIMD document cache for `url`, so a resolve is served from Redis
/// without a network fetch (a cache miss would fail against `.invalid`).
async fn seed_cimd(
  conn: &mut RedisConn,
  prefix: &str,
  url: &str,
  document: &cimd::CimdDocument,
) -> TestResult {
  let payload = serde_json::to_string(document)?;
  redis::cmd("SET")
    .arg(cimd::cache_key(prefix, url))
    .arg(payload)
    .arg("EX")
    .arg(900)
    .query_async::<()>(conn)
    .await?;
  Ok(())
}

/// A minimal `none`-method CIMD document (CIMD draft §4.1).
fn cimd_document(url: &str, redirect_uris: &[&str], scope: &str) -> cimd::CimdDocument {
  cimd::CimdDocument {
    client_id: url.to_owned(),
    redirect_uris: redirect_uris.iter().map(|uri| (*uri).to_owned()).collect(),
    token_endpoint_auth_method: Some("none".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    scope: Some(scope.to_owned()),
    jwks: None,
    jwks_uri: None,
    client_name: None,
    dpop_bound_access_tokens: None,
  }
}

/// A shared-Redis connection plus its unique `{state}`/`{rl}` prefix pair.
async fn shared_redis() -> TestResult<(RedisConn, String, String)> {
  let manager = test_support::redis_manager()
    .await
    .map_err(|error| format!("shared redis: {error}"))?;
  let (token_prefix, ratelimit_prefix) = test_support::unique_prefixes();
  Ok((RedisConn::Single(manager), token_prefix, ratelimit_prefix))
}

/// CIMD settings pointing at this test's cache prefix.
fn cimd_settings(prefix: &str) -> super::CimdRequest<'_> {
  super::CimdRequest {
    token_prefix: prefix,
    max_bytes: 5_120,
    timeout: Duration::from_secs(2),
  }
}

/// A client metadata document client completes `/authorize` with no row and
/// no catalog redirect; a redirect outside the document and a shared-secret
/// document both fail closed (CIMD draft §4.1/§5).
#[tokio::test]
async fn authorize_accepts_cimd_public() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  scope_repo::upsert(&pool, "api:read", "read api").await?;
  let (mut conn, prefix, ratelimit) = shared_redis().await?;
  let store = Store::from_parts(prefix.clone(), ratelimit, DurabilityMode::WaitAof);

  let url = "https://client.invalid/cimd.json";
  seed_cimd(
    &mut conn,
    &prefix,
    url,
    &cimd_document(url, &["https://app.example.test/cb"], "api:read"),
  )
  .await?;

  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = query(&[
    ("client_id", url),
    ("redirect_uri", "https://app.example.test/cb"),
    ("response_type", "code"),
    ("scope", "api:read"),
    ("code_challenge", challenge.as_str()),
    ("code_challenge_method", "S256"),
    ("state", "xyz-state"),
  ]);

  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(cimd_settings(&prefix)),
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  .map_err(|failure| format!("CIMD request rejected: {}", failure.code()))?;
  assert_eq!(validated.client_id, url);
  assert_eq!(validated.redirect_uri, "https://app.example.test/cb");
  assert_eq!(validated.scope.render(), "api:read");
  assert_eq!(validated.state.as_deref(), Some("xyz-state"));

  // A registration-free client writes no row and attaches no catalog redirect.
  assert!(
    client_repo::find_active_by_client_id(&pool, &keys, url)
      .await?
      .is_none(),
    "CIMD must not persist a client row"
  );

  // A redirect outside the document is refused (untrusted: page, no Location).
  let mut mismatch = params.clone();
  mismatch.insert(
    "redirect_uri".to_owned(),
    "https://evil.example.test/cb".to_owned(),
  );
  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(cimd_settings(&prefix)),
    query: &mismatch,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => return Err("document redirect mismatch was accepted".into()),
    Err(failure) => assert_eq!(failure.code(), OAuthErrorCode::InvalidRequest),
  }

  // A document declaring a shared-secret method is invalid metadata.
  let shared_url = "https://client.invalid/secret.json";
  let mut shared = cimd_document(shared_url, &["https://app.example.test/cb"], "api:read");
  shared.token_endpoint_auth_method = Some("client_secret_basic".to_owned());
  seed_cimd(&mut conn, &prefix, shared_url, &shared).await?;
  let mut shared_params = params.clone();
  shared_params.insert("client_id".to_owned(), shared_url.to_owned());
  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(cimd_settings(&prefix)),
    query: &shared_params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("shared-secret CIMD document was accepted".into()),
    Err(failure) => {
      assert_eq!(failure.code(), OAuthErrorCode::InvalidClientMetadata);
      Ok(())
    }
  }
}

/// A document `http://localhost` redirect is accepted only while
/// `allow_localhost_redirect` is on; the request's random port is matched by
/// the RFC 8252 §7.3 loopback rule. With the flag off the document itself is
/// invalid, because `http://localhost` is not a loopback host.
#[tokio::test]
async fn authorize_accepts_cimd_localhost_when_flag_on() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  scope_repo::upsert(&pool, "api:read", "read api").await?;
  let (mut conn, prefix, ratelimit) = shared_redis().await?;
  let store = Store::from_parts(prefix.clone(), ratelimit, DurabilityMode::WaitAof);

  let url = "https://client.invalid/loopback.json";
  seed_cimd(
    &mut conn,
    &prefix,
    url,
    &cimd_document(url, &["http://localhost/cb"], "api:read"),
  )
  .await?;

  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = query(&[
    ("client_id", url),
    ("redirect_uri", "http://localhost:51234/cb"),
    ("response_type", "code"),
    ("scope", "api:read"),
    ("code_challenge", challenge.as_str()),
    ("code_challenge_method", "S256"),
  ]);

  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: true,
    cimd: Some(cimd_settings(&prefix)),
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  .map_err(|failure| {
    format!(
      "CIMD loopback rejected with the flag on: {}",
      failure.code()
    )
  })?;
  assert_eq!(validated.redirect_uri, "http://localhost:51234/cb");
  assert_eq!(validated.scope.render(), "api:read");

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(cimd_settings(&prefix)),
    query: &params,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  {
    Ok(_) => Err("CIMD localhost redirect was accepted with the flag off".into()),
    Err(failure) => {
      assert_eq!(failure.code(), OAuthErrorCode::InvalidRedirectUri);
      Ok(())
    }
  }
}

/// Two catalog resources presented as repeated query indicators validate and
/// pin as a sorted deduped audience set on the validated request.
#[tokio::test]
async fn authorize_accepts_repeated_resource() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  provision(&pool, &keys, "authz-resource", true).await?;
  resource_repo::upsert(&pool, "https://b.example.test/", "b").await?;
  resource_repo::upsert(&pool, "https://a.example.test/", "a").await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let params = valid_query("authz-resource", &challenge);
  let mut conn = offline_redis()?;
  let store = test_store();

  let validated = validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: vec![
      "https://b.example.test/".to_owned(),
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
    ],
    resource_indicators_enabled: true,
  })
  .await
  .map_err(|failure| format!("repeated resource rejected: {}", failure.code()))?;

  if validated.aud
    != vec![
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
    ]
  {
    return Err(format!("aud not pinned sorted deduped: {:?}", validated.aud).into());
  }
  Ok(())
}

/// A query `resource` appended to a PAR `request_uri` must not union into the
/// pinned audience: the request rejects as `invalid_request_object` through
/// the validated redirect (RFC 9101 §5.2, RFC 8707 §2.1).
#[tokio::test]
async fn authorize_rejects_query_resource_beside_par() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let client_id = "authz-par-resource";
  provision(&pool, &keys, client_id, true).await?;
  resource_repo::upsert(&pool, "https://a.example.test/", "a").await?;
  resource_repo::upsert(&pool, "https://b.example.test/", "b").await?;
  let (mut conn, prefix, ratelimit) = shared_redis().await?;
  let store = Store::from_parts(prefix, ratelimit, DurabilityMode::WaitAof);

  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let pushed_params = valid_query(client_id, &challenge);
  let auth = ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  let ctx = ParContext {
    token_endpoint: "https://auth.example.test/token",
    now: OffsetDateTime::now_utc(),
    par_ttl: Duration::from_secs(90),
    allow_localhost_redirect: false,
    cimd: None,
    resource_indicators_enabled: true,
  };
  let pinned = ["https://a.example.test/".to_owned()];
  let pushed = {
    let mut stores = ParStores {
      pool: &pool,
      keys: &keys,
      conn: &mut conn,
      store: &store,
    };
    push_authorization_request(&mut stores, &ctx, &auth, &pushed_params, &pinned)
      .await
      .map_err(|error| format!("PAR push rejected: {}", error.code()))?
  };

  let appended = "https://b.example.test/".to_owned();
  let params = query(&[
    ("client_id", client_id),
    ("request_uri", pushed.request_uri.as_str()),
    ("resource", appended.as_str()),
  ]);

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: vec![appended],
    resource_indicators_enabled: true,
  })
  .await
  {
    Ok(validated) => Err(format!("PAR audience was widened to {:?}", validated.aud).into()),
    Err(AuthorizeFailure::Redirect { target, error, .. }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidRequestObject);
      Ok(())
    }
    Err(other) => Err(format!("expected invalid_request_object, got {}", other.code()).into()),
  }
}

/// A query `resource` beside an inline signed request object is rejected:
/// the audience travels in the object, never the query (RFC 9101 §5.2).
#[tokio::test]
async fn authorize_rejects_query_resource_beside_inline_request() -> TestResult {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let client_id = "authz-jar-resource";
  let signer = TestSigner::generate("jar-resource-key")?;
  provision_signing(&pool, &keys, client_id, signer.jwks.clone()).await?;
  resource_repo::upsert(&pool, "https://b.example.test/", "b").await?;
  let challenge = challenge_from_verifier(VERIFIER).map_err(|_| "bad fixture verifier")?;
  let request = signer.request_object(
    "jar-resource-key",
    client_id,
    serde_json::json!({
      "response_type": "code",
      "redirect_uri": REDIRECT,
      "scope": "api:read",
      "code_challenge": challenge,
      "code_challenge_method": "S256",
      "state": "jar-state",
    }),
  )?;
  let appended = "https://b.example.test/".to_owned();
  let params = query(&[
    ("client_id", client_id),
    ("request", request.as_str()),
    ("resource", appended.as_str()),
  ]);
  let mut conn = offline_redis()?;
  let store = test_store();

  match validate(AuthorizeInput {
    pool: &pool,
    keys: &keys,
    conn: &mut conn,
    store: &store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: None,
    query: &params,
    resources: vec![appended],
    resource_indicators_enabled: true,
  })
  .await
  {
    Ok(validated) => Err(format!("JAR pinned the query audience {:?}", validated.aud).into()),
    Err(AuthorizeFailure::Redirect { target, error, .. }) => {
      assert_eq!(target, REDIRECT);
      assert_eq!(error.code(), OAuthErrorCode::InvalidRequestObject);
      Ok(())
    }
    Err(other) => Err(format!("expected invalid_request_object, got {}", other.code()).into()),
  }
}

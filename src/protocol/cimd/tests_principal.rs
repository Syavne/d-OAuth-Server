//! Registration-free principal tests: the synthetic `Client` threaded
//! through token dispatch, `client_auth`, `/revoke`, `/introspect`,
//! authorize/JAR, and PAR (CIMD draft §3/§4.1/§5, RFC 7009 §2.1/§2.2,
//! RFC 7662 §2.3, RFC 9449).
//!
//! Every test seeds the CIMD document cache directly under
//! `cimd::cache_key` (a miss against `.invalid` can never pass), so no test
//! performs a network fetch. A registered row always wins; `cimd: None`
//! keeps the exact pre-CIMD unknown-client behavior.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{CimdDocument, CimdSettings, cache_key, resolve_client};
use crate::config::{DurabilityMode, TtlConfig};
use crate::crypto::secret::{Argon2Params, hash_secret};
use crate::db::{NewClient, TokenEndpointAuthMethod, client_repo, scope_repo};
use crate::error::{AppError, OAuthErrorCode};
use crate::keys::{KeyId, KeyRing};
use crate::protocol::authorize::{AuthorizeInput, CimdRequest, validate};
use crate::protocol::client_auth::{
  AuthContext, AuthStores, CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthRequest,
  authenticate_client, token_endpoint,
};
use crate::protocol::code::{CodeClientKind, CodeIssueRequest, CodeIssuer, IssuedCode};
use crate::protocol::introspect::{
  IntrospectContext, IntrospectHttpInputs, IntrospectStores, introspect,
};
use crate::protocol::par::{ParContext, ParStores, push_authorization_request};
use crate::protocol::revoke::{
  RevokeContext, RevokeOutcome, RevokeRequest, RevokeStores, revoke_tokens,
};
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::grants::authorization_code::{
  CodeGrantInputs, CodeGrantState, redeem_code,
};
use crate::protocol::token::grants::refresh_token::{RefreshInput, refresh};
use crate::protocol::token::{ClientKind, SenderProof, TokenFormat, TokenService};
use crate::state::RedisConn;
use crate::store::Store;

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the CIMD principal test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] crate::store::StoreError),
  /// The token service failed.
  #[error("service error: {0}")]
  Service(#[from] crate::protocol::token::TokenServiceError),
  /// A key operation failed.
  #[error("keys error: {0}")]
  Keys(#[from] crate::keys::KeyRingError),
  /// A code issuance failed.
  #[error("issuance error: {0}")]
  Issue(#[from] crate::protocol::code::CodeIssueError),
  /// A JWT operation failed.
  #[error("jwt error: {0}")]
  Jwt(#[from] jsonwebtoken::errors::Error),
  /// An application error from a helper under test.
  #[error("app error: {0}")]
  App(#[from] AppError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

static NONCE: AtomicU64 = AtomicU64::new(900_000);

fn unique(label: &str) -> String {
  let n = NONCE.fetch_add(1, Ordering::Relaxed);
  format!("https://client-{n}-{label}.invalid/cimd.json")
}

const ISSUER: &str = "https://auth.example.test";
const REDIRECT: &str = "https://app.example.test/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Live handles for one principal test.
struct Harness {
  _db: crate::test_guard::Lease<crate::db::test_support::Db>,
  pool: sqlx::PgPool,
  conn: RedisConn,
  store: Store,
  token_prefix: String,
  ring: KeyRing,
  ttl: TtlConfig,
  endpoint: String,
}

async fn harness() -> Result<Harness, TestError> {
  let (_db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg: {error}")))?;
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let (token_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let ring = KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("cimd-principal-test-pepper"),
    )],
    vec![(
      KeyId::new("v1"),
      SecretString::from("cimd-principal-test-totp"),
    )],
    vec![(
      KeyId::new("v1"),
      SecretString::from("cimd-principal-test-pii"),
    )],
  )
  .map_err(|error| TestError::Unexpected(format!("keys: {error:?}")))?;
  scope_repo::upsert(&pool, "api:read", "read api").await?;
  Ok(Harness {
    _db,
    pool,
    conn: RedisConn::Single(manager),
    store: Store::from_parts(
      token_prefix.clone(),
      ratelimit_prefix,
      DurabilityMode::WaitAof,
    ),
    token_prefix,
    ring,
    ttl: TtlConfig::default(),
    endpoint: token_endpoint(ISSUER),
  })
}

fn auth_stores(h: &mut Harness) -> AuthStores<'_> {
  AuthStores {
    pool: &h.pool,
    keys: &h.ring,
    conn: &mut h.conn,
    store: &h.store,
  }
}

fn auth_ctx_for<'a>(endpoint: &'a str, token_prefix: &'a str) -> AuthContext<'a> {
  AuthContext {
    token_endpoint: endpoint,
    now: OffsetDateTime::now_utc(),
    cimd: Some(CimdSettings {
      token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
      allow_localhost: false,
    }),
  }
}

/// Seed the document cache for `url` (a miss would fail against `.invalid`).
async fn seed_cimd(h: &mut Harness, url: &str, document: &CimdDocument) -> TestResult {
  let payload =
    serde_json::to_string(document).map_err(|error| TestError::Unexpected(format!("{error}")))?;
  redis::cmd("SET")
    .arg(cache_key(&h.token_prefix, url))
    .arg(payload)
    .arg("EX")
    .arg(900)
    .query_async::<()>(&mut h.conn)
    .await?;
  Ok(())
}

fn document(
  url: &str,
  method: Option<&str>,
  grants: &[&str],
  scope: &str,
  jwks: Option<serde_json::Value>,
  dpop: bool,
) -> CimdDocument {
  CimdDocument {
    client_id: url.to_owned(),
    redirect_uris: vec![REDIRECT.to_owned()],
    token_endpoint_auth_method: method.map(str::to_owned),
    grant_types: Some(grants.iter().map(|grant| (*grant).to_owned()).collect()),
    scope: Some(scope.to_owned()),
    jwks,
    jwks_uri: None,
    client_name: None,
    dpop_bound_access_tokens: Some(dpop),
  }
}

/// An Ed25519 signer plus the matching inline JWKS for one document.
struct DocKey {
  encoding: EncodingKey,
  jwks: serde_json::Value,
}

impl DocKey {
  fn generate(kid: &str) -> Result<Self, TestError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
      .map_err(|_| TestError::Unexpected("ed25519 keygen failed".to_owned()))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
      .map_err(|_| TestError::Unexpected("ed25519 reload failed".to_owned()))?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    Ok(Self {
      encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
      jwks: serde_json::json!({
        "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid }]
      }),
    })
  }

  fn assertion(
    &self,
    kid: &str,
    client_id: &str,
    audience: &str,
    jti: &str,
  ) -> Result<String, TestError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = AssertionClaims {
      iss: client_id.to_owned(),
      sub: client_id.to_owned(),
      aud: audience.to_owned(),
      jti: jti.to_owned(),
      exp: now + 300,
      iat: now,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    Ok(encode(&header, &claims, &self.encoding)?)
  }

  fn request_object(
    &self,
    kid: &str,
    client_id: &str,
    issuer: &str,
    extra: serde_json::Value,
  ) -> Result<String, TestError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = serde_json::json!({
      "iss": client_id,
      "aud": issuer,
      "exp": now + 300,
      "iat": now,
    });
    let object = claims
      .as_object_mut()
      .ok_or_else(|| TestError::Unexpected("claims must be an object".to_owned()))?;
    let extra_object = extra
      .as_object()
      .ok_or_else(|| TestError::Unexpected("extra must be an object".to_owned()))?;
    for (key, value) in extra_object {
      object.insert(key.clone(), value.clone());
    }
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_owned());
    Ok(encode(&header, &claims, &self.encoding)?)
  }
}

/// `private_key_jwt` assertion claims (RFC 7523 §3).
#[derive(Debug, Serialize, Deserialize)]
struct AssertionClaims {
  iss: String,
  sub: String,
  aud: String,
  jti: String,
  exp: i64,
  iat: i64,
}

fn assertion_request<'a>(client_id: &'a str, assertion: &'a str) -> ClientAuthRequest<'a> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER),
    assertion: Some(assertion),
    peer_certs: None,
  }
}

fn bare_request(client_id: &str) -> ClientAuthRequest<'_> {
  ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  }
}

/// Issue a code for a CIMD `client_id` through the real issuer.
async fn issue_code(
  h: &mut Harness,
  client_id: &str,
  kind: CodeClientKind,
  dpop_required: bool,
  dpop_jkt: Option<&str>,
) -> Result<IssuedCode, TestError> {
  let issuer = CodeIssuer::new(&h.ttl, &h.ring)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read")?;
  let request = CodeIssueRequest {
    client_id,
    client_kind: kind,
    dpop_required,
    user_id: "user-1",
    redirect_uri: REDIRECT,
    approved_scope: &approved,
    user_entitled: &entitled,
    code_challenge: CHALLENGE,
    dpop_jkt,
    state: None,
    aud: &[],
    issuer: ISSUER,
  };
  Ok(issuer.issue(&mut h.conn, &h.store, &request).await?)
}

/// Redeem a code as the named CIMD client.
async fn redeem(
  h: &mut Harness,
  code: &str,
  client_id: &str,
  assertion: Option<&str>,
  now: i64,
) -> Result<crate::protocol::token::grants::authorization_code::CodeTokenResponse, AppError> {
  let inputs = CodeGrantInputs {
    code,
    redirect_uri: REDIRECT,
    code_verifier: Some(VERIFIER),
    client_id: Some(client_id),
    basic_header: None,
    body_secret: None,
    assertion_type: assertion.map(|_| CLIENT_ASSERTION_TYPE_JWT_BEARER),
    assertion,
    dpop_proof: None,
    peer_certs: None,
    aud: &[],
  };
  let mut state = CodeGrantState {
    pool: &h.pool,
    conn: &mut h.conn,
    store: &h.store,
    keys: &h.ring,
    issuer: ISSUER,
    ttl: &h.ttl,
    token_format: TokenFormat::Opaque,
    jwt_signer: None,
    cimd: Some(CimdSettings {
      token_prefix: &h.token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
      allow_localhost: false,
    }),
    now_unix: now,
  };
  redeem_code(&mut state, &inputs).await
}

fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// A `private_key_jwt` document redeems a code through the token grant: the
/// assertion verifies against the doc-inline `jwks` and the minted token is
/// returned (CIMD draft §4.1).
#[tokio::test]
async fn token_accepts_cimd_private_key_jwt() -> TestResult {
  let mut h = harness().await?;
  let url = unique("jwt");
  let key = DocKey::generate("doc-key-1")?;
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("private_key_jwt"),
      &["authorization_code", "refresh_token"],
      "api:read",
      Some(key.jwks.clone()),
      false,
    ),
  )
  .await?;
  let issued = issue_code(&mut h, &url, CodeClientKind::Confidential, false, None).await?;
  let assertion = key.assertion("doc-key-1", &url, &h.endpoint.clone(), "cimd-jti-accept-1")?;
  let tokens = redeem(
    &mut h,
    issued.code.as_str(),
    &url,
    Some(&assertion),
    now_unix(),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("cimd redemption rejected: {error}")))?;
  if tokens.access_token.is_empty() || tokens.refresh_token.is_none() {
    return Err(TestError::Unexpected(
      "cimd redemption must mint access and refresh tokens".to_owned(),
    ));
  }
  if tokens.token_type != "Bearer" {
    return Err(TestError::Unexpected(format!(
      "unbound cimd client must get Bearer, got {}",
      tokens.token_type
    )));
  }
  if tokens.scope != "api:read" {
    return Err(TestError::Unexpected(format!(
      "unexpected scope: {}",
      tokens.scope
    )));
  }
  Ok(())
}

/// A document declaring a shared-secret method never resolves: validation
/// rejects it before any principal exists (CIMD draft §4.1).
#[tokio::test]
async fn token_rejects_cimd_secret_method() -> TestResult {
  let mut h = harness().await?;
  let url = unique("secret");
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("client_secret_basic"),
      &["authorization_code"],
      "api:read",
      None,
      false,
    ),
  )
  .await?;
  let req = ClientAuthRequest {
    basic_header: None,
    client_id: Some(&url),
    body_secret: Some(SecretString::from("whatever")),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  let endpoint = h.endpoint.clone();
  let token_prefix = h.token_prefix.clone();
  let ctx = auth_ctx_for(&endpoint, &token_prefix);
  match authenticate_client(&mut auth_stores(&mut h), &ctx, &req).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidClientMetadata => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "secret-method doc must be invalid_client_metadata, got {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "secret-method doc was accepted".to_owned(),
    )),
  }
}

/// A document with `dpop_bound_access_tokens=true` requires a fresh DPoP
/// proof at every gate: redemption without one fails (RFC 9449).
#[tokio::test]
async fn cimd_client_bound_doc_requires_dpop() -> TestResult {
  let mut h = harness().await?;
  let url = unique("bound");
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("none"),
      &["authorization_code"],
      "api:read",
      None,
      true,
    ),
  )
  .await?;
  let issued = issue_code(
    &mut h,
    &url,
    CodeClientKind::Public,
    true,
    Some("bound-test-jkt"),
  )
  .await?;
  match redeem(&mut h, issued.code.as_str(), &url, None, now_unix()).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidDpopProof => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "bound cimd doc must demand DPoP, got {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "bound cimd doc redeemed without DPoP".to_owned(),
    )),
  }
}

/// A `none` document that leaves `dpop_bound_access_tokens` false mints
/// `Bearer` and the pair refreshes without a proof.
#[tokio::test]
async fn cimd_none_unbound_gets_bearer() -> TestResult {
  let mut h = harness().await?;
  let url = unique("unbound");
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("none"),
      &["authorization_code", "refresh_token"],
      "api:read",
      None,
      false,
    ),
  )
  .await?;
  let issued = issue_code(&mut h, &url, CodeClientKind::Public, false, None).await?;
  let tokens = redeem(&mut h, issued.code.as_str(), &url, None, now_unix())
    .await
    .map_err(|error| TestError::Unexpected(format!("unbound cimd redemption rejected: {error}")))?;
  if tokens.token_type != "Bearer" {
    return Err(TestError::Unexpected(format!(
      "unbound cimd client must get Bearer, got {}",
      tokens.token_type
    )));
  }
  let Some(refresh_token) = tokens.refresh_token else {
    return Err(TestError::Unexpected(
      "unbound cimd must mint a refresh token".to_owned(),
    ));
  };
  let service = TokenService::new(&h.ttl, &h.ring)?;
  let enabled = ScopeSet::parse("api:read")?;
  let registered = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::empty();
  let proof = SenderProof {
    dpop_jkt: None,
    mtls_x5t_s256: None,
  };
  let refreshed = refresh(
    &mut h.conn,
    &h.store,
    &service,
    &RefreshInput {
      client_id: &url,
      client_kind: ClientKind::Public,
      dpop_required: false,
      refresh_token: &refresh_token,
      requested_scope: None,
      requested_resources: &[],
      proof: &proof,
      enabled: &enabled,
      client_registered: &registered,
      user_entitled: &entitled,
      token_format: TokenFormat::Opaque,
      now_unix: now_unix(),
    },
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("cimd refresh rejected: {error}")))?;
  if refreshed.token_type != "Bearer" {
    return Err(TestError::Unexpected(format!(
      "refreshed cimd token must stay Bearer, got {}",
      refreshed.token_type
    )));
  }
  Ok(())
}

/// A document that omits the grant is not authorized for it: redeeming a code
/// with a `refresh_token`-only document fails `unauthorized_client`.
#[tokio::test]
async fn cimd_client_enforces_grant_allowlist() -> TestResult {
  let mut h = harness().await?;
  let url = unique("grants");
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("none"),
      &["refresh_token"],
      "api:read",
      None,
      false,
    ),
  )
  .await?;
  let issued = issue_code(&mut h, &url, CodeClientKind::Public, false, None).await?;
  match redeem(&mut h, issued.code.as_str(), &url, None, now_unix()).await {
    Err(error) if error.code() == OAuthErrorCode::UnauthorizedClient => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "grant allowlist must be unauthorized_client, got {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "code redeemed without the authorization_code grant".to_owned(),
    )),
  }
}

/// A `private_key_jwt` CIMD client uses PAR and JAR with its document
/// redirect: a pushed request authorizes, and a signed request object
/// verifies against the inline `jwks` (CIMD draft §5).
#[tokio::test]
async fn cimd_client_jar_or_par() -> TestResult {
  let mut h = harness().await?;
  let url = unique("parjar");
  let key = DocKey::generate("doc-key-par")?;
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("private_key_jwt"),
      &["authorization_code"],
      "api:read",
      Some(key.jwks.clone()),
      false,
    ),
  )
  .await?;

  // PAR: the client authenticates with its assertion and pushes with the
  // document redirect; the returned URN then authorizes.
  let assertion = key.assertion("doc-key-par", &url, &h.endpoint.clone(), "cimd-jti-par-1")?;
  let auth = assertion_request(&url, &assertion);
  let mut params = HashMap::from([
    ("client_id".to_owned(), url.clone()),
    ("response_type".to_owned(), "code".to_owned()),
    ("redirect_uri".to_owned(), REDIRECT.to_owned()),
    ("scope".to_owned(), "api:read".to_owned()),
    ("code_challenge".to_owned(), CHALLENGE.to_owned()),
    ("code_challenge_method".to_owned(), "S256".to_owned()),
    ("state".to_owned(), "par-state".to_owned()),
  ]);
  let endpoint = h.endpoint.clone();
  let token_prefix = h.token_prefix.clone();
  let cimd_request = CimdRequest {
    token_prefix: &token_prefix,
    max_bytes: 5_120,
    timeout: Duration::from_secs(2),
  };
  let pushed = {
    let mut stores = ParStores {
      pool: &h.pool,
      keys: &h.ring,
      conn: &mut h.conn,
      store: &h.store,
    };
    let ctx = ParContext {
      token_endpoint: &endpoint,
      now: OffsetDateTime::now_utc(),
      par_ttl: Duration::from_secs(90),
      allow_localhost_redirect: false,
      cimd: Some(cimd_request),
      resource_indicators_enabled: false,
    };
    push_authorization_request(&mut stores, &ctx, &auth, &params, &[])
      .await
      .map_err(|error| TestError::Unexpected(format!("cimd PAR push rejected: {error}")))?
  };
  if !pushed
    .request_uri
    .starts_with("urn:ietf:params:oauth:request_uri:")
  {
    return Err(TestError::Unexpected(format!(
      "bad request_uri: {}",
      pushed.request_uri
    )));
  }
  let par_query = HashMap::from([
    ("client_id".to_owned(), url.clone()),
    ("request_uri".to_owned(), pushed.request_uri.clone()),
  ]);
  let validated = validate(AuthorizeInput {
    pool: &h.pool,
    keys: &h.ring,
    conn: &mut h.conn,
    store: &h.store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(CimdRequest {
      token_prefix: &h.token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
    }),
    query: &par_query,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  .map_err(|failure| {
    TestError::Unexpected(format!("cimd PAR authorize rejected: {}", failure.code()))
  })?;
  if validated.client_id != url || validated.redirect_uri != REDIRECT {
    return Err(TestError::Unexpected(
      "PAR authorize bound the wrong client".to_owned(),
    ));
  }

  // JAR: an inline request object signed by the document key authorizes
  // with only `client_id` beside it in the query.
  let request = key.request_object(
    "doc-key-par",
    &url,
    ISSUER,
    serde_json::json!({
      "client_id": url,
      "response_type": "code",
      "redirect_uri": REDIRECT,
      "scope": "api:read",
      "code_challenge": CHALLENGE,
      "code_challenge_method": "S256",
      "state": "jar-state",
    }),
  )?;
  params.insert("request".to_owned(), request);
  params.remove("request_uri");
  let mut jar_query = HashMap::from([("client_id".to_owned(), url.clone())]);
  jar_query.insert("request".to_owned(), params["request"].clone());
  let validated = validate(AuthorizeInput {
    pool: &h.pool,
    keys: &h.ring,
    conn: &mut h.conn,
    store: &h.store,
    issuer: ISSUER,
    allow_localhost_redirect: false,
    cimd: Some(CimdRequest {
      token_prefix: &h.token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
    }),
    query: &jar_query,
    resources: Vec::new(),
    resource_indicators_enabled: false,
  })
  .await
  .map_err(|failure| {
    TestError::Unexpected(format!("cimd JAR authorize rejected: {}", failure.code()))
  })?;
  if validated.client_id != url {
    return Err(TestError::Unexpected(
      "JAR authorize bound the wrong client".to_owned(),
    ));
  }
  Ok(())
}

/// A registration-free client revokes its own token (RFC 7009 §2.1); a
/// foreign client's token is a uniform no-op and stays live (RFC 7009 §2.2).
#[tokio::test]
async fn cimd_client_can_revoke() -> TestResult {
  let mut h = harness().await?;
  let url = unique("revoke");
  let key = DocKey::generate("doc-key-revoke")?;
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("private_key_jwt"),
      &["authorization_code", "refresh_token"],
      "api:read",
      Some(key.jwks.clone()),
      false,
    ),
  )
  .await?;
  let first = issue_code(&mut h, &url, CodeClientKind::Confidential, false, None).await?;
  let assertion = key.assertion(
    "doc-key-revoke",
    &url,
    &h.endpoint.clone(),
    "cimd-jti-revoke-1",
  )?;
  let tokens = redeem(
    &mut h,
    first.code.as_str(),
    &url,
    Some(&assertion),
    now_unix(),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("cimd redemption rejected: {error}")))?;
  let second = issue_code(&mut h, &url, CodeClientKind::Confidential, false, None).await?;
  let assertion_two = key.assertion(
    "doc-key-revoke",
    &url,
    &h.endpoint.clone(),
    "cimd-jti-revoke-2",
  )?;
  let other = redeem(
    &mut h,
    second.code.as_str(),
    &url,
    Some(&assertion_two),
    now_unix(),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("second cimd redemption rejected: {error}")))?;

  let service = TokenService::new(&h.ttl, &h.ring)?;
  let endpoint = h.endpoint.clone();
  let token_prefix = h.token_prefix.clone();
  let ctx = RevokeContext {
    token_endpoint: &endpoint,
    now: OffsetDateTime::now_utc(),
    cimd: Some(CimdSettings {
      token_prefix: &token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
      allow_localhost: false,
    }),
    request_id: None,
  };
  // A foreign registration-free client learns nothing and revokes nothing.
  let foreign_url = unique("foreign");
  seed_cimd(
    &mut h,
    &foreign_url,
    &document(
      &foreign_url,
      Some("none"),
      &["authorization_code"],
      "api:read",
      None,
      false,
    ),
  )
  .await?;
  let assertion_three = key.assertion(
    "doc-key-revoke",
    &url,
    &h.endpoint.clone(),
    "cimd-jti-revoke-3",
  )?;
  let auth = assertion_request(&url, &assertion_three);
  let request = RevokeRequest {
    token: &tokens.access_token,
    token_type_hint: None,
    auth: &auth,
  };
  let outcome = {
    let mut stores = RevokeStores {
      pool: &h.pool,
      keys: &h.ring,
      conn: &mut h.conn,
      store: &h.store,
      service: &service,
    };
    revoke_tokens(&mut stores, &ctx, &request, None).await?
  };
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(format!(
      "owner revoke must succeed, got {outcome:?}"
    )));
  }
  if service
    .find_access(&mut h.conn, &h.store, &tokens.access_token)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "revoked cimd token still resolves".to_owned(),
    ));
  }

  let foreign_auth = bare_request(&foreign_url);
  let foreign = RevokeRequest {
    token: &other.access_token,
    token_type_hint: None,
    auth: &foreign_auth,
  };
  let outcome = {
    let mut stores = RevokeStores {
      pool: &h.pool,
      keys: &h.ring,
      conn: &mut h.conn,
      store: &h.store,
      service: &service,
    };
    revoke_tokens(&mut stores, &ctx, &foreign, None).await?
  };
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(format!(
      "foreign revoke must be a no-op, got {outcome:?}"
    )));
  }
  if service
    .find_access(&mut h.conn, &h.store, &other.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "foreign revoke burned the victim token".to_owned(),
    ));
  }
  Ok(())
}

/// Public clients do not introspect (RFC 7662 §2.3): a `none` CIMD document
/// is rejected with `invalid_client` (HTTP 401 challenge semantics).
#[tokio::test]
async fn cimd_none_cannot_introspect() -> TestResult {
  let mut h = harness().await?;
  let url = unique("nointrospect");
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("none"),
      &["authorization_code"],
      "api:read",
      None,
      false,
    ),
  )
  .await?;
  let service = TokenService::new(&h.ttl, &h.ring)?;
  let token_prefix = h.token_prefix.clone();
  let mut stores = IntrospectStores {
    pool: &h.pool,
    keys: &h.ring,
    conn: &mut h.conn,
    store: &h.store,
  };
  let ctx = IntrospectContext {
    issuer: ISSUER,
    now_unix: now_unix(),
    cimd: Some(CimdSettings {
      token_prefix: &token_prefix,
      max_bytes: 5_120,
      timeout: Duration::from_secs(2),
      allow_localhost: false,
    }),
    service: &service,
    jwt_signer: None,
  };
  let inputs = IntrospectHttpInputs {
    token: "opaque-token-that-can-never-resolve",
    token_type_hint: None,
    client_id: Some(&url),
    basic_header: None,
    body_secret: None,
    assertion_type: None,
    assertion: None,
    peer_certs: None,
    resource: &[],
  };
  match introspect(&mut stores, &ctx, &inputs).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidClient => {
      if error.status().as_u16() != 401 {
        return Err(TestError::Unexpected(format!(
          "cimd none introspection must be 401, got {}",
          error.status()
        )));
      }
      Ok(())
    }
    Err(error) => Err(TestError::Unexpected(format!(
      "cimd none introspection must be invalid_client, got {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "cimd none client introspected successfully".to_owned(),
    )),
  }
}

/// A registered row whose `client_id` is an `https://` URL always wins: the
/// cached document is never consulted, even when CIMD is enabled.
#[tokio::test]
async fn cimd_registered_row_wins_over_document() -> TestResult {
  let mut h = harness().await?;
  let url = unique("rowwins");
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Unexpected(format!("{error:?}")))?;
  let secret_hash = hash_secret("row-secret", &params)
    .map_err(|error| TestError::Unexpected(format!("{error:?}")))?;
  client_repo::insert(
    &h.pool,
    &h.ring,
    false,
    &NewClient {
      id: uuid::Uuid::new_v4(),
      client_id: url.clone(),
      client_secret_hash: Some(secret_hash),
      client_secret_expires_at: None,
      client_name: "row wins".to_owned(),
      grant_types: vec!["authorization_code".to_owned()],
      response_types: vec!["code".to_owned()],
      scope: "api:read".to_owned(),
      token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost
        .as_str()
        .to_owned(),
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
  // A conflicting document: different method, different scope. The row must
  // still win.
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("none"),
      &["authorization_code"],
      "other:scope",
      None,
      false,
    ),
  )
  .await?;
  let req = ClientAuthRequest {
    basic_header: None,
    client_id: Some(&url),
    body_secret: Some(SecretString::from("row-secret")),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  let endpoint = h.endpoint.clone();
  let token_prefix = h.token_prefix.clone();
  let ctx = auth_ctx_for(&endpoint, &token_prefix);
  let authenticated = authenticate_client(&mut auth_stores(&mut h), &ctx, &req)
    .await
    .map_err(|error| TestError::Unexpected(format!("registered row rejected: {error}")))?;
  if authenticated.method != TokenEndpointAuthMethod::ClientSecretPost {
    return Err(TestError::Unexpected(format!(
      "row method must win, got {:?}",
      authenticated.method
    )));
  }
  if authenticated.client.scope != "api:read" {
    return Err(TestError::Unexpected(format!(
      "row scope must win, got {}",
      authenticated.client.scope
    )));
  }
  Ok(())
}

/// A replayed assertion `jti` is single-use: the second presentation of the
/// same CIMD assertion fails `invalid_client`.
#[tokio::test]
async fn cimd_replayed_assertion_jti_rejected() -> TestResult {
  let mut h = harness().await?;
  let url = unique("replay");
  let key = DocKey::generate("doc-key-replay")?;
  seed_cimd(
    &mut h,
    &url,
    &document(
      &url,
      Some("private_key_jwt"),
      &["authorization_code"],
      "api:read",
      Some(key.jwks.clone()),
      false,
    ),
  )
  .await?;
  let assertion = key.assertion(
    "doc-key-replay",
    &url,
    &h.endpoint.clone(),
    "cimd-jti-replay-9",
  )?;
  let endpoint = h.endpoint.clone();
  let token_prefix = h.token_prefix.clone();
  let ctx = auth_ctx_for(&endpoint, &token_prefix);
  let req = assertion_request(&url, &assertion);
  authenticate_client(&mut auth_stores(&mut h), &ctx, &req)
    .await
    .map_err(|error| TestError::Unexpected(format!("first assertion rejected: {error}")))?;
  let req = assertion_request(&url, &assertion);
  match authenticate_client(&mut auth_stores(&mut h), &ctx, &req).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidClient => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "replay must be invalid_client, got {}",
      error.code()
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "replayed cimd assertion accepted".to_owned(),
    )),
  }
}

/// Fetch and validation failures map fail-closed: an unfetchable document is
/// `invalid_client_metadata`, and a disabled feature keeps an `https://` id
/// an unknown client.
#[tokio::test]
async fn cimd_fetch_failure_maps_fail_closed() -> TestResult {
  let mut h = harness().await?;
  let url = unique("missing");
  let token_prefix = h.token_prefix.clone();
  let fetch_settings = CimdSettings {
    token_prefix: &token_prefix,
    max_bytes: 5_120,
    timeout: Duration::from_secs(2),
    allow_localhost: false,
  };
  // No cache seed: `.invalid` can never fetch, so this is a pure Fetch
  // failure (CIMD draft §5, fail-closed per Todo 19's mapping).
  match resolve_client(&h.pool, &h.ring, &mut h.conn, Some(fetch_settings), &url).await {
    Err(error) => {
      let app = AppError::from(error);
      if app.code() != OAuthErrorCode::InvalidClientMetadata {
        return Err(TestError::Unexpected(format!(
          "fetch failure must be invalid_client_metadata, got {}",
          app.code()
        )));
      }
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "unfetchable document resolved".to_owned(),
      ));
    }
  }
  // Disabled feature: the same id is an unknown client, exactly as today.
  match resolve_client(&h.pool, &h.ring, &mut h.conn, None, &url).await {
    Ok(None) => Ok(()),
    Ok(Some(_)) => Err(TestError::Unexpected(
      "disabled cimd must not resolve".to_owned(),
    )),
    Err(error) => Err(TestError::Unexpected(format!(
      "disabled cimd must be Ok(None), got {error}"
    ))),
  }
}

//! `test(code_issue)` suite: redirect shape, hash-only storage, TTL bound,
//! entitlement subset enforcement, and the public-client DPoP matrix.

use std::{collections::HashMap, time::Duration};

use secrecy::SecretString;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

use super::{CODE_TTL_CAP, CodeClientKind, CodeIssueError, CodeIssueRequest, CodeIssuer};
use crate::{
  config::{DurabilityMode, TtlConfig, redis::RawRedisConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::scope::ScopeSet,
  state::RedisConn,
  store::{Store, StoreError, codes},
  test_guard::ContainerGuard,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the code-issuance test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// The Redis configuration was rejected.
  #[error("config error: {0}")]
  Config(#[from] crate::config::ConfigError),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] StoreError),
  /// A key-ring build failed.
  #[error("keyring error: {0}")]
  KeyRing(#[from] KeyRingError),
  /// A code issuance failed.
  #[error("issuance error: {0}")]
  Issue(#[from] CodeIssueError),
  /// A scope value did not parse.
  #[error("scope error: {0}")]
  Scope(#[from] crate::error::AppError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

const ISSUER: &str = "https://auth.example.test";
const REDIRECT: &str = "https://app.example.test/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// Build a key ring with one pepper generation plus the mandatory TOTP chain.
fn test_ring() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("code-issue-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("code-issue-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("code-issue-pii"))],
  )?)
}

/// Start a single-node Redis 7.2 with AOF on.
async fn redis_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(vec!["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Connect a [`RedisConn`] plus [`Store`] directly against a live container.
async fn direct_store(url: &str) -> Result<(RedisConn, Store), TestError> {
  let client = redis::Client::open(url)?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let raw = RawRedisConfig {
    url: Some(url.to_owned()),
    durability: Some(DurabilityMode::WaitAof),
    response_timeout_secs: 10,
    connect_timeout_secs: 5,
    ..Default::default()
  };
  let config = crate::config::RedisConfig::from_raw(raw)?;
  Ok((RedisConn::Single(manager), Store::from_config(&config)))
}

/// A consent-approved issuance request over caller-supplied scope sets.
fn request<'a>(
  kind: CodeClientKind,
  approved: &'a ScopeSet,
  entitled: &'a ScopeSet,
  jkt: Option<&'a str>,
  state: Option<&'a str>,
) -> CodeIssueRequest<'a> {
  CodeIssueRequest {
    client_id: "client-abc",
    client_kind: kind,
    user_id: "user-1",
    redirect_uri: REDIRECT,
    approved_scope: approved,
    user_entitled: entitled,
    code_challenge: CHALLENGE,
    dpop_jkt: jkt,
    state,
    issuer: ISSUER,
  }
}

/// Split a redirect `Location` into its query pairs.
fn query_pairs(location: &str) -> Result<HashMap<String, String>, TestError> {
  let query = location.split_once('?').map_or("", |(_, tail)| tail);
  let mut out = HashMap::new();
  if query.is_empty() {
    return Ok(out);
  }
  for pair in query.split('&') {
    let (name, value) = pair
      .split_once('=')
      .ok_or_else(|| TestError::Unexpected("redirect pair without a value".to_owned()))?;
    out.insert(name.to_owned(), value.to_owned());
  }
  Ok(out)
}

/// Whether any key or hash field in the current database contains `needle`.
async fn keyspace_contains(conn: &mut RedisConn, needle: &str) -> Result<bool, TestError> {
  let keys: Vec<String> = redis::cmd("KEYS").arg("*").query_async(conn).await?;
  for key in &keys {
    if key.contains(needle) {
      return Ok(true);
    }
    let kind: String = redis::cmd("TYPE").arg(key).query_async(conn).await?;
    if kind == "string" {
      let value: Option<String> = redis::cmd("GET").arg(key).query_async(conn).await?;
      if value.is_some_and(|text| text.contains(needle)) {
        return Ok(true);
      }
    } else if kind == "hash" {
      let values: Vec<String> = redis::cmd("HVALS").arg(key).query_async(conn).await?;
      if values.iter().any(|text| text.contains(needle)) {
        return Ok(true);
      }
    }
  }
  Ok(false)
}

#[tokio::test]
async fn code_issue_redirect_carries_code_state_iss() -> TestResult {
  let (_guard, url) = redis_container().await?;
  let (mut conn, store) = direct_store(&url).await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read api:admin")?;

  let issued = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Confidential,
        &approved,
        &entitled,
        None,
        Some("state-xyz"),
      ),
    )
    .await?;
  if issued.code.len() != crate::crypto::tokens::TOKEN_STR_LEN {
    return Err(TestError::Unexpected(
      "code must be a 256-bit base64url value".to_owned(),
    ));
  }
  let params = query_pairs(&issued.location)?;
  let code = params
    .get("code")
    .ok_or_else(|| TestError::Unexpected("redirect must carry code".to_owned()))?;
  if code != &issued.code {
    return Err(TestError::Unexpected(
      "redirect code must equal the issued code".to_owned(),
    ));
  }
  let state = params
    .get("state")
    .ok_or_else(|| TestError::Unexpected("redirect must echo state".to_owned()))?;
  if state != "state-xyz" {
    return Err(TestError::Unexpected("redirect must echo state".to_owned()));
  }
  let iss = params
    .get("iss")
    .ok_or_else(|| TestError::Unexpected("redirect must carry RFC 9207 iss".to_owned()))?;
  if iss != "https%3A%2F%2Fauth.example.test" {
    return Err(TestError::Unexpected(
      "redirect iss must be the issuer".to_owned(),
    ));
  }
  for forbidden in ["access_token", "refresh_token", "id_token", "token"] {
    if params.contains_key(forbidden) {
      return Err(TestError::Unexpected(
        "redirect must never carry tokens".to_owned(),
      ));
    }
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_stores_only_hash_with_bounded_ttl() -> TestResult {
  let (_guard, url) = redis_container().await?;
  let (mut conn, store) = direct_store(&url).await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read")?;

  let issued = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Confidential,
        &approved,
        &entitled,
        None,
        None,
      ),
    )
    .await?;
  if issued.code_hash == issued.code {
    return Err(TestError::Unexpected(
      "storage identity must be a hash, not the code".to_owned(),
    ));
  }
  if keyspace_contains(&mut conn, &issued.code).await? {
    return Err(TestError::Unexpected(
      "raw code must never appear in Redis".to_owned(),
    ));
  }
  let key = store.code_key(&issued.code_hash);
  let ttl_ms: i64 = redis::cmd("PTTL").arg(&key).query_async(&mut conn).await?;
  if ttl_ms <= 0 || ttl_ms > CODE_TTL_CAP.as_millis() as i64 {
    return Err(TestError::Unexpected(
      "code TTL must be within (0, 60s]".to_owned(),
    ));
  }
  let record = codes::consume(&mut conn, &store, &issued.code_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("issued code must be consumable once".to_owned()))?;
  if record.client_id != "client-abc"
    || record.subject != "user-1"
    || record.redirect_uri != REDIRECT
    || record.scope != "api:read"
    || record.code_challenge != CHALLENGE
    || !record.cnf.is_empty()
    || record.grant_id != issued.grant_id
  {
    return Err(TestError::Unexpected(
      "stored record must carry the issuance fields".to_owned(),
    ));
  }
  if codes::consume(&mut conn, &store, &issued.code_hash)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected("code must be single-use".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_rejects_unentitled_approval() -> TestResult {
  let (_guard, url) = redis_container().await?;
  let (mut conn, store) = direct_store(&url).await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read api:admin")?;
  let entitled = ScopeSet::parse("api:read")?;

  let outcome = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Confidential,
        &approved,
        &entitled,
        None,
        None,
      ),
    )
    .await;
  if !matches!(outcome, Err(CodeIssueError::UnentitledScope)) {
    return Err(TestError::Unexpected(
      "approval wider than entitlement must be rejected".to_owned(),
    ));
  }
  if keyspace_contains(&mut conn, "client-abc").await? {
    return Err(TestError::Unexpected(
      "rejected issuance must store nothing".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_public_requires_dpop_jkt() -> TestResult {
  let (_guard, url) = redis_container().await?;
  let (mut conn, store) = direct_store(&url).await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read api:admin")?;

  let missing = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Public,
        &approved,
        &entitled,
        None,
        Some("s"),
      ),
    )
    .await;
  if !matches!(missing, Err(CodeIssueError::MissingDpopBinding)) {
    return Err(TestError::Unexpected(
      "public issuance without a jkt must be rejected".to_owned(),
    ));
  }
  let empty = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Public,
        &approved,
        &entitled,
        Some(""),
        Some("s"),
      ),
    )
    .await;
  if !matches!(empty, Err(CodeIssueError::MissingDpopBinding)) {
    return Err(TestError::Unexpected(
      "public issuance with an empty jkt must be rejected".to_owned(),
    ));
  }
  let issued = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Public,
        &approved,
        &entitled,
        Some("jkt-thumbprint-1"),
        Some("s"),
      ),
    )
    .await?;
  let record = codes::consume(&mut conn, &store, &issued.code_hash)
    .await?
    .ok_or_else(|| TestError::Unexpected("public code must be consumable".to_owned()))?;
  if record.cnf != "jkt-thumbprint-1" {
    return Err(TestError::Unexpected(
      "public-client code must carry the dpop_jkt binding".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_ttl_clamped_to_sixty_seconds() -> TestResult {
  let ring = test_ring()?;
  let ttl = TtlConfig {
    code: Duration::from_secs(300),
    ..TtlConfig::default()
  };
  let issuer = CodeIssuer::new(&ttl, &ring)?;
  if issuer.ttl() != CODE_TTL_CAP {
    return Err(TestError::Unexpected(
      "code TTL must clamp to 60s even when configured higher".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_debug_redacts_raw_code() -> TestResult {
  let (_guard, url) = redis_container().await?;
  let (mut conn, store) = direct_store(&url).await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read")?;

  let issued = issuer
    .issue(
      &mut conn,
      &store,
      &request(
        CodeClientKind::Confidential,
        &approved,
        &entitled,
        None,
        None,
      ),
    )
    .await?;
  let rendered = format!("{issued:?}");
  if rendered.contains(&issued.code) {
    return Err(TestError::Unexpected(
      "Debug must never print the raw code".to_owned(),
    ));
  }
  Ok(())
}

//! `test(code_issue)` suite: redirect shape, hash-only storage, TTL bound,
//! entitlement subset enforcement, and the public-client DPoP matrix.

use std::{collections::HashMap, time::Duration};

use redis::aio::ConnectionManager;
use secrecy::SecretString;

use super::{CODE_TTL_CAP, CodeClientKind, CodeIssueError, CodeIssueRequest, CodeIssuer};
use crate::{
  config::{DurabilityMode, TtlConfig, redis::RawRedisConfig},
  keys::{KeyId, KeyRing, KeyRingError},
  protocol::scope::ScopeSet,
  state::RedisConn,
  store::{Store, StoreError, codes},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the code-issuance test scaffolding itself.
#[derive(Debug, thiserror::Error)]
enum TestError {
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

/// Connect a [`RedisConn`] plus [`Store`] to the shared compose Redis, scoped
/// to a per-test unique prefix pair so parallel tests never share a keyspace.
async fn direct_store(
  manager: ConnectionManager,
  token_prefix: &str,
  ratelimit_prefix: &str,
) -> Result<(RedisConn, Store), TestError> {
  let raw = RawRedisConfig {
    url: Some(crate::test_support::test_redis_url()),
    durability: Some(DurabilityMode::WaitAof),
    response_timeout_secs: 10,
    connect_timeout_secs: 5,
    token_key_prefix: Some(token_prefix.to_owned()),
    ratelimit_key_prefix: Some(ratelimit_prefix.to_owned()),
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
    dpop_required: kind == CodeClientKind::Public,
    user_id: "user-1",
    redirect_uri: REDIRECT,
    approved_scope: approved,
    user_entitled: entitled,
    code_challenge: CHALLENGE,
    dpop_jkt: jkt,
    state,
    aud: &[],
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

/// Whether any key or hash field under `state_prefix` contains `needle`.
async fn keyspace_contains(
  conn: &mut RedisConn,
  state_prefix: &str,
  needle: &str,
) -> Result<bool, TestError> {
  let pattern = format!("{state_prefix}*");
  let keys: Vec<String> = redis::cmd("KEYS").arg(&pattern).query_async(conn).await?;
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
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
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

/// An unbound public client is issued a bearer-capable code with no DPoP
/// proof: issuance succeeds and the stored binding is empty.
#[tokio::test]
async fn public_unbound_code_issuance_succeeds() -> TestResult {
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let approved = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read api:admin")?;

  let issued = issuer
    .issue(
      &mut conn,
      &store,
      &CodeIssueRequest {
        client_id: "client-abc",
        client_kind: CodeClientKind::Public,
        dpop_required: false,
        user_id: "user-1",
        redirect_uri: REDIRECT,
        approved_scope: &approved,
        user_entitled: &entitled,
        code_challenge: CHALLENGE,
        dpop_jkt: None,
        state: None,
        aud: &[],
        issuer: ISSUER,
      },
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("unbound issuance rejected: {error}")))?;
  if issued.code.is_empty() {
    return Err(TestError::Unexpected(
      "unbound issuance must return a code".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_stores_only_hash_with_bounded_ttl() -> TestResult {
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
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
  if keyspace_contains(&mut conn, &state_prefix, &issued.code).await? {
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
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
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
  if keyspace_contains(&mut conn, &state_prefix, "client-abc").await? {
    return Err(TestError::Unexpected(
      "rejected issuance must store nothing".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_public_requires_dpop_jkt() -> TestResult {
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
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

#[test]
fn code_issuer_debug_redacts_pepper() -> TestResult {
  let issuer = CodeIssuer::new(&TtlConfig::default(), &test_ring()?)?;
  let rendered = format!("{issuer:?}");
  if rendered.contains("code-issue-pepper") {
    return Err(TestError::Unexpected(
      "Debug must never print raw pepper bytes".to_owned(),
    ));
  }
  if !rendered.contains("[REDACTED]") {
    return Err(TestError::Unexpected(
      "Debug must mark pepper material as [REDACTED]".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn code_issue_debug_redacts_raw_code() -> TestResult {
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let (mut conn, store) = direct_store(
    crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?,
    &state_prefix,
    &ratelimit_prefix,
  )
  .await?;
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

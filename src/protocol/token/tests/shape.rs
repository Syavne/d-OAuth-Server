//! T3-A8: malformed tokens are rejected before HMAC + Redis work.
//!
//! Junk (wrong length or non-base64url charset) must resolve to `Ok(None)` /
//! `Ok(false)` without touching Redis. The tests run against a dead Redis
//! endpoint with short timeouts: any store hit surfaces as `Err`, so reaching
//! `Ok` proves the precheck fired first. A well-formed but unknown token must
//! still reach the store (and thus `Err` here), proving the precheck does not
//! blanket-skip lookups.

use std::time::Duration;

use super::{TestError, TestResult, service};
use crate::{config::DurabilityMode, state::RedisConn, store::Store};

/// A connection/store pair pointed at a dead endpoint: any Redis I/O fails.
///
/// The manager is created lazily (no eager connect), so building it succeeds
/// and only an actual store hit surfaces as `Err`.
async fn dead_conn_store() -> Result<(RedisConn, Store), TestError> {
  let client = redis::Client::open("redis://127.0.0.1:1/")?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_millis(200)))
    .set_connection_timeout(Some(Duration::from_millis(200)))
    .set_number_of_retries(0);
  let manager = redis::aio::ConnectionManager::new_lazy_with_config(client, manager_config)
    .map_err(TestError::from)?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  Ok((RedisConn::Single(manager), store))
}

/// A real minter output: well-formed by construction, but unknown to any
/// store. Coupling to [`crate::crypto::tokens::mint_token`] (instead of a
/// hand-built `"A".repeat(43)`) keeps the positive case honest if the token
/// shape ever changes.
fn well_formed_unknown() -> Result<String, TestError> {
  crate::crypto::tokens::mint_token()
    .map_err(|err| TestError::Unexpected(format!("minter output must mint: {err}")))
}

/// Junk tokens are rejected without a store hit: `Ok(None)` / `Ok(false)`.
#[tokio::test]
async fn token_service_malformed_shape_rejected_before_store() -> TestResult {
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let (mut conn, store) = dead_conn_store().await?;
  let junk: Vec<String> = vec![
    String::new(),
    "short".to_owned(),
    "no-such-token".to_owned(),
    "!!!not-base64url!!!".to_owned(),
    "A".repeat(42),
    "A".repeat(44),
    format!("{}!", "A".repeat(42)),
    format!("{}+", "A".repeat(42)),
  ];
  for raw in &junk {
    if service.find_access(&mut conn, &store, raw).await?.is_some() {
      return Err(TestError::Unexpected(format!(
        "malformed access token must resolve to None: len={}",
        raw.len()
      )));
    }
    if service
      .find_refresh(&mut conn, &store, raw)
      .await?
      .is_some()
    {
      return Err(TestError::Unexpected(format!(
        "malformed refresh token must resolve to None: len={}",
        raw.len()
      )));
    }
    if service.revoke_token(&mut conn, &store, raw).await? {
      return Err(TestError::Unexpected(format!(
        "malformed revoke must report false: len={}",
        raw.len()
      )));
    }
  }
  Ok(())
}

/// A well-formed unknown token still reaches the store (fail-closed `Err`
/// against the dead endpoint), proving the precheck only skips junk.
#[tokio::test]
async fn token_service_consume_tombstone_rejects_malformed_before_store() -> TestResult {
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let (mut conn, store) = dead_conn_store().await?;
  let junk: Vec<String> = vec![
    String::new(),
    "short".to_owned(),
    "no-such-token".to_owned(),
    "!!!not-base64url!!!".to_owned(),
    "A".repeat(42),
    "A".repeat(44),
    format!("{}!", "A".repeat(42)),
    format!("{}+", "A".repeat(42)),
  ];
  for raw in &junk {
    if service
      .consume_tombstone(&mut conn, &store, raw)
      .await?
      .is_some()
    {
      return Err(TestError::Unexpected(format!(
        "malformed tombstone lookup must resolve to None: len={}",
        raw.len()
      )));
    }
  }
  let raw = well_formed_unknown()?;
  if service
    .consume_tombstone(&mut conn, &store, &raw)
    .await
    .is_ok()
  {
    return Err(TestError::Unexpected(
      "well-formed unknown tombstone lookup must hit the store".to_owned(),
    ));
  }
  Ok(())
}
#[tokio::test]
async fn token_service_well_formed_unknown_still_hits_store() -> TestResult {
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let (mut conn, store) = dead_conn_store().await?;
  let raw = well_formed_unknown()?;
  if service.find_access(&mut conn, &store, &raw).await.is_ok() {
    return Err(TestError::Unexpected(
      "well-formed unknown access lookup must hit the store".to_owned(),
    ));
  }
  if service.find_refresh(&mut conn, &store, &raw).await.is_ok() {
    return Err(TestError::Unexpected(
      "well-formed unknown refresh lookup must hit the store".to_owned(),
    ));
  }
  if service.revoke_token(&mut conn, &store, &raw).await.is_ok() {
    return Err(TestError::Unexpected(
      "well-formed unknown revoke must hit the store".to_owned(),
    ));
  }
  Ok(())
}

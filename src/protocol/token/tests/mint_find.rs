//! Mint, find, TTL, grant-set, and revocation assertions.

use super::{
  super::{ClientKind, SenderProof},
  TestError, TestResult, mint_request, now_unix, service, test_redis, unique,
};
use crate::store::grants;

/// Remaining TTL of a key in milliseconds, or a negative PTTL as-is.
async fn pttl_ms(conn: &mut crate::state::RedisConn, key: &str) -> Result<i64, TestError> {
  let ms: i64 = redis::cmd("PTTL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(crate::store::StoreError::Redis)?;
  Ok(ms)
}

/// Mint, find, TTL, and single-token revoke round-trip.
#[tokio::test]
async fn token_service_mint_find_revoke() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let grant = unique("grant");
  let client = unique("client");
  let now = now_unix();

  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(
        &client,
        ClientKind::Confidential,
        &grant,
        SenderProof::none(),
      ),
      now,
    )
    .await?;
  if minted.access_token == minted.refresh_token
    || minted.access_token.is_empty()
    || minted.refresh_token.is_empty()
  {
    return Err(TestError::Unexpected(
      "minted raw tokens must be distinct and non-empty".to_owned(),
    ));
  }
  if minted.access_hash == minted.access_token || minted.refresh_hash == minted.refresh_token {
    return Err(TestError::Unexpected(
      "hashes must never equal raw tokens".to_owned(),
    ));
  }
  if !minted.access_hash.starts_with("v1.") || !minted.refresh_hash.starts_with("v1.") {
    return Err(TestError::Unexpected(
      "hashes must carry the active versioned key id".to_owned(),
    ));
  }
  if minted.issued_at != now
    || minted.access_expires_at - now != 300
    || minted.refresh_expires_at - now != 2_592_000
  {
    return Err(TestError::Unexpected(
      "minted window must be iat/300s/30d".to_owned(),
    ));
  }

  let found_access = service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?;
  let access = match found_access {
    Some(found)
      if found.hash == minted.access_hash
        && found.key_label == "v1"
        && found.record.client_id == client
        && found.record.grant_id == grant =>
    {
      found.record
    }
    _ => {
      return Err(TestError::Unexpected(
        "access token must resolve to its record".to_owned(),
      ));
    }
  };
  if access.scope != "orders:read" || access.subject != "user-1" {
    return Err(TestError::Unexpected(
      "access record must carry scope and subject".to_owned(),
    ));
  }
  let found_refresh = service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?;
  if found_refresh.is_none_or(|found| found.hash != minted.refresh_hash) {
    return Err(TestError::Unexpected(
      "refresh token must resolve to its record".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, "no-such-token")
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "unknown tokens must resolve to None".to_owned(),
    ));
  }

  let access_pttl = pttl_ms(&mut conn, &store.access_key(&minted.access_hash)).await?;
  let refresh_pttl = pttl_ms(&mut conn, &store.refresh_key(&minted.refresh_hash)).await?;
  if !(240_000..=300_000).contains(&access_pttl) {
    return Err(TestError::Unexpected("access TTL must be ~300s".to_owned()));
  }
  if !(2_592_000_000 - 120_000..=2_592_000_000).contains(&refresh_pttl) {
    return Err(TestError::Unexpected("refresh TTL must be ~30d".to_owned()));
  }

  if !service
    .revoke_token(&mut conn, &store, &minted.access_token)
    .await?
  {
    return Err(TestError::Unexpected(
      "revoking a live token must report true".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "revoked tokens must no longer resolve".to_owned(),
    ));
  }
  if service
    .revoke_token(&mut conn, &store, &minted.access_token)
    .await?
  {
    return Err(TestError::Unexpected(
      "revoking an absent token must report false".to_owned(),
    ));
  }
  Ok(())
}

/// The grant set holds both hashes; a grant revoke kills the family.
#[tokio::test]
async fn token_service_grant_set_holds_hashes_and_revoke_grant() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let grant = unique("grant");
  let client = unique("client");

  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(
        &client,
        ClientKind::Confidential,
        &grant,
        SenderProof::none(),
      ),
      now_unix(),
    )
    .await?;
  let members = grants::members(&mut conn, &store, &grant).await?;
  if !members.contains(&minted.access_hash) || !members.contains(&minted.refresh_hash) {
    return Err(TestError::Unexpected(
      "grant set must hold both token hashes".to_owned(),
    ));
  }

  service.revoke_grant(&mut conn, &store, &grant).await?;
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_some()
    || service
      .find_refresh(&mut conn, &store, &minted.refresh_token)
      .await?
      .is_some()
  {
    return Err(TestError::Unexpected(
      "grant revoke must kill the whole family".to_owned(),
    ));
  }
  if !grants::members(&mut conn, &store, &grant).await?.is_empty() {
    return Err(TestError::Unexpected(
      "grant revoke must drop the token index".to_owned(),
    ));
  }
  Ok(())
}

/// A non-`vN` pepper id keeps its identity end to end: the stored hash carries
/// the full string label and the minted token still resolves under it.
#[tokio::test]
async fn token_service_non_numeric_kid_preserved_end_to_end() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("pepper-2026", "token-service-pepper-one")])?;
  let grant = unique("grant");
  let client = unique("client");

  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(
        &client,
        ClientKind::Confidential,
        &grant,
        SenderProof::none(),
      ),
      now_unix(),
    )
    .await?;
  if !minted.access_hash.starts_with("pepper-2026.")
    || !minted.refresh_hash.starts_with("pepper-2026.")
  {
    return Err(TestError::Unexpected(
      "non-numeric kid must survive in the stored hash".to_owned(),
    ));
  }
  let found = service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?;
  match found {
    Some(found) if found.hash == minted.access_hash && found.key_label == "pepper-2026" => Ok(()),
    _ => Err(TestError::Unexpected(
      "token minted under a non-numeric kid must resolve with its label".to_owned(),
    )),
  }
}

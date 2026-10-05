//! Pepper-retention lookup: hashes minted under a retired generation still
//! resolve while the pepper is retained, and stop resolving once dropped.

use super::{
  super::{ClientKind, SenderProof},
  TestError, TestResult, mint_request, now_unix, service, test_redis, unique,
};

/// Lookup retries retained peppers newest-first.
#[tokio::test]
async fn token_service_find_retries_retained_peppers() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let grant = unique("grant");
  let client = unique("client");

  let old_only = service(&[("v1", "token-service-old-pepper")])?;
  let minted = old_only
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
  if !minted.access_hash.starts_with("v1.") {
    return Err(TestError::Unexpected(
      "old-ring mint must hash under v1".to_owned(),
    ));
  }

  let rotated = service(&[
    ("v2", "token-service-new-pepper"),
    ("v1", "token-service-old-pepper"),
  ])?;
  let found_access = rotated
    .find_access(&mut conn, &store, &minted.access_token)
    .await?;
  if found_access.is_none_or(|found| found.hash != minted.access_hash || found.key_label != "v1") {
    return Err(TestError::Unexpected(
      "retained pepper must still resolve the old hash".to_owned(),
    ));
  }
  let found_refresh = rotated
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?;
  if found_refresh.is_none_or(|found| found.hash != minted.refresh_hash) {
    return Err(TestError::Unexpected(
      "retained pepper must still resolve the old refresh hash".to_owned(),
    ));
  }

  let only_new = service(&[("v2", "token-service-new-pepper")])?;
  if only_new
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "a dropped pepper must stop resolving old hashes".to_owned(),
    ));
  }
  Ok(())
}

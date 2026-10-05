//! Reuse cascade: tombstone without a mapping revokes the grant chain.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_grant, mint_grant, service, test_redis,
};
use crate::protocol::{
  scope::ScopeSet,
  token::{ClientKind, grants::refresh_token::refresh},
};

/// Reuse (tombstone, mapping expired) revokes the whole chain: the current
/// pair dies with the old token.
#[tokio::test]
async fn grant_refresh_reuse_cascades_revocation() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("reuse-client");
  let proof = dpop_proof(&super::unique("reuse-jkt"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  let current = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await?;

  let old = service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("tombstoned old token unreadable".to_owned()))?;
  let tombstone = crate::store::tokens::tombstone_of(&mut conn, &store, &old.hash).await?;
  if tombstone.is_none() {
    return Err(TestError::Unexpected(
      "old token is not a tombstone".to_owned(),
    ));
  }
  let request_id = service.request_id_for(&old.hash)?;
  let map_key = store.rotation_map_key(&request_id);
  let _: () = redis::cmd("DEL")
    .arg(&map_key)
    .query_async(&mut conn)
    .await?;

  let reuse = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await;
  let error = match reuse {
    Ok(_) => return Err(TestError::Unexpected("reused token rotated".to_owned())),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "reuse code: {}",
      error.code()
    )));
  }
  let live_access = service
    .find_access(&mut conn, &store, &current.access_token)
    .await?;
  if live_access.is_some() {
    return Err(TestError::Unexpected(
      "cascade left the current access token live".to_owned(),
    ));
  }
  let live_refresh = service
    .find_refresh(&mut conn, &store, &current.refresh_token)
    .await?;
  if live_refresh.is_some() {
    return Err(TestError::Unexpected(
      "cascade left the current refresh token live".to_owned(),
    ));
  }
  Ok(())
}

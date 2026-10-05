//! Happy rotation plus retry-without-cascade.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_grant, mint_grant, service, test_redis,
};
use crate::protocol::{
  scope::ScopeSet,
  token::{ClientKind, grants::refresh_token::refresh},
};

/// Happy rotation: new pair mints, scope is kept, grant chain is unchanged.
#[tokio::test]
async fn grant_refresh_happy_rotates() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("happy-client");
  let proof = dpop_proof(&super::unique("happy-jkt"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read write",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read write")?;

  let first = refresh(
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
  if first.access_token == minted.access_token || first.refresh_token == minted.refresh_token {
    return Err(TestError::Unexpected(
      "rotation returned the presented tokens".to_owned(),
    ));
  }
  if first.scope != "read write" {
    return Err(TestError::Unexpected(format!(
      "scope changed: {}",
      first.scope
    )));
  }
  if first.token_type != "DPoP" {
    return Err(TestError::Unexpected(format!(
      "token_type: {}",
      first.token_type
    )));
  }

  let second = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &first.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await?;
  if second.refresh_token == first.refresh_token {
    return Err(TestError::Unexpected(
      "second rotation did not rotate".to_owned(),
    ));
  }
  if second.grant_id != first.grant_id {
    return Err(TestError::Unexpected(
      "grant chain changed across rotations".to_owned(),
    ));
  }
  Ok(())
}

/// A retry of an already-rotated token is rejected but does NOT cascade: the
/// live mapping absorbs it, so the current pair keeps working.
#[tokio::test]
async fn grant_refresh_retry_with_live_mapping_is_not_reuse() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("retry-client");
  let proof = dpop_proof(&super::unique("retry-jkt"));
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

  let retry = refresh(
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
  let error = match retry {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "retried old token rotated again".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "retry code: {}",
      error.code()
    )));
  }
  let live = service
    .find_refresh(&mut conn, &store, &current.refresh_token)
    .await?;
  if live.is_none() {
    return Err(TestError::Unexpected(
      "retry cascaded the live pair".to_owned(),
    ));
  }
  Ok(())
}

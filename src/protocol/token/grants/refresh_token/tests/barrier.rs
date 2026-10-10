//! Wait-mode barrier failure: the originating request still resolves.
//!
//! On a replica-less node a `WAIT`-mode barrier always fails closed after the
//! rotation write already applied. The originating request id must resolve to
//! its freshly minted pair (not `invalid_grant`): discarding it would lock
//! the originator out while its successor sits live but unreachable. A retry
//! of the spent token stays fail-closed through the mapping.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_grant, mint_grant, service, test_redis,
};
use crate::{
  config::DurabilityMode,
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, grants::refresh_token::refresh},
  },
  store::Store,
};

/// A barrier failure after the originating rotation write returns the minted
/// pair as tokens; a later retry of the spent token is still `invalid_grant`.
#[tokio::test]
async fn grant_refresh_barrier_failure_returns_tokens_for_originator() -> TestResult {
  let (_container, mut conn, durable, _url) = test_redis().await?;
  let fragile = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::Wait,
  );
  let service = service()?;
  let client = super::unique("barrier-client");
  let proof = dpop_proof(&super::unique("barrier-jkt"));
  let initial = mint_grant(
    &service,
    &mut conn,
    &durable,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let grant = service
    .find_refresh(&mut conn, &durable, &initial.refresh_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("initial grant missing".to_owned()))?
    .record
    .grant_id
    .clone();
  let enabled = ScopeSet::parse("read")?;

  let rotated = refresh(
    &mut conn,
    &fragile,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &initial.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await?;
  if rotated.refresh_token == initial.refresh_token || rotated.access_token == initial.access_token
  {
    return Err(TestError::Unexpected(
      "barrier recovery returned the presented tokens".to_owned(),
    ));
  }
  if rotated.grant_id != grant {
    return Err(TestError::Unexpected(
      "barrier recovery changed the grant chain".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut conn, &durable, &rotated.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "recovered refresh token must stay live (not discarded)".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &durable, &rotated.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "recovered access token must stay live (not discarded)".to_owned(),
    ));
  }

  let retry = refresh(
    &mut conn,
    &durable,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &initial.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await;
  let error = match retry {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "replayed old token rotated again".to_owned(),
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
  if service
    .find_refresh(&mut conn, &durable, &rotated.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "replay cascaded the recovered pair".to_owned(),
    ));
  }
  Ok(())
}

//! Concurrency: two simultaneous refreshes → exactly one rotation.

use super::{TestError, TestResult, connect, dpop_proof, input, mint_grant, service, test_redis};
use crate::protocol::{
  scope::ScopeSet,
  token::{ClientKind, grants::refresh_token::refresh},
};

/// Two concurrent refreshes of the same token: exactly one succeeds, the
/// loser is rejected without cascading the winner.
#[tokio::test]
async fn grant_refresh_concurrent_single_winner() -> TestResult {
  let (_container, mut conn_a, store, url) = test_redis().await?;
  let mut conn_b = connect(&url).await?;
  let service = service()?;
  let client = super::unique("race-client");
  let proof = dpop_proof(&super::unique("race-jkt"));
  let minted = mint_grant(
    &service,
    &mut conn_a,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  let in_a = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    None,
    &proof,
    &enabled,
  );
  let in_b = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    None,
    &proof,
    &enabled,
  );

  let (first, second) = tokio::join!(
    refresh(&mut conn_a, &store, &service, &in_a),
    refresh(&mut conn_b, &store, &service, &in_b)
  );
  let winners = [first.is_ok(), second.is_ok()];
  if winners != [true, false] && winners != [false, true] {
    return Err(TestError::Unexpected(
      "expected exactly one rotation to succeed".to_owned(),
    ));
  }
  let won = if first.is_ok() { first } else { second }.map_err(TestError::from)?;
  let live = service
    .find_refresh(&mut conn_a, &store, &won.refresh_token)
    .await?;
  if live.is_none() {
    return Err(TestError::Unexpected("winner pair is not live".to_owned()));
  }
  Ok(())
}

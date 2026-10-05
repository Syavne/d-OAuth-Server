//! Scope narrowing: narrower is kept, wider is rejected.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_scope, mint_grant, service, test_redis,
};
use crate::protocol::{
  scope::ScopeSet,
  token::{ClientKind, grants::refresh_token::refresh},
};

/// Scope narrowing succeeds and the narrowed scope sticks.
#[tokio::test]
async fn grant_refresh_scope_narrow_ok() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("narrow-client");
  let proof = dpop_proof(&super::unique("narrow-jkt"));
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

  let narrowed = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      Some("read"),
      &proof,
      &enabled,
    ),
  )
  .await?;
  if narrowed.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "scope not narrowed: {}",
      narrowed.scope
    )));
  }
  Ok(())
}

/// Scope widening is rejected with `invalid_scope`.
#[tokio::test]
async fn grant_refresh_scope_widen_rejected() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("widen-client");
  let proof = dpop_proof(&super::unique("widen-jkt"));
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
  let enabled = ScopeSet::parse("admin read")?;

  let widened = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      Some("admin read"),
      &proof,
      &enabled,
    ),
  )
  .await;
  let error = match widened {
    Ok(_) => return Err(TestError::Unexpected("widened scope rotated".to_owned())),
    Err(error) => error,
  };
  if !is_invalid_scope(&error) {
    return Err(TestError::Unexpected(format!(
      "widen code: {}",
      error.code()
    )));
  }
  Ok(())
}

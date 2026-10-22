//! Scope narrowing: narrower is kept, wider is rejected.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_scope, mint_grant, now_unix, service,
  test_redis,
};
use crate::protocol::{
  scope::ScopeSet,
  token::{
    ClientKind, TokenFormat,
    grants::refresh_token::{RefreshInput, refresh},
  },
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

/// Narrowing on refresh keeps the new refresh token at the presented scope
/// (draft-ietf-oauth-v2-1-16 §4.3.3) while the access token narrows
/// (§4.3.1): the response reports the narrowed access scope, the stored
/// refresh record keeps the full scope, and the next rotation can still use
/// the full scope.
#[tokio::test]
async fn grant_refresh_narrow_keeps_refresh_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("rt-kept-client");
  let proof = dpop_proof(&super::unique("rt-kept-jkt"));
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
      "response scope not narrowed: {}",
      narrowed.scope
    )));
  }
  let live_refresh = service
    .find_refresh(&mut conn, &store, &narrowed.refresh_token)
    .await?;
  let refresh_scope = match live_refresh {
    Some(found) => found.record.scope,
    None => {
      return Err(TestError::Unexpected(
        "rotated refresh token not found".to_owned(),
      ));
    }
  };
  if refresh_scope != "read write" {
    return Err(TestError::Unexpected(format!(
      "refresh scope narrowed: {refresh_scope}"
    )));
  }
  let live_access = service
    .find_access(&mut conn, &store, &narrowed.access_token)
    .await?;
  let access_scope = match live_access {
    Some(found) => found.record.scope,
    None => {
      return Err(TestError::Unexpected(
        "rotated access token not found".to_owned(),
      ));
    }
  };
  if access_scope != "read" {
    return Err(TestError::Unexpected(format!(
      "access scope not narrowed: {access_scope}"
    )));
  }

  // The retained refresh scope still authorizes the full grant on the next
  // rotation with an omitted scope.
  let restored = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &narrowed.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await?;
  if restored.scope != "read write" {
    return Err(TestError::Unexpected(format!(
      "retained scope lost: {}",
      restored.scope
    )));
  }
  Ok(())
}

/// A revoked entitlement still drops from the retained refresh scope, while
/// an explicit narrower request narrows only the access token.
#[tokio::test]
async fn grant_refresh_narrow_drops_revoked_from_refresh_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("rt-revoked-client");
  let proof = dpop_proof(&super::unique("rt-revoked-jkt"));
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
  let registered = ScopeSet::parse("read write")?;
  // `write` was revoked from the user after issuance.
  let entitled = ScopeSet::parse("read")?;

  let narrowed = refresh(
    &mut conn,
    &store,
    &service,
    &RefreshInput {
      client_id: &client,
      client_kind: ClientKind::Public,
      dpop_required: true,
      refresh_token: &minted.refresh_token,
      requested_scope: Some("read"),
      requested_resources: &[],
      proof: &proof,
      enabled: &enabled,
      client_registered: &registered,
      user_entitled: &entitled,
      token_format: TokenFormat::Opaque,
      now_unix: now_unix(),
    },
  )
  .await?;
  if narrowed.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "response scope not narrowed: {}",
      narrowed.scope
    )));
  }
  let live_refresh = service
    .find_refresh(&mut conn, &store, &narrowed.refresh_token)
    .await?;
  let refresh_scope = match live_refresh {
    Some(found) => found.record.scope,
    None => {
      return Err(TestError::Unexpected(
        "rotated refresh token not found".to_owned(),
      ));
    }
  };
  if refresh_scope != "read" {
    return Err(TestError::Unexpected(format!(
      "revoked scope survived on refresh token: {refresh_scope}"
    )));
  }
  Ok(())
}

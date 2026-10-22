//! Stored-audience re-validation on refresh (RFC 8707 staleness).
//!
//! The dispatcher validates the PRESENTED set after authentication, while
//! [`refresh_with_subject_check`](super::super::refresh_with_subject_check)
//! re-validates the grant's STORED audience against the CURRENT catalog
//! before rotation. A resource server disabled after issuance (or the flag
//! turned off since) fails `invalid_target` with the presented refresh token
//! left live for a retry; an enabled catalog keeps the original audience on
//! both rotated records.

use super::{TestError, TestResult, dpop_proof, now_unix, ring, service, test_redis, unique};
use crate::{
  db::{resource_repo, test_support::migrated_pool},
  error::OAuthErrorCode,
  protocol::{
    scope::ScopeSet,
    token::{
      ClientKind, MintRequest, MintedTokens, SenderProof, TokenService,
      grants::refresh_token::{RefreshInput, RefreshUserStores, refresh_with_subject_check},
    },
  },
  state::RedisConn,
  store::Store,
};

/// Resource indicator pinned into the test grants (RFC 8707).
const RES_A: &str = "https://rs-stale.example.test/api";

/// Whether the rejection is `invalid_target`.
fn is_invalid_target(error: &crate::error::AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidTarget
}

/// Mint one refreshable grant whose records carry `aud` on both halves and
/// whose subject is empty (a bearer-style principal, so no user lookup runs).
async fn mint_aud_grant(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  proof: SenderProof,
  aud: &[String],
) -> Result<MintedTokens, TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: client.to_owned(),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: String::new(),
        scope: "read".to_owned(),
        access_scope: "read".to_owned(),
        grant_id: unique("stale-grant"),
        proof,
        aud: aud.to_vec(),
        refresh_aud: aud.to_vec(),
        format: super::super::TokenFormat::Opaque,
      },
      now_unix(),
    )
    .await?;
  Ok(minted)
}

/// A resource disabled after issuance rejects the resourceless refresh with
/// `invalid_target` BEFORE rotation, leaving the presented token live.
#[tokio::test]
async fn refresh_rejects_disabled_audience_and_keeps_token_live() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg harness: {error}")))?;
  let keys = ring()?;
  let service = service()?;
  resource_repo::upsert(&pool, RES_A, "stale audience test").await?;
  let client = unique("stale-client");
  let proof = dpop_proof(&unique("stale-jkt"));
  let scoped = ScopeSet::parse("read")?;
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    proof.clone(),
    &[RES_A.to_owned()],
  )
  .await?;
  if !resource_repo::disable(&pool, RES_A).await? {
    return Err(TestError::Unexpected(
      "disable must update the seeded row".to_owned(),
    ));
  }

  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };
  let input = RefreshInput {
    client_id: &client,
    client_kind: ClientKind::Public,
    dpop_required: true,
    refresh_token: &minted.refresh_token,
    requested_scope: None,
    requested_resources: &[],
    proof: &proof,
    enabled: &scoped,
    client_registered: &scoped,
    user_entitled: &scoped,
    token_format: super::super::TokenFormat::Opaque,
    resource_indicators_enabled: true,
    now_unix: now_unix(),
  };
  match refresh_with_subject_check(&mut conn, &store, &service, &users, &input).await {
    Err(error) if is_invalid_target(&error) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "disabled audience must be invalid_target, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a disabled audience must never rotate".to_owned(),
      ));
    }
  }
  // Nothing was consumed or rotated: the presented token still works.
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the rejected refresh token was consumed".to_owned(),
    ));
  }
  Ok(())
}

/// The flag turned off since issuance rejects the resourceless refresh the
/// same way, even though the catalog row is still enabled.
#[tokio::test]
async fn refresh_rejects_stale_audience_when_flag_off() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg harness: {error}")))?;
  let keys = ring()?;
  let service = service()?;
  resource_repo::upsert(&pool, RES_A, "stale audience test").await?;
  let client = unique("stale-flag-client");
  let proof = dpop_proof(&unique("stale-flag-jkt"));
  let scoped = ScopeSet::parse("read")?;
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    proof.clone(),
    &[RES_A.to_owned()],
  )
  .await?;

  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };
  let input = RefreshInput {
    client_id: &client,
    client_kind: ClientKind::Public,
    dpop_required: true,
    refresh_token: &minted.refresh_token,
    requested_scope: None,
    requested_resources: &[],
    proof: &proof,
    enabled: &scoped,
    client_registered: &scoped,
    user_entitled: &scoped,
    token_format: super::super::TokenFormat::Opaque,
    resource_indicators_enabled: false,
    now_unix: now_unix(),
  };
  match refresh_with_subject_check(&mut conn, &store, &service, &users, &input).await {
    Err(error) if is_invalid_target(&error) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "flag-off audience must be invalid_target, got {}",
        other.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a flag-off audience must never rotate".to_owned(),
      ));
    }
  }
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the rejected refresh token was consumed".to_owned(),
    ));
  }
  Ok(())
}

/// Control: an enabled catalog plus an omitted `resource` still rotates and
/// keeps the original audience on both records through the checked path.
#[tokio::test]
async fn refresh_with_subject_check_preserves_live_audience() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg harness: {error}")))?;
  let keys = ring()?;
  let service = service()?;
  resource_repo::upsert(&pool, RES_A, "stale audience test").await?;
  let client = unique("stale-control-client");
  let proof = dpop_proof(&unique("stale-control-jkt"));
  let scoped = ScopeSet::parse("read")?;
  let original = vec![RES_A.to_owned()];
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    proof.clone(),
    &original,
  )
  .await?;

  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };
  let input = RefreshInput {
    client_id: &client,
    client_kind: ClientKind::Public,
    dpop_required: true,
    refresh_token: &minted.refresh_token,
    requested_scope: None,
    requested_resources: &[],
    proof: &proof,
    enabled: &scoped,
    client_registered: &scoped,
    user_entitled: &scoped,
    token_format: super::super::TokenFormat::Opaque,
    resource_indicators_enabled: true,
    now_unix: now_unix(),
  };
  let rotated = refresh_with_subject_check(&mut conn, &store, &service, &users, &input)
    .await
    .map_err(|error| TestError::Unexpected(format!("live audience refresh rejected: {error}")))?;
  let access = service
    .find_access(&mut conn, &store, &rotated.access_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("rotated access token not found".to_owned()))?;
  if access.record.aud != original {
    return Err(TestError::Unexpected(
      "rotated access token lost its audience".to_owned(),
    ));
  }
  let refresh = service
    .find_refresh(&mut conn, &store, &rotated.refresh_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("rotated refresh token not found".to_owned()))?;
  if refresh.record.aud != original {
    return Err(TestError::Unexpected(
      "rotated refresh token lost its audience".to_owned(),
    ));
  }
  Ok(())
}

//! Revocation semantics: access-only revoke, refresh cascade, no-op cases.

use axum::http::StatusCode;
use http_body_util::BodyExt as _;
use serde_json::Value;

use super::{TestError, TestResult, mint_request, now_unix, service, test_redis, unique};
use crate::{
  protocol::revoke::{
    HINT_ACCESS, HINT_REFRESH, OwnedToken, RevokeOutcome, outcome_response, revoke_owned,
  },
  store::grants,
};

/// Revoking an access token removes it but leaves its sibling refresh token.
#[tokio::test]
async fn revoke_access_token_removes_only_it() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("client");
  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, &unique("grant")),
      now_unix(),
    )
    .await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &minted.access_token,
      token_type_hint: Some(HINT_ACCESS),
    },
  )
  .await?;
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(
      "owned access token must be revoked".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "revoked access token must no longer resolve".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "access-only revocation must leave the refresh token".to_owned(),
    ));
  }
  Ok(())
}

/// Revoking a refresh token cascades to the whole grant family.
#[tokio::test]
async fn revoke_refresh_token_cascades_to_grant_chain() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("client");
  let grant = unique("grant");
  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, &grant),
      now_unix(),
    )
    .await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &minted.refresh_token,
      token_type_hint: Some(HINT_REFRESH),
    },
  )
  .await?;
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(
      "owned refresh token must be revoked".to_owned(),
    ));
  }
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
      "refresh revocation must kill the chain".to_owned(),
    ));
  }
  if !grants::members(&mut conn, &store, &grant).await?.is_empty() {
    return Err(TestError::Unexpected(
      "refresh revocation must drop the token index".to_owned(),
    ));
  }
  Ok(())
}

/// An unknown token is a silent `200` no-op.
#[tokio::test]
async fn revoke_unknown_token_is_noop_200() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: "client-a",
      token: "no-such-token",
      token_type_hint: None,
    },
  )
  .await?;
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "unknown token must be a no-op".to_owned(),
    ));
  }
  if outcome_response(outcome).status() != StatusCode::OK {
    return Err(TestError::Unexpected("no-op must render 200".to_owned()));
  }
  Ok(())
}

/// Another client's token is a no-op and is never revoked (no cross-client).
#[tokio::test]
async fn revoke_foreign_token_is_noop_and_untouched() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let owner = unique("owner");
  let attacker = unique("attacker");
  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&owner, &unique("grant")),
      now_unix(),
    )
    .await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &attacker,
      token: &minted.access_token,
      token_type_hint: Some(HINT_ACCESS),
    },
  )
  .await?;
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "a foreign token must be a no-op".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "a foreign client must never revoke another client's token".to_owned(),
    ));
  }
  Ok(())
}

/// An unsupported `token_type_hint` is `400 unsupported_token_type`.
#[tokio::test]
async fn revoke_unsupported_hint_is_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: "client-a",
      token: "some-token",
      token_type_hint: Some("password"),
    },
  )
  .await?;
  if outcome != RevokeOutcome::UnsupportedHint {
    return Err(TestError::Unexpected(
      "unknown hint must be unsupported".to_owned(),
    ));
  }
  let response = outcome_response(outcome);
  if response.status() != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(
      "unsupported hint must render 400".to_owned(),
    ));
  }
  let bytes = response.into_body().collect().await?.to_bytes();
  let body: Value = serde_json::from_slice(&bytes)?;
  if body.get("error").and_then(Value::as_str) != Some("unsupported_token_type") {
    return Err(TestError::Unexpected(
      "error code must be unsupported_token_type".to_owned(),
    ));
  }
  Ok(())
}

/// A `refresh_token` hint on an access token still revokes it: the hint only
/// guides the lookup (RFC 7009 §2.1), and the located token's real type
/// decides the scope of revocation (revoke.rs: an access token revokes only
/// itself, so the sibling refresh token survives).
#[tokio::test]
async fn revoke_refresh_hint_on_access_token_still_revokes_it() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("client");
  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, &unique("grant")),
      now_unix(),
    )
    .await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &client,
      token: &minted.access_token,
      token_type_hint: Some(HINT_REFRESH),
    },
  )
  .await?;
  if outcome != RevokeOutcome::Revoked {
    return Err(TestError::Unexpected(
      "the misplaced hint must not block revocation".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "the access token must be gone after revocation".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the hint must not extend revocation beyond an access token".to_owned(),
    ));
  }
  Ok(())
}

/// Revoking another client's refresh token is a silent no-op: `NoOp`, the
/// refresh token stays resolvable, and its access sibling is untouched too.
#[tokio::test]
async fn revoke_foreign_refresh_token_is_noop_and_untouched() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service()?;
  let owner = unique("owner");
  let attacker = unique("attacker");
  let minted = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&owner, &unique("grant")),
      now_unix(),
    )
    .await?;

  let outcome = revoke_owned(
    &mut conn,
    &store,
    &service,
    &OwnedToken {
      owner_client_id: &attacker,
      token: &minted.refresh_token,
      token_type_hint: Some(HINT_REFRESH),
    },
  )
  .await?;
  if outcome != RevokeOutcome::NoOp {
    return Err(TestError::Unexpected(
      "a foreign refresh token must be a no-op".to_owned(),
    ));
  }
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "a foreign client must never revoke another client's refresh token".to_owned(),
    ));
  }
  if service
    .find_access(&mut conn, &store, &minted.access_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the sibling access token must also survive a foreign attempt".to_owned(),
    ));
  }
  Ok(())
}

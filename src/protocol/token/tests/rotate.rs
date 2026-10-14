//! Idempotent rotation: the same request id replays the SAME hashes, and the
//! old token carries a tombstone pointing at its successor.

use std::time::Duration;

use super::{
  super::{ClientKind, SenderProof},
  TestError, TestResult, mint_request, now_unix, service, test_redis, unique,
};
use crate::store::tokens as low;

/// A rotation replayed by `rotation_request_id` returns the SAME tokens.
#[tokio::test]
async fn token_service_rotation_replay_returns_same_tokens() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let grant = unique("grant");
  let client = unique("client");

  let first = service
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
  let second = service
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
  let request_id = service.request_id_for(&first.refresh_hash)?;
  let input = low::RotationInput {
    old_refresh_hash: first.refresh_hash.clone(),
    expected_client_id: client.clone(),
    new_refresh_hash: second.refresh_hash.clone(),
    new_access_hash: second.access_hash.clone(),
    new_refresh: low::RefreshRecord {
      client_id: client.clone(),
      grant_id: grant.clone(),
      scope: "orders:read".to_owned(),
      subject: "user-1".to_owned(),
      cnf: String::new(),
    },
    new_access: low::AccessRecord {
      client_id: client.clone(),
      grant_id: grant.clone(),
      scope: "orders:read".to_owned(),
      subject: "user-1".to_owned(),
      cnf: String::new(),
    },
    new_refresh_ttl: Duration::from_secs(2_592_000),
    new_access_ttl: Duration::from_secs(300),
    request_id: Some(request_id),
  };

  let outcome = service.rotate(&mut conn, &store, &input).await?;
  let (rotated_refresh, rotated_access) = match outcome {
    low::RotateOutcome::Rotated {
      new_refresh_hash,
      new_access_hash,
    } => (new_refresh_hash, new_access_hash),
    _ => {
      return Err(TestError::Unexpected(
        "first rotation must apply".to_owned(),
      ));
    }
  };
  if rotated_refresh != second.refresh_hash || rotated_access != second.access_hash {
    return Err(TestError::Unexpected(
      "rotation must return the minted successor hashes".to_owned(),
    ));
  }

  let replay = service.rotate(&mut conn, &store, &input).await?;
  match replay {
    low::RotateOutcome::Replay {
      new_refresh_hash,
      new_access_hash,
    } if new_refresh_hash == second.refresh_hash && new_access_hash == second.access_hash => {}
    _ => {
      return Err(TestError::Unexpected(
        "replay must return the SAME tokens".to_owned(),
      ));
    }
  }

  let tombstone = service
    .consume_tombstone(&mut conn, &store, &first.refresh_token)
    .await?;
  if tombstone.as_deref() != Some(second.refresh_hash.as_str()) {
    return Err(TestError::Unexpected(
      "old token must tombstone to its successor".to_owned(),
    ));
  }
  Ok(())
}

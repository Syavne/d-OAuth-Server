//! Lost-reply recovery: same rotation input replays the same tokens.

use super::{TestError, TestResult, dpop_proof, mint_grant, service, test_redis};
use crate::{
  protocol::token::ClientKind,
  store::tokens::{AccessRecord, RefreshRecord, RotateOutcome, RotationInput},
};

/// A lost post-`EXEC` reply re-reads by `rotation_request_id` and returns
/// the SAME tokens: rotating twice with one minted input replays the first
/// hashes instead of double-rotating.
#[tokio::test]
async fn grant_refresh_lost_reply_replays_same_tokens() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("replay-client");
  let proof = dpop_proof(&super::unique("replay-jkt"));
  let old = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let found = service
    .find_refresh(&mut conn, &store, &old.refresh_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("initial grant missing".to_owned()))?;
  let next = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let cnf = next.cnf.to_storage()?;
  let input = RotationInput {
    old_refresh_hash: found.hash.clone(),
    expected_client_id: client.clone(),
    new_refresh_hash: next.refresh_hash.clone(),
    new_access_hash: next.access_hash.clone(),
    new_refresh: RefreshRecord {
      client_id: client.clone(),
      grant_id: found.record.grant_id.clone(),
      scope: "read".to_owned(),
      subject: found.record.subject.clone(),
      cnf: cnf.clone(),
      aud: Vec::new(),
    },
    new_access: AccessRecord {
      client_id: client.clone(),
      grant_id: found.record.grant_id.clone(),
      scope: "read".to_owned(),
      subject: found.record.subject.clone(),
      cnf,
      aud: Vec::new(),
    },
    new_refresh_ttl: service.refresh_ttl(),
    new_access_ttl: service.access_ttl(),
    request_id: Some(service.request_id_for(&found.hash)?),
    jwt_jti_hash: None,
  };

  let first = service.rotate(&mut conn, &store, &input).await?;
  let (first_refresh, first_access) = match first {
    RotateOutcome::Rotated {
      new_refresh_hash,
      new_access_hash,
    } => (new_refresh_hash, new_access_hash),
    _ => {
      return Err(TestError::Unexpected(
        "first rotation did not apply".to_owned(),
      ));
    }
  };
  let second = service.rotate(&mut conn, &store, &input).await?;
  match second {
    RotateOutcome::Replay {
      new_refresh_hash,
      new_access_hash,
    } => {
      if new_refresh_hash != first_refresh || new_access_hash != first_access {
        return Err(TestError::Unexpected(
          "replay returned different tokens".to_owned(),
        ));
      }
    }
    _ => {
      return Err(TestError::Unexpected(
        "second rotation did not replay".to_owned(),
      ));
    }
  }
  Ok(())
}

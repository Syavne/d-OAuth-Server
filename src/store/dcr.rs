//! DCR initial-access-token records.
//!
//! Initial access tokens (the `initial_access_token` that authorizes a
//! registration call) live here with a bounded `uses` budget. Registration
//! access tokens are NOT here: their hash lives only in Postgres
//! (`oauth_clients.registration_access_token_hash`) so client management
//! survives a Redis loss.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{SCRIPT_CONSUME_IAT, Store, StoreError, durability_barrier, hset_record, retry_op};
use crate::state::RedisConn;

/// A DCR initial-access-token record, keyed by the token hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialAccessRecord {
  /// Remaining registration calls this token authorizes.
  pub uses_remaining: u64,
  /// Operator label for audit, never a secret.
  pub label: String,
}

impl InitialAccessRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("uses_remaining".to_owned(), self.uses_remaining.to_string()),
      ("label".to_owned(), self.label.clone()),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    let uses = get("uses_remaining")?
      .parse::<u64>()
      .map_err(|_| StoreError::InvalidData)?;
    Ok(Self {
      uses_remaining: uses,
      label: get("label")?,
    })
  }
}

/// Issue an initial-access-token record under its hash.
pub async fn issue(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &InitialAccessRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.dcr_iat_key(token_hash);
  let pairs = record.to_pairs();
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(dcr_redis)
  })
  .map_err(StoreError::Redis)
}

/// Spend one use of an initial-access token: returns the record as stored
/// BEFORE the decrement (or deletion on the final use), `None` when absent
/// or exhausted.
pub async fn consume_one_use(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<Option<InitialAccessRecord>, StoreError> {
  let key = store.dcr_iat_key(token_hash);
  let mut invocation = SCRIPT_CONSUME_IAT.prepare_invoke();
  invocation.key(key.as_str());
  let outcome: Result<redis::Value, StoreError> = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis);
  match outcome {
    Ok(redis::Value::Array(items)) => {
      let mut flat = Vec::with_capacity(items.len());
      for item in items {
        match item {
          redis::Value::BulkString(bytes) => {
            flat.push(String::from_utf8(bytes).map_err(|_| StoreError::InvalidData)?);
          }
          redis::Value::SimpleString(text) => flat.push(text),
          _ => return Err(StoreError::InvalidData),
        }
      }
      InitialAccessRecord::from_map(&super::flat_to_map(flat)?).map(Some)
    }
    Ok(_) => Ok(None),
    Err(error) => {
      if !matches!(error, StoreError::Redis(_)) {
        return Err(error);
      }
      let present: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(conn)
        .await
        .map_err(StoreError::Redis)?;
      if present { Err(error) } else { Ok(None) }
    }
  }
}

/// Claim a replay marker (`dpop_jti` / `client_assertion_jti`): `SET NX` with
/// TTL, so the first claimant wins and retries are idempotent. Returns true
/// when this call created the marker.
///
/// A winning claim is durability-barriered BEFORE the caller treats the proof
/// as fresh (same contract as token rotation in [`super::tokens`]): a marker
/// that could vanish on failover would let a replayed `jti` through. When the
/// barrier fails after the marker was written, the marker is removed before
/// the `Durability` error surfaces, so the originating proof can be claimed
/// again instead of reading back as a replay; a concurrent non-originating
/// claimant still loses while the marker stands.
pub async fn claim_marker(
  conn: &mut RedisConn,
  store: &Store,
  key: &str,
  ttl: Duration,
) -> Result<bool, StoreError> {
  let fresh = retry_op!(conn, store.retry_budget(), async {
    redis::cmd("SET")
      .arg(key)
      .arg("1")
      .arg("PX")
      .arg(ttl.as_millis() as u64)
      .arg("NX")
      .query_async::<Option<String>>(conn)
      .await
  })
  .map(|set| set.is_some())
  .map_err(StoreError::Redis)?;
  if fresh {
    match durability_barrier(conn, store).await {
      Ok(()) => {}
      Err(StoreError::Durability) => {
        let _ = redis::cmd("DEL").arg(key).query_async::<i64>(conn).await;
        return Err(StoreError::Durability);
      }
      Err(other) => return Err(other),
    }
  }
  Ok(fresh)
}

/// Claim a DPoP `jti` replay marker for a `jti` hash.
pub async fn claim_dpop_jti(
  conn: &mut RedisConn,
  store: &Store,
  jti_hash: &str,
  ttl: Duration,
) -> Result<bool, StoreError> {
  claim_marker(conn, store, &store.dpop_jti_key(jti_hash), ttl).await
}

/// Claim a `private_key_jwt` (`client_assertion`) `jti` replay marker.
pub async fn claim_client_assertion_jti(
  conn: &mut RedisConn,
  store: &Store,
  jti_hash: &str,
  ttl: Duration,
) -> Result<bool, StoreError> {
  claim_marker(conn, store, &store.client_assertion_jti_key(jti_hash), ttl).await
}

fn dcr_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store dcr write failed")),
  }
}

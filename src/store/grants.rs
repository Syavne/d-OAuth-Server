//! Grant chains and the per-grant token index.
//!
//! Links rotated families so reuse anywhere in the chain triggers the
//! cascade; no `KEYS` scans in request paths (per-grant sets + Lua).

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{SCRIPT_GRANT_REVOKE, Store, StoreError, hset_record, retry_op};
use crate::state::RedisConn;

/// A grant-chain record: the durable link between rotated token families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
  /// Grant identifier (also the token-set suffix).
  pub grant_id: String,
  /// Client the grant was issued to.
  pub client_id: String,
  /// Resource-owner subject, empty for client-credentials grants.
  pub subject: String,
  /// Space-joined scope.
  pub scope: String,
}

impl GrantRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("grant_id".to_owned(), self.grant_id.clone()),
      ("client_id".to_owned(), self.client_id.clone()),
      ("subject".to_owned(), self.subject.clone()),
      ("scope".to_owned(), self.scope.clone()),
    ]
  }

  fn from_map(grant_id: &str, map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      grant_id: grant_id.to_owned(),
      client_id: get("client_id")?,
      subject: get("subject")?,
      scope: get("scope")?,
    })
  }
}

/// Create a grant-chain record (idempotent rewrite).
pub async fn create(
  conn: &mut RedisConn,
  store: &Store,
  record: &GrantRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.grant_key(&record.grant_id);
  let pairs = record.to_pairs();
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(grants_redis)
  })
  .map_err(StoreError::Redis)
}

/// Read a grant-chain record; `Ok(None)` when absent.
pub async fn get(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
) -> Result<Option<GrantRecord>, StoreError> {
  let key = store.grant_key(grant_id);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(grants_redis)
  })
  .map_err(StoreError::Redis)?;
  map
    .map(|fields| GrantRecord::from_map(grant_id, &fields))
    .transpose()
}

/// Index a token hash in its grant set (idempotent `SADD`).
pub async fn add_token(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
  token_hash: &str,
) -> Result<(), StoreError> {
  let set_key = store.grant_tokens_key(grant_id);
  retry_op!(conn, store.retry_budget(), async {
    let _: () = redis::cmd("SADD")
      .arg(&set_key)
      .arg(token_hash)
      .query_async(conn)
      .await?;
    Ok(())
  })
  .map_err(StoreError::Redis)
}

/// List the token hashes indexed under a grant.
pub async fn members(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
) -> Result<Vec<String>, StoreError> {
  let set_key = store.grant_tokens_key(grant_id);
  retry_op!(conn, store.retry_budget(), async {
    redis::cmd("SMEMBERS")
      .arg(&set_key)
      .query_async::<Vec<String>>(conn)
      .await
  })
  .map_err(StoreError::Redis)
}

/// Cascade-revoke a grant: atomically delete every member token key plus the
/// grant set and record (single-slot Lua, no `KEYS` scan).
///
/// Returns the number of token keys deleted. Unknown grants revoke to zero.
pub async fn revoke(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
) -> Result<u64, StoreError> {
  let set_key = store.grant_tokens_key(grant_id);
  let grant_key = store.grant_key(grant_id);
  let refresh_prefix = store.refresh_key_prefix();
  let access_prefix = store.access_key_prefix();
  let mut invocation = SCRIPT_GRANT_REVOKE.prepare_invoke();
  invocation.key(set_key.as_str()).key(grant_key.as_str());
  invocation
    .arg(refresh_prefix.as_str())
    .arg(access_prefix.as_str());
  let deleted: u64 = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  // Revocation is a reuse-driven security response: barrier it like any
  // tombstone-class write before the caller reports the outcome.
  super::durability_barrier(conn, store).await?;
  Ok(deleted)
}

/// Cascade-revoke the grant family containing `token_hash`: resolve the grant
/// through the token record, then [`revoke`].
pub async fn revoke_by_token_hash(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<u64, StoreError> {
  let grant_id = grant_of_token(conn, store, token_hash).await?;
  match grant_id {
    Some(id) => revoke(conn, store, &id).await,
    None => Ok(0),
  }
}

/// Resolve the grant id holding `token_hash` (refresh record first, then
/// access record); `Ok(None)` when the token is unknown.
async fn grant_of_token(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<Option<String>, StoreError> {
  for key in [store.refresh_key(token_hash), store.access_key(token_hash)] {
    let map = super::hget_record(conn, &key).await?;
    if let Some(fields) = map {
      return fields
        .get("grant_id")
        .cloned()
        .filter(|id| !id.is_empty())
        .map_or(Err(StoreError::InvalidData), |id| Ok(Some(id)));
    }
  }
  Ok(None)
}

fn grants_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store grant write failed")),
  }
}

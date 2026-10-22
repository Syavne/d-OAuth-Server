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
  /// Resource audiences (RFC 8707) pinned to the grant; empty when unbound.
  #[serde(default)]
  pub aud: Vec<String>,
}

impl GrantRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("grant_id".to_owned(), self.grant_id.clone()),
      ("client_id".to_owned(), self.client_id.clone()),
      ("subject".to_owned(), self.subject.clone()),
      ("scope".to_owned(), self.scope.clone()),
      ("aud".to_owned(), super::aud::encode(&self.aud)),
    ]
  }

  fn from_map(grant_id: &str, map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      grant_id: grant_id.to_owned(),
      client_id: get("client_id")?,
      subject: get("subject")?,
      scope: get("scope")?,
      aud: super::aud::decode(map.get("aud"))?,
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

/// Cascade-revoke a grant: delete every member token key plus the grant set
/// and record (single-slot Lua, no `KEYS` scan).
///
/// One script pass is atomic but blind to a mint racing the cascade: a member
/// `SADD`ed after the pass's `SMEMBERS` snapshot would survive with live
/// records. The pass therefore repeats until the set reads empty (bounded),
/// so a token minted mid-cascade is deleted by a later pass instead of
/// surviving the revoke.
///
/// The bound is fail-closed: when the set is still non-empty after the pass
/// budget (a mint landing after every snapshot), revocation reports
/// [`super::StoreError::InvalidData`] instead of a silent success count, and
/// a post-barrier re-read rejects a member `SADD`ed after the final pass the
/// same way — a late `SADD` can never leave a live TTL-less member behind
/// quietly.
///
/// Returns the number of keys deleted: member record keys plus JWT allowlist
/// markers (one `DEL` per member per prefix, plus the stripped marker key for
/// `jwt:`-tagged members). Unknown grants revoke to zero.
pub async fn revoke(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
) -> Result<u64, StoreError> {
  revoke_with_passes(conn, store, grant_id, REVOKE_DRAIN_PASSES).await
}

/// Drain budget: enough passes to absorb a racing mint, small enough to fail
/// closed fast under continuous churn.
const REVOKE_DRAIN_PASSES: u32 = 8;

/// Cascade-revoke with an explicit drain budget (the production path uses
/// [`REVOKE_DRAIN_PASSES`]); a zero budget models an already-exhausted drain.
pub(crate) async fn revoke_with_passes(
  conn: &mut RedisConn,
  store: &Store,
  grant_id: &str,
  max_passes: u32,
) -> Result<u64, StoreError> {
  let set_key = store.grant_tokens_key(grant_id);
  let grant_key = store.grant_key(grant_id);
  let refresh_prefix = store.refresh_key_prefix();
  let access_prefix = store.access_key_prefix();
  let jwt_prefix = store.jwt_key_prefix();
  let mut total = 0_u64;
  let mut drained = false;
  for _ in 0..max_passes {
    let mut invocation = SCRIPT_GRANT_REVOKE.prepare_invoke();
    invocation.key(set_key.as_str()).key(grant_key.as_str());
    invocation
      .arg(refresh_prefix.as_str())
      .arg(access_prefix.as_str())
      .arg(jwt_prefix.as_str());
    let deleted: u64 = invocation
      .invoke_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    total = total.saturating_add(deleted);
    let remaining: Vec<String> = redis::cmd("SMEMBERS")
      .arg(&set_key)
      .query_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    if remaining.is_empty() {
      drained = true;
      break;
    }
  }
  if !drained {
    return Err(StoreError::InvalidData);
  }
  // Revocation is a reuse-driven security response: barrier it like any
  // tombstone-class write before the caller reports the outcome.
  super::durability_barrier(conn, store).await?;
  // A member `SADD`ed after the final pass would otherwise survive with live
  // records behind a success count: re-read after the barrier and fail closed.
  let late: Vec<String> = redis::cmd("SMEMBERS")
    .arg(&set_key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  if late.is_empty() {
    Ok(total)
  } else {
    Err(StoreError::InvalidData)
  }
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

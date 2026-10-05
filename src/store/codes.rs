//! Authorization-code records (short, single-use, PKCE-bound).
//!
//! Codes are stored as Redis hashes keyed by the code hash (never the raw
//! code) and consumed with the atomic [`consume`](consume) Lua helper
//! (`GETDEL` semantics): exactly one consumer observes the record. On an
//! indeterminate transport result the key is re-read instead of replaying the
//! consume, so a surviving record stays available for the client's retry.

use std::{collections::HashMap, time::Duration};

use redis::RedisError;
use serde::{Deserialize, Serialize};

use super::{SCRIPT_CONSUME_HASH, Store, StoreError, flat_to_map, hset_record};
use crate::state::RedisConn;

/// A stored authorization-code record (PKCE-bound, single-use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeRecord {
  /// Client the code was issued to (exact match at redemption).
  pub client_id: String,
  /// Redirect URI the code is bound to.
  pub redirect_uri: String,
  /// Space-joined granted scope.
  pub scope: String,
  /// PKCE `code_challenge` (S256 only).
  pub code_challenge: String,
  /// Resource-owner subject the code was authorized for.
  pub subject: String,
  /// Grant chain this code belongs to.
  pub grant_id: String,
  /// Sender-constraint binding (`cnf`), empty when unconstrained.
  pub cnf: String,
}

impl CodeRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("client_id".to_owned(), self.client_id.clone()),
      ("redirect_uri".to_owned(), self.redirect_uri.clone()),
      ("scope".to_owned(), self.scope.clone()),
      ("code_challenge".to_owned(), self.code_challenge.clone()),
      ("subject".to_owned(), self.subject.clone()),
      ("grant_id".to_owned(), self.grant_id.clone()),
      ("cnf".to_owned(), self.cnf.clone()),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      client_id: get("client_id")?,
      redirect_uri: get("redirect_uri")?,
      scope: get("scope")?,
      code_challenge: get("code_challenge")?,
      subject: get("subject")?,
      grant_id: get("grant_id")?,
      cnf: get("cnf")?,
    })
  }
}

/// Issue a code record under its hash (idempotent rewrite).
pub async fn issue(
  conn: &mut RedisConn,
  store: &Store,
  code_hash: &str,
  record: &CodeRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.code_key(code_hash);
  let pairs = record.to_pairs();
  super::retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(into_redis)
  })
  .map_err(StoreError::Redis)
}

/// Atomically consume a code record: exactly one caller observes `Some`.
pub async fn consume(
  conn: &mut RedisConn,
  store: &Store,
  code_hash: &str,
) -> Result<Option<CodeRecord>, StoreError> {
  let key = store.code_key(code_hash);
  let mut invocation = SCRIPT_CONSUME_HASH.prepare_invoke();
  invocation.key(key.as_str());
  let outcome: Result<redis::Value, StoreError> = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis);
  match outcome {
    Ok(redis::Value::Array(items)) => {
      let flat = items
        .into_iter()
        .map(redis_string)
        .collect::<Result<Vec<_>, _>>()?;
      CodeRecord::from_map(&flat_to_map(flat)?).map(Some)
    }
    // Absent (nil or a `false` reply): no record.
    Ok(_) => Ok(None),
    // Indeterminate transport result: re-read, never replay.
    Err(error) => recover_consume(conn, store, code_hash, error).await,
  }
}

/// Re-read after an indeterminate consume: a surviving key means the consume
/// did not happen (fail closed, the record stays usable); an absent key means
/// it did (report `None`, never replay).
async fn recover_consume(
  conn: &mut RedisConn,
  store: &Store,
  code_hash: &str,
  error: StoreError,
) -> Result<Option<CodeRecord>, StoreError> {
  if !matches!(error, StoreError::Redis(_)) {
    return Err(error);
  }
  let key = store.code_key(code_hash);
  let present: bool = redis::cmd("EXISTS")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  if present { Err(error) } else { Ok(None) }
}

fn redis_string(value: redis::Value) -> Result<String, StoreError> {
  match value {
    redis::Value::BulkString(bytes) => {
      String::from_utf8(bytes).map_err(|_| StoreError::InvalidData)
    }
    redis::Value::SimpleString(text) => Ok(text),
    _ => Err(StoreError::InvalidData),
  }
}

fn into_redis(error: StoreError) -> RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => RedisError::from((redis::ErrorKind::Client, "store record write failed")),
  }
}

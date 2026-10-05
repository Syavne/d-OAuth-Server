//! PAR `request_uri` records (RFC 9126, 90s TTL).

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{SCRIPT_CONSUME_HASH, Store, StoreError, hset_record, retry_op};
use crate::state::RedisConn;

/// A stored pushed-authorization request, keyed by its `request_uri` id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParRecord {
  /// Client that pushed the request.
  pub client_id: String,
  /// Serialized authorized request parameters (JSON).
  pub request: String,
}

impl ParRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("client_id".to_owned(), self.client_id.clone()),
      ("request".to_owned(), self.request.clone()),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      client_id: get("client_id")?,
      request: get("request")?,
    })
  }
}

/// Store a PAR record under its `request_uri` id (idempotent rewrite).
pub async fn put(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
  record: &ParRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.par_key(request_id);
  let pairs = record.to_pairs();
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(par_redis)
  })
  .map_err(StoreError::Redis)
}

/// Atomically consume a PAR record: exactly one caller observes `Some`.
pub async fn consume(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
) -> Result<Option<ParRecord>, StoreError> {
  let key = store.par_key(request_id);
  let mut invocation = SCRIPT_CONSUME_HASH.prepare_invoke();
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
      ParRecord::from_map(&super::flat_to_map(flat)?).map(Some)
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

fn par_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store par write failed")),
  }
}

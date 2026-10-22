//! PAR `request_uri` records (RFC 9126, 90s TTL).

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use redis::Script;
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
  /// Resource audiences (RFC 8707) pinned to the request; empty when unbound.
  #[serde(default)]
  pub aud: Vec<String>,
}

impl ParRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("client_id".to_owned(), self.client_id.clone()),
      ("request".to_owned(), self.request.clone()),
      ("aud".to_owned(), super::aud::encode(&self.aud)),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      client_id: get("client_id")?,
      request: get("request")?,
      aud: super::aud::decode(map.get("aud"))?,
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

/// Guarded single-use consume: the record is deleted only when the expected
/// client matches, otherwise it survives untouched.
///
/// KEYS: PAR record. ARGV: expected `client_id`. Returns the hash fields on
/// a match, `{'MISMATCH'}` when the presenter is foreign (the key is left
/// intact), or `false` when absent. Mirrors the refresh-rotation `client_id`
/// compare-and-set.
static SCRIPT_CONSUME_PAR_GUARDED: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local data = redis.call('HGETALL', KEYS[1])
    if #data == 0 then
      return false
    end
    local h = {}
    for i = 1, #data, 2 do
      h[data[i]] = data[i + 1]
    end
    if h['client_id'] ~= ARGV[1] then
      return {'MISMATCH'}
    end
    redis.call('DEL', KEYS[1])
    return data
    ",
  )
});

/// Outcome of a guarded PAR consume.
#[derive(Debug)]
pub enum ConsumeOutcome {
  /// The presenting client owns the record; it was deleted and is returned.
  Consumed(ParRecord),
  /// A foreign client presented the id; the record survives for its owner.
  Mismatched,
  /// No record under this id (unknown, expired, or already consumed).
  Absent,
}

/// Atomically consume a PAR record bound to its owning client: exactly one
/// matching presenter observes `Consumed`; a foreign presenter observes
/// `Mismatched` without deleting anything.
pub async fn consume_bound(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
  expected_client_id: &str,
) -> Result<ConsumeOutcome, StoreError> {
  let key = store.par_key(request_id);
  let mut invocation = SCRIPT_CONSUME_PAR_GUARDED.prepare_invoke();
  invocation.key(key.as_str());
  invocation.arg(expected_client_id);
  let outcome: Result<redis::Value, StoreError> = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis);
  match outcome {
    Ok(redis::Value::Array(items)) => {
      if is_mismatch(&items) {
        Ok(ConsumeOutcome::Mismatched)
      } else {
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
        ParRecord::from_map(&super::flat_to_map(flat)?).map(ConsumeOutcome::Consumed)
      }
    }
    Ok(_) => Ok(ConsumeOutcome::Absent),
    Err(error) => {
      if !matches!(error, StoreError::Redis(_)) {
        return Err(error);
      }
      let present: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(conn)
        .await
        .map_err(StoreError::Redis)?;
      if present {
        Err(error)
      } else {
        Ok(ConsumeOutcome::Absent)
      }
    }
  }
}

/// Whether a script reply is the single-element `MISMATCH` tag rather than
/// hash fields (field/value pairs always arrive in even length).
fn is_mismatch(items: &[redis::Value]) -> bool {
  match items {
    [single] => {
      matches!(
        single,
        redis::Value::BulkString(bytes) if bytes.as_slice() == b"MISMATCH"
      ) || matches!(single, redis::Value::SimpleString(text) if text == "MISMATCH")
    }
    _ => false,
  }
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

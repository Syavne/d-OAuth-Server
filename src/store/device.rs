//! Device-code records and polling state (RFC 8628).

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{SCRIPT_CONSUME_HASH, Store, StoreError, hset_record, retry_op};
use crate::state::RedisConn;

/// Polling status of a device authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
  /// Awaiting user approval.
  Pending,
  /// Approved by the user; the device may redeem it.
  Approved,
  /// Denied by the user.
  Denied,
}

impl DeviceStatus {
  fn as_str(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Approved => "approved",
      Self::Denied => "denied",
    }
  }

  fn parse(value: &str) -> Result<Self, StoreError> {
    match value {
      "pending" => Ok(Self::Pending),
      "approved" => Ok(Self::Approved),
      "denied" => Ok(Self::Denied),
      _ => Err(StoreError::InvalidData),
    }
  }
}

/// A device-code record, keyed by the device-code hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
  /// Client polling for the token.
  pub client_id: String,
  /// Space-joined requested scope.
  pub scope: String,
  /// Current polling status.
  pub status: DeviceStatus,
  /// Approving subject, empty while pending.
  pub subject: String,
  /// Grant chain, empty until approved.
  pub grant_id: String,
  /// Resource audiences (RFC 8707) requested by the device; empty when unbound.
  #[serde(default)]
  pub aud: Vec<String>,
}

impl DeviceRecord {
  fn to_pairs(&self) -> Vec<(String, String)> {
    vec![
      ("client_id".to_owned(), self.client_id.clone()),
      ("scope".to_owned(), self.scope.clone()),
      ("status".to_owned(), self.status.as_str().to_owned()),
      ("subject".to_owned(), self.subject.clone()),
      ("grant_id".to_owned(), self.grant_id.clone()),
      ("aud".to_owned(), super::aud::encode(&self.aud)),
    ]
  }

  fn from_map(map: &HashMap<String, String>) -> Result<Self, StoreError> {
    let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
    Ok(Self {
      client_id: get("client_id")?,
      scope: get("scope")?,
      status: DeviceStatus::parse(get("status")?.as_str())?,
      subject: get("subject")?,
      grant_id: get("grant_id")?,
      aud: super::aud::decode(map.get("aud"))?,
    })
  }
}

/// Polling-attempt sidecar: last poll time (Unix seconds) for a device hash.
///
/// It derives from the device record key, so it shares the `{state}` hash
/// slot, and it carries the device TTL so it can never outlive its record by
/// more than one issuance lifetime.
#[must_use]
pub fn poll_key(store: &Store, device_hash: &str) -> String {
  format!("{}:poll", store.device_key(device_hash))
}

/// Outcome of one atomic polling-interval gate attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollSlot {
  /// This attempt is allowed; the stamp now reads the attempt time.
  Allowed,
  /// Too fast: wait this many whole seconds (the stamp still advanced).
  SlowDown {
    /// Whole seconds the device should wait before polling again.
    retry_after_secs: u64,
  },
}

/// Store a device record and its user-code mapping (both idempotent rewrites).
pub async fn put(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
  user_code_hash: &str,
  record: &DeviceRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.device_key(device_hash);
  let user_key = store.user_code_key(user_code_hash);
  let pairs = record.to_pairs();
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(device_redis)?;
    redis::cmd("SET")
      .arg(&user_key)
      .arg(device_hash)
      .arg("PX")
      .arg(ttl.as_millis() as u64)
      .query_async::<()>(conn)
      .await?;
    Ok(())
  })
  .map_err(StoreError::Redis)
}

/// Read the current device record without consuming it (polling).
pub async fn poll(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
) -> Result<Option<DeviceRecord>, StoreError> {
  let key = store.device_key(device_hash);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(device_redis)
  })
  .map_err(StoreError::Redis)?;
  map
    .map(|fields| DeviceRecord::from_map(&fields))
    .transpose()
}

/// Resolve a user code to its device hash; `Ok(None)` when unknown.
pub async fn resolve_user_code(
  conn: &mut RedisConn,
  store: &Store,
  user_code_hash: &str,
) -> Result<Option<String>, StoreError> {
  let key = store.user_code_key(user_code_hash);
  let budget = store.retry_budget();
  retry_op!(conn, budget, async {
    redis::cmd("GET")
      .arg(&key)
      .query_async::<Option<String>>(conn)
      .await
  })
  .map_err(StoreError::Redis)
}

/// Record the user's verdict and bind the grant; returns false when the
/// device record is already gone.
///
/// The existence check and the write run as one Lua script, so a verdict
/// racing the atomic consume can neither resurrect a zombie record nor lose
/// the consume's delete. The key TTL is preserved.
pub async fn decide(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
  status: DeviceStatus,
  subject: &str,
  grant_id: &str,
) -> Result<bool, StoreError> {
  let key = store.device_key(device_hash);
  let budget = store.retry_budget();
  let applied: i64 = retry_op!(conn, budget, async {
    let mut invocation = super::SCRIPT_DEVICE_DECIDE.prepare_invoke();
    invocation.key(key.as_str());
    invocation.arg(status.as_str());
    invocation.arg(subject);
    invocation.arg(grant_id);
    invocation.invoke_async(conn).await
  })
  .map_err(StoreError::Redis)?;
  Ok(applied == 1)
}

/// Enforce the polling interval and count this attempt, atomically.
///
/// The read-compare-write runs as one Lua compare-and-set, so concurrent
/// polls cannot both pass the gate: exactly one attempt is admitted and the
/// rest observe `slow_down`. A corrupt marker surfaces as
/// [`StoreError::InvalidData`] (fail closed, never fail open).
pub async fn claim_poll_slot(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
  now_unix: i64,
  interval: Duration,
  device_ttl: Duration,
) -> Result<PollSlot, StoreError> {
  let key = poll_key(store, device_hash);
  let budget = store.retry_budget();
  let interval_secs = interval.as_secs();
  let ttl_ms = device_ttl.as_millis() as u64;
  let outcome: i64 = retry_op!(conn, budget, async {
    let mut invocation = super::SCRIPT_DEVICE_POLL_CAS.prepare_invoke();
    invocation.key(key.as_str());
    invocation.arg(now_unix);
    invocation.arg(interval_secs);
    invocation.arg(ttl_ms);
    invocation.invoke_async(conn).await
  })
  .map_err(StoreError::Redis)?;
  match outcome {
    0 => Ok(PollSlot::Allowed),
    wait if wait > 0 => Ok(PollSlot::SlowDown {
      retry_after_secs: wait as u64,
    }),
    _ => Err(StoreError::InvalidData),
  }
}

/// Atomically consume an approved device record for token issuance.
pub async fn consume(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
) -> Result<Option<DeviceRecord>, StoreError> {
  let key = store.device_key(device_hash);
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
      DeviceRecord::from_map(&super::flat_to_map(flat)?).map(Some)
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

fn device_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store device write failed")),
  }
}

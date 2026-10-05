//! Access/refresh token records with rotation tombstones.
//!
//! Stores only keyed hashes; rotation is atomic (Lua) with a deterministic
//! idempotency key and a tombstone so replay is detectable for the refresh
//! lifetime.
//!
//! Rotation precedence: the new tokens are fixed BEFORE the Lua script runs,
//! and the rotation is keyed by a deterministic `rotation_request_id` derived
//! from the presented old refresh token (see [`derive_rotation_id`]). A
//! duplicate presentation of the SAME old token with a valid request-id
//! mapping returns the SAME tokens ([`RotateOutcome::Replay`]); a
//! presentation without a mapping (or after the grace window) is reuse:
//! [`RotateOutcome::Reused`] plus an automatic grant-cascade revocation.
//!
//! Token-mint/rotation scripts are idempotent, so an indeterminate
//! post-`EXEC` result is re-read (mapping key, then the old record), never
//! blindly replayed; `Script::invoke_async` self-heals `NOSCRIPT`.

use std::{collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};

use super::{
  OpClass, SCRIPT_ROTATE_REFRESH, Store, StoreError, durability_barrier, hmac_sha256, hset_record,
  may_retry_op, retry_op,
};
use crate::state::RedisConn;

/// Grace window for the rotation idempotency mapping (bounded replay-recovery).
const ROTATION_MAP_GRACE: Duration = Duration::from_secs(900);

/// A stored access-token record, keyed by the token hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
  /// Client the token was issued to.
  pub client_id: String,
  /// Grant chain this token belongs to.
  pub grant_id: String,
  /// Space-joined scope.
  pub scope: String,
  /// Resource-owner subject, empty for client-credentials tokens.
  pub subject: String,
  /// Sender-constraint binding (`cnf`), empty when unconstrained.
  pub cnf: String,
}

/// A stored refresh-token record (or tombstone), keyed by the token hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRecord {
  /// Client the token was issued to.
  pub client_id: String,
  /// Grant chain this token belongs to.
  pub grant_id: String,
  /// Space-joined scope.
  pub scope: String,
  /// Resource-owner subject.
  pub subject: String,
  /// Sender-constraint binding (`cnf`), empty when unconstrained.
  pub cnf: String,
}

impl AccessRecord {
  fn to_json(&self) -> Result<String, StoreError> {
    serde_json::to_string(self).map_err(|_| StoreError::InvalidData)
  }
}

impl RefreshRecord {
  fn to_json(&self) -> Result<String, StoreError> {
    serde_json::to_string(self).map_err(|_| StoreError::InvalidData)
  }
}

/// Inputs for one refresh rotation. The new token hashes identify records
/// minted by the caller (task 30); this module never sees raw tokens.
pub struct RotationInput {
  /// Hash of the presented (old) refresh token.
  pub old_refresh_hash: String,
  /// Client presenting the old token (must match the stored record).
  pub expected_client_id: String,
  /// Hash of the new refresh token.
  pub new_refresh_hash: String,
  /// Hash of the new access token.
  pub new_access_hash: String,
  /// New refresh record to store.
  pub new_refresh: RefreshRecord,
  /// New access record to store.
  pub new_access: AccessRecord,
  /// TTL for the new refresh record.
  pub new_refresh_ttl: Duration,
  /// TTL for the new access record.
  pub new_access_ttl: Duration,
  /// Explicit request id; `None` derives it deterministically from the old
  /// token hash (the only production path).
  pub request_id: Option<String>,
}

/// Outcome of a refresh rotation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
  /// Rotation applied; the durability barrier was met before returning.
  Rotated {
    /// Hash of the new refresh token.
    new_refresh_hash: String,
    /// Hash of the new access token.
    new_access_hash: String,
  },
  /// Idempotent retry: the mapping already held these tokens.
  Replay {
    /// Hash of the new refresh token.
    new_refresh_hash: String,
    /// Hash of the new access token.
    new_access_hash: String,
  },
  /// Reuse detected (tombstoned old token, no valid mapping): the grant
  /// family was cascade-revoked before returning.
  Reused {
    /// Hash the old token was rotated to.
    rotated_to: String,
  },
  /// No record for the presented old token.
  Absent,
  /// The stored record belongs to a different client.
  Mismatch,
}

/// Derive the deterministic `rotation_request_id` for an old refresh-token
/// hash: hex `HMAC(pepper, "rot:" + old_hash)`.
pub fn derive_rotation_id(pepper: &[u8], old_refresh_hash: &str) -> Result<String, StoreError> {
  let mut message = Vec::with_capacity(4 + old_refresh_hash.len());
  message.extend_from_slice(b"rot:");
  message.extend_from_slice(old_refresh_hash.as_bytes());
  let digest = hmac_sha256(pepper, &message);
  let mut out = String::with_capacity(64);
  for byte in digest {
    out.push_str(&format!("{byte:02x}"));
  }
  Ok(out)
}

/// Store an access-token record and index it in its grant set, then apply the
/// durability barrier before returning.
pub async fn put_access(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &AccessRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.access_key(token_hash);
  let set_key = store.grant_tokens_key(&record.grant_id);
  let pairs = record_pairs(
    &record.client_id,
    &record.grant_id,
    &record.scope,
    &record.subject,
    &record.cnf,
  );
  retry_op!(conn, store.retry_budget(), async {
    put_member(conn, &key, &pairs, ttl, &set_key, token_hash)
      .await
      .map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  durability_barrier(conn, store).await
}

/// Store a refresh-token record and index it in its grant set, then apply the
/// durability barrier before returning.
pub async fn put_refresh(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &RefreshRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = store.refresh_key(token_hash);
  let set_key = store.grant_tokens_key(&record.grant_id);
  let pairs = record_pairs(
    &record.client_id,
    &record.grant_id,
    &record.scope,
    &record.subject,
    &record.cnf,
  );
  retry_op!(conn, store.retry_budget(), async {
    put_member(conn, &key, &pairs, ttl, &set_key, token_hash)
      .await
      .map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  durability_barrier(conn, store).await
}

/// Read an access-token record; `Ok(None)` when absent.
pub async fn get_access(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<Option<AccessRecord>, StoreError> {
  let key = store.access_key(token_hash);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  map.map(access_from_map).transpose()
}

/// Read a refresh-token record; `Ok(None)` when absent (tombstones included —
/// use [`tombstone_of`] to distinguish replay from absence).
pub async fn get_refresh(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<Option<RefreshRecord>, StoreError> {
  let key = store.refresh_key(token_hash);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  map.map(refresh_from_map).transpose()
}

/// Inspect the tombstone of a rotated refresh token: `Ok(Some(rotated_to))`
/// when the token was rotated, `Ok(None)` when live or absent.
pub async fn tombstone_of(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
) -> Result<Option<String>, StoreError> {
  let key = store.refresh_key(token_hash);
  let budget = store.retry_budget();
  let map = retry_op!(conn, budget, async {
    super::hget_record(conn, &key).await.map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  match map {
    None => Ok(None),
    Some(fields) => {
      if fields.get("used").is_some_and(|used| used == "true") {
        fields
          .get("rotated_to")
          .cloned()
          .filter(|target| !target.is_empty())
          .map_or(Err(StoreError::InvalidData), |target| Ok(Some(target)))
      } else {
        Ok(None)
      }
    }
  }
}

/// Atomically rotate a refresh token (compare-and-set with reuse signal).
///
/// On `Rotated`/`Replay` the durability barrier is met BEFORE returning. On
/// `Reused` the grant family is cascade-revoked before returning. On an
/// indeterminate transport result state is re-read (mapping, then the old
/// record), never blindly replayed.
pub async fn rotate(
  conn: &mut RedisConn,
  store: &Store,
  pepper: &[u8],
  input: &RotationInput,
) -> Result<RotateOutcome, StoreError> {
  let request_id = match &input.request_id {
    Some(id) => id.clone(),
    None => derive_rotation_id(pepper, &input.old_refresh_hash)?,
  };
  let old_key = store.refresh_key(&input.old_refresh_hash);
  let new_refresh_key = store.refresh_key(&input.new_refresh_hash);
  let new_access_key = store.access_key(&input.new_access_hash);
  let grant_key = store.grant_tokens_key(&input.new_refresh.grant_id);
  let map_key = store.rotation_map_key(&request_id);
  let new_refresh_json = input.new_refresh.to_json()?;
  let new_access_json = input.new_access.to_json()?;
  let map_ttl = ROTATION_MAP_GRACE.min(input.new_refresh_ttl);

  let outcome: Result<Vec<String>, StoreError> = retry_op!(conn, store.retry_budget(), async {
    invoke_rotate(
      conn,
      &InvokeRotate {
        old_key: &old_key,
        new_refresh_key: &new_refresh_key,
        new_access_key: &new_access_key,
        grant_key: &grant_key,
        map_key: &map_key,
        expected_client: &input.expected_client_id,
        new_refresh_json: &new_refresh_json,
        new_refresh_ttl: input.new_refresh_ttl,
        new_access_json: &new_access_json,
        new_access_ttl: input.new_access_ttl,
        request_id: &request_id,
        grant_id: &input.new_refresh.grant_id,
        new_refresh_hash: &input.new_refresh_hash,
        new_access_hash: &input.new_access_hash,
        tombstone_ttl: input.new_refresh_ttl,
        map_ttl,
      },
    )
    .await
    .map_err(store_redis)
  })
  .map_err(StoreError::Redis);
  match outcome {
    Ok(parts) => finish_rotate(conn, store, parts).await,
    Err(error) => recover_rotate(conn, store, &request_id, &input.old_refresh_hash, error).await,
  }
}

/// Invoke the rotation script once and decode its `{TAG, ...}` reply.
async fn invoke_rotate(
  conn: &mut RedisConn,
  args: &InvokeRotate<'_>,
) -> Result<Vec<String>, StoreError> {
  let mut invocation = SCRIPT_ROTATE_REFRESH.prepare_invoke();
  invocation
    .key(args.old_key)
    .key(args.new_refresh_key)
    .key(args.new_access_key)
    .key(args.grant_key)
    .key(args.map_key);
  invocation
    .arg(args.expected_client)
    .arg(args.new_refresh_json)
    .arg(args.new_refresh_ttl.as_millis() as u64)
    .arg(args.new_access_json)
    .arg(args.new_access_ttl.as_millis() as u64)
    .arg(args.request_id)
    .arg(args.grant_id)
    .arg(args.new_refresh_hash)
    .arg(args.new_access_hash)
    .arg(args.tombstone_ttl.as_millis() as u64)
    .arg(args.map_ttl.as_millis() as u64);
  let parts: Vec<String> = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(parts)
}

/// Arguments for one rotation-script invocation, bundled so the call stays
/// reviewable (seventeen positional arguments would not be).
struct InvokeRotate<'a> {
  old_key: &'a str,
  new_refresh_key: &'a str,
  new_access_key: &'a str,
  grant_key: &'a str,
  map_key: &'a str,
  expected_client: &'a str,
  new_refresh_json: &'a str,
  new_refresh_ttl: Duration,
  new_access_json: &'a str,
  new_access_ttl: Duration,
  request_id: &'a str,
  grant_id: &'a str,
  new_refresh_hash: &'a str,
  new_access_hash: &'a str,
  tombstone_ttl: Duration,
  map_ttl: Duration,
}

/// Settle a script reply: barrier first for token-bearing outcomes, cascade
/// for reuse.
async fn finish_rotate(
  conn: &mut RedisConn,
  store: &Store,
  parts: Vec<String>,
) -> Result<RotateOutcome, StoreError> {
  let tag = parts.first().cloned().unwrap_or_default();
  match tag.as_str() {
    "ROTATED" => {
      let (new_refresh, new_access) = take_pair(&parts)?;
      durability_barrier(conn, store).await?;
      Ok(RotateOutcome::Rotated {
        new_refresh_hash: new_refresh,
        new_access_hash: new_access,
      })
    }
    "REPLAY" => {
      let (new_refresh, new_access) = take_pair(&parts)?;
      durability_barrier(conn, store).await?;
      Ok(RotateOutcome::Replay {
        new_refresh_hash: new_refresh,
        new_access_hash: new_access,
      })
    }
    "REUSE" => {
      let rotated_to = parts.get(1).cloned().unwrap_or_default();
      if rotated_to.is_empty() {
        return Err(StoreError::InvalidData);
      }
      super::grants::revoke_by_token_hash(conn, store, &rotated_to).await?;
      Ok(RotateOutcome::Reused { rotated_to })
    }
    "ABSENT" => Ok(RotateOutcome::Absent),
    "MISMATCH" => Ok(RotateOutcome::Mismatch),
    _ => Err(StoreError::InvalidData),
  }
}

/// Re-read after an indeterminate rotation: the mapping decides replay, a
/// tombstone decides reuse (plus cascade), a live record fails closed so the
/// client can safely retry, and absence reports `Absent`.
async fn recover_rotate(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
  old_refresh_hash: &str,
  error: StoreError,
) -> Result<RotateOutcome, StoreError> {
  let redis_error = match error {
    StoreError::Redis(inner) => inner,
    other => return Err(other),
  };
  if !may_retry_op(OpClass::ConditionalWrite, &redis_error) {
    return Err(StoreError::Redis(redis_error));
  }
  let map_key = store.rotation_map_key(request_id);
  let mapped: Option<String> = redis::cmd("GET")
    .arg(&map_key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  if let Some(payload) = mapped {
    let members: HashMap<String, String> =
      serde_json::from_str(&payload).map_err(|_| StoreError::InvalidData)?;
    let new_refresh = members.get("refresh").cloned().unwrap_or_default();
    let new_access = members.get("access").cloned().unwrap_or_default();
    if new_refresh.is_empty() || new_access.is_empty() {
      return Err(StoreError::InvalidData);
    }
    durability_barrier(conn, store).await?;
    return Ok(RotateOutcome::Replay {
      new_refresh_hash: new_refresh,
      new_access_hash: new_access,
    });
  }
  match tombstone_of(conn, store, old_refresh_hash).await? {
    Some(rotated_to) => {
      super::grants::revoke_by_token_hash(conn, store, &rotated_to).await?;
      Ok(RotateOutcome::Reused { rotated_to })
    }
    None => {
      let key = store.refresh_key(old_refresh_hash);
      let live = super::hget_record(conn, &key).await?.is_some();
      if live {
        Err(StoreError::Redis(redis_error))
      } else {
        Ok(RotateOutcome::Absent)
      }
    }
  }
}

fn take_pair(parts: &[String]) -> Result<(String, String), StoreError> {
  if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
    return Err(StoreError::InvalidData);
  }
  Ok((parts[1].clone(), parts[2].clone()))
}

fn record_pairs(
  client_id: &str,
  grant_id: &str,
  scope: &str,
  subject: &str,
  cnf: &str,
) -> Vec<(String, String)> {
  vec![
    ("client_id".to_owned(), client_id.to_owned()),
    ("grant_id".to_owned(), grant_id.to_owned()),
    ("scope".to_owned(), scope.to_owned()),
    ("subject".to_owned(), subject.to_owned()),
    ("cnf".to_owned(), cnf.to_owned()),
  ]
}

async fn put_member(
  conn: &mut RedisConn,
  key: &str,
  pairs: &[(String, String)],
  ttl: Duration,
  set_key: &str,
  member: &str,
) -> Result<(), StoreError> {
  hset_record(conn, key, pairs, ttl).await?;
  let _: () = redis::cmd("SADD")
    .arg(set_key)
    .arg(member)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

fn access_from_map(map: HashMap<String, String>) -> Result<AccessRecord, StoreError> {
  let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
  Ok(AccessRecord {
    client_id: get("client_id")?,
    grant_id: get("grant_id")?,
    scope: get("scope")?,
    subject: get("subject")?,
    cnf: get("cnf")?,
  })
}

fn refresh_from_map(map: HashMap<String, String>) -> Result<RefreshRecord, StoreError> {
  let get = |field: &str| map.get(field).cloned().ok_or(StoreError::InvalidData);
  Ok(RefreshRecord {
    client_id: get("client_id")?,
    grant_id: get("grant_id")?,
    scope: get("scope")?,
    subject: get("subject")?,
    cnf: get("cnf")?,
  })
}

fn store_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store token write failed")),
  }
}

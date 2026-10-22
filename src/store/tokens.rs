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
  OpClass, SCRIPT_PUT_MEMBER, SCRIPT_ROTATE_REFRESH, Store, StoreError, durability_barrier,
  hmac_sha256, may_retry_op, retry_op,
};
use crate::state::RedisConn;

/// Grace window for the rotation idempotency mapping (bounded replay-recovery).
const ROTATION_MAP_GRACE: Duration = Duration::from_secs(900);

/// A stored access-token record, keyed by the token hash.
///
/// `Debug` is intentionally derived: the record holds only identifiers
/// (`client_id`, `grant_id`, scope, subject, `cnf`) and never a raw token,
/// so the [`crate::protocol::token::types::FoundAccess`] redaction stays
/// transitive through this field.
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
  /// Resource audiences (RFC 8707) bound to this token; empty when unbound.
  #[serde(
    default,
    serialize_with = "super::aud::serialize",
    deserialize_with = "super::aud::deserialize"
  )]
  pub aud: Vec<String>,
}

/// A stored refresh-token record (or tombstone), keyed by the token hash.
///
/// `Debug` is intentionally derived: the record holds only identifiers
/// (`client_id`, `grant_id`, scope, subject, `cnf`) and never a raw token,
/// so the [`crate::protocol::token::types::FoundRefresh`] redaction stays
/// transitive through this field.
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
  /// Resource audiences (RFC 8707) bound to this token; empty when unbound.
  #[serde(
    default,
    serialize_with = "super::aud::serialize",
    deserialize_with = "super::aud::deserialize"
  )]
  pub aud: Vec<String>,
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
  /// JWT allowlist binding: `Some(jti-hash)` when the new access token is a
  /// JWT, so the rotation script writes the `jwt:<jti-hash>` marker hash in
  /// the SAME script as its `SADD`. `None` for opaque rotations (behavior
  /// unchanged). The pre-mint never sets this through the pending pair;
  /// only the committed rotation writes a marker.
  pub jwt_jti_hash: Option<String>,
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
  /// Rotation applied but the durability barrier failed after this request
  /// id's write already landed. Only the originating request may resolve to
  /// these tokens (returned as-is, never discarded); any non-originating
  /// caller still fails closed through [`RotateOutcome::Replay`] or
  /// [`RotateOutcome::Reused`].
  RotatedUnbarriered {
    /// Hash of the new refresh token.
    new_refresh_hash: String,
    /// Hash of the new access token.
    new_access_hash: String,
  },
  /// Idempotent retry: the mapping already held these tokens. The raw pair of
  /// the first rotation is unrecoverable from hashes alone, so the retry
  /// cannot be served (fail closed without cascading the grant family).
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

/// JWT marker write for one atomic member script invocation.
///
/// `Some` carries the marker key plus the fields the script stores
/// (`grant_id`/`client_id`/`subject`) and the marker TTL (the access TTL).
/// Only the barriered fresh JWT path passes `Some`
/// ([`put_access_jwt`]); the rotation pre-mint pair and every opaque write
/// pass `None` with a dummy marker key, so they can never write a marker.
struct JwtMarker<'a> {
  /// Allowlist marker key (`{state}jwt:<jti-hash>`).
  key: &'a str,
  /// Marker TTL (the access-token TTL).
  ttl: Duration,
  /// Marker `grant_id` field.
  grant_id: &'a str,
  /// Marker `client_id` field.
  client_id: &'a str,
  /// Marker `subject` field (raw; empty for client-credentials).
  subject: &'a str,
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
  put_access_inner(conn, store, token_hash, record, ttl, true, None).await
}

/// Store a JWT access-token record, `SADD` its `jwt:<jti-hash>` member, and
/// write the `jwt:<jti-hash>` allowlist marker hash (`grant_id`/`client_id`/
/// `subject`, TTL = access TTL) in ONE script, then apply the durability
/// barrier before returning.
///
/// Only the barriered fresh mint reaches this: `token_hash` is the member
/// identity `jwt:<jti-hash>` (the record key is `access:<member>`), and the
/// marker fields come from the record itself. The pending pre-mint must use
/// [`put_access_pending`], which writes no marker by construction.
pub async fn put_access_jwt(
  conn: &mut RedisConn,
  store: &Store,
  member: &str,
  record: &AccessRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  let marker_key =
    store.jwt_marker_key(member.strip_prefix("jwt:").ok_or(StoreError::InvalidData)?);
  let marker = JwtMarker {
    key: &marker_key,
    ttl,
    grant_id: &record.grant_id,
    client_id: &record.client_id,
    subject: &record.subject,
  };
  put_access_inner(conn, store, member, record, ttl, true, Some(&marker)).await
}

/// Store an access-token record and index it in its grant set WITHOUT the
/// durability barrier.
///
/// Only for the refresh-rotation pre-mint: the pair is unreachable until the
/// rotation script commits it, and the rotation's own barrier runs on the
/// same connection afterwards, so it covers these writes before any response.
pub async fn put_access_pending(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &AccessRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  put_access_inner(conn, store, token_hash, record, ttl, false, None).await
}

async fn put_access_inner(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &AccessRecord,
  ttl: Duration,
  apply_barrier: bool,
  jwt: Option<&JwtMarker<'_>>,
) -> Result<(), StoreError> {
  let key = store.access_key(token_hash);
  let set_key = store.grant_tokens_key(&record.grant_id);
  let pairs = record_pairs(
    &record.client_id,
    &record.grant_id,
    &record.scope,
    &record.subject,
    &record.cnf,
    &record.aud,
  );
  retry_op!(conn, store.retry_budget(), async {
    put_member(conn, &key, &pairs, ttl, &set_key, token_hash, jwt)
      .await
      .map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  if apply_barrier {
    durability_barrier(conn, store).await
  } else {
    Ok(())
  }
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
  put_refresh_inner(conn, store, token_hash, record, ttl, true).await
}

/// Store a refresh-token record and index it in its grant set WITHOUT the
/// durability barrier.
///
/// Only for the refresh-rotation pre-mint: the pair is unreachable until the
/// rotation script commits it, and the rotation's own barrier runs on the
/// same connection afterwards, so it covers these writes before any response.
pub async fn put_refresh_pending(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &RefreshRecord,
  ttl: Duration,
) -> Result<(), StoreError> {
  put_refresh_inner(conn, store, token_hash, record, ttl, false).await
}

async fn put_refresh_inner(
  conn: &mut RedisConn,
  store: &Store,
  token_hash: &str,
  record: &RefreshRecord,
  ttl: Duration,
  apply_barrier: bool,
) -> Result<(), StoreError> {
  let key = store.refresh_key(token_hash);
  let set_key = store.grant_tokens_key(&record.grant_id);
  let pairs = record_pairs(
    &record.client_id,
    &record.grant_id,
    &record.scope,
    &record.subject,
    &record.cnf,
    &record.aud,
  );
  // Refresh records never carry a JWT marker: the flag is always clear.
  retry_op!(conn, store.retry_budget(), async {
    put_member(conn, &key, &pairs, ttl, &set_key, token_hash, None)
      .await
      .map_err(store_redis)
  })
  .map_err(StoreError::Redis)?;
  if apply_barrier {
    durability_barrier(conn, store).await
  } else {
    Ok(())
  }
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
/// On `Rotated` the durability barrier was met before returning; when the
/// barrier fails after the originating write applied the minted pair is
/// returned as `RotatedUnbarriered` instead of a lockout error. On `Reused`
/// the grant family is cascade-revoked before returning. On an indeterminate
/// transport result state is re-read (mapping, then the old record), never
/// blindly replayed.
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
  let grant_record_key = store.grant_key(&input.new_refresh.grant_id);
  let map_key = store.rotation_map_key(&request_id);
  let new_refresh_json = input.new_refresh.to_json()?;
  let new_access_json = input.new_access.to_json()?;
  let map_ttl = ROTATION_MAP_GRACE.min(input.new_refresh_ttl);

  let (marker_key, jwt_flag, marker_subject) = match &input.jwt_jti_hash {
    Some(hash) => (
      store.jwt_marker_key(hash),
      "1",
      input.new_access.subject.clone(),
    ),
    None => (grant_record_key.clone(), "0", String::new()),
  };
  let outcome: Result<Vec<String>, StoreError> = retry_op!(conn, store.retry_budget(), async {
    invoke_rotate(
      conn,
      &InvokeRotate {
        old_key: &old_key,
        new_refresh_key: &new_refresh_key,
        new_access_key: &new_access_key,
        grant_key: &grant_key,
        grant_record_key: &grant_record_key,
        map_key: &map_key,
        marker_key: &marker_key,
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
        jwt_flag,
        marker_subject: &marker_subject,
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
    .key(args.map_key)
    .key(args.grant_record_key)
    .key(args.marker_key);
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
    .arg(args.map_ttl.as_millis() as u64)
    .arg(args.jwt_flag)
    .arg(args.new_access_ttl.as_millis() as u64)
    .arg(args.marker_subject);
  let parts: Vec<String> = invocation
    .invoke_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(parts)
}

/// Arguments for one rotation-script invocation, bundled so the call stays
/// reviewable.
struct InvokeRotate<'a> {
  old_key: &'a str,
  new_refresh_key: &'a str,
  new_access_key: &'a str,
  grant_key: &'a str,
  grant_record_key: &'a str,
  map_key: &'a str,
  marker_key: &'a str,
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
  jwt_flag: &'a str,
  marker_subject: &'a str,
}

/// Settle a script reply: barrier first for token-bearing outcomes, cascade
/// for reuse, fail closed for a fenced (revoked-grant) write.
async fn finish_rotate(
  conn: &mut RedisConn,
  store: &Store,
  parts: Vec<String>,
) -> Result<RotateOutcome, StoreError> {
  let tag = parts.first().cloned().unwrap_or_default();
  match tag.as_str() {
    "ROTATED" => {
      let (new_refresh, new_access) = take_pair(&parts)?;
      match barrier_or_recover(conn, store).await? {
        BarrierVerdict::Held => Ok(RotateOutcome::Rotated {
          new_refresh_hash: new_refresh,
          new_access_hash: new_access,
        }),
        BarrierVerdict::FailedAfterWrite => Ok(RotateOutcome::RotatedUnbarriered {
          new_refresh_hash: new_refresh,
          new_access_hash: new_access,
        }),
      }
    }
    "REPLAY" => {
      let (new_refresh, new_access) = take_pair(&parts)?;
      barrier_or_recover(conn, store).await?;
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
    "NOGRANT" => Ok(RotateOutcome::Absent),
    "MISMATCH" => Ok(RotateOutcome::Mismatch),
    _ => Err(StoreError::InvalidData),
  }
}

/// Verdict of the durability barrier for a token-bearing outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BarrierVerdict {
  /// The barrier held; the write is durable.
  Held,
  /// The barrier failed after this request id's write already applied: only
  /// the originating request may resolve to its own pair. Any other failure
  /// propagates (fail closed for every non-originating caller).
  FailedAfterWrite,
}

/// Run the durability barrier for a token-bearing outcome, distinguishing a
/// held barrier from a failure after this request id's write applied (the
/// caller resolves the originating request instead of locking out).
async fn barrier_or_recover(
  conn: &mut RedisConn,
  store: &Store,
) -> Result<BarrierVerdict, StoreError> {
  match durability_barrier(conn, store).await {
    Ok(()) => Ok(BarrierVerdict::Held),
    Err(StoreError::Durability) => Ok(BarrierVerdict::FailedAfterWrite),
    Err(other) => Err(other),
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
    barrier_or_recover(conn, store).await?;
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
  aud: &[String],
) -> Vec<(String, String)> {
  vec![
    ("client_id".to_owned(), client_id.to_owned()),
    ("grant_id".to_owned(), grant_id.to_owned()),
    ("scope".to_owned(), scope.to_owned()),
    ("subject".to_owned(), subject.to_owned()),
    ("cnf".to_owned(), cnf.to_owned()),
    ("aud".to_owned(), super::aud::encode(aud)),
  ]
}

/// Write one grant member (record + index entry, plus the JWT marker when
/// `jwt` is `Some`) in a single Lua script.
///
/// Previously this was three round-trips (`HSET`+`PEXPIRE`, `SADD`,
/// arm-or-extend the set TTL), so a revoke drain could interleave between the
/// record write and the `SADD`: with the record deleted but the `SADD` still
/// landing afterwards, the set kept an orphan member (and, symmetrically, a
/// record could sit briefly with no index entry for the drain to find). One
/// script closes that post-barrier late-`SADD` orphan window at the producer:
/// the record and its index entry become visible together.
///
/// The `jwt` flag threads the Todo 26 atomicity rule: only the barriered
/// fresh JWT path passes `Some` (record, `SADD`, and marker in one script);
/// the rotation pre-mint (`put_access_pending`/`put_refresh_pending`) and
/// every opaque write pass `None`, so they can never write a marker. A
/// `None` invocation still passes a dummy marker key (the record key: the
/// guarded script block never touches it).
///
/// Residual limits (by design, not by omission): the script is atomic but a
/// revoke drain is still `SMEMBERS`-then-delete, so a member `SADD`ed after
/// the drain's snapshot still survives that pass — the drain therefore loops
/// until the set reads empty and re-reads after the barrier (see
/// [`super::grants::revoke`]). A mint landing after the final pass leaves a
/// live record the cascade never saw; that survivor is contained, not
/// exploitable: introspection re-checks `users.disabled` (so a
/// disabled-subject orphan still introspects inactive) and refresh re-checks
/// current entitlements before minting.
async fn put_member(
  conn: &mut RedisConn,
  key: &str,
  pairs: &[(String, String)],
  ttl: Duration,
  set_key: &str,
  member: &str,
  jwt: Option<&JwtMarker<'_>>,
) -> Result<(), StoreError> {
  let dummy = key.to_owned();
  let marker_key = jwt.map(|marker| marker.key).unwrap_or(&dummy);
  let (flag, marker_ttl, grant_id, client_id, subject) = match jwt {
    Some(marker) => (
      "1",
      marker.ttl.as_millis() as u64,
      marker.grant_id,
      marker.client_id,
      marker.subject,
    ),
    None => ("0", 0, "", "", ""),
  };
  let mut invocation = SCRIPT_PUT_MEMBER.prepare_invoke();
  invocation
    .key(key)
    .key(set_key)
    .key(marker_key)
    .arg(ttl.as_millis() as u64)
    .arg(member)
    .arg(flag)
    .arg(marker_ttl)
    .arg(grant_id)
    .arg(client_id)
    .arg(subject);
  for (field, value) in pairs {
    invocation.arg(field).arg(value);
  }
  let _: i64 = invocation
    .invoke_async(conn)
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
    aud: super::aud::decode(map.get("aud"))?,
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
    aud: super::aud::decode(map.get("aud"))?,
  })
}

fn store_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store token write failed")),
  }
}

#[cfg(test)]
mod put_member_tests {
  use std::time::Duration;

  use super::{AccessRecord, RefreshRecord, get_access, get_refresh, put_access, put_refresh};
  use crate::{
    config::{DurabilityMode, RedisConfig, redis::RawRedisConfig},
    state::RedisConn,
    store::{Store, StoreError},
  };

  type TestResult = Result<(), TestError>;

  #[derive(Debug, thiserror::Error)]
  enum TestError {
    #[error("test support error: {0}")]
    Support(#[from] crate::test_support::TestError),
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  /// `put_member` lands the record and its grant-set entry in one Lua script,
  /// so a revoke drain can never observe one without the other: every stream
  /// below asserts the no-orphan invariant in both directions (each readable
  /// record is indexed, each indexed member resolves to a live record), the
  /// record and set TTLs are armed, and a shorter-lived second member never
  /// shortens the set TTL.
  #[tokio::test]
  async fn put_member_writes_record_and_index_atomically() -> TestResult {
    let manager = crate::test_support::redis_manager().await?;
    let (token_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
    let mut conn = RedisConn::Single(manager);
    let raw = RawRedisConfig {
      url: Some(crate::test_support::test_redis_url()),
      durability: Some(DurabilityMode::WaitAof),
      response_timeout_secs: 10,
      connect_timeout_secs: 5,
      token_key_prefix: Some(token_prefix),
      ratelimit_key_prefix: Some(ratelimit_prefix),
      ..Default::default()
    };
    let store = Store::from_config(&RedisConfig::from_raw(raw)?);

    let grant = "put-member-grant";
    let client_id = "put-member-client";
    let refresh_hash = "put-member-refresh";
    let access_hash = "put-member-access";
    put_refresh(
      &mut conn,
      &store,
      refresh_hash,
      &RefreshRecord {
        client_id: client_id.to_owned(),
        grant_id: grant.to_owned(),
        scope: "orders:read".to_owned(),
        subject: "user-1".to_owned(),
        cnf: String::new(),
        aud: Vec::new(),
      },
      Duration::from_secs(3600),
    )
    .await?;
    put_access(
      &mut conn,
      &store,
      access_hash,
      &AccessRecord {
        client_id: client_id.to_owned(),
        grant_id: grant.to_owned(),
        scope: "orders:read".to_owned(),
        subject: "user-1".to_owned(),
        cnf: String::new(),
        aud: Vec::new(),
      },
      Duration::from_secs(300),
    )
    .await?;

    // Direction 1: every readable record is indexed.
    if get_refresh(&mut conn, &store, refresh_hash)
      .await?
      .is_none()
    {
      return Err(TestError::Unexpected(
        "refresh record must be readable".to_owned(),
      ));
    }
    if get_access(&mut conn, &store, access_hash).await?.is_none() {
      return Err(TestError::Unexpected(
        "access record must be readable".to_owned(),
      ));
    }
    let set_key = store.grant_tokens_key(grant);
    for hash in [refresh_hash, access_hash] {
      let indexed: bool = redis::cmd("SISMEMBER")
        .arg(&set_key)
        .arg(hash)
        .query_async(&mut conn)
        .await?;
      if !indexed {
        return Err(TestError::Unexpected(format!(
          "{hash} must be indexed in the grant set"
        )));
      }
    }

    // Direction 2: every indexed member resolves to a live record (no orphan
    // index entries from a record write racing its own SADD).
    let members: Vec<String> = redis::cmd("SMEMBERS")
      .arg(&set_key)
      .query_async(&mut conn)
      .await?;
    if members.len() != 2 {
      return Err(TestError::Unexpected(format!(
        "grant set must hold exactly the pair, saw {}",
        members.len()
      )));
    }
    for member in &members {
      let live = get_refresh(&mut conn, &store, member).await?.is_some()
        || get_access(&mut conn, &store, member).await?.is_some();
      if !live {
        return Err(TestError::Unexpected(format!(
          "indexed {member} must resolve to a record"
        )));
      }
    }

    // TTLs preserved: the record and the set both carry an expiry.
    let record_pttl: i64 = redis::cmd("PTTL")
      .arg(store.refresh_key(refresh_hash))
      .query_async(&mut conn)
      .await?;
    let set_pttl: i64 = redis::cmd("PTTL")
      .arg(&set_key)
      .query_async(&mut conn)
      .await?;
    if record_pttl <= 0 {
      return Err(TestError::Unexpected(
        "refresh record must carry a TTL".to_owned(),
      ));
    }
    if set_pttl <= 0 {
      return Err(TestError::Unexpected(
        "grant set must carry a TTL".to_owned(),
      ));
    }
    // The 300 s access member must not have shortened the set TTL armed by the
    // 3600 s refresh member (arm-or-extend, never shorten).
    if set_pttl <= 1_000_000 {
      return Err(TestError::Unexpected(format!(
        "grant set TTL must track the longest-lived member, saw {set_pttl} ms"
      )));
    }
    Ok(())
  }
}

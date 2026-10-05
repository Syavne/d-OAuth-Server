//! Redis ephemeral store: codes, tokens, grants, sessions, PAR, device.
//!
//! All short-lived state lives here under hash-tagged keys (single-slot
//! atomicity), keyspace-separated from rate-limit counters. Rotation and
//! replay-marker writes are idempotent and durability-barriered.
//!
//! Key layout (every key below carries the `{state}` hash tag through the
//! configured token prefix, default `oauth:{state}:`, so every key touched by
//! one atomic Lua op shares a hash slot):
//!
//! - `oauth:{state}:code:<hash>` — single-use authorization codes.
//! - `oauth:{state}:access:<hash>` — access-token records.
//! - `oauth:{state}:refresh:<hash>` — refresh-token records and tombstones.
//! - `oauth:{state}:grant:<id>` — grant-chain records.
//! - `oauth:{state}:grant:<id>:tokens` — per-grant token-member sets.
//! - `oauth:{state}:session:<id>` — server-side login sessions.
//! - `oauth:{state}:par:<id>` — PAR `request_uri` records.
//! - `oauth:{state}:pending:<id>` — validated pending-auth JSON records.
//! - `oauth:{state}:device:<hash>` — device-code records.
//! - `oauth:{state}:user_code:<code-hash>` — user-code to device mapping.
//! - `oauth:{state}:dcr_iat:<hash>` — DCR initial-access-token records.
//! - `oauth:{state}:dpop_jti:<hash>` — DPoP `jti` replay markers.
//! - `oauth:{state}:client_assertion_jti:<hash>` — `private_key_jwt` replay markers.
//! - `oauth:{state}:rotation:<request-id>` — rotation idempotency mappings.
//! - `oauth:{rl}:ratelimit:<bucket-hash>` — rate-limit counters (own keyspace).
//!
//! Registration access tokens are NOT here: their hash lives only in Postgres
//! (`oauth_clients.registration_access_token_hash`) so client management
//! survives a Redis loss. Raw tokens are never keys: every `<hash>` above is
//! the hex/base64url form of a keyed hash (see [`crate::crypto::tokens`]).
//!
//! Durability: [`durability_barrier`] issues `WAIT` (replicated topologies) or
//! `WAITAOF` (single-node) as a SEPARATE command AFTER the Lua write returns
//! and BEFORE tokens are handed out — never inside a script or MULTI/EXEC,
//! where `WAIT`/`WAITAOF` do not block. A barrier below the required level is
//! [`StoreError::Durability`] (fail closed, `503`-mappable).
//!
//! Retries: only idempotent reads and `SET NX`/Lua compare-and-set are
//! retried, and only on [`ErrorClass::Transient`] errors (see
//! [`may_retry_op`]). Non-idempotent token operations are never blindly
//! replayed: on an indeterminate post-`EXEC` result the caller re-reads state
//! (mapping key, then the record) instead of re-issuing the write.

use std::{collections::HashMap, sync::LazyLock, time::Duration};

use redis::{ErrorKind, RedisError, Script, ServerErrorKind};
use sha2::{Digest as _, Sha256};

use crate::{
  config::{DurabilityMode, RedisConfig},
  state::RedisConn,
};

pub mod codes;
pub mod dcr;
pub mod device;
pub mod grants;
pub mod par;
pub mod pending;
pub mod ratelimit;
pub mod sessions;
pub mod tokens;

#[cfg(test)]
mod tests_store;

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

/// Fail-closed store failures for the Redis ephemeral state.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
  /// Redis was unreachable or a command failed.
  #[error("redis unavailable")]
  Redis(#[from] RedisError),
  /// A stored record did not parse (never carries secret material).
  #[error("stored record is malformed")]
  InvalidData,
  /// The post-write durability barrier was not met (fail closed, 503).
  #[error("durability barrier not met")]
  Durability,
  /// The presented credential does not match the stored record.
  #[error("credential does not match stored record")]
  Mismatch,
}

impl From<StoreError> for crate::error::AppError {
  /// Map a store failure to a client-safe error: transient Redis outages and
  /// unmet durability barriers render `503 temporarily_unavailable` (fail
  /// closed); everything else is masked as `server_error`.
  fn from(error: StoreError) -> Self {
    match error {
      StoreError::Durability => Self::temporarily_unavailable(),
      StoreError::Redis(ref inner) if classify_redis(inner) == ErrorClass::Transient => {
        Self::temporarily_unavailable()
      }
      other => Self::internal(other),
    }
  }
}

/// Whether a Redis error is worth retrying (idempotent ops only) or must fail
/// closed immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
  /// I/O, dropped connections, timeouts, `LOADING`/`TRYAGAIN`/`MASTERDOWN`/
  /// `CLUSTERDOWN`: retryable for idempotent reads and `SET NX`/Lua CAS only.
  Transient,
  /// `OOM` under noeviction, `READONLY`, auth failures, `CROSSSLOT`, type
  /// errors, and everything unknown: fail closed, never retry.
  Permanent,
}

/// Classify a Redis error as [`ErrorClass::Transient`] or
/// [`ErrorClass::Permanent`].
#[must_use]
pub fn classify_redis(error: &RedisError) -> ErrorClass {
  if error.is_timeout() || error.is_connection_dropped() || error.is_io_error() {
    return ErrorClass::Transient;
  }
  match error.kind() {
    ErrorKind::Io => ErrorClass::Transient,
    ErrorKind::Server(
      ServerErrorKind::BusyLoading
      | ServerErrorKind::TryAgain
      | ServerErrorKind::MasterDown
      | ServerErrorKind::ClusterDown
      | ServerErrorKind::Moved
      | ServerErrorKind::Ask,
    ) => ErrorClass::Transient,
    // `READONLY`, `CROSSSLOT`, auth/ACL, type errors and anything
    // unrecognized (non-exhaustive enum): fail closed.
    ErrorKind::Server(_) => ErrorClass::Permanent,
    ErrorKind::Extension => match error.code() {
      Some("LOADING") | Some("TRYAGAIN") | Some("MASTERDOWN") | Some("CLUSTERDOWN") => {
        ErrorClass::Transient
      }
      // `NOSCRIPT` self-heals inside `Script::invoke_async`; a surfaced one is
      // still safe to retry once behind an idempotent script.
      Some("NOSCRIPT") => ErrorClass::Transient,
      _ => ErrorClass::Permanent,
    },
    ErrorKind::ClusterConnectionNotFound
    | ErrorKind::MasterNameNotFoundBySentinel
    | ErrorKind::NoValidReplicasFoundBySentinel => ErrorClass::Transient,
    ErrorKind::Parse
    | ErrorKind::AuthenticationFailed
    | ErrorKind::UnexpectedReturnType
    | ErrorKind::InvalidClientConfig
    | ErrorKind::Client
    | ErrorKind::EmptySentinelList
    | ErrorKind::RESP3NotSupported => ErrorClass::Permanent,
    // `ErrorKind` is non-exhaustive: fail closed on anything unrecognized.
    _ => ErrorClass::Permanent,
  }
}

/// Which operations may be retried, and only on transient errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
  /// Plain reads (`GET`, `HGETALL`, `SMEMBERS`): safe to retry.
  IdempotentRead,
  /// `SET NX` and idempotent Lua compare-and-set (rotation, replay markers):
  /// safe to retry.
  ConditionalWrite,
  /// Destructive single-use consumes and `INCR` counters: NEVER retried; on an
  /// indeterminate result the caller re-reads instead of replaying.
  NonIdempotent,
}

/// Whether `error` may be retried for an operation of class `op`.
#[must_use]
pub fn may_retry_op(op: OpClass, error: &RedisError) -> bool {
  matches!(op, OpClass::IdempotentRead | OpClass::ConditionalWrite)
    && classify_redis(error) == ErrorClass::Transient
}

/// Run `$op` (an async block evaluated fresh per attempt) against `$conn`
/// with a bounded retry budget, retrying only transient errors.
///
/// A `macro_rules!` instead of a generic helper: the operation borrows
/// `&mut` connection state per attempt, which cannot escape an `FnMut`
/// closure body, and the inline expansion keeps every future transparently
/// `Send` for spawned tasks. Evaluates to `Result<_, redis::RedisError>`.
///
/// Callers must pass idempotent reads or `SET NX`/Lua compare-and-set only;
/// non-idempotent token operations must never reach this macro.
macro_rules! retry_op {
  ($conn:expr, $budget:expr, $op:expr) => {{
    let budget__: u32 = $budget;
    let mut attempt__: u32 = 0;
    loop {
      match ($op).await {
        Ok(value__) => break Ok::<_, redis::RedisError>(value__),
        Err(error__) => {
          if !matches!(
            $crate::store::classify_redis(&error__),
            $crate::store::ErrorClass::Transient
          ) || attempt__ >= budget__
          {
            break Err(error__);
          }
          attempt__ += 1;
          let backoff__ = 50_u64.saturating_mul(1_u64 << attempt__.min(4));
          tokio::time::sleep(std::time::Duration::from_millis(backoff__.min(500))).await;
        }
      }
    }
  }};
}

pub(crate) use retry_op;

// ---------------------------------------------------------------------------
// Store handle and key layout
// ---------------------------------------------------------------------------

/// Handle for the Redis ephemeral state: key layout plus the durability
/// contract selected from the topology.
#[derive(Debug, Clone)]
pub struct Store {
  token_prefix: String,
  ratelimit_prefix: String,
  durability: DurabilityMode,
  barrier_timeout: Duration,
  retry_budget: u32,
}

impl Store {
  /// Build a store handle from the validated Redis configuration.
  #[must_use]
  pub fn from_config(redis: &RedisConfig) -> Self {
    Self {
      token_prefix: redis.token_key_prefix.clone(),
      ratelimit_prefix: redis.ratelimit_key_prefix.clone(),
      durability: redis.durability,
      barrier_timeout: redis.response_timeout,
      retry_budget: redis.retry_budget,
    }
  }

  /// Build a store handle from explicit parts (tests and callers that already
  /// validated the prefixes).
  #[must_use]
  pub fn from_parts(
    token_prefix: String,
    ratelimit_prefix: String,
    durability: DurabilityMode,
  ) -> Self {
    Self {
      token_prefix,
      ratelimit_prefix,
      durability,
      barrier_timeout: Duration::from_secs(2),
      retry_budget: 6,
    }
  }

  /// The durability mode this store barriers on.
  #[must_use]
  pub fn durability(&self) -> DurabilityMode {
    self.durability
  }

  /// Retry budget for idempotent operations.
  #[must_use]
  pub fn retry_budget(&self) -> u32 {
    self.retry_budget
  }

  /// Assert the token and rate-limit keyspaces are separated and carry their
  /// cluster hash tags (`{state}` / `{rl}`), so counters can never evict
  /// tokens and multi-key Lua ops stay single-slot.
  pub fn assert_keyspace_separation(&self) -> Result<(), StoreError> {
    if self.token_prefix == self.ratelimit_prefix
      || !self.token_prefix.contains("{state}")
      || !self.ratelimit_prefix.contains("{rl}")
    {
      return Err(StoreError::InvalidData);
    }
    Ok(())
  }

  fn token_key(&self, kind: &str, id: &str) -> String {
    format!("{}{kind}:{id}", self.token_prefix)
  }

  /// Authorization-code record key for a code hash.
  #[must_use]
  pub fn code_key(&self, code_hash: &str) -> String {
    self.token_key("code", code_hash)
  }

  /// Access-token record key for a token hash.
  #[must_use]
  pub fn access_key(&self, token_hash: &str) -> String {
    self.token_key("access", token_hash)
  }

  /// Refresh-token record (or tombstone) key for a token hash.
  #[must_use]
  pub fn refresh_key(&self, token_hash: &str) -> String {
    self.token_key("refresh", token_hash)
  }

  /// Grant-chain record key.
  #[must_use]
  pub fn grant_key(&self, grant_id: &str) -> String {
    self.token_key("grant", grant_id)
  }

  /// Per-grant token-member set key (revocation index; no `KEYS` scans).
  #[must_use]
  pub fn grant_tokens_key(&self, grant_id: &str) -> String {
    format!("{}grant:{grant_id}:tokens", self.token_prefix)
  }

  /// Server-side session record key.
  #[must_use]
  pub fn session_key(&self, session_id: &str) -> String {
    self.token_key("session", session_id)
  }

  /// PAR `request_uri` record key.
  #[must_use]
  pub fn par_key(&self, request_id: &str) -> String {
    self.token_key("par", request_id)
  }

  /// Device-code record key for a device-code hash.
  #[must_use]
  pub fn device_key(&self, device_hash: &str) -> String {
    self.token_key("device", device_hash)
  }

  /// User-code to device-code mapping key (value holds the device hash).
  #[must_use]
  pub fn user_code_key(&self, user_code_hash: &str) -> String {
    self.token_key("user_code", user_code_hash)
  }

  /// DCR initial-access-token record key.
  #[must_use]
  pub fn dcr_iat_key(&self, token_hash: &str) -> String {
    self.token_key("dcr_iat", token_hash)
  }

  /// DPoP `jti` replay-marker key.
  #[must_use]
  pub fn dpop_jti_key(&self, jti_hash: &str) -> String {
    self.token_key("dpop_jti", jti_hash)
  }

  /// `private_key_jwt` (`client_assertion`) `jti` replay-marker key.
  #[must_use]
  pub fn client_assertion_jti_key(&self, jti_hash: &str) -> String {
    self.token_key("client_assertion_jti", jti_hash)
  }

  /// Rotation idempotency-mapping key for a deterministic `rotation_request_id`.
  #[must_use]
  pub fn rotation_map_key(&self, request_id: &str) -> String {
    self.token_key("rotation", request_id)
  }

  /// Failed-login counter key for a hashed account label (never a raw email).
  #[must_use]
  pub fn login_fail_key(&self, account_hash: &str) -> String {
    self.token_key("loginfail", account_hash)
  }

  /// TOTP used-code replay-marker key for a fingerprint hash (task 25).
  ///
  /// Genuine gap noted by the login task: the replay cache needs a
  /// single-slot key under the `{state}` prefix, like every other ephemeral
  /// record. Pure addition; no existing key layout changes.
  #[must_use]
  pub fn totp_replay_key(&self, fingerprint: &str) -> String {
    self.token_key("totp_replay", fingerprint)
  }

  /// Rate-limit counter key for a hashed bucket (own `{rl}` keyspace).
  #[must_use]
  pub fn ratelimit_key(&self, bucket_hash: &str) -> String {
    format!("{}ratelimit:{bucket_hash}", self.ratelimit_prefix)
  }

  /// Key prefixes used to rebuild member keys inside the grant-revoke script.
  #[must_use]
  pub(crate) fn refresh_key_prefix(&self) -> String {
    format!("{}refresh:", self.token_prefix)
  }

  /// Key prefixes used to rebuild member keys inside the grant-revoke script.
  #[must_use]
  pub(crate) fn access_key_prefix(&self) -> String {
    format!("{}access:", self.token_prefix)
  }
}

/// SHA-256 hex of `input` (key/bucket hashing; never a raw secret or token).
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
  let digest = Sha256::digest(input);
  let mut out = String::with_capacity(64);
  for byte in digest {
    out.push_str(&format!("{byte:02x}"));
  }
  out
}

/// HMAC-SHA256 with an RFC 2104 §2 key schedule (long peppers are hashed,
/// short peppers zero-padded), infallible by construction.
pub(crate) fn hmac_sha256(pepper: &[u8], message: &[u8]) -> [u8; 32] {
  use hmac::digest::{KeyInit, Mac as _};

  use sha2::digest::Key;
  let mut block = [0u8; 64];
  if pepper.len() > block.len() {
    let hashed = Sha256::digest(pepper);
    block[..hashed.len()].copy_from_slice(&hashed);
  } else {
    block[..pepper.len()].copy_from_slice(pepper);
  }
  let key: &Key<hmac::Hmac<Sha256>> = (&block).into();
  let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new(key);
  mac.update(message);
  let out = mac.finalize().into_bytes();
  let mut digest = [0u8; 32];
  digest.copy_from_slice(&out);
  digest
}

// ---------------------------------------------------------------------------
// Typed hash-keyed access
// ---------------------------------------------------------------------------

/// Write a record as a Redis hash plus TTL (idempotent rewrite; safe to retry
/// on transient errors via [`retry_op`]).
pub(crate) async fn hset_record(
  conn: &mut RedisConn,
  key: &str,
  pairs: &[(String, String)],
  ttl: Duration,
) -> Result<(), StoreError> {
  let mut pipe = redis::pipe();
  {
    let cmd = pipe.cmd("HSET").arg(key);
    for (field, value) in pairs {
      cmd.arg(field).arg(value);
    }
  }
  pipe
    .cmd("PEXPIRE")
    .arg(key)
    .arg(ttl.as_millis() as u64)
    .query_async::<()>(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

/// Read a record hash; `Ok(None)` when the key is absent.
pub(crate) async fn hget_record(
  conn: &mut RedisConn,
  key: &str,
) -> Result<Option<HashMap<String, String>>, StoreError> {
  let flat: Vec<String> = redis::cmd("HGETALL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  if flat.is_empty() {
    return Ok(None);
  }
  if !flat.len().is_multiple_of(2) {
    return Err(StoreError::InvalidData);
  }
  let mut map = HashMap::with_capacity(flat.len() / 2);
  let mut iter = flat.into_iter();
  while let (Some(field), Some(value)) = (iter.next(), iter.next()) {
    map.insert(field, value);
  }
  Ok(Some(map))
}

/// Parse an `HGETALL` flat array (as returned by the consume scripts) into a map.
pub(crate) fn flat_to_map(flat: Vec<String>) -> Result<HashMap<String, String>, StoreError> {
  if flat.is_empty() || !flat.len().is_multiple_of(2) {
    return Err(StoreError::InvalidData);
  }
  let mut map = HashMap::with_capacity(flat.len() / 2);
  let mut iter = flat.into_iter();
  while let (Some(field), Some(value)) = (iter.next(), iter.next()) {
    map.insert(field, value);
  }
  Ok(map)
}

// ---------------------------------------------------------------------------
// Lua registry (every multi-key op is single-slot via the `{state}` tag)
// ---------------------------------------------------------------------------

/// Single-use consume with `GETDEL` semantics: return the hash fields and
/// delete the key atomically, or `false` when absent.
pub(crate) static SCRIPT_CONSUME_HASH: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local data = redis.call('HGETALL', KEYS[1])
    if #data == 0 then
      return false
    end
    redis.call('DEL', KEYS[1])
    return data
    ",
  )
});

/// Refresh rotation compare-and-set.
///
/// KEYS: old refresh, new refresh, new access, grant token set, request map.
/// ARGV: expected client, new-refresh JSON, new-refresh TTL ms, new-access
/// JSON, new-access TTL ms, request id, grant id, new refresh member,
/// new access member, tombstone TTL ms, map TTL ms.
///
/// Returns `{TAG, ...}`: `ROTATED`, `REPLAY` (idempotent retry: same tokens),
/// `REUSE` (tombstoned: rotated-to member), `ABSENT`, or `MISMATCH`.
pub(crate) static SCRIPT_ROTATE_REFRESH: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local mapped = redis.call('GET', KEYS[5])
    if mapped then
      local parts = cjson.decode(mapped)
      return {'REPLAY', parts['refresh'], parts['access']}
    end
    local old = redis.call('HGETALL', KEYS[1])
    if #old == 0 then
      return {'ABSENT'}
    end
    local h = {}
    for i = 1, #old, 2 do
      h[old[i]] = old[i + 1]
    end
    if h['used'] == 'true' then
      return {'REUSE', h['rotated_to'] or ''}
    end
    if h['client_id'] ~= ARGV[1] then
      return {'MISMATCH'}
    end
    local new_refresh = cjson.decode(ARGV[2])
    local new_access = cjson.decode(ARGV[4])
    local rargs = {KEYS[2]}
    for k, v in pairs(new_refresh) do
      rargs[#rargs + 1] = k
      rargs[#rargs + 1] = v
    end
    redis.call('HSET', unpack(rargs))
    redis.call('PEXPIRE', KEYS[2], ARGV[3])
    local aargs = {KEYS[3]}
    for k, v in pairs(new_access) do
      aargs[#aargs + 1] = k
      aargs[#aargs + 1] = v
    end
    redis.call('HSET', unpack(aargs))
    redis.call('PEXPIRE', KEYS[3], ARGV[5])
    redis.call('SADD', KEYS[4], ARGV[8], ARGV[9])
    local pttl = redis.call('PTTL', KEYS[1])
    local tomb_ttl = tonumber(ARGV[10])
    if pttl > 0 and pttl < tomb_ttl then
      tomb_ttl = pttl
    end
    redis.call('HSET', KEYS[1], 'used', 'true', 'rotated_to', ARGV[8])
    redis.call('PEXPIRE', KEYS[1], tomb_ttl)
    local mapping = cjson.encode({refresh = ARGV[8], access = ARGV[9]})
    redis.call('SET', KEYS[5], mapping, 'PX', ARGV[11])
    return {'ROTATED', ARGV[8], ARGV[9]}
    ",
  )
});

/// Grant cascade revoke: delete every member token key plus the grant set and
/// record. Member keys are rebuilt from the key prefixes (same hash slot).
/// KEYS: grant token set, grant record. ARGV: refresh prefix, access prefix.
pub(crate) static SCRIPT_GRANT_REVOKE: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local members = redis.call('SMEMBERS', KEYS[1])
    local deleted = 0
    for _, member in ipairs(members) do
      deleted = deleted + redis.call('DEL', ARGV[1] .. member, ARGV[2] .. member)
    end
    redis.call('DEL', KEYS[1], KEYS[2])
    return deleted
    ",
  )
});

/// Fixed-window rate-limit counter: `INCR` plus `PEXPIRE`-on-first.
pub(crate) static SCRIPT_RATELIMIT_INCR: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then
      redis.call('PEXPIRE', KEYS[1], ARGV[1])
    end
    return count
    ",
  )
});

/// Decrement-on-use for DCR initial-access tokens (`uses` budget).
/// KEYS: iat record. Returns the record fields, or `false` when absent or
/// exhausted. The final use deletes the record.
pub(crate) static SCRIPT_CONSUME_IAT: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local data = redis.call('HGETALL', KEYS[1])
    if #data == 0 then
      return false
    end
    local remaining = nil
    for i = 1, #data, 2 do
      if data[i] == 'uses_remaining' then
        remaining = tonumber(data[i + 1])
      end
    end
    if remaining == nil or remaining <= 0 then
      return false
    end
    if remaining == 1 then
      redis.call('DEL', KEYS[1])
    else
      redis.call('HSET', KEYS[1], 'uses_remaining', remaining - 1)
    end
    return data
    ",
  )
});

// ---------------------------------------------------------------------------
// Durability barrier (separate command, after the write, before tokens out)
// ---------------------------------------------------------------------------

/// Apply the topology-selected durability barrier after a rotation/replay
/// write: `WAIT 1 <timeout>` where replicas exist, `WAITAOF 1 0 <timeout>` on
/// single-node, or an `appendfsync always` assertion for the fallback mode.
///
/// The server-side wait leaves 500 ms of headroom under the client response
/// timeout, so an expired barrier surfaces as [`StoreError::Durability`]
/// rather than an ambiguous client timeout. A barrier below the required
/// level returns [`StoreError::Durability`] (fail closed). This must never run
/// inside a Lua script or MULTI/EXEC.
pub async fn durability_barrier(conn: &mut RedisConn, store: &Store) -> Result<(), StoreError> {
  // Server-side wait, strictly inside the client response timeout.
  let server_wait_ms = store
    .barrier_timeout
    .as_millis()
    .saturating_sub(500)
    .max(500) as u64;
  match store.durability {
    DurabilityMode::Wait => {
      let acked: i64 = redis::cmd("WAIT")
        .arg(1)
        .arg(server_wait_ms)
        .query_async(conn)
        .await
        .map_err(StoreError::Redis)?;
      if acked >= 1 {
        Ok(())
      } else {
        Err(StoreError::Durability)
      }
    }
    DurabilityMode::WaitAof => {
      match redis::cmd("WAITAOF")
        .arg(1)
        .arg(0)
        .arg(server_wait_ms)
        .query_async::<Vec<i64>>(conn)
        .await
      {
        Ok(acked) => {
          if acked.first().is_some_and(|local| *local >= 1) {
            Ok(())
          } else {
            Err(StoreError::Durability)
          }
        }
        Err(error) => {
          // Pre-7.2 servers lack `WAITAOF`: accept only the documented
          // fallback (instance-wide `appendfsync always`), else fail closed.
          if is_unknown_command(&error) && appendfsync_is_always(conn).await? {
            Ok(())
          } else {
            Err(StoreError::Redis(error))
          }
        }
      }
    }
    DurabilityMode::AppendFsyncAlways => {
      if appendfsync_is_always(conn).await? {
        Ok(())
      } else {
        Err(StoreError::Durability)
      }
    }
  }
}

/// Whether a Redis error reports an unknown command (pre-7.2 `WAITAOF`).
fn is_unknown_command(error: &RedisError) -> bool {
  error.code() == Some("ERR")
    && error
      .detail()
      .is_some_and(|detail| detail.contains("unknown command"))
}

/// Whether the server runs instance-wide `appendfsync always`.
async fn appendfsync_is_always(conn: &mut RedisConn) -> Result<bool, StoreError> {
  let pair: Vec<String> = redis::cmd("CONFIG")
    .arg("GET")
    .arg("appendfsync")
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(pair.into_iter().nth(1).as_deref() == Some("always"))
}

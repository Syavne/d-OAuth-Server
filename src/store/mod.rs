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
//! - `oauth:{state}:access:<hash>:act` — token-exchange `act` claim sidecar.
//! - `oauth:{state}:refresh:<hash>` — refresh-token records and tombstones.
//! - `oauth:{state}:grant:<id>` — grant-chain records.
//! - `oauth:{state}:grant:<id>:tokens` — per-grant token-member sets.
//! - `oauth:{state}:session:<id>` — server-side login sessions.
//! - `oauth:{state}:session:<id>:meta` — session sidecar: CSRF secret, bound
//!   `request_id`, and post-logout client/URI (see `purge_subject`).
//! - `oauth:{state}:par:<id>` — PAR `request_uri` records.
//! - `oauth:{state}:pending:<id>` — validated pending-auth JSON records.
//! - `oauth:{state}:device:<hash>` — device-code records.
//! - `oauth:{state}:device:<hash>:cnf` — device sender-binding sidecar.
//! - `oauth:{state}:device:<hash>:poll` — device poll-throttle marker.
//! - `oauth:{state}:user_code:<code-hash>` — user-code to device mapping.
//! - `oauth:{state}:dcr_iat:<hash>` — DCR initial-access-token records.
//! - `oauth:{state}:dpop_jti:<hash>` — DPoP `jti` replay markers.
//! - `oauth:{state}:client_assertion_jti:<hash>` — `private_key_jwt` replay markers.
//! - `oauth:{state}:rotation:<request-id>` — rotation idempotency mappings.
//! - `oauth:{state}:loginfail:<sha256>` — per-account failed-login counter.
//! - `oauth:{state}:loginfail:ip:<sha256>:<sha256>` — composite per-IP counter.
//! - `oauth:{state}:loginfail:unknown:<sha256>` — unknown-label IP bucket.
//! - `oauth:{state}:totp_replay:<fingerprint>` — TOTP used-code replay marker.
//! - `oauth:{state}:jwt:<jti-hash>` — JWT access-token kill markers (allowlist;
//!   a signed token is valid only while its marker is live).
//! - `oauth:{state}:cimd:<sha256>` — cached client-id-metadata document.
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
  /// Map a store failure to a client-safe error: genuine Redis infrastructure
  /// failures (transient timeouts/connections, `OOM`, `READONLY`,
  /// `CROSSSLOT`, auth, and connection-type errors) and unmet durability
  /// barriers render `503 temporarily_unavailable` (fail closed);
  /// programming-error classes (`Parse`, `UnexpectedReturnType`, `Client`,
  /// `WRONGTYPE` type errors surfaced as `Extension` or `Server`, and generic
  /// Lua-runtime `ERR`/`EXECABORT` server failures) are
  /// masked as `server_error` (500) so 500-alerts still fire on real bugs.
  /// Genuinely internal bugs (`InvalidData`, `Mismatch`) are likewise masked
  /// as `server_error`.
  fn from(error: StoreError) -> Self {
    match error {
      StoreError::Durability => Self::temporarily_unavailable(),
      StoreError::Redis(inner) if is_infra_redis_error(&inner) => Self::temporarily_unavailable(),
      StoreError::Redis(inner) => Self::internal(inner),
      other => Self::internal(other),
    }
  }
}

/// Whether a Redis error is genuine infrastructure (503) rather than a
/// programming error (500): transient errors plus `OOM`/`READONLY`/
/// `CROSSSLOT`/auth/connection-type errors fail closed, while `Parse`,
/// `UnexpectedReturnType`, `Client`, `WRONGTYPE` type errors, and generic
/// Lua-runtime `ERR`/`EXECABORT` server failures stay visible as masked
/// `server_error`.
fn is_infra_redis_error(error: &RedisError) -> bool {
  if is_wrongtype(error) {
    return false;
  }
  // Generic Lua/script-runtime failures (`ERR` class, `EXECABORT`) are bugs
  // in the script or its arguments, not sick infrastructure: report them as
  // masked `server_error` (500) so 500-alerts fire. Transient kinds,
  // `NOSCRIPT` (self-healed), `OOM`/`READONLY`/`CROSSSLOT`, auth, and
  // connection errors keep their 503 fail-closed mapping below.
  if matches!(
    error.kind(),
    ErrorKind::Server(ServerErrorKind::ResponseError | ServerErrorKind::ExecAbort)
  ) {
    return false;
  }
  !matches!(
    error.kind(),
    ErrorKind::Parse | ErrorKind::UnexpectedReturnType | ErrorKind::Client
  )
}

/// Whether a Redis error is a `WRONGTYPE` type error: an `Extension` with code
/// `WRONGTYPE`, or any server error whose code or detail carries it (the
/// `WRONGTYPE ... wrong kind of value` detail on a generic `ERR`).
fn is_wrongtype(error: &RedisError) -> bool {
  if error
    .code()
    .is_some_and(|code| code.eq_ignore_ascii_case("WRONGTYPE"))
  {
    return true;
  }
  error.detail().is_some_and(|detail| {
    let lower = detail.to_ascii_lowercase();
    lower.contains("wrongtype") || lower.contains("wrong kind")
  })
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

  /// Composite failed-login counter key for one source IP and one account.
  ///
  /// Both halves are hashes (never a raw IP or email). The `ip:` infix keeps
  /// these keys disjoint from the per-account `loginfail:<hash>` keys so an
  /// admin sweep can match `loginfail:ip:*:<account-hash>`.
  #[must_use]
  pub fn login_fail_ip_key(&self, ip_hash: &str, account_hash: &str) -> String {
    format!("{}ip:{ip_hash}:{account_hash}", self.login_fail_prefix())
  }

  /// Unknown-label failed-login bucket key for one source IP (never a label).
  ///
  /// Attempts for absent accounts share this single per-IP bucket instead of
  /// minting one key per probed label, so label enumeration cannot spray the
  /// keyspace.
  #[must_use]
  pub fn login_fail_unknown_key(&self, ip_hash: &str) -> String {
    format!("{}unknown:{ip_hash}", self.login_fail_prefix())
  }

  /// Key prefix covering every failed-login counter (account, composite, and
  /// unknown buckets).
  #[must_use]
  pub(crate) fn login_fail_prefix(&self) -> String {
    format!("{}loginfail:", self.token_prefix)
  }

  /// Key prefix covering the composite per-IP counters.
  #[must_use]
  pub(crate) fn login_fail_ip_prefix(&self) -> String {
    format!("{}ip:", self.login_fail_prefix())
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

  /// JWT access-token kill-marker key for a `jti` hash (RFC 9068 allowlist).
  ///
  /// A signed access token is valid only while this hash exists, so revoke and
  /// `user disable` stay effective for the AS path. The marker carries exactly
  /// `grant_id`, `client_id`, and `subject` (the raw email/user-id string, so
  /// the [`crate::protocol::purge`] `subject` decoder matches it; empty for
  /// client-credentials tokens), and shares the access-token TTL.
  #[must_use]
  pub fn jwt_marker_key(&self, jti_hash: &str) -> String {
    self.token_key("jwt", jti_hash)
  }

  /// CIMD client-id-metadata-document cache key for a URL hash.
  ///
  /// Shares the `{state}` keyspace (never `{rl}`), so it stays single-slot
  /// with the rest of token state.
  #[must_use]
  pub fn cimd_cache_key(&self, url_hash: &str) -> String {
    self.token_key("cimd", url_hash)
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

  /// Key prefix for server-side login session records (`session:<id>`).
  #[must_use]
  pub(crate) fn session_key_prefix(&self) -> String {
    format!("{}session:", self.token_prefix)
  }

  /// Key prefix for authorization-code records (`code:<hash>`).
  #[must_use]
  pub(crate) fn code_key_prefix(&self) -> String {
    format!("{}code:", self.token_prefix)
  }

  /// Key prefix for device-code records (`device:<hash>`).
  #[must_use]
  pub(crate) fn device_key_prefix(&self) -> String {
    format!("{}device:", self.token_prefix)
  }

  /// Key prefix for user-code to device-hash mappings (`user_code:<hash>`).
  #[must_use]
  pub(crate) fn user_code_key_prefix(&self) -> String {
    format!("{}user_code:", self.token_prefix)
  }

  /// Key prefix for grant-chain records (`grant:<id>`).
  #[must_use]
  pub(crate) fn grant_key_prefix(&self) -> String {
    format!("{}grant:", self.token_prefix)
  }

  /// Key prefix for JWT allowlist marker hashes (`jwt:<jti-hash>`).
  ///
  /// The cascade script receives this as its third `ARGV` so a grant revoke
  /// deletes the marker alongside the member record keys, in the same script.
  #[must_use]
  pub(crate) fn jwt_key_prefix(&self) -> String {
    format!("{}jwt:", self.token_prefix)
  }
}

/// Audience codec: a record's `aud` list is stored as a JSON array string so a
/// URI that itself contains a comma can never collide with a delimiter join.
///
/// A record written by a replica that predates audiences carries no `aud`
/// field; [`decode`] reads that as an empty list (rolling-deploy safe) instead
/// of failing the record closed. A present-but-malformed field still fails
/// closed.
pub(crate) mod aud {
  use serde::{Deserialize, Deserializer, Serializer};

  use super::StoreError;

  /// Encode an audience list as a JSON array string.
  #[must_use]
  pub(crate) fn encode(aud: &[String]) -> String {
    serde_json::to_string(aud).unwrap_or_else(|_| "[]".to_owned())
  }

  /// Decode an optional stored `aud` field; absent or empty reads as `[]`.
  ///
  /// # Errors
  ///
  /// [`StoreError::InvalidData`] when the field is present but not a JSON
  /// string array.
  pub(crate) fn decode(raw: Option<&String>) -> Result<Vec<String>, StoreError> {
    match raw {
      None => Ok(Vec::new()),
      Some(value) if value.is_empty() => Ok(Vec::new()),
      Some(value) => serde_json::from_str(value).map_err(|_| StoreError::InvalidData),
    }
  }

  /// `serde(serialize_with)`: emit the string form so the rotation script's
  /// `cjson.decode` receives a string value, not a Lua table.
  pub(crate) fn serialize<S, T>(aud: &T, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
    T: AsRef<[String]> + ?Sized,
  {
    serializer.serialize_str(&encode(aud.as_ref()))
  }

  /// `serde(deserialize_with)`: read the string form, absent or empty → `[]`.
  pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw.as_deref() {
      None | Some("") => Ok(Vec::new()),
      Some(value) => serde_json::from_str(value).map_err(serde::de::Error::custom),
    }
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

/// Write a record as one atomic `HSET` + `PEXPIRE` script (idempotent
/// rewrite; safe to retry on transient errors via [`retry_op`]). The fields
/// and the expiry land together, so no crash can leave an immortal key.
pub(crate) async fn hset_record(
  conn: &mut RedisConn,
  key: &str,
  pairs: &[(String, String)],
  ttl: Duration,
) -> Result<(), StoreError> {
  // A field-less `HSET` is a Redis arity error; with nothing to write, the
  // TTL touch alone remains (a no-op on a missing key, a refresh otherwise).
  if pairs.is_empty() {
    let _: () = redis::cmd("PEXPIRE")
      .arg(key)
      .arg(ttl.as_millis() as u64)
      .query_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    return Ok(());
  }
  let mut invocation = HSET_TTL.prepare_invoke();
  invocation.key(key).arg(ttl.as_millis() as u64);
  for (field, value) in pairs {
    invocation.arg(field).arg(value);
  }
  let _: i64 = invocation
    .invoke_async(conn)
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

/// Atomic record write: `HSET` the fields, then `PEXPIRE` the key, before the
/// script returns — the record can never be observed (or survive a crash)
/// without its TTL.
///
/// KEYS: record. ARGV: TTL ms, then the flattened field/value pairs (never
/// empty: [`hset_record`] guards that case).
pub(crate) static HSET_TTL: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    redis.call('HSET', KEYS[1], unpack(ARGV, 2))
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
    return 1
    ",
  )
});

/// Atomic grant-member write: `HSET` the record fields, `PEXPIRE` the
/// record, `SADD` the member into the grant set, then arm-or-extend the set
/// TTL (never shorten), before the script returns. When the JWT flag is set,
/// the `jwt:<jti-hash>` allowlist marker hash (`grant_id`/`client_id`/
/// `subject`, TTL = access TTL) lands in the SAME script, after the `SADD`,
/// so a marker can never exist without its membership and a late `SADD` can
/// never follow a committed marker (marker-after-`SADD` is forbidden: the
/// post-barrier drain re-read in `grants::revoke` catches a late `SADD` but
/// not a late marker write).
///
/// KEYS: record, grant token set, marker key (a same-slot dummy the caller
/// passes when the flag is clear; the script never touches it then). ARGV:
/// record TTL ms, member, JWT flag (`1` writes the marker), marker TTL ms,
/// marker `grant_id`, marker `client_id`, marker `subject`, then the
/// flattened record field/value pairs. The record, its index entry, and (for
/// JWT) its marker land together, so a revoke drain cannot interleave
/// between the record write and the index write and leave an orphan in
/// either direction.
///
/// Only the barriered fresh JWT path sets the flag
/// ([`tokens::put_access_jwt`]); the rotation pre-mint pair
/// (`put_access_pending`/`put_refresh_pending`) always passes the flag
/// clear with a dummy marker key, so a pre-mint can never write a live
/// marker for a pair a later REUSE/REPLAY/ABSENT/MISMATCH outcome discards.
pub(crate) static SCRIPT_PUT_MEMBER: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    if #ARGV > 7 then
      redis.call('HSET', KEYS[1], unpack(ARGV, 8))
      redis.call('PEXPIRE', KEYS[1], ARGV[1])
    end
    redis.call('SADD', KEYS[2], ARGV[2])
    local set_pttl = redis.call('PTTL', KEYS[2])
    if set_pttl < 0 or set_pttl < tonumber(ARGV[1]) then
      redis.call('PEXPIRE', KEYS[2], ARGV[1])
    end
    if ARGV[3] == '1' then
      redis.call('HSET', KEYS[3], 'grant_id', ARGV[5], 'client_id', ARGV[6], 'subject', ARGV[7])
      redis.call('PEXPIRE', KEYS[3], ARGV[4])
    end
    return 1
    ",
  )
});

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

/// Device verdict conditional write (RFC 8628 user decision).
///
/// KEYS: device record. ARGV: status, subject, grant id. Sets the verdict
/// fields only when the record still exists, so a verdict racing the atomic
/// consume can never resurrect a zombie record (no lost update). The key TTL
/// is left untouched. Returns 1 when applied, 0 when the record is gone.
pub(crate) static SCRIPT_DEVICE_DECIDE: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    if redis.call('EXISTS', KEYS[1]) == 0 then
      return 0
    end
    redis.call('HSET', KEYS[1], 'status', ARGV[1], 'subject', ARGV[2], 'grant_id', ARGV[3])
    return 1
    ",
  )
});

/// Device poll-interval compare-and-set (RFC 8628 §3.5 `slow_down`).
///
/// KEYS: poll sidecar. ARGV: now (Unix seconds), interval (seconds), TTL ms.
/// Reads the last attempt, compares, and stamps this attempt in one step, so
/// concurrent polls cannot both pass the gate. The stamp advances on every
/// path, so fast polls keep backing off instead of racing the window edge.
/// Returns 0 when this attempt is allowed, the whole seconds to wait when it
/// is too fast, or -1 when the stored marker is corrupt.
pub(crate) static SCRIPT_DEVICE_POLL_CAS: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local last = redis.call('GET', KEYS[1])
    if not last then
      redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
      return 0
    end
    local last_secs = tonumber(last)
    if not last_secs then
      return -1
    end
    local elapsed = tonumber(ARGV[1]) - last_secs
    if elapsed < 0 then
      elapsed = 0
    end
    local interval_secs = tonumber(ARGV[2])
    if elapsed < interval_secs then
      redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
      local wait = interval_secs - elapsed
      if wait < 1 then
        wait = 1
      end
      return wait
    end
    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
    return 0
    ",
  )
});

/// Refresh rotation compare-and-set.
///
/// KEYS: old refresh, new refresh, new access, grant token set, request map,
/// grant record, JWT marker key (a same-slot dummy when the flag is clear;
/// the script never touches it then). ARGV: expected client, new-refresh
/// JSON, new-refresh TTL ms, new-access JSON, new-access TTL ms, request id,
/// grant id, new refresh member, new access member, tombstone TTL ms, map
/// TTL ms, JWT flag (`1` writes the marker), marker TTL ms, marker subject.
///
/// When the JWT flag is set, the `jwt:<jti-hash>` allowlist marker hash
/// (`grant_id` from ARGV[7], `client_id` from ARGV[1], `subject` from
/// ARGV[14], TTL from ARGV[13]) lands in the SAME script as the `SADD`, so
/// rotation commits marker and membership atomically and a late marker can
/// never follow a committed membership. The flag is clear for opaque
/// rotations, whose behavior is unchanged.
///
/// Returns `{TAG, ...}`: `ROTATED`, `REPLAY` (idempotent retry: same tokens),
/// `REUSE` (tombstoned: rotated-to member), `NOGRANT` (grant record gone: a
/// mint racing a cascade is fenced before writing, fail closed with no
/// cascade), `ABSENT`, or `MISMATCH`.
///
/// Precedence is intentional: the idempotency-map `REPLAY` check runs before
/// the `NOGRANT` grant-record fence, so a retried request whose grant was
/// revoked mid-cascade still resolves to its already-minted pair instead of
/// locking out. `REPLAY` mints nothing new — the re-resolved hashes name
/// records the cascade already deleted, so the service layer safely discards
/// them — and only map-miss rotations reach the fence, which writes nothing,
/// indexes nothing, and cascades nothing.
pub(crate) static SCRIPT_ROTATE_REFRESH: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local mapped = redis.call('GET', KEYS[5])
    if mapped then
      local parts = cjson.decode(mapped)
      return {'REPLAY', parts['refresh'], parts['access']}
    end
    if redis.call('EXISTS', KEYS[6]) == 0 then
      return {'NOGRANT'}
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
    local set_pttl = redis.call('PTTL', KEYS[4])
    if set_pttl < 0 or set_pttl < tonumber(ARGV[3]) then
      redis.call('PEXPIRE', KEYS[4], ARGV[3])
    end
    if ARGV[12] == '1' then
      redis.call('HSET', KEYS[7], 'grant_id', ARGV[7], 'client_id', ARGV[1], 'subject', ARGV[14])
      redis.call('PEXPIRE', KEYS[7], ARGV[13])
    end
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

/// Grant cascade revoke: delete every member token key, every JWT allowlist
/// marker, plus the grant set and record. Member keys are rebuilt from the key
/// prefixes (same hash slot). KEYS: grant token set, grant record. ARGV:
/// refresh prefix, access prefix, jwt marker prefix.
///
/// A JWT member is `jwt:<jti-hash>`: `ARGV[2] .. member` already deletes its
/// `access:jwt:<jti-hash>` record, while the marker hash is
/// `<jwt-prefix><jti-hash>` (the member minus its `jwt:` tag). The script
/// deletes `ARGV[3] .. member` verbatim (a no-op guard key when the member is
/// a JWT member) and, for `jwt:`-tagged members, the stripped marker key, so
/// the marker can never survive the cascade that removed its membership.
pub(crate) static SCRIPT_GRANT_REVOKE: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    local members = redis.call('SMEMBERS', KEYS[1])
    local deleted = 0
    for _, member in ipairs(members) do
      deleted = deleted + redis.call('DEL', ARGV[1] .. member, ARGV[2] .. member, ARGV[3] .. member)
      if string.sub(member, 1, 4) == 'jwt:' then
        deleted = deleted + redis.call('DEL', ARGV[3] .. string.sub(member, 5))
      end
    end
    redis.call('DEL', KEYS[1], KEYS[2])
    return deleted
    ",
  )
});

/// Atomic orphan cleanup for a discarded JWT rotation pre-mint.
///
/// KEYS: access record, grant token set (or a same-slot dummy when there is
/// no grant id), allowlist marker. ARGV: member, grant id (empty means the
/// `SREM` is skipped). One command so a discarded pre-mint can never leave a
/// live marker next to a surviving record/member.
pub(crate) static SCRIPT_DISCARD_ACCESS_JWT: LazyLock<Script> = LazyLock::new(|| {
  Script::new(
    r"
    redis.call('DEL', KEYS[1])
    if ARGV[2] ~= '' then
      redis.call('SREM', KEYS[2], ARGV[1])
    end
    redis.call('DEL', KEYS[3])
    return 1
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

//! Pending authorization requests (post-validation, pre-consent).
//!
//! After `/authorize` validates a request (task 23) the normalized parameters
//! are stashed here under an opaque 256-bit `request_id` with a short TTL. The
//! request NEVER travels in a cookie or the query string: only the opaque,
//! random id does, and it is bound to the login session so a post-login
//! redirect can only reach the recorded `redirect_uri`.
//!
//! The record is stored as a JSON hash field under a `{state}`-hash-tagged key
//! (`oauth:{state}:pending:<request_id>`), so it stays single-slot. [`consume`]
//! uses the shared atomic `GETDEL`-style Lua helper: it is destructive and
//! delete-on-read, so a request can never be replayed after use, and an
//! unknown/expired/already-used id is [`PendingError::Unknown`] (mapped to
//! `invalid_request`).
//!
//! [`get`] is the non-destructive read used by login/consent to display the
//! client and scope without spending the request; only the terminal code
//! issuance consumes it.

use std::{collections::HashMap, time::Duration};

use redis::RedisError;
use serde::{Deserialize, Serialize};

use super::{
  SCRIPT_CONSUME_HASH, Store, StoreError, flat_to_map, hget_record, hset_record, retry_op,
};
use crate::{crypto::tokens::mint_token, error::AppError, state::RedisConn};

/// Hash field carrying the JSON-serialized [`PendingAuth`] record.
const RECORD_FIELD: &str = "record";

/// The normalized authorization request stashed between validation and consent.
///
/// Only values that survived validation are present: the exact registered
/// `redirect_uri`, the granted `scope`, the S256 `code_challenge`, and the
/// sender-constraint inputs. `state`, `dpop_jkt`, and `iss` are optional
/// protocol members and stay `None` when the request omitted them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAuth {
  /// Client the request is bound to (exact match at code issuance).
  pub client_id: String,
  /// Registered redirect URI the request is bound to.
  pub redirect_uri: String,
  /// Space-joined requested scope (intersected at consent).
  pub scope: String,
  /// PKCE `code_challenge` (S256 only).
  pub code_challenge: String,
  /// Opaque `state` to echo on the final redirect, when supplied.
  pub state: Option<String>,
  /// DPoP JWK thumbprint the request must be bound to, when supplied.
  pub dpop_jkt: Option<String>,
  /// Issuer identifier (RFC 9207 `iss`), always present.
  pub iss: String,
  /// The client's single registered post-logout return URI, when it has one.
  /// Recorded at validation time so a later logout can return the browser to
  /// the client without accepting any redirect target from the request.
  pub post_logout_uri: Option<String>,
}

impl PendingAuth {
  /// Parse the JSON hash field back into a record.
  fn from_fields(fields: &HashMap<String, String>) -> Result<Self, StoreError> {
    let json = fields.get(RECORD_FIELD).ok_or(StoreError::InvalidData)?;
    serde_json::from_str(json).map_err(|_| StoreError::InvalidData)
  }
}

/// Why a pending authorization request could not be resolved.
///
/// [`Unknown`](PendingError::Unknown) collapses the three indistinguishable
/// failure modes — never stored, expired, and already consumed — into one
/// client-safe `invalid_request`, so replay attempts cannot be told apart from
/// a stale id.
#[derive(Debug, thiserror::Error)]
pub enum PendingError {
  /// The request id is unknown, expired, or already consumed.
  #[error("the pending authorization request is unknown, expired, or already used")]
  Unknown,
  /// The backing store failed (fail closed).
  #[error(transparent)]
  Store(#[from] StoreError),
}

impl From<PendingError> for AppError {
  /// Map a missing/replayed request to `invalid_request`; store failures keep
  /// their fail-closed mapping.
  fn from(error: PendingError) -> Self {
    match error {
      PendingError::Unknown => {
        Self::invalid_request("the authorization request is unknown or has expired")
      }
      PendingError::Store(inner) => inner.into(),
    }
  }
}

/// The hash-tagged key holding one pending request (single-slot `{state}`).
fn pending_key(store: &Store, request_id: &str) -> String {
  store.token_key("pending", request_id)
}

/// Mint an opaque 256-bit base64url request id.
///
/// The id is the ONLY thing that leaves the server for this state; it carries
/// no request material. Callers store it in the login session (never in a
/// cookie or the query string).
///
/// # Errors
///
/// Returns [`crate::crypto::tokens::TokenError::UnavailableRandomness`] when
/// the OS RNG fails (fail closed).
pub fn new_request_id() -> Result<String, crate::crypto::tokens::TokenError> {
  mint_token()
}

/// Stash a normalized request under `request_id` with a short TTL.
///
/// Idempotent rewrite of a fresh id (safe to retry on transient Redis errors).
/// The JSON record is the only stored value; no secret is keyed here.
///
/// # Errors
///
/// Returns [`StoreError::Redis`] on transient/permanent Redis failure and
/// [`StoreError::InvalidData`] if the record cannot be serialized.
pub async fn put(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
  request: &PendingAuth,
  ttl: Duration,
) -> Result<(), StoreError> {
  let key = pending_key(store, request_id);
  let json = serde_json::to_string(request).map_err(|_| StoreError::InvalidData)?;
  let pairs = [(RECORD_FIELD.to_owned(), json)];
  retry_op!(conn, store.retry_budget(), async {
    hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(into_redis)
  })
  .map_err(StoreError::Redis)
}

/// Read a pending request WITHOUT consuming it; `Ok(None)` when absent/expired.
///
/// Used by login/consent to render the bound client and scope. The request is
/// only spent by [`consume`].
///
/// # Errors
///
/// Returns [`StoreError::Redis`] on Redis failure and
/// [`StoreError::InvalidData`] if the stored record is malformed.
pub async fn get(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
) -> Result<Option<PendingAuth>, StoreError> {
  let key = pending_key(store, request_id);
  let budget = store.retry_budget();
  let fields = retry_op!(conn, budget, async {
    hget_record(conn, &key).await.map_err(into_redis)
  })
  .map_err(StoreError::Redis)?;
  fields.as_ref().map(PendingAuth::from_fields).transpose()
}

/// Atomically consume a pending request, exactly once.
///
/// The shared `HGETALL`+`DEL` Lua helper runs as one command: the first caller
/// observes the record and deletes the key; every later caller observes
/// [`PendingError::Unknown`]. A request can therefore never be replayed after
/// use. On an indeterminate transport result the key is re-read (never
/// replayed): a surviving key means the request is still spendable and the
/// store error is surfaced; an absent key means it was consumed.
///
/// # Errors
///
/// Returns [`PendingError::Unknown`] for an unknown, expired, or already-used
/// id, and [`PendingError::Store`] for a Redis failure or malformed record.
pub async fn consume(
  conn: &mut RedisConn,
  store: &Store,
  request_id: &str,
) -> Result<PendingAuth, PendingError> {
  let key = pending_key(store, request_id);
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
        flat.push(redis_string(item)?);
      }
      PendingAuth::from_fields(&flat_to_map(flat)?).map_err(PendingError::Store)
    }
    // `false`/nil reply: the key was absent, so nothing to spend.
    Ok(_) => Err(PendingError::Unknown),
    Err(error) => {
      // Never replay a destructive consume: re-read instead.
      if !matches!(error, StoreError::Redis(_)) {
        return Err(PendingError::Store(error));
      }
      let present: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(conn)
        .await
        .map_err(|inner| PendingError::Store(StoreError::Redis(inner)))?;
      if present {
        Err(PendingError::Store(error))
      } else {
        Err(PendingError::Unknown)
      }
    }
  }
}

/// Decode one Lua array element as a UTF-8 string.
fn redis_string(value: redis::Value) -> Result<String, PendingError> {
  match value {
    redis::Value::BulkString(bytes) => {
      String::from_utf8(bytes).map_err(|_| PendingError::Store(StoreError::InvalidData))
    }
    redis::Value::SimpleString(text) => Ok(text),
    _ => Err(PendingError::Store(StoreError::InvalidData)),
  }
}

/// Convert a store error into a Redis error for the retry macro.
fn into_redis(error: StoreError) -> RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => RedisError::from((redis::ErrorKind::Client, "store pending write failed")),
  }
}

#[cfg(test)]
mod tests {
  use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
  };

  use axum::http::StatusCode;
  use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
  };

  use super::{PendingAuth, PendingError, consume, get, new_request_id, pending_key, put};
  use crate::{
    config::{ConfigError, DurabilityMode, RedisConfig, redis::RawRedisConfig},
    error::{AppError, OAuthErrorCode},
    state::RedisConn,
    store::{Store, StoreError},
    test_guard::ContainerGuard,
  };

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult = Result<(), TestError>;

  /// Errors raised by the pending-auth test scaffolding itself.
  #[derive(Debug, thiserror::Error)]
  enum TestError {
    /// A testcontainers operation failed.
    #[error("container error: {0}")]
    Containers(#[from] testcontainers::TestcontainersError),
    /// The Redis configuration was rejected.
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    /// A Redis command failed.
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    /// A store operation failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// A pending-auth consume failed.
    #[error("pending error: {0}")]
    Pending(#[from] PendingError),
    /// The OS RNG failed while minting a request id.
    #[error("token error: {0}")]
    Token(#[from] crate::crypto::tokens::TokenError),
    /// A test assertion observed an unexpected value.
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  static TEST_NONCE: AtomicU64 = AtomicU64::new(100_000);

  fn unique(label: &str) -> String {
    let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
    format!("pending-auth-{n}-{label}")
  }

  /// A representative validated request with every optional field supplied.
  fn sample_record() -> PendingAuth {
    PendingAuth {
      client_id: "client-abc".to_owned(),
      redirect_uri: "https://client.example.test/cb".to_owned(),
      scope: "orders:read orders:write".to_owned(),
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
      state: Some("state-xyz".to_owned()),
      dpop_jkt: Some("thumbprint-123".to_owned()),
      iss: "https://as.example.test".to_owned(),
      post_logout_uri: Some("https://client.example.test/signed-out".to_owned()),
    }
  }

  /// Start a single-node Redis 7.2 with AOF on.
  async fn redis_container() -> Result<(ContainerGuard, String), TestError> {
    let container = GenericImage::new("redis", "7.2-alpine")
      .with_exposed_port(6379.tcp())
      .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
      .with_cmd(vec!["redis-server", "--appendonly", "yes"])
      .start()
      .await?;
    let guarded = ContainerGuard::new(container);
    let port = guarded.get_host_port_ipv4(6379).await?;
    Ok((guarded, format!("redis://127.0.0.1:{port}")))
  }

  /// Connect a [`RedisConn`] plus [`Store`] directly against a live container.
  async fn direct_store(url: &str) -> Result<(RedisConn, Store), TestError> {
    let client = redis::Client::open(url)?;
    let manager_config = redis::aio::ConnectionManagerConfig::new()
      .set_response_timeout(Some(Duration::from_secs(10)))
      .set_connection_timeout(Some(Duration::from_secs(5)));
    let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
    let raw = RawRedisConfig {
      url: Some(url.to_owned()),
      durability: Some(DurabilityMode::WaitAof),
      response_timeout_secs: 10,
      connect_timeout_secs: 5,
      ..Default::default()
    };
    let config = RedisConfig::from_raw(raw)?;
    Ok((RedisConn::Single(manager), Store::from_config(&config)))
  }

  /// The request id is opaque, base64url, and the key is `{state}`-tagged.
  #[test]
  fn pending_auth_request_id_and_key_are_opaque_and_tagged() -> TestResult {
    let store = Store::from_parts(
      "oauth:{state}:".to_owned(),
      "oauth:{rl}:".to_owned(),
      DurabilityMode::WaitAof,
    );
    let request_id = new_request_id()?;
    if request_id.len() != crate::crypto::TOKEN_STR_LEN {
      return Err(TestError::Unexpected(
        "request id must be a 256-bit base64url value".to_owned(),
      ));
    }
    if !request_id
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
      return Err(TestError::Unexpected(
        "request id must be base64url with no padding".to_owned(),
      ));
    }
    let key = pending_key(&store, &request_id);
    if !key.contains("{state}") || !key.contains("pending:") || !key.ends_with(&request_id) {
      return Err(TestError::Unexpected(format!(
        "pending key must be {{state}}-tagged: {key}"
      )));
    }
    Ok(())
  }

  /// store → load (non-destructive) → consume exactly once; replay rejected.
  #[tokio::test]
  async fn pending_auth_store_load_consume_exactly_once() -> TestResult {
    let (_container, url) = redis_container().await?;
    let (mut conn, store) = direct_store(&url).await?;
    let request_id = unique("req");
    let record = sample_record();

    put(
      &mut conn,
      &store,
      &request_id,
      &record,
      Duration::from_secs(300),
    )
    .await?;

    // Load does not spend the request: it reads back twice unchanged.
    for _ in 0..2 {
      let loaded = get(&mut conn, &store, &request_id).await?;
      if loaded.as_ref() != Some(&record) {
        return Err(TestError::Unexpected(
          "load must return the stored request without consuming it".to_owned(),
        ));
      }
    }

    // The first consume returns the record and deletes it.
    let consumed = consume(&mut conn, &store, &request_id).await?;
    if consumed != record {
      return Err(TestError::Unexpected(
        "first consume must return the stored request".to_owned(),
      ));
    }

    // Replay: the second consume finds nothing.
    match consume(&mut conn, &store, &request_id).await {
      Err(PendingError::Unknown) => {}
      _ => {
        return Err(TestError::Unexpected(
          "second consume must be rejected as unknown".to_owned(),
        ));
      }
    }
    if get(&mut conn, &store, &request_id).await?.is_some() {
      return Err(TestError::Unexpected(
        "a consumed request must not be readable".to_owned(),
      ));
    }
    Ok(())
  }

  /// Unknown and expired ids both render `invalid_request`.
  #[tokio::test]
  async fn pending_auth_unknown_and_expired_are_invalid_request() -> TestResult {
    let (_container, url) = redis_container().await?;
    let (mut conn, store) = direct_store(&url).await?;

    // Unknown id: consume rejects, get is empty.
    let missing = unique("missing");
    match consume(&mut conn, &store, &missing).await {
      Err(error) => {
        let app: AppError = error.into();
        if app.code() != OAuthErrorCode::InvalidRequest || app.status() != StatusCode::BAD_REQUEST {
          return Err(TestError::Unexpected(
            "unknown request must map to invalid_request".to_owned(),
          ));
        }
      }
      Ok(_) => {
        return Err(TestError::Unexpected(
          "unknown request must not be consumable".to_owned(),
        ));
      }
    }
    if get(&mut conn, &store, &missing).await?.is_some() {
      return Err(TestError::Unexpected(
        "unknown request must not be readable".to_owned(),
      ));
    }

    // Expired id: a 1 ms TTL is gone well before the read below.
    let expiring = unique("expiring");
    put(
      &mut conn,
      &store,
      &expiring,
      &sample_record(),
      Duration::from_millis(1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    match consume(&mut conn, &store, &expiring).await {
      Err(PendingError::Unknown) => Ok(()),
      _ => Err(TestError::Unexpected(
        "expired request must be rejected as unknown".to_owned(),
      )),
    }
  }
}

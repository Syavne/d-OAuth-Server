//! Subject-scoped ephemeral-state purge for `user disable`.
//!
//! [`purge_subject`] deletes every Redis record whose `subject` field names
//! the user (canonical email or user-id string): login sessions (plus their
//! `:meta` sidecars), the lockout counters (the account key plus every
//! per-IP composite key), authorization codes, device records
//! (plus `:cnf`/`:poll` sidecars and `user_code` mappings), and token grants
//! (cascade-revoked through [`grants::revoke`] so member token keys, the
//! member set, and the barrier stay correct, plus standalone access/refresh
//! records and `:act` sidecars).
//!
//! Records without a `subject` field are never touched: `par:`, `pending:`,
//! `dpop_jti:`, `client_assertion_jti:`, `rotation:`, `totp_replay:`, and the
//! `{rl}` rate-limit counters carry no subject, so they cannot name a user.
//!
//! Like the DCR `DELETE` revocation this scans the keyspaces with `SCAN MATCH
//! <prefix>* COUNT 100` and filters on the raw `subject` hash field. `user
//! disable` is a rare administrative call, so a bounded linear scan is
//! proportionate; on Cluster topologies the scan covers the contacted node
//! only (documented limit — Single and Sentinel scan fully).

use std::collections::{HashMap, HashSet};

use crate::db::user_repo::normalize_email;
use crate::error::AppError;
use crate::state::RedisConn;
use crate::store::{Store, StoreError, grants, sha256_hex};

/// How many records one subject purge removed, per key kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgedSubject {
  /// Login session records deleted (each also removed its `:meta` sidecar).
  pub sessions: u64,
  /// Lockout counters deleted (the account key plus every per-IP composite).
  pub lockouts: u64,
  /// Authorization-code records deleted.
  pub codes: u64,
  /// Device-code records deleted (each also removed `:cnf`/`:poll` sidecars).
  pub devices: u64,
  /// `user_code` mappings deleted.
  pub user_codes: u64,
  /// Grant families cascade-revoked.
  pub grants: u64,
  /// Standalone access-token records deleted (each also removed `:act`).
  pub access: u64,
  /// Standalone refresh-token records deleted.
  pub refresh: u64,
}

/// Delete every Redis record whose `subject` is `email` or `user_id`.
///
/// `email` must be the canonical (lowercase) address from
/// [`user_repo::find_by_email`](crate::db::user_repo::find_by_email); the
/// lockout key is derived from it with the same normalization the login flow
/// uses. Refresh-owned families cascade through [`grants::revoke`]; the
/// grant's member `:act` sidecars are removed alongside because the revoke
/// script deletes member keys only.
///
/// # Errors
///
/// Returns a fail-closed store failure when Redis is unavailable; callers
/// (notably `user disable`) must leave the Postgres `disabled` flag untouched
/// on error.
pub async fn purge_subject(
  conn: &mut RedisConn,
  store: &Store,
  email: &str,
  user_id: &str,
) -> Result<PurgedSubject, AppError> {
  let mut summary = PurgedSubject::default();

  let session_prefix = store.session_key_prefix();
  for key in scan_keys(conn, &session_prefix).await? {
    if key.ends_with(":meta") {
      continue;
    }
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      del_key(conn, &format!("{key}:meta")).await?;
      summary.sessions += 1;
    }
  }

  let fail_key = store.login_fail_key(&sha256_hex(normalize_email(email).as_bytes()));
  let removed: i64 = redis::cmd("DEL")
    .arg(&fail_key)
    .query_async(conn)
    .await
    .map_err(store_mapped)?;
  if removed > 0 {
    summary.lockouts += 1;
  }
  let account_hash = sha256_hex(normalize_email(email).as_bytes());
  let composite_pattern = format!("{}*:{account_hash}", store.login_fail_ip_prefix());
  let mut cursor = "0".to_owned();
  loop {
    let (next, batch): (String, Vec<String>) = redis::cmd("SCAN")
      .arg(&cursor)
      .arg("MATCH")
      .arg(&composite_pattern)
      .arg("COUNT")
      .arg(100)
      .query_async(conn)
      .await
      .map_err(store_mapped)?;
    for key in &batch {
      del_key(conn, key).await?;
      summary.lockouts += 1;
    }
    if next == "0" {
      break;
    }
    cursor = next;
  }

  for key in scan_keys(conn, &store.code_key_prefix()).await? {
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      summary.codes += 1;
    }
  }

  let device_prefix = store.device_key_prefix();
  let mut device_hashes: HashSet<String> = HashSet::new();
  for key in scan_keys(conn, &device_prefix).await? {
    if key.ends_with(":cnf") || key.ends_with(":poll") {
      continue;
    }
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      del_key(conn, &format!("{key}:cnf")).await?;
      del_key(conn, &format!("{key}:poll")).await?;
      if let Some(hash) = key.strip_prefix(&device_prefix) {
        device_hashes.insert(hash.to_owned());
      }
      summary.devices += 1;
    }
  }
  if !device_hashes.is_empty() {
    for key in scan_keys(conn, &store.user_code_key_prefix()).await? {
      let target: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(conn)
        .await
        .map_err(store_mapped)?;
      if target.is_some_and(|hash| device_hashes.contains(&hash)) {
        del_key(conn, &key).await?;
        summary.user_codes += 1;
      }
    }
  }

  let grant_prefix = store.grant_key_prefix();
  let access_prefix = store.access_key_prefix();
  let mut grant_ids: Vec<String> = Vec::new();
  for key in scan_keys(conn, &grant_prefix).await? {
    if key.ends_with(":tokens") {
      continue;
    }
    if is_subject(&read_fields(conn, &key).await?, email, user_id)
      && let Some(id) = key.strip_prefix(&grant_prefix)
    {
      grant_ids.push(id.to_owned());
    }
  }
  for grant_id in &grant_ids {
    let members: Vec<String> = redis::cmd("SMEMBERS")
      .arg(store.grant_tokens_key(grant_id))
      .query_async(conn)
      .await
      .map_err(store_mapped)?;
    grants::revoke(conn, store, grant_id)
      .await
      .map_err(AppError::from)?;
    for member in &members {
      del_key(conn, &format!("{access_prefix}{member}:act")).await?;
    }
    summary.grants += 1;
  }

  for key in scan_keys(conn, &access_prefix).await? {
    if key.ends_with(":act") {
      continue;
    }
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      del_key(conn, &format!("{key}:act")).await?;
      summary.access += 1;
    }
  }

  for key in scan_keys(conn, &store.refresh_key_prefix()).await? {
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      summary.refresh += 1;
    }
  }

  Ok(summary)
}

/// Delete every login session (plus `:meta` sidecar) whose `subject` is
/// `email` or `user_id`, except the session named by `keep_session_id`.
///
/// The credential-change path (`change_password` / `confirm_totp` in
/// `src/ui/login.rs`) calls this before the database update and before
/// re-issuing the current session, so a password or TOTP change revokes the
/// subject's other sessions while the session in hand survives. The sweep
/// runs first so a Redis outage fails before any credential is written (the
/// password stays unchanged); a later database failure then costs only
/// re-authentication. Tokens, codes,
/// and grants are deliberately untouched: ending the login sessions forces
/// re-authentication, while live OAuth tokens keep working until they expire
/// or the account is disabled (which runs the full [`purge_subject`]).
///
/// # Errors
///
/// Returns a fail-closed store failure when Redis is unavailable; callers
/// must surface the error instead of reporting success with siblings intact.
pub async fn purge_sibling_sessions(
  conn: &mut RedisConn,
  store: &Store,
  email: &str,
  user_id: &str,
  keep_session_id: &str,
) -> Result<u64, AppError> {
  let keep_key = store.session_key(keep_session_id);
  let mut revoked = 0;
  let session_prefix = store.session_key_prefix();
  for key in scan_keys(conn, &session_prefix).await? {
    if key.ends_with(":meta") || key == keep_key {
      continue;
    }
    if is_subject(&read_fields(conn, &key).await?, email, user_id) {
      del_key(conn, &key).await?;
      del_key(conn, &format!("{key}:meta")).await?;
      revoked += 1;
    }
  }
  Ok(revoked)
}

/// Whether a record's `subject` field names this user by email or id.
fn is_subject(fields: &HashMap<String, String>, email: &str, user_id: &str) -> bool {
  fields
    .get("subject")
    .is_some_and(|subject| subject == email || subject == user_id)
}

/// List every key under `prefix` with a bounded `SCAN` loop.
async fn scan_keys(conn: &mut RedisConn, prefix: &str) -> Result<Vec<String>, AppError> {
  let pattern = format!("{prefix}*");
  let mut cursor = "0".to_owned();
  let mut out = Vec::new();
  loop {
    let (next, batch): (String, Vec<String>) = redis::cmd("SCAN")
      .arg(&cursor)
      .arg("MATCH")
      .arg(&pattern)
      .arg("COUNT")
      .arg(100)
      .query_async(conn)
      .await
      .map_err(store_mapped)?;
    out.extend(batch);
    if next == "0" {
      break;
    }
    cursor = next;
  }
  Ok(out)
}

/// Read one record's hash fields; a missing key reads as empty.
async fn read_fields(conn: &mut RedisConn, key: &str) -> Result<HashMap<String, String>, AppError> {
  redis::cmd("HGETALL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(store_mapped)
}

/// Delete one key.
async fn del_key(conn: &mut RedisConn, key: &str) -> Result<(), AppError> {
  let _: () = redis::cmd("DEL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(store_mapped)?;
  Ok(())
}

/// Map a Redis failure onto the fail-closed store policy (transient outages
/// render `503`, everything else is masked).
fn store_mapped(error: redis::RedisError) -> AppError {
  AppError::from(StoreError::Redis(error))
}

#[cfg(test)]
mod tests {
  use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
  };

  use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
  };

  use super::{PurgedSubject, purge_sibling_sessions, purge_subject};
  use crate::{
    config::DurabilityMode,
    error::{AppError, OAuthErrorCode},
    state::RedisConn,
    store::Store,
    test_guard::ContainerGuard,
  };

  #[derive(Debug, thiserror::Error)]
  enum TestError {
    #[error("container error: {0}")]
    Containers(#[from] testcontainers::TestcontainersError),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("app error: {0}")]
    App(#[from] crate::error::AppError),
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  type TestResult = Result<(), TestError>;

  static NONCE: AtomicU64 = AtomicU64::new(1);

  async fn harness() -> Result<(ContainerGuard, RedisConn, Store), TestError> {
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    let container = GenericImage::new("redis", "8-alpine")
      .with_exposed_port(6379.tcp())
      .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
      .with_cmd(["redis-server", "--appendonly", "yes"])
      .start()
      .await?;
    let guarded = ContainerGuard::new(container);
    let port = guarded.get_host_port_ipv4(6379).await?;
    let url = format!("redis://127.0.0.1:{port}");
    let client = redis::Client::open(url.as_str())?;
    let manager_config = redis::aio::ConnectionManagerConfig::new()
      .set_response_timeout(Some(Duration::from_secs(10)))
      .set_connection_timeout(Some(Duration::from_secs(5)));
    let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
    let store = Store::from_parts(
      format!("purge-test-{n}:{{state}}:"),
      "oauth:{rl}:".to_owned(),
      DurabilityMode::WaitAof,
    );
    Ok((guarded, RedisConn::Single(manager), store))
  }

  async fn hset(conn: &mut RedisConn, key: &str, pairs: &[(&str, &str)]) -> TestResult {
    let mut cmd = redis::cmd("HSET");
    cmd.arg(key);
    for (field, value) in pairs {
      cmd.arg(field).arg(value);
    }
    cmd.query_async::<()>(conn).await?;
    redis::cmd("PEXPIRE")
      .arg(key)
      .arg(60_000)
      .query_async::<()>(conn)
      .await?;
    Ok(())
  }

  async fn set(conn: &mut RedisConn, key: &str, value: &str) -> TestResult {
    redis::cmd("SET")
      .arg(key)
      .arg(value)
      .arg("PX")
      .arg(60_000)
      .query_async::<()>(conn)
      .await?;
    Ok(())
  }

  async fn exists(conn: &mut RedisConn, key: &str) -> Result<bool, TestError> {
    let count: i64 = redis::cmd("EXISTS").arg(key).query_async(conn).await?;
    Ok(count > 0)
  }

  async fn require_gone(conn: &mut RedisConn, key: &str) -> TestResult {
    if exists(conn, key).await? {
      return Err(TestError::Unexpected(format!("key survived purge: {key}")));
    }
    Ok(())
  }

  async fn require_present(conn: &mut RedisConn, key: &str) -> TestResult {
    if !exists(conn, key).await? {
      return Err(TestError::Unexpected(format!("key missing: {key}")));
    }
    Ok(())
  }

  #[tokio::test]
  async fn purge_subject_deletes_all_subject_state() -> TestResult {
    let (_guard, mut conn, store) = harness().await?;
    let email = "alice@example.test";
    let user_id = uuid::Uuid::new_v4().to_string();
    let decoy = "bob@example.test";

    let session = "sess-alice";
    let session_key = store.session_key(session);
    hset(
      &mut conn,
      &session_key,
      &[
        ("subject", email),
        ("mfa_verified", "true"),
        ("restricted", "false"),
      ],
    )
    .await?;
    hset(
      &mut conn,
      &format!("{session_key}:meta"),
      &[
        ("auth_time", "1700000000"),
        ("csrf", "csrf-secret"),
        ("request_id", "req-1"),
      ],
    )
    .await?;

    let fail_key = store.login_fail_key(&crate::store::sha256_hex(email.as_bytes()));
    redis::cmd("INCR")
      .arg(&fail_key)
      .query_async::<()>(&mut conn)
      .await?;

    let code_key = store.code_key("codehashalice");
    hset(
      &mut conn,
      &code_key,
      &[
        ("client_id", "client-a"),
        ("redirect_uri", "https://client.example.test/cb"),
        ("scope", "orders:read"),
        (
          "code_challenge",
          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("subject", email),
        ("grant_id", "grant-code"),
        ("cnf", ""),
      ],
    )
    .await?;

    let device_hash = "devicehashalice";
    let device_key = store.device_key(device_hash);
    hset(
      &mut conn,
      &device_key,
      &[
        ("client_id", "client-a"),
        ("scope", "orders:read"),
        ("status", "approved"),
        ("subject", user_id.as_str()),
        ("grant_id", ""),
      ],
    )
    .await?;
    set(&mut conn, &format!("{device_key}:cnf"), "binding").await?;
    set(&mut conn, &format!("{device_key}:poll"), "1700000000").await?;
    let user_code_hash = "usercodehashalice";
    let user_code_key = store.user_code_key(user_code_hash);
    set(&mut conn, &user_code_key, device_hash).await?;

    let grant_id = "grant-alice";
    let grant_key = store.grant_key(grant_id);
    hset(
      &mut conn,
      &grant_key,
      &[
        ("grant_id", grant_id),
        ("client_id", "client-a"),
        ("subject", email),
        ("scope", "orders:read"),
      ],
    )
    .await?;
    let access_hash = "accesshashalice";
    let refresh_hash = "refreshhashalice";
    let access_key = store.access_key(access_hash);
    let refresh_key = store.refresh_key(refresh_hash);
    for (key, hash) in [(&access_key, access_hash), (&refresh_key, refresh_hash)] {
      hset(
        &mut conn,
        key,
        &[
          ("client_id", "client-a"),
          ("grant_id", grant_id),
          ("scope", "orders:read"),
          ("subject", email),
          ("cnf", ""),
        ],
      )
      .await?;
      redis::cmd("SADD")
        .arg(store.grant_tokens_key(grant_id))
        .arg(hash)
        .query_async::<()>(&mut conn)
        .await?;
    }
    set(&mut conn, &format!("{access_key}:act"), "jkt").await?;

    let lone_access_key = store.access_key("loneaccessalice");
    hset(
      &mut conn,
      &lone_access_key,
      &[
        ("client_id", "client-a"),
        ("grant_id", "orphan"),
        ("scope", "orders:read"),
        ("subject", email),
        ("cnf", ""),
      ],
    )
    .await?;
    set(&mut conn, &format!("{lone_access_key}:act"), "jkt").await?;
    let lone_refresh_key = store.refresh_key("lonerefreshalice");
    hset(
      &mut conn,
      &lone_refresh_key,
      &[
        ("client_id", "client-a"),
        ("grant_id", "orphan"),
        ("scope", "orders:read"),
        ("subject", email),
        ("cnf", ""),
      ],
    )
    .await?;

    let decoy_session_key = store.session_key("sess-bob");
    hset(
      &mut conn,
      &decoy_session_key,
      &[
        ("subject", decoy),
        ("mfa_verified", "true"),
        ("restricted", "false"),
      ],
    )
    .await?;
    let decoy_access_key = store.access_key("accesshashbob");
    hset(
      &mut conn,
      &decoy_access_key,
      &[
        ("client_id", "client-b"),
        ("grant_id", "grant-bob"),
        ("scope", "orders:read"),
        ("subject", decoy),
        ("cnf", ""),
      ],
    )
    .await?;

    let summary = purge_subject(&mut conn, &store, email, &user_id).await?;
    let expected = PurgedSubject {
      sessions: 1,
      lockouts: 1,
      codes: 1,
      devices: 1,
      user_codes: 1,
      grants: 1,
      access: 1,
      refresh: 1,
    };
    if summary != expected {
      return Err(TestError::Unexpected(format!(
        "wrong purge summary: {summary:?} (expected {expected:?})"
      )));
    }

    for key in [
      session_key.clone(),
      format!("{session_key}:meta"),
      fail_key,
      code_key,
      device_key.clone(),
      format!("{device_key}:cnf"),
      format!("{device_key}:poll"),
      user_code_key,
      grant_key,
      store.grant_tokens_key(grant_id),
      access_key.clone(),
      format!("{access_key}:act"),
      refresh_key,
      lone_access_key.clone(),
      format!("{lone_access_key}:act"),
      lone_refresh_key,
    ] {
      require_gone(&mut conn, &key).await?;
    }

    require_present(&mut conn, &decoy_session_key).await?;
    require_present(&mut conn, &decoy_access_key).await?;
    Ok(())
  }

  #[tokio::test]
  async fn purge_subject_with_no_matching_state_returns_zero() -> TestResult {
    let (_guard, mut conn, store) = harness().await?;
    let summary = purge_subject(&mut conn, &store, "nobody@example.test", "no-id").await?;
    if summary != PurgedSubject::default() {
      return Err(TestError::Unexpected(format!(
        "expected zero summary, got {summary:?}"
      )));
    }
    Ok(())
  }

  async fn dead_conn() -> Result<RedisConn, TestError> {
    let client = redis::Client::open("redis://127.0.0.1:1")?;
    let manager = redis::aio::ConnectionManager::new_lazy_with_config(
      client,
      redis::aio::ConnectionManagerConfig::new()
        .set_number_of_retries(0)
        .set_response_timeout(Some(Duration::from_millis(200)))
        .set_connection_timeout(Some(Duration::from_millis(200))),
    )?;
    Ok(RedisConn::Single(manager))
  }

  fn require_unavailable(error: AppError) -> TestResult {
    if error.code() != OAuthErrorCode::TemporarilyUnavailable {
      return Err(TestError::Unexpected(format!(
        "a store outage must be temporarily_unavailable, got {:?}",
        error.code()
      )));
    }
    if error.status().as_u16() != 503 {
      return Err(TestError::Unexpected(format!(
        "a store outage must render 503, got {}",
        error.status()
      )));
    }
    Ok(())
  }

  #[tokio::test]
  async fn purge_sibling_sessions_deletes_meta_sidecar_and_keeps_current() -> TestResult {
    let (_guard, mut conn, store) = harness().await?;
    let email = "sibling-meta@example.test";
    let user_id = uuid::Uuid::new_v4().to_string();
    let current_key = store.session_key("sess-current");
    hset(
      &mut conn,
      &current_key,
      &[("subject", email), ("mfa_verified", "true")],
    )
    .await?;
    hset(&mut conn, &format!("{current_key}:meta"), &[("csrf", "a")]).await?;
    let sibling_key = store.session_key("sess-sibling");
    hset(
      &mut conn,
      &sibling_key,
      &[("subject", email), ("mfa_verified", "true")],
    )
    .await?;
    hset(&mut conn, &format!("{sibling_key}:meta"), &[("csrf", "b")]).await?;

    let revoked =
      purge_sibling_sessions(&mut conn, &store, email, &user_id, "sess-current").await?;
    if revoked != 1 {
      return Err(TestError::Unexpected(format!(
        "exactly one sibling must be revoked, got {revoked}"
      )));
    }
    require_present(&mut conn, &current_key).await?;
    require_present(&mut conn, &format!("{current_key}:meta")).await?;
    require_gone(&mut conn, &sibling_key).await?;
    require_gone(&mut conn, &format!("{sibling_key}:meta")).await?;
    Ok(())
  }

  #[tokio::test]
  async fn purge_sibling_sessions_leaves_other_subjects_tokens_and_grants() -> TestResult {
    let (_guard, mut conn, store) = harness().await?;
    let email = "sibling-scope@example.test";
    let user_id = uuid::Uuid::new_v4().to_string();
    let other = "stranger@example.test";
    let victim_key = store.session_key("sess-victim");
    hset(&mut conn, &victim_key, &[("subject", email)]).await?;
    let other_key = store.session_key("sess-other");
    hset(&mut conn, &other_key, &[("subject", other)]).await?;
    hset(&mut conn, &format!("{other_key}:meta"), &[("csrf", "c")]).await?;
    let grant_id = "grant-survivor";
    hset(
      &mut conn,
      &store.grant_key(grant_id),
      &[("subject", email), ("scope", "orders:read")],
    )
    .await?;
    redis::cmd("SADD")
      .arg(store.grant_tokens_key(grant_id))
      .arg("memberhash")
      .query_async::<()>(&mut conn)
      .await?;
    let access_key = store.access_key("survivoraccess");
    hset(&mut conn, &access_key, &[("subject", email)]).await?;
    set(&mut conn, &format!("{access_key}:act"), "jkt").await?;
    let refresh_key = store.refresh_key("survivorrefresh");
    hset(&mut conn, &refresh_key, &[("subject", email)]).await?;
    let code_key = store.code_key("survivorcode");
    hset(&mut conn, &code_key, &[("subject", email)]).await?;

    let revoked = purge_sibling_sessions(&mut conn, &store, email, &user_id, "sess-victim").await?;
    if revoked != 0 {
      return Err(TestError::Unexpected(format!(
        "keeping the only own session must revoke nothing, got {revoked}"
      )));
    }
    for key in [
      victim_key,
      other_key.clone(),
      format!("{other_key}:meta"),
      store.grant_key(grant_id),
      store.grant_tokens_key(grant_id),
      access_key.clone(),
      format!("{access_key}:act"),
      refresh_key,
      code_key,
    ] {
      require_present(&mut conn, &key).await?;
    }
    Ok(())
  }

  #[tokio::test]
  async fn purge_sibling_sessions_matches_subject_by_user_id() -> TestResult {
    let (_guard, mut conn, store) = harness().await?;
    let email = "sibling-id@example.test";
    let user_id = uuid::Uuid::new_v4().to_string();
    let current_key = store.session_key("sess-id-current");
    hset(&mut conn, &current_key, &[("subject", user_id.as_str())]).await?;
    let sibling_key = store.session_key("sess-id-sibling");
    hset(&mut conn, &sibling_key, &[("subject", user_id.as_str())]).await?;

    let revoked =
      purge_sibling_sessions(&mut conn, &store, email, &user_id, "sess-id-current").await?;
    if revoked != 1 {
      return Err(TestError::Unexpected(format!(
        "a user-id-keyed sibling must be revoked, got {revoked}"
      )));
    }
    require_present(&mut conn, &current_key).await?;
    require_gone(&mut conn, &sibling_key).await?;
    Ok(())
  }

  #[tokio::test]
  async fn purge_subject_fails_closed_on_store_outage() -> TestResult {
    let mut conn = dead_conn().await?;
    let store = Store::from_parts(
      "purge-outage:{state}:".to_owned(),
      "oauth:{rl}:".to_owned(),
      DurabilityMode::WaitAof,
    );
    match purge_subject(&mut conn, &store, "outage@example.test", "outage-id").await {
      Err(error) => require_unavailable(error),
      Ok(_) => Err(TestError::Unexpected(
        "purge_subject on a dead store must fail, never report success".to_owned(),
      )),
    }
  }

  #[tokio::test]
  async fn purge_sibling_sessions_fails_closed_on_store_outage() -> TestResult {
    let mut conn = dead_conn().await?;
    let store = Store::from_parts(
      "purge-outage:{state}:".to_owned(),
      "oauth:{rl}:".to_owned(),
      DurabilityMode::WaitAof,
    );
    match purge_sibling_sessions(
      &mut conn,
      &store,
      "outage@example.test",
      "outage-id",
      "sess-keep",
    )
    .await
    {
      Err(error) => require_unavailable(error),
      Ok(_) => Err(TestError::Unexpected(
        "purge_sibling_sessions on a dead store must fail, never report success".to_owned(),
      )),
    }
  }
}

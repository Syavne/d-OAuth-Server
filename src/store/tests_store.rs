//! `test(store)` suite: atomic Lua, tombstones, grant index, durability.
//!
//! Every test here spins its own single-node Redis 7.2 container with AOF
//! enabled (mirroring `state::test_support`), so persistence, barriers, and
//! concurrent compare-and-set run against a real server.

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

use super::{
  ErrorClass, OpClass, Store, StoreError, classify_redis, codes, dcr, device, durability_barrier,
  grants, may_retry_op, par, pending, ratelimit, retry_op, sessions, sha256_hex, tokens,
};
use crate::{
  config::{ConfigError, DurabilityMode, RedisConfig, TtlConfig, redis::RawRedisConfig},
  state::RedisConn,
  test_guard::ContainerGuard,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Errors raised by the store test scaffolding itself.
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
  /// A spawned task failed to join.
  #[error("task join failed")]
  Join,
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

static TEST_NONCE: AtomicU64 = AtomicU64::new(10_000);

fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("store-test-{n}-{label}")
}

/// Start a single-node Redis with AOF on plus extra server flags.
///
/// The guard removes the container synchronously when the test drops it.
async fn redis_container(extra: Vec<&str>) -> Result<(ContainerGuard, String), TestError> {
  let mut args = vec!["redis-server", "--appendonly", "yes"];
  args.extend(extra);
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(args)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Connect a [`RedisConn`] plus [`Store`] directly (startup assertions live in
/// task 4; here the store contract is what is under test).
///
/// Timeouts are generous on purpose: the blocking `WAITAOF` barrier may wait
/// out a full `everysec` fsync cycle, so the client response timeout must sit
/// well above the server-side barrier wait.
async fn direct_store(
  url: &str,
  durability: DurabilityMode,
) -> Result<(RedisConn, Store), TestError> {
  let client = redis::Client::open(url)?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let raw = RawRedisConfig {
    url: Some(url.to_owned()),
    durability: Some(durability),
    response_timeout_secs: 10,
    connect_timeout_secs: 5,
    ..Default::default()
  };
  let config = RedisConfig::from_raw(raw)?;
  Ok((RedisConn::Single(manager), Store::from_config(&config)))
}

fn code_record(client: &str, grant: &str) -> codes::CodeRecord {
  codes::CodeRecord {
    client_id: client.to_owned(),
    redirect_uri: "https://client.example.test/cb".to_owned(),
    scope: "orders:read".to_owned(),
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    subject: "user-1".to_owned(),
    grant_id: grant.to_owned(),
    cnf: String::new(),
  }
}

fn refresh_record(client: &str, grant: &str) -> tokens::RefreshRecord {
  tokens::RefreshRecord {
    client_id: client.to_owned(),
    grant_id: grant.to_owned(),
    scope: "orders:read".to_owned(),
    subject: "user-1".to_owned(),
    cnf: String::new(),
  }
}

fn access_record(client: &str, grant: &str) -> tokens::AccessRecord {
  tokens::AccessRecord {
    client_id: client.to_owned(),
    grant_id: grant.to_owned(),
    scope: "orders:read".to_owned(),
    subject: "user-1".to_owned(),
    cnf: String::new(),
  }
}

fn rotation_input(
  old: &str,
  client: &str,
  new_refresh: &str,
  new_access: &str,
  grant: &str,
  request_id: Option<String>,
) -> tokens::RotationInput {
  tokens::RotationInput {
    old_refresh_hash: old.to_owned(),
    expected_client_id: client.to_owned(),
    new_refresh_hash: new_refresh.to_owned(),
    new_access_hash: new_access.to_owned(),
    new_refresh: refresh_record(client, grant),
    new_access: access_record(client, grant),
    new_refresh_ttl: Duration::from_secs(3600),
    new_access_ttl: Duration::from_secs(300),
    request_id,
  }
}

/// Remaining TTL of a key in milliseconds (`-1` persistent, `-2` absent).
async fn pttl_ms(conn: &mut RedisConn, key: &str) -> Result<i64, TestError> {
  let pttl: i64 = redis::cmd("PTTL").arg(key).query_async(conn).await?;
  Ok(pttl)
}

/// Assert a key carries a live TTL inside the design window `(0, cap]`.
///
/// `cap` comes from the configured/design lifetime, never from the observed
/// value. A non-positive TTL means the key is persistent or absent (a defect:
/// the artifact would outlive its intended window); the upper bound can only
/// drift downward while the test runs, so a slow run cannot flake it.
fn assert_ttl_within(pttl: i64, cap: Duration) -> TestResult {
  if pttl <= 0 || pttl > cap.as_millis() as i64 {
    return Err(TestError::Unexpected(format!(
      "PTTL {pttl} ms must be within (0, {} ms]",
      cap.as_millis()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn store_code_consume_exactly_once() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let hash = unique("code");
  let grant = unique("grant");
  let client = unique("client");

  codes::issue(
    &mut conn,
    &store,
    &hash,
    &code_record(&client, &grant),
    Duration::from_secs(60),
  )
  .await?;
  let first = codes::consume(&mut conn, &store, &hash).await?;
  let second = codes::consume(&mut conn, &store, &hash).await?;

  if first
    .as_ref()
    .is_none_or(|record| record.client_id != client)
  {
    return Err(TestError::Unexpected(
      "first consume must return the record".to_owned(),
    ));
  }
  if second.is_some() {
    return Err(TestError::Unexpected(
      "second consume must return None".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_refresh_rotate_idempotent_replay() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let old = unique("old-refresh");
  let new_refresh = unique("new-refresh");
  let new_access = unique("new-access");
  let pepper = b"store-test-pepper";

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &old,
    &refresh_record(&client, &grant),
    Duration::from_secs(3600),
  )
  .await?;

  // Same old token presented twice (deterministic request id): the SAME new
  // tokens come back, never a double rotation.
  let first = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(&old, &client, &new_refresh, &new_access, &grant, None),
  )
  .await?;
  let second = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(&old, &client, &new_refresh, &new_access, &grant, None),
  )
  .await?;
  match (first, second) {
    (
      tokens::RotateOutcome::Rotated {
        new_refresh_hash: first_r,
        new_access_hash: first_a,
      },
      tokens::RotateOutcome::Replay {
        new_refresh_hash: second_r,
        new_access_hash: second_a,
      },
    ) if first_r == new_refresh
      && first_a == new_access
      && second_r == new_refresh
      && second_a == new_access =>
    {
      Ok(())
    }
    _ => Err(TestError::Unexpected(
      "expected Rotated then Replay with identical tokens".to_owned(),
    )),
  }
}

#[tokio::test]
async fn store_refresh_concurrent_cas_one_rotated_one_reuse() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let old = unique("old-refresh");
  let pepper = b"store-test-pepper";

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &old,
    &refresh_record(&client, &grant),
    Duration::from_secs(3600),
  )
  .await?;

  // Two concurrent rotations with DISTINCT request ids (two spend attempts):
  // exactly one rotates, the other observes reuse.
  let first_tag = unique("race-refresh");
  let second_tag = unique("race-refresh");
  let first = tokio::spawn({
    let conn = conn.clone();
    let store = store.clone();
    let grant = grant.clone();
    let client = client.clone();
    let old = old.clone();
    async move {
      let mut conn = conn;
      let input = rotation_input(
        &old,
        &client,
        &first_tag,
        &format!("{first_tag}-access"),
        &grant,
        Some("req-1".to_owned()),
      );
      tokens::rotate(&mut conn, &store, pepper, &input).await
    }
  });
  let second = tokio::spawn({
    let conn = conn.clone();
    let store = store.clone();
    async move {
      let mut conn = conn;
      let input = rotation_input(
        &old,
        &client,
        &second_tag,
        &format!("{second_tag}-access"),
        &grant,
        Some("req-2".to_owned()),
      );
      tokens::rotate(&mut conn, &store, pepper, &input).await
    }
  });
  let first = first.await.map_err(|_| TestError::Join)??;
  let second = second.await.map_err(|_| TestError::Join)??;
  let rotated = u8::from(matches!(first, tokens::RotateOutcome::Rotated { .. }))
    + u8::from(matches!(second, tokens::RotateOutcome::Rotated { .. }));
  let reused = u8::from(matches!(first, tokens::RotateOutcome::Reused { .. }))
    + u8::from(matches!(second, tokens::RotateOutcome::Reused { .. }));
  if rotated == 1 && reused == 1 {
    Ok(())
  } else {
    Err(TestError::Unexpected(
      "expected exactly one Rotated and one Reused".to_owned(),
    ))
  }
}

#[tokio::test]
async fn store_refresh_reuse_without_mapping_cascades() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let old = unique("old-refresh");
  let new_refresh = unique("new-refresh");
  let new_access = unique("new-access");
  let pepper = b"store-test-pepper";

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &old,
    &refresh_record(&client, &grant),
    Duration::from_secs(3600),
  )
  .await?;
  let first = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(&old, &client, &new_refresh, &new_access, &grant, None),
  )
  .await?;
  if !matches!(first, tokens::RotateOutcome::Rotated { .. }) {
    return Err(TestError::Unexpected(
      "first rotation must apply".to_owned(),
    ));
  }

  // Expire the grace mapping (grace window elapsed), then replay the old
  // token: reuse, and the whole family dies.
  let request_id = tokens::derive_rotation_id(pepper, &old)?;
  let map_key = store.rotation_map_key(&request_id);
  let _: () = redis::cmd("DEL")
    .arg(&map_key)
    .query_async(&mut conn)
    .await?;
  let replay = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(
      &old,
      &client,
      &unique("other"),
      &unique("other-a"),
      &grant,
      None,
    ),
  )
  .await?;
  match replay {
    tokens::RotateOutcome::Reused { rotated_to } if rotated_to == new_refresh => {}
    _ => {
      return Err(TestError::Unexpected(
        "expected Reused pointing at the rotated token".to_owned(),
      ));
    }
  }
  if tokens::get_refresh(&mut conn, &store, &new_refresh)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "cascade must delete the rotated refresh token".to_owned(),
    ));
  }
  if tokens::get_access(&mut conn, &store, &new_access)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "cascade must delete the rotated access token".to_owned(),
    ));
  }
  if grants::get(&mut conn, &store, &grant).await?.is_some() {
    return Err(TestError::Unexpected(
      "cascade must delete the grant record".to_owned(),
    ));
  }
  if !grants::members(&mut conn, &store, &grant).await?.is_empty() {
    return Err(TestError::Unexpected(
      "cascade must empty the grant set".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_grant_revoke_cascade() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let refresh = unique("refresh");
  let access = unique("access");

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &refresh,
    &refresh_record(&client, &grant),
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_access(
    &mut conn,
    &store,
    &access,
    &access_record(&client, &grant),
    Duration::from_secs(300),
  )
  .await?;
  if grants::members(&mut conn, &store, &grant).await?.len() != 2 {
    return Err(TestError::Unexpected(
      "grant set must index both tokens".to_owned(),
    ));
  }

  let deleted = grants::revoke(&mut conn, &store, &grant).await?;
  if deleted < 2 {
    return Err(TestError::Unexpected(
      "revoke must delete both token keys".to_owned(),
    ));
  }
  if tokens::get_refresh(&mut conn, &store, &refresh)
    .await?
    .is_some()
    || tokens::get_access(&mut conn, &store, &access)
      .await?
      .is_some()
  {
    return Err(TestError::Unexpected(
      "revoke must delete member records".to_owned(),
    ));
  }
  // Unknown grants revoke to zero (idempotent).
  if grants::revoke(&mut conn, &store, &unique("no-such-grant")).await? != 0 {
    return Err(TestError::Unexpected(
      "unknown grant must revoke to zero".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_tombstone_detectable_after_rotation() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let old = unique("old-refresh");
  let new_refresh = unique("new-refresh");
  let new_access = unique("new-access");
  let pepper = b"store-test-pepper";

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &old,
    &refresh_record(&client, &grant),
    Duration::from_secs(3600),
  )
  .await?;

  // Live token: no tombstone; unknown hash: no tombstone.
  if tokens::tombstone_of(&mut conn, &store, &old)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "live token must not look tombstoned".to_owned(),
    ));
  }
  if tokens::tombstone_of(&mut conn, &store, &unique("absent"))
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "absent token must not look tombstoned".to_owned(),
    ));
  }
  let outcome = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(&old, &client, &new_refresh, &new_access, &grant, None),
  )
  .await?;
  if !matches!(outcome, tokens::RotateOutcome::Rotated { .. }) {
    return Err(TestError::Unexpected("rotation must apply".to_owned()));
  }
  match tokens::tombstone_of(&mut conn, &store, &old).await? {
    Some(rotated_to) if rotated_to == new_refresh => Ok(()),
    _ => Err(TestError::Unexpected(
      "tombstone must point at the new token".to_owned(),
    )),
  }
}

#[tokio::test]
async fn store_persistence_survives_restart() -> TestResult {
  let (container, url) = redis_container(vec!["--appendfsync", "always"]).await?;
  let grant = unique("grant");
  let client = unique("client");
  let code_hash = unique("code");
  let refresh_hash = unique("refresh");
  let jti = unique("jti");
  {
    let (mut conn, store) = direct_store(&url, DurabilityMode::AppendFsyncAlways).await?;
    codes::issue(
      &mut conn,
      &store,
      &code_hash,
      &code_record(&client, &grant),
      Duration::from_secs(600),
    )
    .await?;
    tokens::put_refresh(
      &mut conn,
      &store,
      &refresh_hash,
      &refresh_record(&client, &grant),
      Duration::from_secs(3600),
    )
    .await?;
    if !dcr::claim_dpop_jti(&mut conn, &store, &jti, Duration::from_secs(600)).await? {
      return Err(TestError::Unexpected("marker claim must win".to_owned()));
    }
  }
  container.stop_with_timeout(Some(10)).await?;
  container.start().await?;
  let port = container.get_host_port_ipv4(6379).await?;
  let (mut conn, store) = direct_store(
    &format!("redis://127.0.0.1:{port}"),
    DurabilityMode::AppendFsyncAlways,
  )
  .await?;

  let code = codes::consume(&mut conn, &store, &code_hash).await?;
  if code
    .as_ref()
    .is_none_or(|record| record.client_id != client)
  {
    return Err(TestError::Unexpected(
      "code must survive the restart".to_owned(),
    ));
  }
  let refresh = tokens::get_refresh(&mut conn, &store, &refresh_hash).await?;
  if refresh
    .as_ref()
    .is_none_or(|record| record.grant_id != grant)
  {
    return Err(TestError::Unexpected(
      "refresh record must survive the restart".to_owned(),
    ));
  }
  if dcr::claim_dpop_jti(&mut conn, &store, &jti, Duration::from_secs(600)).await? {
    return Err(TestError::Unexpected(
      "replay marker must survive the restart".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_durability_barrier_modes() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  // Single-node: WAITAOF barrier succeeds after a write.
  let (mut conn, waitaof) = direct_store(&url, DurabilityMode::WaitAof).await?;
  durability_barrier(&mut conn, &waitaof).await?;
  // `WAIT 1` on a replica-less node acknowledges zero: fail closed.
  let wait = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::Wait,
  );
  if durability_barrier(&mut conn, &wait).await.is_ok() {
    return Err(TestError::Unexpected(
      "WAIT without replicas must fail closed".to_owned(),
    ));
  }
  // `appendfsync always` assertion fails on an everysec node: fail closed.
  let always = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::AppendFsyncAlways,
  );
  if durability_barrier(&mut conn, &always).await.is_ok() {
    return Err(TestError::Unexpected(
      "everysec node must fail the always barrier".to_owned(),
    ));
  }
  // ...and succeeds where the server actually fsyncs always.
  let (_always_container, always_url) = redis_container(vec!["--appendfsync", "always"]).await?;
  let (mut always_conn, _) = direct_store(&always_url, DurabilityMode::AppendFsyncAlways).await?;
  durability_barrier(&mut always_conn, &always).await?;
  Ok(())
}

#[tokio::test]
async fn store_ratelimit_fixed_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let bucket = unique("bucket");
  let window = Duration::from_secs(60);

  for _ in 0..3 {
    let decision = ratelimit::check_and_incr(&mut conn, &store, &bucket, window, 3).await?;
    if !decision.allowed {
      return Err(TestError::Unexpected(
        "first three hits must be allowed".to_owned(),
      ));
    }
  }
  let limited = ratelimit::check_and_incr(&mut conn, &store, &bucket, window, 3).await?;
  if limited.allowed || limited.count != 4 || limited.retry_after_secs == 0 {
    return Err(TestError::Unexpected(
      "fourth hit must be limited with Retry-After".to_owned(),
    ));
  }
  // Buckets are hashed under the `{rl}` keyspace, never raw labels.
  let key = store.ratelimit_key(&ratelimit::hash_bucket(&bucket));
  if !key.contains("{rl}") || key.contains(&bucket) {
    return Err(TestError::Unexpected(
      "counter key must be hashed and {rl}-tagged".to_owned(),
    ));
  }
  if ratelimit::hash_bucket(&bucket) != ratelimit::hash_bucket(&bucket) {
    return Err(TestError::Unexpected(
      "bucket hashing must be deterministic".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_replay_markers_first_claim_wins() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let jti = unique("jti");
  let assertion = unique("assertion");

  if !dcr::claim_dpop_jti(&mut conn, &store, &jti, Duration::from_secs(300)).await? {
    return Err(TestError::Unexpected(
      "first DPoP claim must win".to_owned(),
    ));
  }
  if dcr::claim_dpop_jti(&mut conn, &store, &jti, Duration::from_secs(300)).await? {
    return Err(TestError::Unexpected(
      "second DPoP claim must lose".to_owned(),
    ));
  }
  if !dcr::claim_client_assertion_jti(&mut conn, &store, &assertion, Duration::from_secs(300))
    .await?
  {
    return Err(TestError::Unexpected(
      "first assertion claim must win".to_owned(),
    ));
  }
  if dcr::claim_client_assertion_jti(&mut conn, &store, &assertion, Duration::from_secs(300))
    .await?
  {
    return Err(TestError::Unexpected(
      "second assertion claim must lose".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_sessions_and_login_counters() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let old_session = unique("session");
  let new_session = unique("session");
  let record = sessions::SessionRecord {
    subject: "user-1".to_owned(),
    mfa_verified: true,
    restricted: false,
  };

  sessions::put(
    &mut conn,
    &store,
    &old_session,
    &record,
    Duration::from_secs(3600),
  )
  .await?;
  sessions::rotate(
    &mut conn,
    &store,
    &old_session,
    &new_session,
    &record,
    Duration::from_secs(3600),
  )
  .await?;
  if sessions::get(&mut conn, &store, &old_session)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "old session must be gone after rotate".to_owned(),
    ));
  }
  let current = sessions::get(&mut conn, &store, &new_session).await?;
  if current.as_ref().is_none_or(|session| !session.mfa_verified) {
    return Err(TestError::Unexpected(
      "new session must verify MFA".to_owned(),
    ));
  }
  sessions::destroy(&mut conn, &store, &new_session).await?;
  if sessions::get(&mut conn, &store, &new_session)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "destroyed session must be gone".to_owned(),
    ));
  }

  let account = unique("alice@example.test");
  let first =
    sessions::record_failed_login(&mut conn, &store, &account, Duration::from_secs(300)).await?;
  let second =
    sessions::record_failed_login(&mut conn, &store, &account, Duration::from_secs(300)).await?;
  if (first, second) != (1, 2) {
    return Err(TestError::Unexpected(
      "failed-login counter must increment".to_owned(),
    ));
  }
  if sessions::failed_login_count(&mut conn, &store, &account).await? != 2 {
    return Err(TestError::Unexpected(
      "failed-login count must read back".to_owned(),
    ));
  }
  sessions::clear_failed_logins(&mut conn, &store, &account).await?;
  if sessions::failed_login_count(&mut conn, &store, &account).await? != 0 {
    return Err(TestError::Unexpected(
      "cleared counter must read zero".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn store_device_par_and_dcr_round_trip() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let client = unique("client");

  // Device flow: put, poll, approve, consume exactly once.
  let device_hash = unique("device");
  let user_code = unique("user-code");
  device::put(
    &mut conn,
    &store,
    &device_hash,
    &user_code,
    &device::DeviceRecord {
      client_id: client.clone(),
      scope: "orders:read".to_owned(),
      status: device::DeviceStatus::Pending,
      subject: String::new(),
      grant_id: String::new(),
    },
    Duration::from_secs(600),
  )
  .await?;
  if device::resolve_user_code(&mut conn, &store, &user_code)
    .await?
    .as_deref()
    != Some(device_hash.as_str())
  {
    return Err(TestError::Unexpected(
      "user code must resolve to the device".to_owned(),
    ));
  }
  let grant = unique("grant");
  if !device::decide(
    &mut conn,
    &store,
    &device_hash,
    device::DeviceStatus::Approved,
    "user-1",
    &grant,
  )
  .await?
  {
    return Err(TestError::Unexpected("approve must apply".to_owned()));
  }
  let approved = device::poll(&mut conn, &store, &device_hash).await?;
  if approved
    .as_ref()
    .is_none_or(|record| record.status != device::DeviceStatus::Approved)
  {
    return Err(TestError::Unexpected(
      "poll must observe approval".to_owned(),
    ));
  }
  if device::consume(&mut conn, &store, &device_hash)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "first device consume must return the record".to_owned(),
    ));
  }
  if device::consume(&mut conn, &store, &device_hash)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "second device consume must return None".to_owned(),
    ));
  }

  // PAR: put, consume exactly once.
  let request_id = unique("par");
  par::put(
    &mut conn,
    &store,
    &request_id,
    &par::ParRecord {
      client_id: client.clone(),
      request: "{\"response_type\":\"code\"}".to_owned(),
    },
    Duration::from_secs(90),
  )
  .await?;
  if par::consume(&mut conn, &store, &request_id)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "first PAR consume must return the record".to_owned(),
    ));
  }
  if par::consume(&mut conn, &store, &request_id)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "second PAR consume must return None".to_owned(),
    ));
  }

  // DCR initial-access token: two uses, then exhausted.
  let iat = unique("iat");
  dcr::issue(
    &mut conn,
    &store,
    &iat,
    &dcr::InitialAccessRecord {
      uses_remaining: 2,
      label: "ops-token".to_owned(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  let first_use = dcr::consume_one_use(&mut conn, &store, &iat).await?;
  if first_use
    .as_ref()
    .is_none_or(|record| record.uses_remaining != 2)
  {
    return Err(TestError::Unexpected(
      "first use must report the pre-decrement budget".to_owned(),
    ));
  }
  if dcr::consume_one_use(&mut conn, &store, &iat)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "second (final) use must succeed".to_owned(),
    ));
  }
  if dcr::consume_one_use(&mut conn, &store, &iat)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "exhausted token must return None".to_owned(),
    ));
  }
  Ok(())
}

/// docs/REDIS.md: `oauth:{state}:code:<hash>` carries the authorization-code
/// lifetime, capped at [`crate::protocol::code::CODE_TTL_CAP`] (60 s).
#[tokio::test]
async fn store_code_ttl_within_configured_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let ttl = TtlConfig::default();
  let hash = unique("code");

  codes::issue(
    &mut conn,
    &store,
    &hash,
    &code_record(&unique("client"), &unique("grant")),
    ttl.code,
  )
  .await?;
  let cap = ttl.code.min(crate::protocol::code::CODE_TTL_CAP);
  assert_ttl_within(pttl_ms(&mut conn, &store.code_key(&hash)).await?, cap)
}

/// docs/REDIS.md: the PAR handle lives under `ttl.par` (90 s) and both the
/// device-code record and its user-code mapping under `ttl.device` (600 s).
#[tokio::test]
async fn store_par_device_and_user_code_ttl_within_configured_windows() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let ttl = TtlConfig::default();
  let client = unique("client");

  let request_id = unique("par");
  par::put(
    &mut conn,
    &store,
    &request_id,
    &par::ParRecord {
      client_id: client.clone(),
      request: "{\"response_type\":\"code\"}".to_owned(),
    },
    ttl.par,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.par_key(&request_id)).await?,
    ttl.par,
  )?;

  let device_hash = unique("device");
  let user_code = unique("user-code");
  device::put(
    &mut conn,
    &store,
    &device_hash,
    &user_code,
    &device::DeviceRecord {
      client_id: client,
      scope: "orders:read".to_owned(),
      status: device::DeviceStatus::Pending,
      subject: String::new(),
      grant_id: String::new(),
    },
    ttl.device,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.device_key(&device_hash)).await?,
    ttl.device,
  )?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.user_code_key(&user_code)).await?,
    ttl.device,
  )
}

/// docs/REDIS.md: the DCR initial-access-token record lives under the CLI
/// `--ttl`, defaulting to the configured `ttl.dcr_initial_access` (24 h).
#[tokio::test]
async fn store_dcr_initial_access_ttl_within_configured_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let ttl = TtlConfig::default();
  let iat = unique("iat");

  dcr::issue(
    &mut conn,
    &store,
    &iat,
    &dcr::InitialAccessRecord {
      uses_remaining: 2,
      label: "ops-token".to_owned(),
    },
    ttl.dcr_initial_access,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.dcr_iat_key(&iat)).await?,
    ttl.dcr_initial_access,
  )
}

/// docs/REDIS.md: the rotation idempotency mapping is bounded by
/// `min(900 s, refresh TTL)`, the old refresh record becomes a tombstone with
/// the refresh lifetime, and the per-grant token index lives with the grant.
#[tokio::test]
async fn store_rotation_grace_tombstone_and_grant_index_ttl() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let grant = unique("grant");
  let client = unique("client");
  let old = unique("old-refresh");
  let new_refresh = unique("new-refresh");
  let new_access = unique("new-access");
  let pepper = b"store-test-pepper";
  let refresh_ttl = Duration::from_secs(3600);
  let access_ttl = Duration::from_secs(300);
  let rotation_grace = Duration::from_secs(900);

  grants::create(
    &mut conn,
    &store,
    &grants::GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "orders:read".to_owned(),
    },
    refresh_ttl,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.grant_key(&grant)).await?,
    refresh_ttl,
  )?;

  // The index is born with the access member, then extended by the refresh
  // member: it must outlive the short access TTL and stay within the grant's.
  tokens::put_access(
    &mut conn,
    &store,
    &unique("access-seed"),
    &access_record(&client, &grant),
    access_ttl,
  )
  .await?;
  tokens::put_refresh(
    &mut conn,
    &store,
    &old,
    &refresh_record(&client, &grant),
    refresh_ttl,
  )
  .await?;
  let index_key = store.grant_tokens_key(&grant);
  let index_ttl = pttl_ms(&mut conn, &index_key).await?;
  if index_ttl <= access_ttl.as_millis() as i64 {
    return Err(TestError::Unexpected(
      "grant index must outlive the access-token TTL".to_owned(),
    ));
  }
  assert_ttl_within(index_ttl, refresh_ttl)?;

  // Simulate the index having expired: the rotation script must re-arm it
  // rather than recreate it persistent.
  let _: () = redis::cmd("DEL")
    .arg(&index_key)
    .query_async(&mut conn)
    .await?;
  let outcome = tokens::rotate(
    &mut conn,
    &store,
    pepper,
    &rotation_input(&old, &client, &new_refresh, &new_access, &grant, None),
  )
  .await?;
  if !matches!(outcome, tokens::RotateOutcome::Rotated { .. }) {
    return Err(TestError::Unexpected("rotation must apply".to_owned()));
  }
  assert_ttl_within(pttl_ms(&mut conn, &index_key).await?, refresh_ttl)?;

  let request_id = tokens::derive_rotation_id(pepper, &old)?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.rotation_map_key(&request_id)).await?,
    rotation_grace.min(refresh_ttl),
  )?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.refresh_key(&old)).await?,
    refresh_ttl,
  )
}

/// docs/REDIS.md: `oauth:{state}:session:<id>` lives under `ttl.session`
/// (12 h); a presession is the same record before login binds a subject.
#[tokio::test]
async fn store_session_and_presession_ttl_within_configured_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let session_ttl = TtlConfig::default().session;

  let session_id = unique("session");
  sessions::put(
    &mut conn,
    &store,
    &session_id,
    &sessions::SessionRecord {
      subject: "user-1".to_owned(),
      mfa_verified: true,
      restricted: false,
    },
    session_ttl,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.session_key(&session_id)).await?,
    session_ttl,
  )?;

  let presession_id = unique("presession");
  sessions::put(
    &mut conn,
    &store,
    &presession_id,
    &sessions::SessionRecord {
      subject: String::new(),
      mfa_verified: false,
      restricted: false,
    },
    session_ttl,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.session_key(&presession_id)).await?,
    session_ttl,
  )
}

/// docs/REDIS.md: `oauth:{state}:pending:<id>` is short, request-scoped
/// (`routes::PENDING_TTL`, 300 s).
#[tokio::test]
async fn store_pending_auth_ttl_within_request_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let request_id = unique("pending");

  pending::put(
    &mut conn,
    &store,
    &request_id,
    &pending::PendingAuth {
      client_id: unique("client"),
      redirect_uri: "https://client.example.test/cb".to_owned(),
      scope: "orders:read".to_owned(),
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
      state: Some("state-xyz".to_owned()),
      dpop_jkt: None,
      iss: "https://as.example.test".to_owned(),
      post_logout_uri: None,
    },
    crate::routes::PENDING_TTL,
  )
  .await?;
  assert_ttl_within(
    pttl_ms(&mut conn, &store.token_key("pending", &request_id)).await?,
    crate::routes::PENDING_TTL,
  )
}

/// docs/REDIS.md: the failed-login counter lives under the lockout window
/// (`ui::login::LOCKOUT_WINDOW`, 15 min) and keys a hash of the account label.
#[tokio::test]
async fn store_login_failure_counter_ttl_within_lockout_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let window = crate::ui::login::LOCKOUT_WINDOW;
  let account = unique("alice@example.test");

  sessions::record_failed_login(&mut conn, &store, &account, window).await?;
  let key = store.login_fail_key(&sha256_hex(account.as_bytes()));
  assert_ttl_within(pttl_ms(&mut conn, &key).await?, window)
}

/// docs/REDIS.md: the DPoP and `private_key_jwt` replay markers are bounded by
/// the proof window ([`crate::jose::dpop::DPOP_JTI_TTL`] and the assertion
/// module's `JTI_TTL`, both 300 s).
#[tokio::test]
async fn store_replay_marker_ttl_within_proof_window() -> TestResult {
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;

  let dpop_ttl = crate::jose::dpop::DPOP_JTI_TTL;
  let jti = unique("jti");
  if !dcr::claim_dpop_jti(&mut conn, &store, &jti, dpop_ttl).await? {
    return Err(TestError::Unexpected(
      "first DPoP claim must win".to_owned(),
    ));
  }
  assert_ttl_within(
    pttl_ms(&mut conn, &store.dpop_jti_key(&jti)).await?,
    dpop_ttl,
  )?;

  let assertion_ttl = Duration::from_secs(300);
  let assertion = unique("assertion");
  if !dcr::claim_client_assertion_jti(&mut conn, &store, &assertion, assertion_ttl).await? {
    return Err(TestError::Unexpected(
      "first assertion claim must win".to_owned(),
    ));
  }
  assert_ttl_within(
    pttl_ms(&mut conn, &store.client_assertion_jti_key(&assertion)).await?,
    assertion_ttl,
  )
}

#[test]
fn store_keys_share_hash_tag_and_keyspaces_split() -> TestResult {
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  store.assert_keyspace_separation()?;
  for key in [
    store.code_key("h"),
    store.access_key("h"),
    store.refresh_key("h"),
    store.grant_key("g"),
    store.grant_tokens_key("g"),
    store.session_key("s"),
    store.par_key("p"),
    store.device_key("d"),
    store.user_code_key("u"),
    store.dcr_iat_key("i"),
    store.dpop_jti_key("j"),
    store.client_assertion_jti_key("j"),
    store.rotation_map_key("r"),
    store.login_fail_key("l"),
  ] {
    if !key.contains("{state}") {
      return Err(TestError::Unexpected(
        "token key must carry the {state} tag".to_owned(),
      ));
    }
  }
  if !store.ratelimit_key("b").contains("{rl}") {
    return Err(TestError::Unexpected(
      "counter key must carry the {rl} tag".to_owned(),
    ));
  }
  // Colliding prefixes are rejected so counters can never evict tokens.
  let colliding = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{state}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  if colliding.assert_keyspace_separation().is_ok() {
    return Err(TestError::Unexpected(
      "colliding keyspaces must be rejected".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn store_durability_selected_from_topology() -> TestResult {
  // Single-node topologies must barrier on WAITAOF, never WAIT.
  let single = RawRedisConfig {
    url: Some("redis://127.0.0.1:6379".to_owned()),
    durability: Some(DurabilityMode::Wait),
    ..Default::default()
  };
  if RedisConfig::from_raw(single).is_ok() {
    return Err(TestError::Unexpected(
      "single-node WAIT must be rejected".to_owned(),
    ));
  }
  let single = RawRedisConfig {
    url: Some("redis://127.0.0.1:6379".to_owned()),
    durability: Some(DurabilityMode::WaitAof),
    ..Default::default()
  };
  let config = RedisConfig::from_raw(single)?;
  if Store::from_config(&config).durability() != DurabilityMode::WaitAof {
    return Err(TestError::Unexpected(
      "single-node store must barrier on WAITAOF".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn store_rotation_id_deterministic_per_old_token() -> TestResult {
  let pepper = b"store-test-pepper";
  let first = tokens::derive_rotation_id(pepper, "old-hash")?;
  let second = tokens::derive_rotation_id(pepper, "old-hash")?;
  if first != second || first.is_empty() {
    return Err(TestError::Unexpected(
      "rotation id must be deterministic".to_owned(),
    ));
  }
  if tokens::derive_rotation_id(pepper, "other-hash")? == first {
    return Err(TestError::Unexpected(
      "rotation id must differ per token".to_owned(),
    ));
  }
  if tokens::derive_rotation_id(b"other-pepper", "old-hash")? == first {
    return Err(TestError::Unexpected(
      "rotation id must differ per pepper".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn store_error_classification_and_retry_scope() -> TestResult {
  let transient_io = redis::RedisError::from(std::io::Error::new(
    std::io::ErrorKind::TimedOut,
    "timed out",
  ));
  let loading = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::BusyLoading),
    "busy",
  ));
  let try_again = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::TryAgain),
    "retry",
  ));
  let master_down = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::MasterDown),
    "down",
  ));
  let cluster_down = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::ClusterDown),
    "down",
  ));
  for error in [
    &transient_io,
    &loading,
    &try_again,
    &master_down,
    &cluster_down,
  ] {
    if classify_redis(error) != ErrorClass::Transient {
      return Err(TestError::Unexpected(
        "expected a transient class".to_owned(),
      ));
    }
    if !may_retry_op(OpClass::IdempotentRead, error)
      || !may_retry_op(OpClass::ConditionalWrite, error)
      || may_retry_op(OpClass::NonIdempotent, error)
    {
      return Err(TestError::Unexpected(
        "retry scope must exclude non-idempotent ops".to_owned(),
      ));
    }
  }

  let cross_slot = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::CrossSlot),
    "slot",
  ));
  let readonly = redis::RedisError::from((
    redis::ErrorKind::Server(redis::ServerErrorKind::ReadOnly),
    "ro",
  ));
  let type_error = redis::RedisError::from((redis::ErrorKind::UnexpectedReturnType, "type"));
  let auth = redis::RedisError::from((redis::ErrorKind::AuthenticationFailed, "auth"));
  for error in [&cross_slot, &readonly, &type_error, &auth] {
    if classify_redis(error) != ErrorClass::Permanent {
      return Err(TestError::Unexpected(
        "expected a permanent class".to_owned(),
      ));
    }
    if may_retry_op(OpClass::IdempotentRead, error) {
      return Err(TestError::Unexpected(
        "permanent errors must never retry".to_owned(),
      ));
    }
  }

  // Server-extension codes (`OOM`, ...) classify by code: fail closed.
  let oom_value = redis::parse_redis_value(b"-OOM command not allowed\r\n");
  match oom_value {
    Ok(redis::Value::ServerError(server)) => {
      let error = redis::RedisError::from(server);
      if classify_redis(&error) != ErrorClass::Permanent {
        return Err(TestError::Unexpected("OOM must fail closed".to_owned()));
      }
    }
    _ => {
      return Err(TestError::Unexpected(
        "expected an OOM server error value".to_owned(),
      ));
    }
  }
  Ok(())
}

#[tokio::test]
async fn store_retry_budget_bounds_idempotent_reads() -> TestResult {
  use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
  static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
  ATTEMPTS.store(0, AtomicOrdering::Relaxed);
  let (_container, url) = redis_container(Vec::new()).await?;
  let (mut _conn, store) = direct_store(&url, DurabilityMode::WaitAof).await?;
  let outcome: Result<(), redis::RedisError> = retry_op!(&mut _conn, store.retry_budget(), async {
    ATTEMPTS.fetch_add(1, AtomicOrdering::Relaxed);
    Err::<(), redis::RedisError>(redis::RedisError::from((
      redis::ErrorKind::Server(redis::ServerErrorKind::CrossSlot),
      "slot",
    )))
  });
  match outcome {
    Err(error)
      if classify_redis(&error) == ErrorClass::Permanent
        && ATTEMPTS.load(AtomicOrdering::Relaxed) == 1 => {}
    _ => {
      return Err(TestError::Unexpected(
        "permanent errors must not retry".to_owned(),
      ));
    }
  }
  Ok(())
}

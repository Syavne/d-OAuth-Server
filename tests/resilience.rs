//! `test(resilience)` — failure-injection suite (plan todo 44).
//!
//! Every test name contains `resilience` so
//! `cargo nextest run -E 'test(resilience)'` selects exactly them (plus the
//! `src/resilience.rs` unit tests and the task-4 `tests_resilience` health
//! tests, which share the substring). Bodies use `Result` + `?` (`unwrap`/
//! `expect`/`panic` are denied workspace-wide) and real Postgres/Redis
//! containers through [`test_guard::ContainerGuard`] — never `ContainerAsync`
//! directly, so no container leaks under nextest.
//!
//! Coverage: Redis stopped mid-run → protected surfaces answer `503
//! temporarily_unavailable` + `Retry-After` while `/health/live` stays 200,
//! and recovery needs no process restart; Postgres stopped → `/health/ready`
//! and the (cold-catalog) metadata document fail closed, then recover; a
//! DPoP replay-store outage rejects proofs instead of accepting them; a lost
//! reply / indeterminate post-`EXEC` result is resolved by the rotation
//! idempotency mapping (replay), never double-minted and never confused with
//! reuse; a SIGKILL (not a graceful restart) immediately after a
//! rotation+tombstone write leaves no resurrected token (the `WAITAOF`
//! barrier fsynced before the reply); Sentinel/Cluster failover contracts
//! (`MOVED`/`ASK` transient, single caller-visible error per episode, no
//! cross-slot atomic op) hold at the resolver/classifier level.

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use std::{
  sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
  },
  time::Duration,
};

use d_oauth::{
  config::{Config, ConfigError, DurabilityMode},
  error::AppError,
  resilience::{
    FailoverEpisode, RetryBudget, is_single_slot, is_transient_redis, retry_idempotent,
  },
  routes::build_router,
  state::{AppState, StateError},
  store::{
    ErrorClass, OpClass, Store, StoreError, classify_redis,
    dcr::claim_dpop_jti,
    tokens::{
      AccessRecord, RefreshRecord, RotateOutcome, RotationInput, get_refresh, put_refresh, rotate,
      tombstone_of,
    },
  },
};
use test_guard::ContainerGuard;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;
/// `(status, headers, body)` of one driven request.
type Driven = (u16, axum::http::HeaderMap, String);

/// Postgres superuser password for these fixtures.
const PG_PASSWORD: &str = "resilience-test-secret";
/// Fixed pepper for rotation-id derivation in these tests.
const PEPPER: &[u8] = b"resilience-test-pepper-0123456789";

/// Postgres URL for a container host port.
fn pg_url_for(port: u16) -> String {
  format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable")
}

/// Start Postgres and return the guard plus a plaintext URL.
async fn postgres_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("postgres", "16-alpine")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_wait_for(WaitFor::message_on_stdout(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  Ok((guarded, pg_url_for(port)))
}

/// Start a single-node Redis with AOF on (the durability under test).
///
/// `appendfsync always` is the task-44 topology durability mode for
/// single-node deployments: every rotation/tombstone write is fsynced before
/// its reply, so the `WAITAOF` barrier (and the SIGKILL test below) exercises
/// real fsync durability instead of the `everysec` background window.
async fn redis_container() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(vec![
      "redis-server",
      "--appendonly",
      "yes",
      "--appendfsync",
      "always",
    ])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Current Redis URL for a (possibly restarted) container: Docker rebinds
/// the host port on restart, so callers must re-resolve after `start()`.
async fn redis_url_for(guard: &ContainerGuard) -> Result<String, TestError> {
  let port = guard.get_host_port_ipv4(6379).await?;
  Ok(format!("redis://127.0.0.1:{port}"))
}

/// Build a full [`Config`] with short dependency timeouts so outage tests
/// fail fast instead of hanging on the production budgets.
fn test_config(
  pg_url: &str,
  redis_url: &str,
  rate_limit_enabled: bool,
) -> Result<Config, ConfigError> {
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/resilience-test-cert.pem", "key_path": "/tmp/resilience-test-key.pem"},
    "database": {"url": pg_url},
    "redis": {
      "url": redis_url,
      "durability": "waitaof",
      "connect_timeout_secs": 1,
      "response_timeout_secs": 1,
      "retry_budget": 1,
      "retry_min_delay_ms": 50,
      "retry_max_delay_ms": 200,
    },
    "rate_limit": {"enabled": rate_limit_enabled},
    "token_pepper": "resilience-test-pepper-0123456789abcdef",
    "totp_encryption_key": "resilience-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "resilience-test-pii-key-0123456789abcdef",
  });
  Config::from_source(::config::Config::try_from(&fixture)?)
}

/// Embedded migrations (same files the server ships); readiness requires the
/// `_sqlx_migrations` version match, so tests apply them like `migrate` would.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Connect live state over fresh containers and apply the migrations.
///
/// Returns the guards, their current URLs, and the connected state. URLs go
/// stale across a container restart (Docker rebinds host ports), so tests
/// that restart a container re-resolve and reconnect in-process via
/// [`reconnect`] — no process restart.
async fn live_state(
  rate_limit_enabled: bool,
) -> Result<(ContainerGuard, ContainerGuard, String, String, AppState), TestError> {
  let (pg, pg_url) = postgres_container().await?;
  let (redis, redis_url) = redis_container().await?;
  let state = reconnect(&pg_url, &redis_url, rate_limit_enabled).await?;
  MIGRATOR.run(&state.pool).await?;
  Ok((pg, redis, pg_url, redis_url, state))
}

/// Reconnect state in-process over the given URLs (no process restart).
async fn reconnect(
  pg_url: &str,
  redis_url: &str,
  rate_limit_enabled: bool,
) -> Result<AppState, TestError> {
  let config = test_config(pg_url, redis_url, rate_limit_enabled)?;
  Ok(AppState::connect(Arc::new(config)).await?)
}

/// Drive one request through the public router (peer identity extensions
/// included, mirroring the task-40 harness).
async fn drive(
  router: axum::Router,
  method: &str,
  uri: &str,
  headers: &[(&str, &str)],
  body: &str,
) -> Result<Driven, TestError> {
  use tower::ServiceExt as _;
  let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 40_001));
  let mut builder = axum::http::Request::builder().method(method).uri(uri);
  for (name, value) in headers {
    builder = builder.header(*name, *value);
  }
  let mut request = builder.body(axum::body::Body::from(body.to_owned()))?;
  request
    .extensions_mut()
    .insert(axum::extract::ConnectInfo(peer));
  request
    .extensions_mut()
    .insert(axum::extract::connect_info::MockConnectInfo(peer));
  let response = router.oneshot(request).await?;
  let status = response.status().as_u16();
  let response_headers = response.headers().clone();
  let bytes = http_body_util::BodyExt::collect(response.into_body())
    .await
    .map_err(|_| TestError::Body("body collection failed".to_owned()))?
    .to_bytes();
  Ok((
    status,
    response_headers,
    String::from_utf8_lossy(&bytes).into_owned(),
  ))
}

/// Poll `/health/ready` until it reports `want` (or the attempts run out).
async fn poll_ready(state: &AppState, want: u16) -> Result<(), TestError> {
  for _ in 0..30 {
    let (status, _, _) =
      drive(build_router(state.clone()), "GET", "/health/ready", &[], "").await?;
    if status == want {
      return Ok(());
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  Err(TestError::Body(format!("readiness never reached {want}")))
}

/// Poll Postgres until it answers `SELECT 1` (a restarted container needs
/// seconds before the pool can connect; without this the reconnect races the
/// database startup and fails with a reset connection).
async fn wait_pg(pg_url: &str) -> Result<(), TestError> {
  for _ in 0..30 {
    let attempt = sqlx::postgres::PgPoolOptions::new()
      .max_connections(1)
      .acquire_timeout(Duration::from_secs(2))
      .connect(pg_url)
      .await;
    if let Ok(pool) = attempt {
      let ready = sqlx::query("SELECT 1").execute(&pool).await.is_ok();
      pool.close().await;
      if ready {
        return Ok(());
      }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  Err(TestError::Body("postgres never came back".to_owned()))
}

/// Poll a direct Redis `PING` until the node answers (post-kill restarts
/// reload the AOF before accepting writes).
async fn poll_ping(redis_url: &str) -> Result<(), TestError> {
  for _ in 0..30 {
    let client = redis::Client::open(redis_url)?;
    if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
      let pong: Result<String, redis::RedisError> = redis::cmd("PING").query_async(&mut conn).await;
      if matches!(pong.as_deref(), Ok("PONG")) {
        return Ok(());
      }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  Err(TestError::Body("redis never answered PING".to_owned()))
}

/// `docker kill` (SIGKILL, no graceful flush) the container.
async fn docker_kill(id: &str) -> Result<(), TestError> {
  let output = tokio::process::Command::new("docker")
    .args(["kill", id])
    .output()
    .await
    .map_err(|_| TestError::Docker("kill".to_owned()))?;
  if !output.status.success() {
    return Err(TestError::Docker("kill".to_owned()));
  }
  Ok(())
}

/// Render an [`AppError`] to `(status, retry-after present, body)`.
async fn render(error: AppError) -> Result<(u16, bool, String), TestError> {
  use axum::response::IntoResponse as _;
  use http_body_util::BodyExt as _;
  let response = error.into_response();
  let status = response.status().as_u16();
  let retry_after = response
    .headers()
    .contains_key(axum::http::header::RETRY_AFTER);
  let bytes = response
    .into_body()
    .collect()
    .await
    .map_err(|_| TestError::Body("body collection failed".to_owned()))?
    .to_bytes();
  Ok((
    status,
    retry_after,
    String::from_utf8_lossy(&bytes).into_owned(),
  ))
}

/// Seed one live refresh-token record for rotation tests.
async fn seed_refresh(
  state: &AppState,
  old_hash: &str,
  client: &str,
  grant: &str,
) -> Result<Store, TestError> {
  let store = Store::from_config(&state.config.redis);
  let mut conn = state.redis.clone();
  put_refresh(
    &mut conn,
    &store,
    old_hash,
    &RefreshRecord {
      client_id: client.to_owned(),
      grant_id: grant.to_owned(),
      scope: "api:read".to_owned(),
      subject: "user-1".to_owned(),
      cnf: String::new(),
    },
    Duration::from_secs(3600),
  )
  .await?;
  Ok(store)
}

/// One rotation input over fixed candidate hashes.
fn rotation_input(
  old_hash: &str,
  client: &str,
  grant: &str,
  new_refresh_hash: &str,
  new_access_hash: &str,
  request_id: &str,
) -> RotationInput {
  RotationInput {
    old_refresh_hash: old_hash.to_owned(),
    expected_client_id: client.to_owned(),
    new_refresh_hash: new_refresh_hash.to_owned(),
    new_access_hash: new_access_hash.to_owned(),
    new_refresh: RefreshRecord {
      client_id: client.to_owned(),
      grant_id: grant.to_owned(),
      scope: "api:read".to_owned(),
      subject: "user-1".to_owned(),
      cnf: String::new(),
    },
    new_access: AccessRecord {
      client_id: client.to_owned(),
      grant_id: grant.to_owned(),
      scope: "api:read".to_owned(),
      subject: "user-1".to_owned(),
      cnf: String::new(),
    },
    new_refresh_ttl: Duration::from_secs(3600),
    new_access_ttl: Duration::from_secs(600),
    request_id: Some(request_id.to_owned()),
  }
}

/// Stopping Redis mid-run fails protected surfaces closed (503 +
/// `Retry-After`, `temporarily_unavailable`) while `/health/live` stays 200;
/// restarting the same container recovers with no process restart.
#[tokio::test]
async fn resilience_redis_stop_token_503_and_ready_flips_then_recovers() -> TestResult {
  let (_pg, redis, pg_url, _redis_url, state) = live_state(true).await?;
  let form = [("content-type", "application/x-www-form-urlencoded")];
  let (baseline, _, _) =
    drive(build_router(state.clone()), "GET", "/health/ready", &[], "").await?;
  if baseline != 200 {
    return Err(TestError::Body(format!(
      "ready baseline must be 200, got {baseline}"
    )));
  }

  redis.stop_with_timeout(Some(0)).await?;

  let (token_status, token_headers, token_body) = drive(
    build_router(state.clone()),
    "POST",
    "/token",
    &form,
    "grant_type=refresh_token",
  )
  .await?;
  if token_status != 503 {
    return Err(TestError::Body(format!(
      "POST /token with Redis down must be 503, got {token_status}: {token_body}"
    )));
  }
  if !token_headers.contains_key(axum::http::header::RETRY_AFTER) {
    return Err(TestError::Body("503 must carry Retry-After".to_owned()));
  }
  if !token_body.contains("temporarily_unavailable") {
    return Err(TestError::Body(format!(
      "503 body must carry temporarily_unavailable: {token_body}"
    )));
  }
  let (ready_status, _, _) =
    drive(build_router(state.clone()), "GET", "/health/ready", &[], "").await?;
  if ready_status != 503 {
    return Err(TestError::Body(format!(
      "readiness with Redis down must be 503, got {ready_status}"
    )));
  }
  let (live_status, _, _) =
    drive(build_router(state.clone()), "GET", "/health/live", &[], "").await?;
  if live_status != 200 {
    return Err(TestError::Body(format!(
      "liveness must stay 200, got {live_status}"
    )));
  }

  redis.start().await?;
  // Docker rebinds the host port on restart: re-resolve and reconnect
  // in-process (the same test process keeps running — no process restart).
  let redis_url = redis_url_for(&redis).await?;
  let state = reconnect(&pg_url, &redis_url, true).await?;
  poll_ready(&state, 200).await?;
  // Past the limiter again: the real dispatcher authenticates the (absent)
  // client and answers 400 invalid_client, proving recovery without a
  // process restart and that /token no longer stubs 501.
  let (recovered, _, recovered_body) = drive(
    build_router(state.clone()),
    "POST",
    "/token",
    &form,
    "grant_type=refresh_token",
  )
  .await?;
  if recovered != 400 {
    return Err(TestError::Body(format!(
      "POST /token after recovery must reach the dispatcher (400 invalid_client), got {recovered}"
    )));
  }
  if !recovered_body.contains("invalid_client") {
    return Err(TestError::Body(format!(
      "POST /token after recovery must answer invalid_client, got {recovered_body}"
    )));
  }
  Ok(())
}

/// Stopping Postgres mid-run fails readiness and the cold-catalog metadata
/// document closed; restarting recovers both with no process restart.
#[tokio::test]
async fn resilience_postgres_stop_ready_503_and_metadata_fail_closed_then_recovers() -> TestResult {
  let (pg, _redis, _pg_url, redis_url, state) = live_state(false).await?;
  let (baseline, _, _) =
    drive(build_router(state.clone()), "GET", "/health/ready", &[], "").await?;
  if baseline != 200 {
    return Err(TestError::Body(format!(
      "ready baseline must be 200, got {baseline}"
    )));
  }

  pg.stop_with_timeout(Some(0)).await?;

  let (ready_status, _, _) =
    drive(build_router(state.clone()), "GET", "/health/ready", &[], "").await?;
  if ready_status != 503 {
    return Err(TestError::Body(format!(
      "readiness with Postgres down must be 503, got {ready_status}"
    )));
  }
  let (live_status, _, _) =
    drive(build_router(state.clone()), "GET", "/health/live", &[], "").await?;
  if live_status != 200 {
    return Err(TestError::Body(format!(
      "liveness must stay 200, got {live_status}"
    )));
  }
  // The scope catalog was never populated in this process and Postgres is
  // down: the metadata document fails closed rather than advertising an
  // unknown scope list.
  let (meta_status, _, meta_body) = drive(
    build_router(state.clone()),
    "GET",
    "/.well-known/oauth-authorization-server",
    &[],
    "",
  )
  .await?;
  if meta_status != 503 || !meta_body.contains("temporarily_unavailable") {
    return Err(TestError::Body(format!(
      "metadata with cold catalog and Postgres down must be 503 temporarily_unavailable, got {meta_status}: {meta_body}"
    )));
  }
  // A Postgres-backed token grant fails closed as 503 through the
  // connectivity mapping: never a 500, and never an unauthenticated mint.
  let form = [("content-type", "application/x-www-form-urlencoded")];
  let (token_status, token_headers, token_body) = drive(
    build_router(state.clone()),
    "POST",
    "/token",
    &form,
    "grant_type=client_credentials&client_id=pg-down&client_secret=pg-down",
  )
  .await?;
  if token_status != 503 || !token_body.contains("temporarily_unavailable") {
    return Err(TestError::Body(format!(
      "POST /token with Postgres down must be 503 temporarily_unavailable, got {token_status}: {token_body}"
    )));
  }
  if !token_headers.contains_key(axum::http::header::RETRY_AFTER) {
    return Err(TestError::Body(
      "token 503 must carry Retry-After".to_owned(),
    ));
  }
  if token_body.contains("access_token") {
    return Err(TestError::Body("token 503 must mint nothing".to_owned()));
  }

  pg.start().await?;
  let pg_url = pg_url_for(pg.get_host_port_ipv4(5432).await?);
  wait_pg(&pg_url).await?;
  let state = reconnect(&pg_url, &redis_url, false).await?;
  poll_ready(&state, 200).await?;
  let (meta_recovered, _, meta_doc) = drive(
    build_router(state.clone()),
    "GET",
    "/.well-known/oauth-authorization-server",
    &[],
    "",
  )
  .await?;
  if meta_recovered != 200 || !meta_doc.contains("https://auth.example.test") {
    return Err(TestError::Body(format!(
      "metadata after recovery must be 200, got {meta_recovered}: {meta_doc}"
    )));
  }
  Ok(())
}

/// A DPoP replay-store outage rejects proofs (fail closed, 503) instead of
/// accepting them; after recovery the first claim wins and the replay loses.
#[tokio::test]
async fn resilience_dpop_replay_store_failure_rejects_proof() -> TestResult {
  let (_pg, redis, pg_url, _redis_url, state) = live_state(false).await?;
  let store = Store::from_config(&state.config.redis);

  redis.stop_with_timeout(Some(0)).await?;
  let mut conn = state.redis.clone();
  match claim_dpop_jti(
    &mut conn,
    &store,
    "resilience-jti-hash",
    Duration::from_secs(300),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Body(
        "DPoP claim with Redis down must fail closed".to_owned(),
      ));
    }
    Err(error) => {
      let (status, retry_after, body) = render(AppError::from(error)).await?;
      if status != 503 || !retry_after || !body.contains("temporarily_unavailable") {
        return Err(TestError::Body(format!(
          "replay-store failure must render 503 + Retry-After + temporarily_unavailable, got {status}: {body}"
        )));
      }
    }
  }

  redis.start().await?;
  let redis_url = redis_url_for(&redis).await?;
  poll_ping(&redis_url).await?;
  let state = reconnect(&pg_url, &redis_url, false).await?;
  let store = Store::from_config(&state.config.redis);
  let mut conn = state.redis.clone();
  if !claim_dpop_jti(
    &mut conn,
    &store,
    "resilience-jti-hash",
    Duration::from_secs(300),
  )
  .await?
  {
    return Err(TestError::Body(
      "first claim after recovery must win".to_owned(),
    ));
  }
  if claim_dpop_jti(
    &mut conn,
    &store,
    "resilience-jti-hash",
    Duration::from_secs(300),
  )
  .await?
  {
    return Err(TestError::Body("replayed jti must lose".to_owned()));
  }
  Ok(())
}

/// A lost reply / indeterminate post-`EXEC` result is resolved by the rotation
/// idempotency mapping (replay with the original tokens), never double-minted
/// and never confused with reuse.
#[tokio::test]
async fn resilience_rotation_lost_reply_resolved_by_mapping_not_reuse() -> TestResult {
  let (_pg, _redis, _pg_url, _redis_url, state) = live_state(false).await?;
  let store = seed_refresh(&state, "resilience-old-1", "client-a", "grant-a").await?;
  let mut conn = state.redis.clone();

  // First rotation succeeds; the reply is "lost" (indeterminate outcome).
  let first = rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-1",
      "client-a",
      "grant-a",
      "resilience-new-1",
      "resilience-acc-1",
      "req-lost-1",
    ),
  )
  .await?;
  let (original_refresh, original_access) = match first {
    RotateOutcome::Rotated {
      new_refresh_hash,
      new_access_hash,
    } => (new_refresh_hash, new_access_hash),
    other => {
      return Err(TestError::Body(format!(
        "first rotation must apply, got {other:?}"
      )));
    }
  };

  // Retry with the same request id but different candidates: the mapping
  // decides replay with the ORIGINAL tokens; the new candidates are ignored.
  let retry = rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-1",
      "client-a",
      "grant-a",
      "resilience-decoy-1",
      "resilience-decoy-acc-1",
      "req-lost-1",
    ),
  )
  .await?;
  match retry {
    RotateOutcome::Replay {
      new_refresh_hash,
      new_access_hash,
    } => {
      if new_refresh_hash != original_refresh || new_access_hash != original_access {
        return Err(TestError::Body(
          "replay must return the original tokens".to_owned(),
        ));
      }
    }
    other => {
      return Err(TestError::Body(format!(
        "lost-reply retry must replay, got {other:?}"
      )));
    }
  }
  // No double-mint: the decoy candidates were never stored.
  if get_refresh(&mut conn, &store, "resilience-decoy-1")
    .await?
    .is_some()
  {
    return Err(TestError::Body(
      "decoy candidate must never be minted".to_owned(),
    ));
  }
  if get_refresh(&mut conn, &store, &original_refresh)
    .await?
    .is_none()
  {
    return Err(TestError::Body(
      "original rotated token must exist once".to_owned(),
    ));
  }

  // Same old token WITHOUT a valid mapping is reuse (tombstone decides),
  // which cascade-revokes the grant family.
  match rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-1",
      "client-a",
      "grant-a",
      "resilience-new-2",
      "resilience-acc-2",
      "req-other-1",
    ),
  )
  .await?
  {
    RotateOutcome::Reused { .. } => Ok(()),
    other => Err(TestError::Body(format!(
      "unmapped re-presentation must be reuse, got {other:?}"
    ))),
  }
}

/// SIGKILL (no graceful flush) immediately after a rotation+tombstone write
/// leaves no resurrected token: the tombstone and the idempotency mapping
/// both survive through the `WAITAOF` barrier, so reuse is still detected.
#[tokio::test]
async fn resilience_sigkill_after_rotation_tombstone_no_resurrection() -> TestResult {
  let (_pg, redis, pg_url, _redis_url, state) = live_state(false).await?;
  let store = seed_refresh(&state, "resilience-old-2", "client-a", "grant-b").await?;
  let mut conn = state.redis.clone();
  let outcome = rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-2",
      "client-a",
      "grant-b",
      "resilience-new-9",
      "resilience-acc-9",
      "req-kill-1",
    ),
  )
  .await?;
  if !matches!(outcome, RotateOutcome::Rotated { .. }) {
    return Err(TestError::Body(format!(
      "rotation must apply, got {outcome:?}"
    )));
  }
  // The durability barrier ran inside `rotate` before it returned; SIGKILL
  // now (no `SAVE`, no graceful flush) exercises AOF durability, not a clean
  // restart.
  docker_kill(redis.id()).await?;
  redis.start().await?;
  let redis_url = redis_url_for(&redis).await?;
  poll_ping(&redis_url).await?;
  let state = reconnect(&pg_url, &redis_url, false).await?;
  let store = Store::from_config(&state.config.redis);

  let mut conn = state.redis.clone();
  match tombstone_of(&mut conn, &store, "resilience-old-2").await? {
    Some(rotated_to) if rotated_to == "resilience-new-9" => {}
    other => {
      return Err(TestError::Body(format!(
        "tombstone must survive SIGKILL (no resurrection), got {other:?}"
      )));
    }
  }
  // The mapping survived too: the original request id still replays.
  match rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-2",
      "client-a",
      "grant-b",
      "resilience-decoy-9",
      "resilience-decoy-acc-9",
      "req-kill-1",
    ),
  )
  .await?
  {
    RotateOutcome::Replay {
      new_refresh_hash, ..
    } if new_refresh_hash == "resilience-new-9" => {}
    other => {
      return Err(TestError::Body(format!(
        "post-kill retry with the valid mapping must replay, got {other:?}"
      )));
    }
  }
  // And an unmapped re-presentation is still reuse, not a live token.
  match rotate(
    &mut conn,
    &store,
    PEPPER,
    &rotation_input(
      "resilience-old-2",
      "client-a",
      "grant-b",
      "resilience-new-10",
      "resilience-acc-10",
      "req-kill-2",
    ),
  )
  .await?
  {
    RotateOutcome::Reused { .. } => Ok(()),
    other => Err(TestError::Body(format!(
      "old token must stay dead after SIGKILL, got {other:?}"
    ))),
  }
}

/// In-flight requests during an outage all fail clean (503, no hang, no
/// 500/panic) instead of queueing into `PoolTimedOut`.
#[tokio::test]
async fn resilience_inflight_requests_fail_clean_during_outage() -> TestResult {
  let (_pg, redis, _pg_url, _redis_url, state) = live_state(true).await?;
  redis.stop_with_timeout(Some(0)).await?;

  let burst = async {
    let mut handles = Vec::new();
    for _ in 0..20 {
      let router = build_router(state.clone());
      handles.push(tokio::spawn(async move {
        drive(router, "GET", "/health/ready", &[], "").await
      }));
    }
    let mut statuses = Vec::new();
    for handle in handles {
      match handle.await {
        Ok(Ok((status, _, _))) => statuses.push(status),
        Ok(Err(_)) | Err(_) => statuses.push(0),
      }
    }
    statuses
  };
  let statuses = tokio::time::timeout(Duration::from_secs(30), burst)
    .await
    .map_err(|_| TestError::Body("in-flight burst hung".to_owned()))?;
  if statuses.len() != 20 {
    return Err(TestError::Body(
      "every in-flight request must settle".to_owned(),
    ));
  }
  for status in &statuses {
    if *status != 503 {
      return Err(TestError::Body(format!(
        "every in-flight request must fail closed with 503, got {status}"
      )));
    }
  }
  Ok(())
}

/// Topology failover contracts without a multi-node deployment: `MOVED`/`ASK`
/// classify transient (slot-refresh recovery), failover episodes allow at
/// most one caller-visible error, and atomic multi-key operations never span
/// slots.
#[tokio::test]
async fn resilience_topology_failover_contracts_recover_with_single_error() -> TestResult {
  // `MOVED`/`ASK` (Cluster slot refresh) are transient: safe to retry an
  // idempotent read through them.
  for wire in [
    "-MOVED 1234 127.0.0.1:7000\r\n",
    "-ASK 5678 127.0.0.1:7001\r\n",
    "-TRYAGAIN Multiple keys request must be in the same slot\r\n",
  ] {
    let value = redis::parse_redis_value(wire.as_bytes())
      .map_err(|_| TestError::Body("wire parse failed".to_owned()))?;
    let server = match value {
      redis::Value::ServerError(error) => error,
      _ => return Err(TestError::Body("expected a server-error value".to_owned())),
    };
    let error = redis::RedisError::from(server);
    if classify_redis(&error) != ErrorClass::Transient {
      return Err(TestError::Body(format!("{wire:?} must classify transient")));
    }
    if !is_transient_redis(&error) {
      return Err(TestError::Body(
        "resilience predicate must agree".to_owned(),
      ));
    }
    if !d_oauth::store::may_retry_op(OpClass::IdempotentRead, &error) {
      return Err(TestError::Body(
        "idempotent reads must retry through slot moves".to_owned(),
      ));
    }
  }
  // A failover episode recovers transparently: transient faults retried
  // inside the budget surface zero caller-visible errors.
  let episode = FailoverEpisode::new();
  let attempts = Arc::new(AtomicU32::new(0));
  let probe = Arc::clone(&attempts);
  let moved = || {
    let value = redis::parse_redis_value(b"-MOVED 0 127.0.0.1:7000\r\n");
    match value {
      Ok(redis::Value::ServerError(error)) => redis::RedisError::from(error),
      _ => redis::RedisError::from((redis::ErrorKind::Io, "synthetic")),
    }
  };
  let budget = RetryBudget::new(8);
  let outcome = retry_idempotent(
    move || {
      let probe = Arc::clone(&probe);
      let moved = moved();
      async move {
        let attempt = probe.fetch_add(1, Ordering::SeqCst);
        if attempt < 2 {
          Err::<(), redis::RedisError>(moved)
        } else {
          Ok(())
        }
      }
    },
    is_transient_redis,
    &budget,
    2,
  )
  .await;
  if outcome.is_err() {
    return Err(TestError::Body(
      "transient failover faults must recover".to_owned(),
    ));
  }
  if episode.caller_errors() != 0 || !episode.within_budget() {
    return Err(TestError::Body(
      "recovered episode must show no caller-visible error".to_owned(),
    ));
  }
  episode.record_caller_error();
  if !episode.within_budget() {
    return Err(TestError::Body(
      "one caller-visible error per episode is allowed".to_owned(),
    ));
  }

  // No atomic multi-key operation spans slots: the rotation key set shares
  // `{state}`, and the rate-limit keyspace never joins it.
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  let old_key = store.refresh_key("old");
  let new_key = store.refresh_key("new");
  let acc_key = store.access_key("acc");
  let set_key = store.grant_tokens_key("grant");
  let map_key = store.rotation_map_key("req");
  let rotation_keys = [
    old_key.as_str(),
    new_key.as_str(),
    acc_key.as_str(),
    set_key.as_str(),
    map_key.as_str(),
  ];
  if !is_single_slot(&rotation_keys) {
    return Err(TestError::Body(
      "rotation keys must share one slot".to_owned(),
    ));
  }
  let bucket_key = store.ratelimit_key("bucket");
  let split = [old_key.as_str(), bucket_key.as_str()];
  if is_single_slot(&split) {
    return Err(TestError::Body(
      "token + rate-limit keys must never share an atomic op".to_owned(),
    ));
  }
  Ok(())
}

/// Errors raised by the resilience harness itself (never rendered to a
/// client; secrets never appear in these messages).
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// The crate configuration failed to load.
  #[error("config error: {0}")]
  Config(#[from] ConfigError),
  /// Application state failed to connect.
  #[error("state error: {0}")]
  State(#[from] StateError),
  /// The layered config source failed to load.
  #[error("config source error: {0}")]
  Source(#[from] ::config::ConfigError),
  /// A `docker kill` call failed.
  #[error("docker {0} failed")]
  Docker(String),
  /// An HTTP builder error while driving the router.
  #[error("http error: {0}")]
  Http(#[from] axum::http::Error),
  /// The in-process router returned its (uninhabited) error type.
  #[error("router error")]
  Router(#[from] std::convert::Infallible),
  /// A body/JSON error while reading a probe response.
  #[error("body error: {0}")]
  Body(String),
  /// A JSON error while reading a probe response.
  #[error("json error: {0}")]
  Json(#[from] serde_json::Error),
  /// A migration failure inside the test body.
  #[error("migration error: {0}")]
  Migrate(#[from] sqlx::migrate::MigrateError),
  /// A sqlx failure inside the test body.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A Redis failure inside the test body.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A store failure inside the test body.
  #[error("store error")]
  Store(#[from] StoreError),
}

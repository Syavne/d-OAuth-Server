//! `test(health)` topology suite: single, Sentinel, Cluster.
//!
//! Every topology spins real containers and proves the same contract:
//! `RedisConn` builds from the topology, `/health/live` is 200,
//! `/health/ready` is 200 once migrated, and the pool options match the
//! configured values.

use std::{sync::Arc, time::Duration};

use testcontainers::{GenericImage, ImageExt, core::WaitFor, runners::AsyncRunner};

use super::{
  AppState,
  test_support::{
    TestError, TestResult, get_health, mark_migrated, postgres_container, redis_single_container,
    single_redis_block, test_config,
  },
};
use crate::test_guard::ContainerGuard;

/// Single node: ready 200, live 200, pool counts match the config.
#[tokio::test]
async fn health_ready_single_reports_ready() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;

  assert_eq!(state.redis.topology_name(), "single");
  assert_eq!(state.pool.options().get_max_connections(), 15);
  assert_eq!(state.pool.options().get_min_connections(), 2);
  assert_eq!(
    state.pool.options().get_acquire_timeout(),
    Duration::from_secs(3)
  );
  assert_eq!(
    state.pool.options().get_idle_timeout(),
    Some(Duration::from_secs(300))
  );
  assert_eq!(
    state.pool.options().get_max_lifetime(),
    Some(Duration::from_secs(1800))
  );
  assert!(state.pool.options().get_test_before_acquire());
  // `connect_with` eagerly opens at least one connection; the exact eager
  // count is a sqlx internal, so only the configured bounds are pinned here.
  assert!((1..=15).contains(&state.pool.size()));

  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, ready_body) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 200);
  assert_eq!(
    ready_body.get("status").and_then(|v| v.as_str()),
    Some("ready")
  );
  Ok(())
}

/// Single node with AUTH: the mounted-file password is injected into the URL.
#[tokio::test]
async fn health_single_uses_password_from_config() -> TestResult {
  let secret = "health-redis-pw-9f2";
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(Some(secret)).await?;
  let pw_path = std::env::temp_dir().join("d-oauth-health-redis-pw.txt");
  std::fs::write(&pw_path, format!("{secret}\n"))
    .map_err(|_| TestError::Body("pw write".into()))?;
  let redis_block = serde_json::json!({
    "url": redis_url,
    "durability": "waitaof",
    "aof_required": false,
    "password_file": pw_path.to_string_lossy(),
  });
  let config = test_config(&pg_url, redis_block)?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;
  let (ready_status, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(ready_status, 200);
  let _ = std::fs::remove_file(&pw_path);
  Ok(())
}

/// Start a Sentinel pair: `master` serves data, `sentinel` monitors it.
/// Returns the guards plus the sentinel bridge address.
async fn sentinel_pair() -> Result<(ContainerGuard, ContainerGuard, String), TestError> {
  let master = ContainerGuard::new(
    GenericImage::new("redis", "7.2-alpine")
      .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
      .with_cmd(["redis-server", "--port", "6379", "--appendonly", "yes"])
      .start()
      .await?,
  );
  let master_ip = master.get_bridge_ip_address().await?;
  let sentinel_conf = format!(
    "port 26379\nsentinel monitor mymaster {master_ip} 6379 1\n\
     sentinel down-after-milliseconds mymaster 1500\n\
     sentinel failover-timeout mymaster 5000\ndir /tmp\n"
  );
  let script = format!(
    "printf '%s' '{sentinel_conf}' > /tmp/sentinel.conf && exec redis-sentinel /tmp/sentinel.conf"
  );
  let sentinel = ContainerGuard::new(
    GenericImage::new("redis", "7.2-alpine")
      .with_wait_for(WaitFor::message_on_stdout("+monitor master"))
      .with_cmd(vec!["sh".to_owned(), "-c".to_owned(), script])
      .start()
      .await?,
  );
  let sentinel_ip = sentinel.get_bridge_ip_address().await?;
  Ok((master, sentinel, format!("{sentinel_ip}:26379")))
}

/// Sentinel: master resolved via real Sentinel, ready 200 once migrated.
#[tokio::test]
async fn health_ready_sentinel_reports_ready() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_master, _sentinel, sentinel_node) = sentinel_pair().await?;
  let redis_block = serde_json::json!({
    "nodes": [sentinel_node],
    "master_name": "mymaster",
    "durability": "wait",
  });
  let config = test_config(&pg_url, redis_block)?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;

  assert_eq!(state.redis.topology_name(), "sentinel");
  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, ready_body) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 200);
  assert_eq!(
    ready_body.get("status").and_then(|v| v.as_str()),
    Some("ready")
  );
  Ok(())
}

/// Bootstrap a one-node cluster inside the container and wait for it to be
/// OK: pin the announced address to the bridge IP (otherwise the node
/// gossips an empty address), assign all slots, meet self.
async fn clustered_container() -> Result<(ContainerGuard, String), TestError> {
  let node = ContainerGuard::new(
    GenericImage::new("redis", "7.2-alpine")
      .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
      .with_cmd([
        "redis-server",
        "--port",
        "6379",
        "--cluster-enabled",
        "yes",
        "--cluster-config-file",
        "nodes.conf",
        "--cluster-node-timeout",
        "5000",
        "--appendonly",
        "yes",
      ])
      .start()
      .await?,
  );
  let ip = node.get_bridge_ip_address().await?;
  let client = ::redis::Client::open(format!("redis://{ip}:6379").as_str())?;
  let mut conn = client.get_multiplexed_async_connection().await?;
  let ip_string = ip.to_string();
  ::redis::cmd("CONFIG")
    .arg("SET")
    .arg("cluster-announce-ip")
    .arg(&ip_string)
    .query_async::<()>(&mut conn)
    .await?;
  ::redis::cmd("CLUSTER")
    .arg("ADDSLOTSRANGE")
    .arg("0")
    .arg("16383")
    .query_async::<()>(&mut conn)
    .await?;
  ::redis::cmd("CLUSTER")
    .arg("MEET")
    .arg(&ip_string)
    .arg("6379")
    .query_async::<()>(&mut conn)
    .await?;
  for _ in 0..40 {
    let info: String = ::redis::cmd("CLUSTER")
      .arg("INFO")
      .query_async(&mut conn)
      .await?;
    if info.contains("cluster_state:ok") {
      return Ok((node, format!("{ip}:6379")));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
  }
  Err(TestError::Body("cluster never reached state ok".to_owned()))
}

/// Cluster: native slot refresh against a real one-node cluster, ready 200.
#[tokio::test]
async fn health_ready_cluster_reports_ready() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_node, seed) = clustered_container().await?;
  let redis_block = serde_json::json!({"seeds": [seed], "durability": "wait"});
  let config = test_config(&pg_url, redis_block)?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;

  assert_eq!(state.redis.topology_name(), "cluster");
  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, ready_body) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 200);
  assert_eq!(
    ready_body.get("status").and_then(|v| v.as_str()),
    Some("ready")
  );
  Ok(())
}

/// The health-only router 404s every OAuth route on the plaintext listener.
#[tokio::test]
async fn health_router_404s_oauth_routes() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  for path in ["/authorize", "/oauth/token", "/par", "/nope"] {
    let (status, _) = get_health(&state, path).await?;
    assert_eq!(status, 404, "expected 404 for {path}");
  }
  Ok(())
}

//! `test(topology)` — Redis topology harness (task 42).
//!
//! In-process fixtures via `redis-test` (no Docker needed):
//! * `topology_sentinel_master_resolves` — a 1-master/1-replica/1-sentinel
//!   `RedisSentinelCluster` boots, the master is resolved through
//!   `SentinelClientBuilder` exactly like `state::sentinel` does, and a
//!   SET/GET round-trip flows through the resolved master.
//! * `topology_cluster_single_slot_roundtrip` — a 3-node `RedisCluster`
//!   boots and a `{state}`-tagged key round-trips through
//!   `ClusterClient` (the single-slot convention the token store relies on).
//!
//! Shared-service parity for CI environments without a `redis-server`
//! binary:
//! * `topology_single_node_store_roundtrip` — same assertions shape against
//!   the shared Redis from `compose.test.yaml`
//!   (`docker compose -f compose.test.yaml up -d`) with unique key prefixes,
//!   driving the real `Store::put_access`/`get_access` through our key layout.
//!
//! The `redis-test` legs skip gracefully (green, noted on stderr) when no
//! `redis-server` binary is on `PATH`; CI installs one via apt (see
//! `.github/workflows/ci.yml`). Bodies use `Result` + `?`
//! (`unwrap`/`expect`/`panic` are denied workspace-wide).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use d_oauth::{
  config::DurabilityMode,
  state::RedisConn,
  store::{
    Store, StoreError,
    tokens::{AccessRecord, get_access, put_access},
  },
};
use redis::{
  ConnectionAddr,
  sentinel::{SentinelClientBuilder, SentinelServerType},
};
use redis_test::{
  cluster::{RedisCluster, RedisClusterConfiguration},
  sentinel::RedisSentinelCluster,
};

mod common;

use common::{redis_url, unique_prefixes};

/// Test-body error.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// The shared test service is unreachable (usually: compose not started).
  #[error("test setup: {0}")]
  Setup(String),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] StoreError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Whether the `redis-test` fixtures can spawn (they exec `redis-server`).
fn redis_server_available() -> bool {
  std::process::Command::new("redis-server")
    .arg("--version")
    .output()
    .map(|output| output.status.success())
    .unwrap_or(false)
}

/// RAII owner of a Sentinel fixture: `stop()` runs even when the test body
/// returns early via `?` (child processes must not outlive the test).
struct SentinelFixture {
  inner: Option<RedisSentinelCluster>,
}

impl SentinelFixture {
  fn start() -> Self {
    Self {
      inner: Some(RedisSentinelCluster::new(1, 1, 1)),
    }
  }
}

impl Drop for SentinelFixture {
  fn drop(&mut self) {
    if let Some(mut cluster) = self.inner.take() {
      cluster.stop();
    }
  }
}

/// RAII owner of a cluster fixture (same teardown contract as above).
struct ClusterFixture {
  inner: Option<RedisCluster>,
}

impl ClusterFixture {
  fn start() -> Self {
    Self {
      inner: Some(RedisCluster::new(RedisClusterConfiguration::default())),
    }
  }

  /// Three masters with one replica each (the node-failover harness).
  fn start_with_replicas() -> Self {
    Self {
      inner: Some(RedisCluster::new(
        RedisClusterConfiguration::single_replica_config(),
      )),
    }
  }
}

impl Drop for ClusterFixture {
  fn drop(&mut self) {
    if let Some(mut cluster) = self.inner.take() {
      cluster.stop();
    }
  }
}

/// Sentinel resolves the current master; reads/writes flow through it.
#[tokio::test]
async fn topology_sentinel_master_resolves() -> TestResult {
  if !redis_server_available() {
    eprintln!("SKIP topology_sentinel_master_resolves: no redis-server on PATH");
    return Ok(());
  }
  let mut fixture = SentinelFixture::start();
  let cluster = fixture
    .inner
    .as_ref()
    .ok_or(TestError::Unexpected("fixture missing".to_owned()))?;

  // Only the sentinel addresses are known up front — the master port is
  // discovered through Sentinel, exactly like `state::sentinel::connect`.
  let mut addrs = Vec::new();
  for server in cluster.iter_sentinel_servers() {
    match server.host_and_port() {
      Some((host, port)) => addrs.push(ConnectionAddr::Tcp(host.to_owned(), port)),
      None => return Err(TestError::Unexpected("sentinel has no address".to_owned())),
    }
  }
  if addrs.is_empty() {
    return Err(TestError::Unexpected("no sentinel addresses".to_owned()));
  }
  if let Some(server) = cluster.iter_sentinel_servers().next()
    && let Some((host, port)) = server.host_and_port()
  {
    wait_for_sentinel(host, port).await?;
  }
  let mut sentinel =
    SentinelClientBuilder::new(addrs, "master0", SentinelServerType::Master)?.build()?;
  let master = sentinel.async_get_client().await?;
  let mut conn = master.get_multiplexed_async_connection().await?;

  let key = "topology-sentinel-probe";
  let _: () = redis::cmd("SET")
    .arg(key)
    .arg("master-ok")
    .query_async(&mut conn)
    .await?;
  let got: String = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
  if got != "master-ok" {
    return Err(TestError::Unexpected(
      "sentinel master round-trip mismatch".to_owned(),
    ));
  }
  if let Some(mut cluster) = fixture.inner.take() {
    cluster.stop();
  }
  Ok(())
}

/// A `{state}`-tagged key round-trips on a real 3-node cluster.
#[tokio::test]
async fn topology_cluster_single_slot_roundtrip() -> TestResult {
  if !redis_server_available() {
    eprintln!("SKIP topology_cluster_single_slot_roundtrip: no redis-server on PATH");
    return Ok(());
  }
  let mut fixture = ClusterFixture::start();
  let cluster = fixture
    .inner
    .as_ref()
    .ok_or(TestError::Unexpected("fixture missing".to_owned()))?;

  let mut seeds = Vec::new();
  for server in cluster.iter_servers() {
    match server.host_and_port() {
      Some((_, port)) => seeds.push(format!("redis://127.0.0.1:{port}")),
      None => {
        return Err(TestError::Unexpected(
          "cluster node has no address".to_owned(),
        ));
      }
    }
  }
  if seeds.is_empty() {
    return Err(TestError::Unexpected("no cluster seeds".to_owned()));
  }
  let client = redis::cluster::ClusterClient::new(seeds)?;
  let mut conn = client.get_async_connection().await?;

  // The token store keeps multi-key Lua ops in one slot via the `{state}`
  // hash tag; the harness pins that the tag round-trips on a real cluster.
  let key = "oauth:{state}:topology-probe";
  let _: () = redis::cmd("SET")
    .arg(key)
    .arg("cluster-ok")
    .query_async(&mut conn)
    .await?;
  let got: String = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
  if got != "cluster-ok" {
    return Err(TestError::Unexpected(
      "cluster round-trip mismatch".to_owned(),
    ));
  }
  if let Some(mut cluster) = fixture.inner.take() {
    cluster.stop();
  }
  Ok(())
}

/// Parity leg that needs only the shared services: the real token-store
/// access path against the shared Redis with unique key prefixes, so CI
/// stays green where no `redis-server` binary exists but Docker does.
#[tokio::test]
async fn topology_single_node_store_roundtrip() -> TestResult {
  let url = redis_url();
  let client = redis::Client::open(url.as_str()).map_err(|error| {
    TestError::Setup(format!(
      "cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`"
    ))
  })?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config)
    .await
    .map_err(|error| {
      TestError::Setup(format!(
        "cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`"
      ))
    })?;
  let mut conn = RedisConn::Single(manager);
  let (token_prefix, ratelimit_prefix) = unique_prefixes();
  let store = Store::from_parts(token_prefix, ratelimit_prefix, DurabilityMode::WaitAof);

  let token_hash = "topology-parity-probe";
  let record = AccessRecord {
    client_id: "topology-client".to_owned(),
    grant_id: "topology-grant".to_owned(),
    scope: "read".to_owned(),
    subject: "user-1".to_owned(),
    cnf: String::new(),
  };
  put_access(
    &mut conn,
    &store,
    token_hash,
    &record,
    Duration::from_secs(300),
  )
  .await?;
  match get_access(&mut conn, &store, token_hash).await? {
    Some(found) => {
      if found != record {
        return Err(TestError::Unexpected(
          "stored access record mismatch".to_owned(),
        ));
      }
    }
    None => {
      return Err(TestError::Unexpected(
        "stored access record missing".to_owned(),
      ));
    }
  }
  Ok(())
}

/// The current Sentinel master port, resolved by the sentinel itself.
async fn sentinel_master_port(host: &str, port: u16) -> Result<u16, TestError> {
  let client = redis::Client::open(format!("redis://{host}:{port}"))?;
  let mut conn = client.get_multiplexed_async_connection().await?;
  let reply: Vec<String> = redis::cmd("SENTINEL")
    .arg("GET-MASTER-ADDR-BY-NAME")
    .arg("master0")
    .query_async(&mut conn)
    .await?;
  reply
    .get(1)
    .and_then(|value| value.parse::<u16>().ok())
    .ok_or_else(|| TestError::Unexpected("sentinel has no master address".to_owned()))
}

/// Wait until the sentinel is reachable and resolves a master.
///
/// The `redis-test` fixture readiness-waits only the master and replica, never
/// the sentinel, so under a loaded runner the sentinel can lag behind them and
/// the first sentinel command fails with `Connection refused`.
async fn wait_for_sentinel(host: &str, port: u16) -> TestResult {
  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    if sentinel_master_port(host, port).await.is_ok() {
      return Ok(());
    }
    if Instant::now() >= deadline {
      return Err(TestError::Unexpected(
        "sentinel never became reachable".to_owned(),
      ));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
  }
}

/// Whether Sentinel reports at least one replica with a live replication
/// link (`master-link-status: ok`). `SENTINEL FAILOVER` refuses with
/// `NOGOODSLAVE` while the only replica is still handshaking, so the
/// failover harness gates on this before issuing the failover.
async fn sentinel_replica_synced(host: &str, port: u16) -> bool {
  let Ok(client) = redis::Client::open(format!("redis://{host}:{port}")) else {
    return false;
  };
  let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
    return false;
  };
  let Ok(replicas): Result<Vec<HashMap<String, String>>, _> = redis::cmd("SENTINEL")
    .arg("REPLICAS")
    .arg("master0")
    .query_async(&mut conn)
    .await
  else {
    return false;
  };
  replicas.iter().any(|replica| {
    replica
      .get("master-link-status")
      .is_some_and(|status| status == "ok")
  })
}

/// A real `SENTINEL FAILOVER master0` promotes the replica: the resolved
/// master changes and a write round-trips through the promoted node.
#[tokio::test]
async fn topology_sentinel_failover_promotes_replica() -> TestResult {
  if !redis_server_available() {
    eprintln!("SKIP topology_sentinel_failover_promotes_replica: no redis-server on PATH");
    return Ok(());
  }
  let mut fixture = SentinelFixture::start();
  let cluster = fixture
    .inner
    .as_ref()
    .ok_or(TestError::Unexpected("fixture missing".to_owned()))?;

  let mut sentinel_addr = None;
  for server in cluster.iter_sentinel_servers() {
    match server.host_and_port() {
      Some((host, port)) => {
        sentinel_addr.get_or_insert((host.to_owned(), port));
      }
      None => return Err(TestError::Unexpected("sentinel has no address".to_owned())),
    }
  }
  let Some((sentinel_host, sentinel_port)) = sentinel_addr else {
    return Err(TestError::Unexpected("no sentinel addresses".to_owned()));
  };

  wait_for_sentinel(&sentinel_host, sentinel_port).await?;
  let old_port = sentinel_master_port(&sentinel_host, sentinel_port).await?;

  // The replica link is still handshaking right after fixture boot on loaded
  // runners; Sentinel refuses the failover with `NOGOODSLAVE` until the link
  // is up, so wait for a synced replica first.
  let sync_deadline = Instant::now() + Duration::from_secs(30);
  loop {
    if sentinel_replica_synced(&sentinel_host, sentinel_port).await {
      break;
    }
    if Instant::now() >= sync_deadline {
      return Err(TestError::Unexpected(
        "sentinel replica never finished syncing".to_owned(),
      ));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
  }

  let admin = redis::Client::open(format!("redis://{sentinel_host}:{sentinel_port}"))?;
  let mut admin_conn = admin.get_multiplexed_async_connection().await?;
  let _: () = redis::cmd("SENTINEL")
    .arg("FAILOVER")
    .arg("master0")
    .query_async(&mut admin_conn)
    .await?;

  let deadline = Instant::now() + Duration::from_secs(30);
  let new_port = loop {
    if let Ok(port) = sentinel_master_port(&sentinel_host, sentinel_port).await
      && port != old_port
    {
      break port;
    }
    if Instant::now() >= deadline {
      return Err(TestError::Unexpected(
        "SENTINEL FAILOVER did not promote a new master".to_owned(),
      ));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
  };

  let promoted = redis::Client::open(format!("redis://127.0.0.1:{new_port}"))?;
  let mut conn = promoted.get_multiplexed_async_connection().await?;
  let key = "topology-sentinel-failover-probe";
  let _: () = redis::cmd("SET")
    .arg(key)
    .arg("promoted-ok")
    .query_async(&mut conn)
    .await?;
  let got: String = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
  if got != "promoted-ok" {
    return Err(TestError::Unexpected(
      "promoted master round-trip mismatch".to_owned(),
    ));
  }
  if let Some(mut cluster) = fixture.inner.take() {
    cluster.stop();
  }
  Ok(())
}

/// Whether a `ROLE` reply names a master.
fn role_is_master(role: &redis::Value) -> bool {
  match role {
    redis::Value::Array(items) => matches!(
      items.first(),
      Some(redis::Value::BulkString(bytes)) if bytes == b"master"
    ),
    _ => false,
  }
}

/// `CLUSTER NODES` text from one cluster seed.
async fn cluster_nodes(seed: &str) -> Result<String, TestError> {
  let client = redis::Client::open(seed)?;
  let mut conn = client.get_multiplexed_async_connection().await?;
  let text: String = redis::cmd("CLUSTER")
    .arg("NODES")
    .query_async(&mut conn)
    .await?;
  Ok(text)
}

/// `CLUSTER INFO` text from one cluster seed.
async fn cluster_info(seed: &str) -> Result<String, TestError> {
  let client = redis::Client::open(seed)?;
  let mut conn = client.get_multiplexed_async_connection().await?;
  let text: String = redis::cmd("CLUSTER")
    .arg("INFO")
    .query_async(&mut conn)
    .await?;
  Ok(text)
}

/// The slot spec of the node whose address ends in `port`, if any.
fn node_slots(nodes: &str, port: u16) -> Option<(String, String)> {
  let needle = format!(":{port}@");
  for line in nodes.lines() {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let addr = fields.get(1)?;
    if !addr.contains(&needle) {
      continue;
    }
    let id = fields.first().copied().unwrap_or_default().to_owned();
    let slots = fields.get(8..).unwrap_or_default().join(" ");
    return Some((id, slots));
  }
  None
}

/// A real cluster node failure: the stopped master's slots are served by a
/// different node (its replica) and the cluster returns to `cluster_state:ok`.
#[tokio::test]
async fn topology_cluster_node_failover_heals() -> TestResult {
  if !redis_server_available() {
    eprintln!("SKIP topology_cluster_node_failover_heals: no redis-server on PATH");
    return Ok(());
  }
  let mut fixture = ClusterFixture::start_with_replicas();
  let (seeds, victim_port) = {
    let cluster = fixture
      .inner
      .as_ref()
      .ok_or(TestError::Unexpected("fixture missing".to_owned()))?;
    let mut seeds = Vec::new();
    let mut victim = None;
    for server in cluster.iter_servers() {
      let Some((host, port)) = server.host_and_port() else {
        continue;
      };
      seeds.push(format!("redis://{host}:{port}"));
      if victim.is_none() {
        let client = redis::Client::open(format!("redis://{host}:{port}"))?;
        let mut conn = client.get_multiplexed_async_connection().await?;
        let role: redis::Value = redis::cmd("ROLE").query_async(&mut conn).await?;
        if role_is_master(&role) {
          victim = Some(port);
        }
      }
    }
    let victim = victim.ok_or_else(|| TestError::Unexpected("no cluster master".to_owned()))?;
    (seeds, victim)
  };

  let survivor = seeds
    .iter()
    .find(|seed| !seed.ends_with(&format!(":{victim_port}")))
    .cloned()
    .ok_or_else(|| TestError::Unexpected("no surviving seed".to_owned()))?;
  let before = cluster_nodes(&survivor).await?;
  let (victim_id, victim_slots) = node_slots(&before, victim_port)
    .ok_or_else(|| TestError::Unexpected("victim slots not found".to_owned()))?;
  if victim_slots.is_empty() || victim_slots == "-" {
    return Err(TestError::Unexpected(
      "victim master owns no slots".to_owned(),
    ));
  }

  {
    let cluster = fixture
      .inner
      .as_mut()
      .ok_or(TestError::Unexpected("fixture missing".to_owned()))?;
    for server in &mut cluster.servers {
      if server.host_and_port().map(|(_, port)| port) == Some(victim_port) {
        server.stop();
      }
    }
  }

  let deadline = Instant::now() + Duration::from_secs(60);
  let promoted = loop {
    let healed = cluster_info(&survivor)
      .await
      .is_ok_and(|info| info.contains("cluster_state:ok"));
    if healed && let Ok(nodes) = cluster_nodes(&survivor).await {
      let victim_failed = nodes.lines().any(|line| {
        line.split_whitespace().next() == Some(victim_id.as_str())
          && line
            .split_whitespace()
            .nth(2)
            .is_some_and(|flags| flags.contains("fail"))
      });
      let first_slot = victim_slots.split_whitespace().next().unwrap_or_default();
      let moved = nodes.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let id = fields.first().copied().unwrap_or_default();
        id != victim_id && fields.get(8..).unwrap_or_default().contains(&first_slot)
      });
      if victim_failed && moved {
        break true;
      }
    }
    if Instant::now() >= deadline {
      break false;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
  };
  if !promoted {
    return Err(TestError::Unexpected(
      "cluster did not promote a replica for the failed master".to_owned(),
    ));
  }

  let client = redis::cluster::ClusterClient::new(seeds.clone())?;
  let mut conn = client.get_async_connection().await?;
  let key = "oauth:{state}:topology-failover-probe";
  let _: () = redis::cmd("SET")
    .arg(key)
    .arg("cluster-healed")
    .query_async(&mut conn)
    .await?;
  let got: String = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
  if got != "cluster-healed" {
    return Err(TestError::Unexpected(
      "post-failover cluster round-trip mismatch".to_owned(),
    ));
  }
  if let Some(mut cluster) = fixture.inner.take() {
    cluster.stop();
  }
  Ok(())
}

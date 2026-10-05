//! `test(health)` resilience suite: fail-closed behavior.
//!
//! Dependency outage flips `/health/ready` to 503 while `/health/live` stays
//! 200; recovery needs no process restart. Startup rejects a wrong eviction
//! policy and malformed topologies, and an un-migrated database is not ready.

use std::{sync::Arc, time::Duration};

use super::{
  AppState,
  test_support::{
    TestError, TestResult, docker_pause, get_health, mark_migrated, postgres_container,
    redis_single_container, single_redis_block, test_config,
  },
};

/// Pausing Redis flips ready to 503 (live stays 200); unpausing recovers.
#[tokio::test]
async fn health_ready_flips_when_redis_paused() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (redis, redis_url) = redis_single_container(None).await?;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;
  let (before, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(before, 200);

  docker_pause(redis.id(), true).await?;
  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, ready_body) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 503);
  assert_eq!(
    ready_body.get("status").and_then(|v| v.as_str()),
    Some("not_ready")
  );

  docker_pause(redis.id(), false).await?;
  let (recovered, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(recovered, 200);
  Ok(())
}

/// Pausing Postgres flips ready to 503 (live stays 200); unpausing recovers.
#[tokio::test]
async fn health_ready_flips_when_postgres_paused() -> TestResult {
  let (pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;
  mark_migrated(&state).await?;

  docker_pause(pg.id(), true).await?;
  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 503);

  docker_pause(pg.id(), false).await?;
  // The pool heals without a restart; allow one acquire-budget cycle.
  let mut recovered = 503;
  for _ in 0..6 {
    (recovered, _) = get_health(&state, "/health/ready").await?;
    if recovered == 200 {
      break;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  assert_eq!(recovered, 200);
  Ok(())
}

/// A fresh (un-migrated) database is live but NOT ready.
#[tokio::test]
async fn health_ready_rejects_unmigrated_database() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  let state = AppState::connect(Arc::new(config)).await?;

  let (live_status, _) = get_health(&state, "/health/live").await?;
  let (ready_status, _) = get_health(&state, "/health/ready").await?;
  assert_eq!(live_status, 200);
  assert_eq!(ready_status, 503);
  Ok(())
}

/// Startup fails when the eviction policy is not `noeviction`.
#[tokio::test]
async fn health_startup_rejects_wrong_eviction_policy() -> TestResult {
  let (_pg, pg_url) = postgres_container().await?;
  let (_redis, redis_url) = redis_single_container(None).await?;
  {
    let client = ::redis::Client::open(redis_url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    ::redis::cmd("CONFIG")
      .arg("SET")
      .arg("maxmemory-policy")
      .arg("allkeys-lru")
      .query_async::<()>(&mut conn)
      .await?;
  }
  let config = test_config(&pg_url, single_redis_block(&redis_url))?;
  match AppState::connect(Arc::new(config)).await {
    Err(crate::state::StateError::Config(crate::config::ConfigError::RedisEvictionPolicy {
      observed,
    })) => {
      assert_eq!(observed, "allkeys-lru");
      Ok(())
    }
    Err(other) => Err(TestError::Body(format!("wrong startup error: {other}"))),
    Ok(_) => Err(TestError::Body("connect unexpectedly succeeded".to_owned())),
  }
}

/// Sentinel with no nodes fails startup without touching the network.
#[tokio::test]
async fn health_startup_rejects_empty_sentinel_nodes() -> TestResult {
  use super::redis::connect_redis;
  use crate::config::{DurabilityMode, RedisConfig, RedisTopology};
  let config = RedisConfig {
    topology: RedisTopology::Sentinel {
      nodes: Vec::new(),
      master_name: "mymaster".to_owned(),
      sentinel_auth: None,
      data_auth: None,
      tls: false,
    },
    connect_timeout: Duration::from_secs(3),
    response_timeout: Duration::from_secs(2),
    retry_budget: 2,
    retry_min_delay: Duration::from_millis(100),
    retry_max_delay: Duration::from_secs(5),
    durability: DurabilityMode::Wait,
    noeviction_required: true,
    aof_required: false,
    token_key_prefix: "oauth:{state}:".to_owned(),
    ratelimit_key_prefix: "oauth:{rl}:".to_owned(),
    root_cert_path: None,
    password: None,
  };
  match connect_redis(&config).await {
    Err(_) => Ok(()),
    Ok(_) => Err(TestError::Body(
      "sentinel connect unexpectedly succeeded".to_owned(),
    )),
  }
}

/// Cluster with an unroutable seed fails startup fast.
#[tokio::test]
async fn health_startup_rejects_unreachable_cluster_seed() -> TestResult {
  use super::redis::connect_redis;
  use crate::config::{DurabilityMode, RedisConfig, RedisTopology};
  let config = RedisConfig {
    topology: RedisTopology::Cluster {
      seeds: vec!["127.0.0.1:9".to_owned()],
      auth: None,
      tls: false,
    },
    connect_timeout: Duration::from_secs(2),
    response_timeout: Duration::from_secs(1),
    retry_budget: 1,
    retry_min_delay: Duration::from_millis(50),
    retry_max_delay: Duration::from_millis(200),
    durability: DurabilityMode::Wait,
    noeviction_required: false,
    aof_required: false,
    token_key_prefix: "oauth:{state}:".to_owned(),
    ratelimit_key_prefix: "oauth:{rl}:".to_owned(),
    root_cert_path: None,
    password: None,
  };
  match connect_redis(&config).await {
    Err(_) => Ok(()),
    Ok(_) => Err(TestError::Body(
      "cluster connect unexpectedly succeeded".to_owned(),
    )),
  }
}

/// The failover classifier fires on a genuine `-READONLY` server error and
/// stays quiet for client-side configuration errors.
#[tokio::test]
async fn health_failover_classifier_matches_readonly() -> TestResult {
  use super::sentinel::is_failover;
  // A genuine `-READONLY` wire reply parses to `Value::ServerError`; convert
  // it exactly as `query_async` does and classify the resulting error.
  let value =
    ::redis::parse_redis_value(b"-READONLY You can't write against a read only replica.\r\n")
      .map_err(|_| TestError::Body("wire parse failed".to_owned()))?;
  let server = match value {
    ::redis::Value::ServerError(err) => err,
    _ => return Err(TestError::Body("expected a server-error value".to_owned())),
  };
  assert!(is_failover(&::redis::RedisError::from(server)));
  let config_error =
    ::redis::RedisError::from((::redis::ErrorKind::InvalidClientConfig, "bad topology"));
  assert!(!is_failover(&config_error));
  Ok(())
}

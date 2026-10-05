//! `test(resilience)` unit suite: retry budget, fail-closed policy, failover
//! accounting, and slot guards without containers.
//!
//! Every test name contains `resilience` so
//! `cargo nextest run -E 'test(resilience)'` selects exactly them alongside
//! `tests/resilience.rs`. Bodies use `Result` + `?` (`unwrap`/`expect`/
//! `panic` are denied workspace-wide).

use std::{
  sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
  },
  time::Duration,
};

use d_oauth::{
  config::FailurePolicy,
  resilience::{
    FailoverEpisode, MAX_RETRIES, ResilienceConfig, ResilienceLayer, RetryBudget, SECURITY_PATHS,
    dependency_unavailable, fail_closed_for_path, hash_tag, is_security_path, is_single_slot,
    is_transient_redis, map_store_error, may_retry_redis, retry_idempotent,
  },
  store::{OpClass, StoreError},
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn transient_redis_error() -> redis::RedisError {
  redis::RedisError::from((redis::ErrorKind::Io, "connection reset"))
}

fn permanent_redis_error() -> redis::RedisError {
  redis::RedisError::from((redis::ErrorKind::AuthenticationFailed, "bad password"))
}

#[tokio::test]
async fn resilience_retry_budget_caps_retries_at_two() -> TestResult {
  let budget = RetryBudget::new(1_000);
  let attempts = Arc::new(AtomicU32::new(0));
  let probe = Arc::clone(&attempts);
  let outcome = retry_idempotent(
    move || {
      let probe = Arc::clone(&probe);
      async move {
        probe.fetch_add(1, Ordering::SeqCst);
        Err::<(), redis::RedisError>(transient_redis_error())
      }
    },
    is_transient_redis,
    &budget,
    usize::MAX,
  )
  .await;
  if outcome.is_ok() {
    return Err("always-failing op must stay failed".into());
  }
  // One initial attempt plus at most MAX_RETRIES retries.
  if attempts.load(Ordering::SeqCst) != 1 + MAX_RETRIES as u32 {
    return Err(format!("expected {} attempts", 1 + MAX_RETRIES).into());
  }
  Ok(())
}

#[tokio::test]
async fn resilience_retry_exhausted_budget_means_one_attempt() -> TestResult {
  let budget = RetryBudget::new(0);
  let attempts = Arc::new(AtomicU32::new(0));
  let probe = Arc::clone(&attempts);
  let outcome = retry_idempotent(
    move || {
      let probe = Arc::clone(&probe);
      async move {
        probe.fetch_add(1, Ordering::SeqCst);
        Err::<(), redis::RedisError>(transient_redis_error())
      }
    },
    is_transient_redis,
    &budget,
    usize::MAX,
  )
  .await;
  if outcome.is_ok() {
    return Err("always-failing op must stay failed".into());
  }
  if attempts.load(Ordering::SeqCst) != 1 {
    return Err("exhausted budget must allow exactly one attempt".into());
  }
  Ok(())
}

#[tokio::test]
async fn resilience_retry_never_retries_permanent_errors() -> TestResult {
  let budget = RetryBudget::new(1_000);
  let attempts = Arc::new(AtomicU32::new(0));
  let probe = Arc::clone(&attempts);
  let outcome = retry_idempotent(
    move || {
      let probe = Arc::clone(&probe);
      async move {
        probe.fetch_add(1, Ordering::SeqCst);
        Err::<(), redis::RedisError>(permanent_redis_error())
      }
    },
    is_transient_redis,
    &budget,
    usize::MAX,
  )
  .await;
  if outcome.is_ok() {
    return Err("always-failing op must stay failed".into());
  }
  if attempts.load(Ordering::SeqCst) != 1 {
    return Err("permanent errors must never be retried".into());
  }
  if budget.remaining() != 1_000 {
    return Err("untaken retries must not consume the budget".into());
  }
  Ok(())
}

#[tokio::test]
async fn resilience_retry_never_retries_non_idempotent_ops() -> TestResult {
  // The op-class gate sits below the retry helper: non-idempotent writes
  // are ineligible even for transient errors.
  if may_retry_redis(OpClass::NonIdempotent, &transient_redis_error()) {
    return Err("non-idempotent writes must never be retried".into());
  }
  if !may_retry_redis(OpClass::IdempotentRead, &transient_redis_error()) {
    return Err("idempotent reads must be retryable on transient errors".into());
  }
  if !may_retry_redis(OpClass::ConditionalWrite, &transient_redis_error()) {
    return Err("SET NX / Lua CAS must be retryable on transient errors".into());
  }
  if may_retry_redis(OpClass::IdempotentRead, &permanent_redis_error()) {
    return Err("permanent errors must never be retried".into());
  }
  Ok(())
}

#[test]
fn resilience_failover_episode_allows_single_caller_error() -> TestResult {
  let episode = FailoverEpisode::new();
  if !episode.within_budget() {
    return Err("a fresh episode must be within budget".into());
  }
  episode.record_caller_error();
  if !episode.within_budget() {
    return Err("one caller-visible error per episode must be allowed".into());
  }
  episode.record_caller_error();
  if episode.within_budget() {
    return Err("two caller-visible errors must breach the episode budget".into());
  }
  Ok(())
}

#[test]
fn resilience_single_slot_guards_cross_slot_splits() -> TestResult {
  let token_keys = [
    "oauth:{state}:refresh:aaa",
    "oauth:{state}:access:bbb",
    "oauth:{state}:grant:g1:tokens",
  ];
  if !is_single_slot(&token_keys) {
    return Err("token keyspace keys must share one slot".into());
  }
  let split = ["oauth:{state}:refresh:aaa", "oauth:{rl}:ratelimit:bbb"];
  if is_single_slot(&split) {
    return Err("token + rate-limit keys must never share a slot op".into());
  }
  if is_single_slot(&[]) {
    return Err("an empty key set is not a valid atomic op".into());
  }
  if hash_tag("oauth:refresh:aaa").is_some() {
    return Err("untagged keys must report no hash tag".into());
  }
  Ok(())
}

#[test]
fn resilience_fail_closed_policy_matrix() -> TestResult {
  for path in SECURITY_PATHS {
    if !fail_closed_for_path(path) {
      return Err(format!("{path} must fail closed").into());
    }
    if !is_security_path(path) {
      return Err(format!("{path} must be classified security-critical").into());
    }
  }
  for path in ["/login", "/login/totp/confirm", "/register/some-client"] {
    if !fail_closed_for_path(path) {
      return Err(format!("{path} must fail closed").into());
    }
  }
  if fail_closed_for_path("/health/live") {
    return Err("/health/live is dependency-free and must not fail closed".into());
  }
  if !fail_closed_for_path("/health/ready") {
    return Err("/health/ready must fail closed".into());
  }
  Ok(())
}

#[test]
fn resilience_config_clamps_retry_ceiling_to_two() -> TestResult {
  let policy = FailurePolicy {
    retry_budget: 6,
    request_timeout: Duration::from_secs(10),
    ..FailurePolicy::default()
  };
  let tuned = ResilienceConfig::from_policy(&policy);
  if tuned.max_retries != MAX_RETRIES {
    return Err("policy budgets above the ceiling must clamp to 2".into());
  }
  // Layers construct (compile-time proof the tower features are wired).
  let _ = tuned.timeout_layer();
  let _ = tuned.concurrency_limit_layer();
  let _ = ResilienceConfig::load_shed_layer();
  Ok(())
}

#[tokio::test]
async fn resilience_dependency_failures_render_503_retry_after() -> TestResult {
  use axum::http::header;
  use axum::response::IntoResponse as _;
  use http_body_util::BodyExt as _;

  for error in [
    map_store_error(StoreError::Durability),
    map_store_error(StoreError::Redis(transient_redis_error())),
    dependency_unavailable(),
  ] {
    let response = error.into_response();
    if response.status() != axum::http::StatusCode::SERVICE_UNAVAILABLE {
      return Err("dependency failures must render 503".into());
    }
    if response.headers().get(header::RETRY_AFTER).is_none() {
      return Err("503 responses must carry Retry-After".into());
    }
    let bytes = response
      .into_body()
      .collect()
      .await
      .map_err(|_| "body collection failed")?
      .to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    if !body.contains("temporarily_unavailable") {
      return Err("503 body must carry temporarily_unavailable".into());
    }
  }
  Ok(())
}

#[tokio::test]
async fn resilience_probe_stack_service() -> TestResult {
  let tuned = ResilienceConfig {
    request_timeout: Duration::from_secs(10),
    max_in_flight: 8,
    max_retries: MAX_RETRIES,
  };
  let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
  let router = router.layer(ResilienceLayer::from_config(&tuned));
  let request = axum::http::Request::builder()
    .uri("/")
    .body(axum::body::Body::empty())?;
  let response = tower::ServiceExt::oneshot(router, request)
    .await
    .map_err(|_| "router error")?;
  if response.status() != axum::http::StatusCode::OK {
    return Err("request through the stack must be 200".into());
  }
  Ok(())
}

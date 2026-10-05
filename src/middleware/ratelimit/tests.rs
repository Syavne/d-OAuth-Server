//! `test(ratelimit)` suite: fixed-window enforcement against real Redis.
//!
//! Each test owns a throwaway `redis:7.2-alpine` container (AOF on), so
//! counter keys never leak across tests. Fixtures live in [`super::test_support`].

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use tower::Layer;

use super::RateLimitLayer;
use super::test_support::{
  Passthrough, TestResult, live_state, peer, redis_container, retry_after, scan_keys, send,
  test_config, unavailable_state,
};

/// N in-window requests pass; the N+1th is `429` + `Retry-After`.
#[tokio::test]
async fn ratelimit_token_per_ip_rejects_over_budget_with_retry_after() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 3, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  for attempt in 0..3 {
    let response = send(
      service.clone(),
      "POST",
      "/token",
      "grant_type=authorization_code&client_id=client-a",
      peer(1),
    )
    .await?;
    assert_eq!(
      response.status(),
      StatusCode::OK,
      "request {attempt} within budget must pass"
    );
  }

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-a",
    peer(1),
  )
  .await?;
  assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
  assert!(
    retry_after(&blocked).is_some_and(|seconds| seconds >= 1),
    "429 must carry a positive Retry-After"
  );
  Ok(())
}

/// The per-client budget is enforced across distinct source IPs, proving the
/// client bucket (parsed from the form body) is keyed independently of the IP.
#[tokio::test]
async fn ratelimit_token_per_client_spans_source_ips() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1000, "token_per_client": 2}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  for octet in [1_u8, 2_u8] {
    let response = send(
      service.clone(),
      "POST",
      "/token",
      "grant_type=authorization_code&client_id=client-x",
      peer(octet),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
  }

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-x",
    peer(3),
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "third request for the same client from a new IP must be limited"
  );
  Ok(())
}

/// A counter resets after its window, so the next request is admitted again.
#[tokio::test]
async fn ratelimit_recovers_after_window_expires() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 1, "per_ip": 1}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let first = send(service.clone(), "POST", "/token", "client_id=c", peer(1)).await?;
  assert_eq!(first.status(), StatusCode::OK);

  let blocked = send(service.clone(), "POST", "/token", "client_id=c", peer(1)).await?;
  assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

  tokio::time::sleep(Duration::from_millis(1_200)).await;

  let recovered = send(service.clone(), "POST", "/token", "client_id=c", peer(1)).await?;
  assert_eq!(
    recovered.status(),
    StatusCode::OK,
    "window must reset the counter"
  );
  Ok(())
}

/// Counter keys are hash-tagged and contain no raw IP or `client_id`.
#[tokio::test]
async fn ratelimit_keys_are_hashed_and_cluster_tagged() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 100, "token_per_client": 100}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let source = SocketAddr::from(([203, 0, 113, 7], 40_000));
  let response = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=raw-client-id-marker",
    source,
  )
  .await?;
  assert_eq!(response.status(), StatusCode::OK);

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert!(
    keys.len() >= 2,
    "both IP and client counters must exist: {keys:?}"
  );
  for key in &keys {
    assert!(
      key.contains("{rl}"),
      "counter key lacks the {{rl}} tag: {key}"
    );
    assert!(
      !key.contains("203.0.113.7"),
      "raw IP appeared in key: {key}"
    );
    assert!(
      !key.contains("raw-client-id-marker"),
      "raw client_id appeared in key: {key}"
    );
  }
  Ok(())
}

/// Token is fail-closed on store outage: `503` + `Retry-After`, never a pass.
#[tokio::test]
async fn ratelimit_token_fails_closed_on_store_outage() -> TestResult {
  let config = test_config(
    "redis://127.0.0.1:1",
    json!({"enabled": true, "window_secs": 60, "per_ip": 10, "token_per_client": 10}),
  )?;
  let state = unavailable_state(config)?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let response = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=c",
    peer(1),
  )
  .await?;
  assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
  assert!(
    retry_after(&response).is_some_and(|seconds| seconds >= 1),
    "fail-closed response must carry Retry-After"
  );
  Ok(())
}

/// Protected-path classification is exact: an unlisted path is untouched even
/// while the store is down.
#[tokio::test]
async fn ratelimit_leaves_unlisted_paths_untouched_on_store_outage() -> TestResult {
  let config = test_config("redis://127.0.0.1:1", json!({"enabled": true}))?;
  let state = unavailable_state(config)?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let response = send(service.clone(), "GET", "/health/live", "", peer(1)).await?;
  assert_eq!(response.status(), StatusCode::OK);
  Ok(())
}

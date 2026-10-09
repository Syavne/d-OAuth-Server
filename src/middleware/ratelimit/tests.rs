//! `test(ratelimit)` suite: fixed-window enforcement against real Redis.
//!
//! Each test owns a throwaway `redis:7.2-alpine` container (AOF on), so
//! counter keys never leak across tests. Fixtures live in [`super::test_support`].

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use tower::Layer;

use super::RateLimitLayer;
use super::identity::counter_key;
use super::test_support::{
  Extras, Passthrough, TestResult, live_state, peer, redis_container, retry_after, scan_keys, send,
  send_with, test_config, unavailable_state,
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

/// Without a `trusted_proxy`, a forged `X-Forwarded-For` is never an identity:
/// the limiter keys off the recorded peer, so rotating spoofed addresses
/// cannot mint a fresh bucket and evade the limit.
#[tokio::test]
async fn ratelimit_ignores_spoofed_x_forwarded_for_without_trusted_proxy() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let first = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(peer(1)),
      headers: &[("x-forwarded-for", "198.51.100.10")],
    },
  )
  .await?;
  assert_eq!(first.status(), StatusCode::OK);

  let blocked = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(peer(1)),
      headers: &[("x-forwarded-for", "198.51.100.11")],
    },
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "rotating X-Forwarded-For must not evade the real peer's bucket"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert_eq!(
    keys,
    vec![counter_key(&prefix, "ip", "127.0.0.1")],
    "only the hashed real peer IP may be counted: {keys:?}"
  );
  for spoofed in ["198.51.100.10", "198.51.100.11"] {
    assert!(
      !keys.contains(&counter_key(&prefix, "ip", spoofed)),
      "spoofed address became key material: {keys:?}"
    );
  }
  Ok(())
}

/// The same rule for RFC 7239 `Forwarded`: with no `trusted_proxy` it can
/// never select a bucket different from the recorded peer.
#[tokio::test]
async fn ratelimit_ignores_spoofed_forwarded_header_without_trusted_proxy() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let first = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(peer(1)),
      headers: &[("forwarded", "for=198.51.100.20;proto=https")],
    },
  )
  .await?;
  assert_eq!(first.status(), StatusCode::OK);

  let blocked = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(peer(1)),
      headers: &[("forwarded", "for=198.51.100.21;proto=https")],
    },
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "rotating Forwarded must not evade the real peer's bucket"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert_eq!(
    keys,
    vec![counter_key(&prefix, "ip", "127.0.0.1")],
    "only the hashed real peer IP may be counted: {keys:?}"
  );
  Ok(())
}

/// An IPv6 peer owns a bucket distinct from IPv4: exhausting the IPv4 bucket
/// never limits the same traffic from `::1`, and the reverse.
#[tokio::test]
async fn ratelimit_ipv6_peer_owns_a_distinct_bucket() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let ipv4 = peer(1);
  let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 40_000);

  let v4_first = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    ipv4,
  )
  .await?;
  assert_eq!(v4_first.status(), StatusCode::OK);
  let v4_second = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    ipv4,
  )
  .await?;
  assert_eq!(v4_second.status(), StatusCode::TOO_MANY_REQUESTS);

  let v6_first = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    ipv6,
  )
  .await?;
  assert_eq!(
    v6_first.status(),
    StatusCode::OK,
    "an exhausted IPv4 bucket must not leak into the IPv6 peer's bucket"
  );
  let v6_second = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    ipv6,
  )
  .await?;
  assert_eq!(
    v6_second.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "the IPv6 peer's own bucket must still enforce the budget"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  for expected in [
    counter_key(&prefix, "ip", "127.0.0.1"),
    counter_key(&prefix, "ip", "::1"),
  ] {
    assert!(
      keys.contains(&expected),
      "missing peer bucket {expected}: {keys:?}"
    );
  }
  assert_eq!(
    keys.len(),
    2,
    "IPv4 and IPv6 peers must not share a bucket: {keys:?}"
  );
  Ok(())
}

/// The per-IP budget stands alone: once a peer is over it, a brand-new
/// `client_id` from that peer is still limited, and every bucket stays keyed
/// separately.
#[tokio::test]
async fn ratelimit_per_ip_budget_blocks_fresh_client_from_same_ip() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let first = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-a",
    peer(1),
  )
  .await?;
  assert_eq!(first.status(), StatusCode::OK);

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-b",
    peer(1),
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "a fresh client from an exhausted peer must hit the per-IP budget"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  for expected in [
    counter_key(&prefix, "ip", "127.0.0.1"),
    counter_key(&prefix, "client", "client-a"),
    counter_key(&prefix, "client", "client-b"),
  ] {
    assert!(
      keys.contains(&expected),
      "missing independent bucket {expected}: {keys:?}"
    );
  }
  assert_eq!(
    keys.len(),
    3,
    "IP and client buckets must not collide: {keys:?}"
  );
  Ok(())
}

/// A breach advertises a positive whole-second wait no longer than the
/// configured window.
#[tokio::test]
async fn ratelimit_retry_after_is_positive_and_bounded_by_window() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let first = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    peer(1),
  )
  .await?;
  assert_eq!(first.status(), StatusCode::OK);

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    peer(1),
  )
  .await?;
  assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

  let seconds = retry_after(&blocked).ok_or("429 must carry Retry-After")?;
  assert!(
    (1..=60).contains(&seconds),
    "Retry-After must be within 1..=window seconds, got {seconds}"
  );
  Ok(())
}

/// `rate_limit.enabled = false` is an explicit pass-through: requests far past
/// the configured budget are admitted and no limiter key is written.
#[tokio::test]
async fn ratelimit_disabled_never_limits_and_writes_no_keys() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": false, "window_secs": 60, "per_ip": 1, "token_per_client": 1}),
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
      "attempt {attempt} must never be limited while disabled"
    );
  }

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert!(
    keys.is_empty(),
    "a disabled limiter must not write counter keys: {keys:?}"
  );
  Ok(())
}

/// A request with no recorded peer fails closed: `503` with the contractual
/// `Retry-After: 1`, and no counter key is written because no identity exists
/// to count.
#[tokio::test]
async fn ratelimit_missing_peer_fails_closed_without_keys() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 10, "token_per_client": 10}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  let response = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: None,
      headers: &[],
    },
  )
  .await?;
  assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
  assert_eq!(
    retry_after(&response),
    Some(1),
    "fail-closed response must carry the contractual Retry-After: 1"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert!(
    keys.is_empty(),
    "a request with no identity must not write counter keys: {keys:?}"
  );
  Ok(())
}

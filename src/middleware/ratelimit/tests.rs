//! `test(ratelimit)` suite: fixed-window enforcement against real Redis.
//!
//! Each test owns a throwaway `redis:8-alpine` container (AOF on), so
//! counter keys never leak across tests. Fixtures live in [`super::test_support`].

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use tower::Layer;

use super::RateLimitLayer;
use super::identity::{client_bucket_raw, counter_key};
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

/// The per-client budget is enforced per `(peer_ip, client_id)`: repeating
/// the same client from the same peer past its budget is limited, while the
/// same client from a different peer owns a separate bucket (T3-C2).
#[tokio::test]
async fn ratelimit_token_per_client_enforced_per_peer() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1000, "token_per_client": 2}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  for _ in 0..2 {
    let response = send(
      service.clone(),
      "POST",
      "/token",
      "grant_type=authorization_code&client_id=client-x",
      peer(1),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
  }

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-x",
    peer(1),
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "third request for the same client from the same peer must be limited"
  );

  let other_peer = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=client-x",
    peer(2),
  )
  .await?;
  assert_eq!(
    other_peer.status(),
    StatusCode::OK,
    "the same client from a different peer must own a separate bucket"
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

/// A forged `X-Forwarded-For` is never an identity: the limiter keys off the
/// recorded peer, so rotating spoofed addresses cannot mint a fresh bucket and
/// evade the limit.
#[tokio::test]
async fn ratelimit_ignores_spoofed_x_forwarded_for() -> TestResult {
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

/// The same rule for RFC 7239 `Forwarded`: it can never select a bucket
/// different from the recorded peer.
#[tokio::test]
async fn ratelimit_ignores_spoofed_forwarded_header() -> TestResult {
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
    counter_key(
      &prefix,
      "client",
      &client_bucket_raw(&peer(1).ip(), "client-a"),
    ),
    counter_key(
      &prefix,
      "client",
      &client_bucket_raw(&peer(1).ip(), "client-b"),
    ),
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

/// T3-C2 (a): an unauthenticated `client_id` is not a global bucket. An
/// attacker at one peer that floods a victim's `client_id` must not exhaust
/// the victim's own bucket at a different peer: the client bucket is keyed by
/// `(peer_ip, client_id)`, so the victim's request still passes.
#[tokio::test]
async fn ratelimit_client_bucket_is_scoped_to_peer_ip() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 1000, "token_per_client": 2}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  for _ in 0..2 {
    let response = send(
      service.clone(),
      "POST",
      "/token",
      "grant_type=authorization_code&client_id=victim-client",
      peer(9),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
  }
  let attacker_blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=victim-client",
    peer(9),
  )
  .await?;
  assert_eq!(
    attacker_blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "attacker peer must hit its own client budget"
  );

  let victim = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=victim-client",
    peer(1),
  )
  .await?;
  assert_eq!(
    victim.status(),
    StatusCode::OK,
    "victim peer with the same client_id must own a separate bucket"
  );
  Ok(())
}

/// T3-C2 (b): rotating fake `client_id` values from one peer must not evade
/// the limit. The per-IP bucket is the primary control and counts every
/// request regardless of the claimed client identity.
#[tokio::test]
async fn ratelimit_rotating_fake_client_ids_does_not_evade_ip_budget() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({"enabled": true, "window_secs": 60, "per_ip": 2, "token_per_client": 1000}),
  )?;
  let state = live_state(config, &url).await?;
  let service = RateLimitLayer::new(state).layer(Passthrough);

  for (index, client_id) in ["fake-1", "fake-2"].iter().enumerate() {
    let response = send(
      service.clone(),
      "POST",
      "/token",
      &format!("grant_type=authorization_code&client_id={client_id}"),
      peer(1),
    )
    .await?;
    assert_eq!(
      response.status(),
      StatusCode::OK,
      "request {index} within the IP budget must pass"
    );
  }

  let blocked = send(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code&client_id=fake-3",
    peer(1),
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "a rotated fake client_id from an exhausted peer must hit the per-IP budget"
  );
  Ok(())
}

/// T3-C3 end to end: `trusted_proxies` flows from config through
/// `RateLimitLayer` into Redis. Requests from the trusted proxy peer are
/// attributed to their `X-Forwarded-For` client: repeating the same claimed
/// client exhausts its bucket, while a different claimed client through the
/// same proxy owns a fresh bucket, and no counter is ever keyed by the proxy
/// peer itself.
#[tokio::test]
async fn ratelimit_trusted_proxy_end_to_end_attributes_xff_bucket() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({
      "enabled": true,
      "window_secs": 60,
      "per_ip": 1,
      "token_per_client": 1000,
      "trusted_proxies": ["10.0.0.1"],
    }),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);
  let proxy = SocketAddr::from(([10, 0, 0, 1], 40_000));

  let first = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "198.51.100.7")],
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
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "198.51.100.7")],
    },
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "repeating the same XFF client through the trusted proxy must exhaust its bucket"
  );

  let other_client = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "198.51.100.8")],
    },
  )
  .await?;
  assert_eq!(
    other_client.status(),
    StatusCode::OK,
    "a different XFF client through the same proxy must own a fresh bucket"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  for expected in [
    counter_key(&prefix, "ip", "198.51.100.7"),
    counter_key(&prefix, "ip", "198.51.100.8"),
  ] {
    assert!(
      keys.contains(&expected),
      "missing attributed client bucket {expected}: {keys:?}"
    );
  }
  assert!(
    !keys.contains(&counter_key(&prefix, "ip", "10.0.0.1")),
    "the proxy peer itself must never own a bucket: {keys:?}"
  );
  assert_eq!(
    keys.len(),
    2,
    "only the two attributed client buckets may exist: {keys:?}"
  );
  Ok(())
}

/// T3-C3 end to end: bracketed, port-suffixed, and `unknown` XFF entries are
/// never bare IPs, so from a trusted peer they fall back to the verified peer
/// bucket through the full layer instead of minting a foreign bucket.
#[tokio::test]
async fn ratelimit_trusted_proxy_unparseable_xff_falls_back_to_peer() -> TestResult {
  let (_redis, url) = redis_container().await?;
  let config = test_config(
    &url,
    json!({
      "enabled": true,
      "window_secs": 60,
      "per_ip": 1,
      "token_per_client": 1000,
      "trusted_proxies": ["10.0.0.1"],
    }),
  )?;
  let state = live_state(config, &url).await?;
  let prefix = state.config.redis.ratelimit_key_prefix.clone();
  let service = RateLimitLayer::new(state).layer(Passthrough);
  let proxy = SocketAddr::from(([10, 0, 0, 1], 40_000));

  let first = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "[2001:db8::1]")],
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
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "198.51.100.9:4123")],
    },
  )
  .await?;
  assert_eq!(
    blocked.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "an unparseable XFF entry must fall back to the peer bucket, not evade it"
  );

  let unknown = send_with(
    service.clone(),
    "POST",
    "/token",
    "grant_type=authorization_code",
    Extras {
      peer: Some(proxy),
      headers: &[("x-forwarded-for", "unknown")],
    },
  )
  .await?;
  assert_eq!(
    unknown.status(),
    StatusCode::TOO_MANY_REQUESTS,
    "`unknown` must likewise count against the peer bucket"
  );

  let keys = scan_keys(&url, "oauth:{rl}:*").await?;
  assert_eq!(
    keys,
    vec![counter_key(&prefix, "ip", "10.0.0.1")],
    "only the verified peer bucket may exist: {keys:?}"
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

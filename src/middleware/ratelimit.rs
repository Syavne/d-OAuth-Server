//! Redis-backed rate-limit middleware (own keyspace).
//!
//! A fixed-window limiter over the sibling `RedisConn`: every request to a
//! protected endpoint increments one counter per identity (peer IP and, when
//! the request carries a `client_id`, the client). Counters live under the
//! configured rate-limit prefix (`oauth:{rl}:`, enforced by config validation)
//! so they never share the token-state keyspace and always carry the `{rl}`
//! hash tag that keeps a multi-key write in one Cluster slot.
//!
//! [`identity`] hashes the IP and `client_id` before they become key material.
//! The increment and its window expiry run in one Lua script, so a counter can
//! never exist without a TTL (which would otherwise pin the key forever).
//!
//! The limiter fails **closed**: if the endpoint is protected and the counter
//! store errors, the request is answered `503 temporarily_unavailable` +
//! `Retry-After` rather than being allowed through. Token and login endpoints
//! are the mandated minimum for that behavior; every protected endpoint
//! follows it because the plan's failure policy forbids fail-open on a
//! security path. A limit breach is `429 Too Many Requests` + `Retry-After`.
//!
//! [`super::request_id`] is the layout precedent for the Tower `Layer`/`Service`
//! pair; the router (task 40) is expected to mount this layer on the
//! authorize/token/register/login/consent/device/introspect/revoke routes.

mod identity;

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Request, Response, StatusCode, header};
use axum::response::IntoResponse;
use redis::Script;
use serde::Serialize;
use tower::{Layer, Service};

use crate::config::RateLimitConfig;
use crate::state::AppState;
use identity::{counter_key, extract_client_id, peer_ip};

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

/// Atomic fixed-window counter: increment every key, attach the window expiry
/// on first write, and return each key's count and remaining TTL (ms).
///
/// All keys passed here share the `{rl}` hash tag, so the script stays within
/// one Cluster slot; redis-rs routes the script by its first key.
const LUA: &str = r#"
local window = tonumber(ARGV[1])
local out = {}
for i = 1, #KEYS do
  local count = redis.call('INCR', KEYS[i])
  if count == 1 then
    redis.call('PEXPIRE', KEYS[i], window)
  end
  local ttl = redis.call('PTTL', KEYS[i])
  if ttl < 0 then
    redis.call('PEXPIRE', KEYS[i], window)
    ttl = window
  end
  out[i] = {count, ttl}
end
return out
"#;

/// Compiled-once Lua script (SHA-addressed `EVALSHA`; redis-rs self-heals
/// `NOSCRIPT` by loading and retrying once).
static SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(LUA));

/// The buckets a protected endpoint enforces. `per_client` is `None` for
/// endpoints that have no client identity (login, registration).
#[derive(Debug, Clone, Copy)]
struct Rule {
  /// Per-IP request budget per window.
  per_ip: u32,
  /// Per-client request budget per window, when a client is identifiable.
  per_client: Option<u32>,
}

impl Rule {
  /// Classify a path by its last segment so both `/token` and `/oauth/token`
  /// (and similar prefixes) match.
  fn for_path(limits: RateLimitConfig, path: &str) -> Option<Self> {
    let last = path
      .trim_end_matches('/')
      .rsplit('/')
      .next()
      .unwrap_or_default();
    match last {
      "token" => Some(Self {
        per_ip: limits.per_ip,
        per_client: Some(limits.token_per_client),
      }),
      "login" => Some(Self {
        per_ip: limits.login_per_ip,
        per_client: None,
      }),
      "register" => Some(Self {
        per_ip: limits.per_ip,
        per_client: None,
      }),
      "authorize"
      | "consent"
      | "device"
      | "device_authorization"
      | "device_verification"
      | "introspect"
      | "revoke" => Some(Self {
        per_ip: limits.per_ip,
        per_client: Some(limits.per_client),
      }),
      _ => None,
    }
  }
}

/// Outcome of one counter check.
enum Outcome {
  /// Every bucket is within budget.
  Allow,
  /// At least one bucket is over budget; retry after `retry_after` seconds.
  Deny {
    /// Whole seconds until the breached window resets (at least 1).
    retry_after: u64,
  },
}

/// Tower layer enforcing rate limits over the inner service.
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
  state: AppState,
}

impl RateLimitLayer {
  /// Build the layer from shared application state.
  #[must_use]
  pub const fn new(state: AppState) -> Self {
    Self { state }
  }
}

impl<S> Layer<S> for RateLimitLayer {
  type Service = RateLimitService<S>;

  fn layer(&self, inner: S) -> Self::Service {
    RateLimitService {
      inner,
      state: self.state.clone(),
    }
  }
}

/// Service produced by [`RateLimitLayer`].
#[derive(Debug, Clone)]
pub struct RateLimitService<S> {
  inner: S,
  state: AppState,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
  S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
  S::Future: Send + 'static,
  S::Error: Send + 'static,
{
  type Response = Response<Body>;
  type Error = S::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, mut request: Request<Body>) -> Self::Future {
    let state = self.state.clone();
    let mut inner = self.inner.clone();

    Box::pin(async move {
      let path = request.uri().path().to_owned();
      let Some(rule) = Rule::for_path(state.config.rate_limit, &path) else {
        return inner.call(request).await;
      };

      if !state.config.rate_limit.enabled {
        tracing::warn!(%path, "rate limiting disabled by configuration");
        return inner.call(request).await;
      }

      // Without a peer address there is no identity to count against; the
      // endpoint is protected, so this is a misconfiguration, not a pass.
      let Some(ip) = peer_ip(&request) else {
        tracing::error!(%path, "rate limit: no peer address; failing closed");
        return Ok(service_unavailable(1));
      };

      let client_id = extract_client_id(&mut request).await;
      let buckets = counter_keys(&state, rule, ip, client_id.as_deref());
      if buckets.is_empty() {
        return inner.call(request).await;
      }

      let window = state.config.rate_limit.window;
      match enforce(&state, &buckets, window).await {
        Ok(Outcome::Allow) => inner.call(request).await,
        Ok(Outcome::Deny { retry_after }) => Ok(too_many_requests(retry_after)),
        Err(()) => {
          tracing::error!(%path, "rate limit store unavailable; failing closed");
          Ok(service_unavailable(1))
        }
      }
    })
  }
}

/// The hashed counter keys and limits for one request, in evaluation order.
///
/// `limit == 0` disables that bucket (a documented "off" switch); the IP
/// bucket is always present because `peer_ip` already proved it.
fn counter_keys(
  state: &AppState,
  rule: Rule,
  ip: IpAddr,
  client_id: Option<&str>,
) -> Vec<(String, u32)> {
  let prefix = &state.config.redis.ratelimit_key_prefix;
  let mut buckets = Vec::new();
  if rule.per_ip > 0 {
    buckets.push((counter_key(prefix, "ip", &ip.to_string()), rule.per_ip));
  }
  if let Some(limit) = rule.per_client.filter(|limit| *limit > 0)
    && let Some(client_id) = client_id
  {
    buckets.push((counter_key(prefix, "client", client_id), limit));
  }
  buckets
}

/// Run the atomic increment for every bucket and fold the results.
///
/// Any store error or malformed reply maps to `Err(())`, which the caller
/// turns into a fail-closed `503`.
async fn enforce(
  state: &AppState,
  buckets: &[(String, u32)],
  window: Duration,
) -> Result<Outcome, ()> {
  let mut conn = state.redis.clone();
  let window_ms = i64::try_from(window.as_millis()).unwrap_or(i64::MAX).max(1);

  let mut invocation = SCRIPT.prepare_invoke();
  for (key, _limit) in buckets {
    invocation.key(key.as_str());
  }
  invocation.arg(window_ms);

  let raw: Vec<Vec<i64>> = invocation.invoke_async(&mut conn).await.map_err(|_| ())?;

  let mut breached_ttl_ms: Option<i64> = None;
  for (index, (_key, limit)) in buckets.iter().enumerate() {
    let cell = raw.get(index).ok_or(())?;
    let count = *cell.first().ok_or(())?;
    let ttl_ms = *cell.get(1).ok_or(())?;
    if count > i64::from(*limit) {
      let ttl_ms = ttl_ms.max(0);
      breached_ttl_ms = Some(breached_ttl_ms.map_or(ttl_ms, |current| current.max(ttl_ms)));
    }
  }

  let Some(ttl_ms) = breached_ttl_ms else {
    return Ok(Outcome::Allow);
  };
  // Ceil to whole seconds and never advertise a zero-second wait.
  let retry_after = u64::try_from(ttl_ms.max(0))
    .unwrap_or(0)
    .div_ceil(1000)
    .max(1);
  Ok(Outcome::Deny { retry_after })
}

/// Rate-limit error body, matching the RFC error shape used elsewhere.
#[derive(Debug, Serialize)]
struct RateLimitBody<'a> {
  error: &'a str,
  error_description: &'a str,
}

/// `429 Too Many Requests` with a `Retry-After` hint.
fn too_many_requests(retry_after: u64) -> Response<Body> {
  let mut response = (
    StatusCode::TOO_MANY_REQUESTS,
    axum::Json(RateLimitBody {
      error: "rate_limited",
      error_description: "Too many requests; retry after the indicated delay.",
    }),
  )
    .into_response();
  attach_retry_after(&mut response, retry_after);
  response
}

/// `503 Service Unavailable` + `Retry-After` for the fail-closed store outage.
fn service_unavailable(retry_after: u64) -> Response<Body> {
  let mut response = (
    StatusCode::SERVICE_UNAVAILABLE,
    axum::Json(RateLimitBody {
      error: "temporarily_unavailable",
      error_description: "The authorization server is temporarily unable to handle the request.",
    }),
  )
    .into_response();
  attach_retry_after(&mut response, retry_after);
  response
}

/// Attach a seconds-valued `Retry-After` header.
fn attach_retry_after(response: &mut Response<Body>, seconds: u64) {
  if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
    response.headers_mut().insert(header::RETRY_AFTER, value);
  }
}

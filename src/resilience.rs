//! Connection resilience: bounded retries, load-shedding, fail-closed policy.
//!
//! The layer fixed by [`FailurePolicy`](crate::config::FailurePolicy):
//!
//! - [`ResilienceConfig::timeout_layer`] (`tower` `TimeoutLayer`) bounds every
//!   request end-to-end, so a hung dependency surfaces as a fast failure
//!   instead of a hung connection.
//! - [`ResilienceConfig::concurrency_limit_layer`] (`tower`
//!   `ConcurrencyLimitLayer`) plus [`ResilienceConfig::load_shed_layer`]
//!   (`tower` `LoadShedLayer`) shed overload with `503` instead of queueing
//!   into `PoolTimedOut`.
//! - [`retry_idempotent`] runs `backon` jittered retries (max
//!   [`MAX_RETRIES`]) **only** for idempotent reads and `SET NX`/Lua
//!   compare-and-set, and only on transient errors. Every retry consumes a
//!   [`RetryBudget`] permit, so a dependency fault cannot turn into a retry
//!   storm. Non-idempotent writes (`POST /token`, code redemption, consumes)
//!   must never reach it — see [`OpClass`](crate::store::OpClass).
//! - Dependency failures map to [`AppError::temporarily_unavailable`]
//!   (`503` + `Retry-After`), never `500`/panic; [`fail_closed_for_path`]
//!   encodes the per-endpoint fail-closed policy (only `/health/live`
//!   avoids dependencies).
//! - [`FailoverEpisode`] accounts caller-visible errors across one
//!   Sentinel/Cluster failover (at most one), and [`is_single_slot`] guards
//!   atomic multi-key operations against cross-slot splits.

use std::{
  future::Future,
  pin::Pin,
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use axum::{
  body::Body,
  http::Request,
  response::{IntoResponse as _, Response},
};
use backon::{ExponentialBuilder, Retryable};
use tower::{
  Layer, Service,
  limit::{ConcurrencyLimit, ConcurrencyLimitLayer},
  load_shed::{LoadShed, LoadShedLayer},
  timeout::{Timeout, TimeoutLayer},
};

use crate::{
  config::FailurePolicy,
  error::AppError,
  store::{ErrorClass, OpClass, StoreError, classify_redis, may_retry_op},
};

/// Maximum `backon` retries for one idempotent operation (3 attempts total).
pub const MAX_RETRIES: usize = 2;
/// Floor for the jittered retry backoff.
pub const RETRY_MIN_DELAY: Duration = Duration::from_millis(50);
/// Ceiling for the jittered retry backoff.
pub const RETRY_MAX_DELAY: Duration = Duration::from_millis(500);
/// Default cap on concurrent in-flight requests before shedding load.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 512;
/// Default permits for the process-wide retry budget (retries, not requests).
pub const DEFAULT_RETRY_BUDGET: u32 = 64;

/// Security-critical paths: dependency outage fails closed, never open.
pub const SECURITY_PATHS: [&str; 11] = [
  "/token",
  "/authorize",
  "/par",
  "/device_authorization",
  "/device",
  "/login",
  "/consent",
  "/register",
  "/revoke",
  "/introspect",
  "/.well-known/oauth-authorization-server",
];

/// Tower-layer tuning derived from the [`FailurePolicy`].
#[derive(Debug, Clone, Copy)]
pub struct ResilienceConfig {
  /// End-to-end request bound (the `request` rung of the timeout ladder).
  pub request_timeout: Duration,
  /// Cap on concurrent in-flight requests.
  pub max_in_flight: usize,
  /// Per-operation retry ceiling (clamped to [`MAX_RETRIES`]).
  pub max_retries: usize,
}

impl ResilienceConfig {
  /// Derive layer tuning from the failure policy. The policy retry budget
  /// above [`MAX_RETRIES`] is clamped: task 44 fixes the ceiling at 2
  /// retries for idempotent reads and `SET NX`/Lua compare-and-set.
  #[must_use]
  pub fn from_policy(policy: &FailurePolicy) -> Self {
    Self {
      request_timeout: policy.request_timeout,
      max_in_flight: DEFAULT_MAX_IN_FLIGHT,
      max_retries: (policy.retry_budget as usize).min(MAX_RETRIES),
    }
  }

  /// Bound every request end-to-end (outermost functional layer).
  #[must_use]
  pub fn timeout_layer(&self) -> TimeoutLayer {
    TimeoutLayer::new(self.request_timeout)
  }

  /// Cap concurrent in-flight requests (sheds via `503` when saturated, via
  /// the load-shed layer outside it, instead of queueing into `PoolTimedOut`).
  #[must_use]
  pub fn concurrency_limit_layer(&self) -> ConcurrencyLimitLayer {
    ConcurrencyLimitLayer::new(self.max_in_flight)
  }

  /// Shed overload immediately instead of queueing it.
  #[must_use]
  pub fn load_shed_layer() -> LoadShedLayer {
    LoadShedLayer::new()
  }
}

/// Map a boxed layer error (request timeout or shed overload) to fail-closed
/// `503 temporarily_unavailable` + `Retry-After`.
fn layer_unavailable(_: tower::BoxError) -> Response {
  AppError::temporarily_unavailable().into_response()
}

/// The task-44 middleware layer: load-shed → timeout → concurrency-limit →
/// inner service, with timeout/overload failures mapped to `503
/// temporarily_unavailable` + `Retry-After`.
///
/// The three tower layers are composed directly (rather than stacked with
/// `ServiceBuilder`) so the error mapping is total: the composed service's
/// `Error` is `Infallible`, which is what `Router::layer` requires.
#[derive(Debug, Clone, Copy)]
pub struct ResilienceLayer {
  request_timeout: Duration,
  max_in_flight: usize,
}

impl ResilienceLayer {
  /// Build the layer from tuned values.
  #[must_use]
  pub fn new(request_timeout: Duration, max_in_flight: usize) -> Self {
    Self {
      request_timeout,
      max_in_flight,
    }
  }

  /// Build the layer from [`ResilienceConfig`].
  #[must_use]
  pub fn from_config(config: &ResilienceConfig) -> Self {
    Self::new(config.request_timeout, config.max_in_flight)
  }
}

impl<S> Layer<S> for ResilienceLayer {
  type Service = ResilienceService<S>;

  fn layer(&self, inner: S) -> Self::Service {
    ResilienceService {
      inner: LoadShed::new(Timeout::new(
        ConcurrencyLimit::new(inner, self.max_in_flight),
        self.request_timeout,
      )),
    }
  }
}

/// `Router`-ready service over `LoadShed<Timeout<ConcurrencyLimit<S>>>`.
///
/// Overload sheds before it can queue into `PoolTimedOut`; the timeout
/// bounds everything below the shed; depth contention never surfaces as
/// anything but fail-closed `503`.
#[derive(Debug, Clone)]
pub struct ResilienceService<S> {
  inner: LoadShed<Timeout<ConcurrencyLimit<S>>>,
}

impl<S> Service<Request<Body>> for ResilienceService<S>
where
  S: Service<Request<Body>> + Send + 'static,
  S::Response: axum::response::IntoResponse + Send,
  S::Error: Into<tower::BoxError> + Send,
  S::Future: Send,
{
  type Response = Response;
  type Error = std::convert::Infallible;
  type Future = Pin<Box<dyn Future<Output = Result<Response, Self::Error>> + Send>>;

  fn poll_ready(
    &mut self,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), Self::Error>> {
    // Readiness is faithful: claiming `Ready` early would let `call` hit the
    // concurrency gate without a permit (a panic in tower), so `Pending`
    // propagates and the uninhabited error arm diverges instead of mapping.
    match self.inner.poll_ready(cx) {
      std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
      std::task::Poll::Ready(Err(_)) => never_ready(),
      std::task::Poll::Pending => std::task::Poll::Pending,
    }
  }

  fn call(&mut self, request: Request<Body>) -> Self::Future {
    let response = self.inner.call(request);
    Box::pin(async move {
      match response.await {
        Ok(ok) => Ok(ok.into_response()),
        Err(_) => Ok(layer_unavailable_response()),
      }
    })
  }
}

/// Diverge on an uninhabited readiness error: the only error the composed
/// inner service can report is `Route`'s `Infallible`, so this arm is dead by
/// construction (park-diverge, matching `test_guard.rs`, keeps the deny
/// lints quiet without `panic!`).
fn never_ready() -> std::task::Poll<Result<(), std::convert::Infallible>> {
  loop {
    std::thread::park();
  }
}

/// Fail-closed 503 response for timeout/overload failures.
fn layer_unavailable_response() -> Response {
  layer_unavailable(tower::BoxError::from(
    "resilience: dependency timeout or overload",
  ))
}

/// Process-wide retry budget: every retry consumes one permit.
///
/// The budget caps the aggregate retry rate under a dependency fault, so a
/// fleet of idempotent readers cannot amplify an outage into a retry storm.
/// Permits are never refilled within a budget's lifetime; owners rotate the
/// budget (e.g. per readiness window) by replacing it.
pub struct RetryBudget {
  permits: AtomicU32,
}

impl RetryBudget {
  /// A budget holding `permits` total retries.
  #[must_use]
  pub fn new(permits: u32) -> Self {
    Self {
      permits: AtomicU32::new(permits),
    }
  }

  /// Consume one permit; `false` when the budget is exhausted.
  pub fn try_acquire(&self) -> bool {
    self
      .permits
      .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
        if left == 0 { None } else { Some(left - 1) }
      })
      .is_ok()
  }

  /// Permits still available.
  #[must_use]
  pub fn remaining(&self) -> u32 {
    self.permits.load(Ordering::SeqCst)
  }
}

/// Run an idempotent operation with jittered `backon` retries (max
/// [`MAX_RETRIES`]), guarded by `budget`.
///
/// Retries happen only when `is_transient` classifies the error AND the
/// budget still holds a permit; the first permit check happens before the
/// first retry, so an exhausted budget means exactly one attempt. Callers
/// must pass idempotent reads or `SET NX`/Lua compare-and-set only — never
/// `POST /token`, code redemption, or any other non-idempotent write.
pub async fn retry_idempotent<T, E, Op, Fut, IsTransient>(
  op: Op,
  is_transient: IsTransient,
  budget: &RetryBudget,
  max_retries: usize,
) -> Result<T, E>
where
  Op: FnMut() -> Fut,
  Fut: Future<Output = Result<T, E>>,
  IsTransient: Fn(&E) -> bool,
{
  let backoff = ExponentialBuilder::default()
    .with_jitter()
    .with_min_delay(RETRY_MIN_DELAY)
    .with_max_delay(RETRY_MAX_DELAY)
    .with_max_times(max_retries.min(MAX_RETRIES));
  op.retry(&backoff)
    .when(|error| is_transient(error) && budget.try_acquire())
    .await
}

/// Whether a Redis error may be retried for an operation of class `op`.
#[must_use]
pub fn may_retry_redis(op: OpClass, error: &redis::RedisError) -> bool {
  may_retry_op(op, error)
}

/// Whether a Redis error is transient (retryable for idempotent ops only).
#[must_use]
pub fn is_transient_redis(error: &redis::RedisError) -> bool {
  classify_redis(error) == ErrorClass::Transient
}

/// Map a store failure to a client-safe error: transient Redis outages and
/// unmet durability barriers render `503 temporarily_unavailable` (fail
/// closed, with `Retry-After`); everything else is masked as `server_error`.
///
/// This is the single funnel through which dependency failures reach callers,
/// so no dependency fault can surface as `500` detail or a panic.
#[must_use]
pub fn map_store_error(error: StoreError) -> AppError {
  AppError::from(error)
}

/// Fail-closed dependency outage as a client-safe error (`503` +
/// `Retry-After`).
#[must_use]
pub fn dependency_unavailable() -> AppError {
  AppError::temporarily_unavailable()
}

/// Whether `path` fails closed when a dependency is unavailable.
///
/// Every path fails closed except `/health/live`, which touches no
/// dependency. Security paths (token issuance, authorize/code issuance,
/// login/TOTP, consent, DCR, device, revocation, introspection, and DPoP
/// `jti` replay writes) must never fail open; the metadata document serves
/// from an in-process scope-catalog cache but fails closed with `503` when
/// the catalog was never populated and Postgres is down.
#[must_use]
pub fn fail_closed_for_path(path: &str) -> bool {
  path != "/health/live"
}

/// Whether `path` is a security-critical endpoint (must never fail open).
#[must_use]
pub fn is_security_path(path: &str) -> bool {
  SECURITY_PATHS
    .iter()
    .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// Caller-visible error accounting for one Sentinel/Cluster failover episode.
///
/// The resolver re-resolves transparently (Sentinel master re-resolution,
/// Cluster `MOVED`/`ASK` slot refresh); at most one error per episode may
/// reach a caller — [`within_budget`](Self::within_budget) enforces that.
pub struct FailoverEpisode {
  caller_errors: AtomicU32,
}

impl FailoverEpisode {
  /// Start accounting a new failover episode.
  #[must_use]
  pub fn new() -> Self {
    Self {
      caller_errors: AtomicU32::new(0),
    }
  }

  /// Record one caller-visible error during the episode.
  pub fn record_caller_error(&self) {
    self.caller_errors.fetch_add(1, Ordering::SeqCst);
  }

  /// Caller-visible errors recorded so far.
  #[must_use]
  pub fn caller_errors(&self) -> u32 {
    self.caller_errors.load(Ordering::SeqCst)
  }

  /// Whether the episode stayed within the single-caller-error budget.
  #[must_use]
  pub fn within_budget(&self) -> bool {
    self.caller_errors() <= 1
  }
}

impl Default for FailoverEpisode {
  fn default() -> Self {
    Self::new()
  }
}

/// Extract the `{tag}` hash tag of a Redis key, if any.
#[must_use]
pub fn hash_tag(key: &str) -> Option<&str> {
  let start = key.find('{')?;
  let end = key[start..].find('}')?;
  let tag = &key[start + 1..start + end];
  if tag.is_empty() { None } else { Some(tag) }
}

/// Whether every key shares one non-empty hash tag, so an atomic multi-key
/// Lua operation is never split across Cluster slots.
#[must_use]
pub fn is_single_slot(keys: &[&str]) -> bool {
  let mut tags = keys.iter().filter_map(|key| hash_tag(key));
  match tags.next() {
    None => false,
    Some(first) => tags.all(|tag| tag == first),
  }
}

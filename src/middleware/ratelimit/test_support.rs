//! Fixtures for the `test(ratelimit)` suite: a real Redis container, a lazy
//! Postgres pool the limiter never touches, and a `Send` passthrough handler.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, header};
use serde_json::{Value, json};
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use tower::{Service, ServiceExt};

use crate::config::{Config, ConfigError};
use crate::state::{AppState, Clock, RedisConn};
use crate::test_guard::ContainerGuard;

/// Result alias keeping `?` usable across containers, Redis, config, and sqlx.
pub(super) type TestResult = Result<(), Box<dyn Error>>;

/// Inner service standing in for the real downstream handler. A concrete
/// `Send` future keeps the layered service's `Future: Send` bound satisfiable.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Passthrough;

impl Service<Request<Body>> for Passthrough {
  type Response = Response<Body>;
  type Error = std::convert::Infallible;
  type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

  fn poll_ready(
    &mut self,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), Self::Error>> {
    std::task::Poll::Ready(Ok(()))
  }

  fn call(&mut self, _request: Request<Body>) -> Self::Future {
    std::future::ready(Ok(Response::new(Body::empty())))
  }
}

/// Start a single-node Redis with AOF enabled and return its URL.
///
/// The guard removes the container synchronously when the test drops it.
pub(super) async fn redis_container() -> Result<(ContainerGuard, String), Box<dyn Error>> {
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Build a validated config over `redis_url` with the given rate-limit block.
pub(super) fn test_config(redis_url: &str, rate_limit: Value) -> Result<Config, ConfigError> {
  let fixture = json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/ratelimit-test-cert.pem", "key_path": "/tmp/ratelimit-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/ratelimit"},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "ratelimit-test-pepper-0123456789abcdef",
    "totp_encryption_key": "ratelimit-test-totp-key-0123456789abcdef",
    "pii_encryption_key": "ratelimit-test-pii-key-0123456789abcdef",
    "rate_limit": rate_limit,
  });
  let source = ::config::Config::try_from(&fixture)?;
  Config::from_source(source)
}

/// Assemble state around a live Redis connection (lazy Postgres, never used).
fn build_state(
  pool: sqlx::PgPool,
  manager: ::redis::aio::ConnectionManager,
  config: Config,
) -> AppState {
  let config = Arc::new(config);
  let keys = Arc::new(config.keys.clone());
  AppState {
    pool,
    redis: RedisConn::Single(manager),
    config,
    keys,
    transition_unsafe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    clock: Clock::system(),
  }
}

/// State backed by a live Redis container.
pub(super) async fn live_state(
  config: Config,
  redis_url: &str,
) -> Result<AppState, Box<dyn Error>> {
  let pool =
    sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://127.0.0.1:1/ratelimit")?;
  let client = ::redis::Client::open(redis_url)?;
  let manager = ::redis::aio::ConnectionManager::new(client).await?;
  Ok(build_state(pool, manager, config))
}

/// State whose Redis points at a refused port; the first command fails fast.
pub(super) fn unavailable_state(config: Config) -> Result<AppState, Box<dyn Error>> {
  let pool =
    sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://127.0.0.1:1/ratelimit")?;
  let client = ::redis::Client::open("redis://127.0.0.1:1")?;
  let manager = ::redis::aio::ConnectionManager::new_lazy_with_config(
    client,
    ::redis::aio::ConnectionManagerConfig::new()
      .set_number_of_retries(0)
      .set_response_timeout(Some(Duration::from_millis(200)))
      .set_connection_timeout(Some(Duration::from_millis(200))),
  )?;
  Ok(build_state(pool, manager, config))
}

/// A loopback peer address with a caller-chosen last octet.
pub(super) fn peer(last: u8) -> SocketAddr {
  SocketAddr::from(([127, 0, 0, last], 40_000))
}

/// Connection and header extras for one test request.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Extras<'a> {
  /// Peer address recorded in `ConnectInfo`; `None` models a request the
  /// limiter receives with no recorded peer.
  pub peer: Option<SocketAddr>,
  /// Additional request headers, such as a forged `X-Forwarded-For`.
  pub headers: &'a [(&'a str, &'a str)],
}

/// Drive one request through the layered service from `peer_addr`.
pub(super) async fn send<S>(
  service: S,
  method: &str,
  uri: &str,
  body: &str,
  peer_addr: SocketAddr,
) -> Result<Response<Body>, Box<dyn Error>>
where
  S: Service<Request<Body>, Response = Response<Body>, Error = std::convert::Infallible>
    + Clone
    + Send
    + 'static,
  S::Future: Send + 'static,
{
  send_with(
    service,
    method,
    uri,
    body,
    Extras {
      peer: Some(peer_addr),
      headers: &[],
    },
  )
  .await
}

/// Drive one request through the layered service with [`Extras`].
///
/// `extras.peer == None` omits `ConnectInfo`, modeling a request whose peer
/// the limiter cannot identify.
pub(super) async fn send_with<S>(
  service: S,
  method: &str,
  uri: &str,
  body: &str,
  extras: Extras<'_>,
) -> Result<Response<Body>, Box<dyn Error>>
where
  S: Service<Request<Body>, Response = Response<Body>, Error = std::convert::Infallible>
    + Clone
    + Send
    + 'static,
  S::Future: Send + 'static,
{
  let mut builder = Request::builder()
    .method(method)
    .uri(uri)
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
  for (name, value) in extras.headers {
    builder = builder.header(*name, *value);
  }
  let mut request = builder.body(Body::from(body.to_owned()))?;
  if let Some(peer_addr) = extras.peer {
    request.extensions_mut().insert(ConnectInfo(peer_addr));
  }
  Ok(service.oneshot(request).await?)
}

/// Parse the seconds value of a `Retry-After` header.
pub(super) fn retry_after(response: &Response<Body>) -> Option<u64> {
  response
    .headers()
    .get(header::RETRY_AFTER)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
}

/// Collect every key matching `pattern` with a cursor-based `SCAN` (never a
/// blocking `KEYS`).
pub(super) async fn scan_keys(
  redis_url: &str,
  pattern: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
  let client = ::redis::Client::open(redis_url)?;
  let mut conn = client.get_multiplexed_async_connection().await?;
  let mut cursor: u64 = 0;
  let mut keys = Vec::new();
  loop {
    let (next, batch): (u64, Vec<String>) = ::redis::cmd("SCAN")
      .arg(cursor)
      .arg("MATCH")
      .arg(pattern)
      .arg("COUNT")
      .arg(100)
      .query_async(&mut conn)
      .await?;
    keys.extend(batch);
    cursor = next;
    if cursor == 0 {
      break;
    }
  }
  Ok(keys)
}

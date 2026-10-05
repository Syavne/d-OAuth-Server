//! Server bootstrap and graceful shutdown (`serve`).
//!
//! [`run`] is the whole `serve` subcommand: load [`Config`], install the
//! JSON tracing subscriber, connect [`AppState`] (which fails closed when
//! Postgres or Redis is unreachable or Redis violates the no-eviction/AOF
//! durability contract), build the public router with
//! [`build_router`](crate::routes::build_router), load the rustls server
//! config with
//! [`build_server_config`](crate::routes::build_server_config), drive the
//! **TLS public listener** with [`serve_tls`](crate::tls::serve_tls) (the
//! custom hyper-util/tokio-rustls accept loop that injects the verified
//! peer chain — never `axum::serve`, which cannot carry a per-connection
//! acceptor), and drive the **plaintext health listener** (`health_addr`,
//! the pod IP, never loopback-only) with `axum::serve` on the dedicated
//! [`health_router`](crate::state::health_router) (liveness + readiness
//! only, so every OAuth route 404s there by construction).
//!
//! Migrations are NEVER run here; the `migrate` subcommand owns them and
//! readiness fails closed when the schema version does not match.
//!
//! On SIGTERM (or SIGINT): `/health/ready` flips to 503 immediately, a
//! short propagation grace lets the kubelet observe it, in-flight requests
//! drain under a bounded deadline (below `terminationGracePeriodSeconds`),
//! then the pools close and the process exits 0. No business logic lives
//! here — only listener wiring and shutdown plumbing.

use std::{
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use axum::{
  Json,
  extract::{Request, State},
  http::StatusCode,
  middleware::{Next, from_fn_with_state},
  response::{IntoResponse, Response},
};
use tokio::net::TcpListener;

use crate::{cli::CliError, config::Config, state::AppState};

/// Grace between the readiness flip and listener shutdown, so the kubelet
/// observes 503 before endpoints are removed.
pub const PROPAGATION_GRACE: Duration = Duration::from_secs(1);
/// Upper bound for in-flight drain after the grace; under the
/// `terminationGracePeriodSeconds: 45` budget from the deployment manifests.
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// Run the `serve` subcommand to completion (returns on clean shutdown).
///
/// # Errors
/// Returns [`CliError`] for invalid configuration, a loopback health
/// address, unreadable TLS material, unconnectable state, bind failures, or
/// a listener that dies mid-serve. Every error path closes the pools.
pub async fn run() -> Result<(), CliError> {
  let _ = crate::middleware::observability::init();
  let config = Arc::new(Config::load()?);
  ensure_health_not_loopback(config.health_addr)?;
  let state = AppState::connect(config.clone()).await?;
  tracing::info!(
    redis_topology = state.redis.topology_name(),
    bind_addr = %config.bind_addr,
    health_addr = %config.health_addr,
    "server starting"
  );

  let acceptor = load_tls_acceptor(&config).await?;
  let draining = Arc::new(AtomicBool::new(false));
  let public = crate::routes::build_router(state.clone())
    .layer(from_fn_with_state(draining.clone(), drain_guard));
  let health = crate::state::health_router(state.clone())
    .layer(from_fn_with_state(draining.clone(), drain_guard));

  let tls_listener = TcpListener::bind(config.bind_addr).await?;
  let health_listener = TcpListener::bind(config.health_addr).await?;
  let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
  let mut tls_task = tokio::spawn(crate::tls::serve_tls(tls_listener, acceptor, public));
  let mut health_task = tokio::spawn(async move {
    axum::serve(health_listener, health.into_make_service())
      .with_graceful_shutdown(async {
        let _ = shutdown_rx.await;
      })
      .await
  });

  tokio::select! {
    outcome = &mut tls_task => {
      abort(&mut health_task);
      state.pool.close().await;
      return match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(CliError::Io(error)),
        Err(error) => Err(CliError::Input(format!("tls listener task failed: {error}"))),
      };
    }
    () = wait_termination() => {}
  }

  draining.store(true, Ordering::SeqCst);
  tracing::warn!("shutdown signal received: readiness now 503");
  tokio::time::sleep(PROPAGATION_GRACE).await;
  let _ = shutdown_tx.send(());
  if tokio::time::timeout(DRAIN_DEADLINE, &mut health_task)
    .await
    .is_err()
  {
    tracing::warn!("health listener drain timed out; aborting");
    abort(&mut health_task);
  }
  tls_task.abort();
  state.pool.close().await;
  tracing::warn!("shutdown complete");
  Ok(())
}

/// Refuse a loopback-only health listener: kubelet probes originate from
/// the node netns and cannot reach pod-loopback.
///
/// # Errors
/// Returns [`CliError::Input`] when `addr` is loopback.
fn ensure_health_not_loopback(addr: SocketAddr) -> Result<(), CliError> {
  if addr.ip().is_loopback() {
    return Err(CliError::Input(format!(
      "health_addr must bind the pod IP, not loopback: {addr}"
    )));
  }
  Ok(())
}

/// Load the PEM material and build the rustls acceptor for the public
/// listener. Any unreadable or invalid material fails closed here, so the
/// server never starts half-secured.
///
/// # Errors
/// Returns [`CliError`] when a file cannot be read or the material is
/// invalid.
async fn load_tls_acceptor(config: &Config) -> Result<tokio_rustls::TlsAcceptor, CliError> {
  let chain = tokio::fs::read(&config.tls.cert_path).await?;
  let key = tokio::fs::read(&config.tls.key_path).await?;
  let client_ca = match &config.tls.client_ca_path {
    Some(path) => Some(tokio::fs::read(path).await?),
    None => None,
  };
  let server_config = crate::routes::build_server_config(&chain, &key, client_ca.as_deref())
    .map_err(|error| CliError::Crypto(format!("invalid TLS material: {error}")))?;
  Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

/// Wait for SIGTERM (or SIGINT for local development).
async fn wait_termination() {
  #[cfg(unix)]
  {
    let term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
    let (term, interrupt) = match (term, interrupt) {
      (Ok(term), Ok(interrupt)) => (term, interrupt),
      _ => return,
    };
    tokio::select! {
      _ = wait_for(term) => {}
      _ = wait_for(interrupt) => {}
    }
  }
  #[cfg(not(unix))]
  {
    let _ = tokio::signal::ctrl_c().await;
  }
}

/// Resolve one unix signal stream.
#[cfg(unix)]
async fn wait_for(mut signal: tokio::signal::unix::Signal) {
  signal.recv().await;
}

/// Abort a listener task that is no longer needed.
fn abort<T>(task: &mut tokio::task::JoinHandle<T>) {
  task.abort();
}

/// See [`run`]: while draining, `/health/ready` answers 503 so the
/// endpoint is pulled before connections close; every other route passes
/// through untouched.
async fn drain_guard(
  State(draining): State<Arc<AtomicBool>>,
  request: Request,
  next: Next,
) -> Response {
  if draining.load(Ordering::SeqCst) && request.uri().path() == "/health/ready" {
    return (
      StatusCode::SERVICE_UNAVAILABLE,
      Json(serde_json::json!({ "status": "not_ready" })),
    )
      .into_response();
  }
  next.run(request).await
}

#[cfg(test)]
mod bootstrap_tests {
  use super::{DRAIN_DEADLINE, PROPAGATION_GRACE, drain_guard, ensure_health_not_loopback};
  use std::{sync::Arc, sync::atomic::AtomicBool, time::Duration};

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult = Result<(), Box<dyn std::error::Error>>;

  /// A loopback health listener is refused: kubelet probes cannot reach it.
  #[test]
  fn bootstrap_health_loopback_is_refused() -> TestResult {
    for addr in ["127.0.0.1:8081", "[::1]:8081"] {
      let parsed: std::net::SocketAddr = addr.parse()?;
      if ensure_health_not_loopback(parsed).is_ok() {
        return Err(format!("loopback health_addr must be refused: {addr}").into());
      }
    }
    for addr in ["0.0.0.0:8081", "[::]:8081"] {
      let parsed: std::net::SocketAddr = addr.parse()?;
      ensure_health_not_loopback(parsed)?;
    }
    Ok(())
  }

  /// The drain budget fits inside `terminationGracePeriodSeconds: 45`.
  #[test]
  fn bootstrap_drain_deadline_fits_termination_grace() -> TestResult {
    if DRAIN_DEADLINE + PROPAGATION_GRACE >= Duration::from_secs(45) {
      return Err("drain budget must stay below terminationGracePeriodSeconds".into());
    }
    Ok(())
  }

  /// While draining, `/health/ready` flips to 503 and `/health/live`
  /// stays 200.
  #[tokio::test]
  async fn bootstrap_drain_flips_ready_not_live() -> TestResult {
    use tower::ServiceExt as _;
    let draining = Arc::new(AtomicBool::new(false));
    let router = axum::Router::new()
      .route("/health/live", axum::routing::get(|| async { "live" }))
      .route("/health/ready", axum::routing::get(|| async { "ready" }))
      .layer(axum::middleware::from_fn_with_state(
        draining.clone(),
        drain_guard,
      ));
    let get = |router: axum::Router, path: &'static str| async move {
      let request = axum::http::Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())?;
      let response = router.oneshot(request).await.map_err(|_| "router error")?;
      Ok::<_, Box<dyn std::error::Error>>(response.status())
    };
    if get(router.clone(), "/health/live").await? != axum::http::StatusCode::OK {
      return Err("live must be 200 before drain".into());
    }
    draining.store(true, std::sync::atomic::Ordering::SeqCst);
    if get(router.clone(), "/health/ready").await? != axum::http::StatusCode::SERVICE_UNAVAILABLE {
      return Err("ready must flip to 503 while draining".into());
    }
    if get(router, "/health/live").await? != axum::http::StatusCode::OK {
      return Err("live must stay 200 while draining".into());
    }
    Ok(())
  }
}

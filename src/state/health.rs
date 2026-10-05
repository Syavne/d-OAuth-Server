//! Health-only router: `/health/live` + `/health/ready`, nothing else.
//!
//! Served on the plaintext `health_addr` listener (pod IP, never localhost
//! only, on a port not exposed via `Service`/`Ingress`). `/health/live`
//! touches no dependency and always returns 200. `/health/ready` returns 200
//! only when Postgres AND Redis answer AND the DB schema version matches the
//! binary's embedded migrations ([`MIGRATOR`]); anything else is a fail-closed
//! 503. The router mounts exactly these two routes, so every OAuth route 404s
//! on the plaintext listener by construction.

use std::collections::HashSet;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use tokio::time::timeout;

use super::{AppState, MIGRATOR, READINESS_TIMEOUT};

/// Liveness body.
#[derive(Serialize)]
struct LiveBody {
  status: &'static str,
}

/// Readiness body.
#[derive(Serialize)]
struct ReadyBody {
  status: &'static str,
}

/// Liveness: dependency-free, always 200.
async fn live() -> impl IntoResponse {
  (StatusCode::OK, Json(LiveBody { status: "live" }))
}

/// Whether every embedded migration is applied (fail-closed on any error).
async fn schema_ready(pool: &sqlx::PgPool) -> bool {
  let rows = sqlx::query("SELECT version FROM _sqlx_migrations WHERE success")
    .fetch_all(pool)
    .await;
  let rows = match rows {
    Ok(rows) => rows,
    Err(_) => return false,
  };
  let applied: HashSet<i64> = rows
    .iter()
    .filter_map(|row| {
      use sqlx::Row as _;
      row.try_get::<i64, &str>("version").ok()
    })
    .collect();
  MIGRATOR
    .migrations
    .iter()
    .all(|migration| applied.contains(&migration.version))
}

/// Readiness: Postgres ping + Redis ping + schema version, all bounded by
/// [`READINESS_TIMEOUT`]. Dependency outage is 503, never a panic or hang.
async fn ready(State(state): State<AppState>) -> impl IntoResponse {
  let healthy = timeout(READINESS_TIMEOUT, async {
    if sqlx::query("SELECT 1").execute(&state.pool).await.is_err() {
      return false;
    }
    let mut redis = state.redis.clone();
    let pong: Result<String, redis::RedisError> = redis::cmd("PING").query_async(&mut redis).await;
    if !matches!(pong.as_deref(), Ok("PONG")) {
      return false;
    }
    schema_ready(&state.pool).await
  })
  .await
  .is_ok_and(|healthy| healthy);
  if healthy {
    (StatusCode::OK, Json(ReadyBody { status: "ready" })).into_response()
  } else {
    (
      StatusCode::SERVICE_UNAVAILABLE,
      Json(ReadyBody {
        status: "not_ready",
      }),
    )
      .into_response()
  }
}

/// The dedicated health-only router (`/health/live` + `/health/ready` ONLY).
pub fn health_router(state: AppState) -> axum::Router {
  axum::Router::new()
    .route("/health/live", get(live))
    .route("/health/ready", get(ready))
    .with_state(state)
}

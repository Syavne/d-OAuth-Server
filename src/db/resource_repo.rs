//! `resource_servers` catalog repository (RFC 8707 resource indicators).
//!
//! Runtime-managed and starts empty, mirroring the `scopes` catalog: rows are
//! inserted via `upsert` and only ever disabled, never widened by matching.
//! `identifier` is the exact RFC 8707 resource identifier — lookups use plain
//! equality, with no prefix, suffix, URI normalization, or wildcard matching.
//!
//! Every query is a parameterized `sqlx` macro call. A database outage maps to
//! the crate-wide fail-closed `503 temporarily_unavailable` via
//! [`crate::error::AppError`].

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AppError;

/// A catalog resource server (RFC 8707 resource indicator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServer {
  /// Surrogate primary key.
  pub id: Uuid,
  /// Exact RFC 8707 resource identifier (unique in the catalog).
  pub identifier: String,
  /// Human-readable description.
  pub description: String,
  /// Whether the identifier may be requested and is advertised.
  pub enabled: bool,
  /// Row creation timestamp.
  pub created_at: OffsetDateTime,
}

/// Insert a resource server or update its description, preserving its
/// `enabled` state and surrogate id.
///
/// Idempotent, so configuration sync may run repeatedly: a resource server
/// disabled by an operator is not silently re-enabled by a later sync.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn upsert(
  pool: &PgPool,
  identifier: &str,
  description: &str,
) -> Result<ResourceServer, AppError> {
  let record = sqlx::query_as!(
    ResourceServer,
    r#"INSERT INTO resource_servers (id, identifier, description, enabled, created_at)
       VALUES ($1, $2, $3, true, now())
       ON CONFLICT (identifier) DO UPDATE
         SET description = EXCLUDED.description
       RETURNING id, identifier, description, enabled, created_at"#,
    Uuid::new_v4(),
    identifier,
    description,
  )
  .fetch_one(pool)
  .await?;
  Ok(record)
}

/// Look up an enabled resource server by its exact identifier; `None` when it
/// is unknown or disabled.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn find_enabled(
  pool: &PgPool,
  identifier: &str,
) -> Result<Option<ResourceServer>, AppError> {
  let record = sqlx::query_as!(
    ResourceServer,
    r#"SELECT id, identifier, description, enabled, created_at
         FROM resource_servers WHERE identifier = $1 AND enabled"#,
    identifier,
  )
  .fetch_optional(pool)
  .await?;
  Ok(record)
}

/// List every enabled resource server, ordered by identifier.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn list_enabled(pool: &PgPool) -> Result<Vec<ResourceServer>, AppError> {
  let records = sqlx::query_as!(
    ResourceServer,
    r#"SELECT id, identifier, description, enabled, created_at
         FROM resource_servers WHERE enabled ORDER BY identifier"#,
  )
  .fetch_all(pool)
  .await?;
  Ok(records)
}

/// Disable a resource server by its exact identifier. Returns whether a row was
/// updated; an unknown identifier is a no-op.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn disable(pool: &PgPool, identifier: &str) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE resource_servers SET enabled = false WHERE identifier = $1"#,
    identifier,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

#[cfg(test)]
mod tests;

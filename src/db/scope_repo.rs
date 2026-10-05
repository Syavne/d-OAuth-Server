//! `scopes` catalog repository (runtime-managed, starts empty).
//!
//! Single source of truth for `scopes_supported`; populated only via
//! `config sync` / `scope create`, never by migrations. A scope row may only be
//! deleted while no `user_scopes` entitlement references it, so the catalog
//! cannot silently strip an entitlement's target.

use crate::error::AppError;

/// A catalog scope entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRecord {
  /// Scope token (primary key).
  pub name: String,
  /// Human-readable description.
  pub description: String,
  /// Whether the scope is offered in discovery and may be requested.
  pub enabled: bool,
}

/// Insert a scope or update its description, preserving its `enabled` state.
///
/// Idempotent, so `config sync` may run repeatedly: a scope disabled by an
/// operator is not silently re-enabled by a later sync.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn upsert(
  pool: &sqlx::PgPool,
  name: &str,
  description: &str,
) -> Result<ScopeRecord, AppError> {
  let record = sqlx::query_as!(
    ScopeRecord,
    r#"INSERT INTO scopes (name, description, enabled, created_at, updated_at)
       VALUES ($1, $2, true, now(), now())
       ON CONFLICT (name) DO UPDATE
         SET description = EXCLUDED.description, updated_at = now()
       RETURNING name, description, enabled"#,
    name,
    description,
  )
  .fetch_one(pool)
  .await?;
  Ok(record)
}

/// Look up a scope by name; `None` when absent.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn get(pool: &sqlx::PgPool, name: &str) -> Result<Option<ScopeRecord>, AppError> {
  let record = sqlx::query_as!(
    ScopeRecord,
    r#"SELECT name, description, enabled FROM scopes WHERE name = $1"#,
    name,
  )
  .fetch_optional(pool)
  .await?;
  Ok(record)
}

/// List every enabled scope, ordered by name.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn list_enabled(pool: &sqlx::PgPool) -> Result<Vec<ScopeRecord>, AppError> {
  let records = sqlx::query_as!(
    ScopeRecord,
    r#"SELECT name, description, enabled FROM scopes
        WHERE enabled ORDER BY name"#,
  )
  .fetch_all(pool)
  .await?;
  Ok(records)
}

/// List every scope (enabled and disabled), ordered by name.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn list_all(pool: &sqlx::PgPool) -> Result<Vec<ScopeRecord>, AppError> {
  let records = sqlx::query_as!(
    ScopeRecord,
    r#"SELECT name, description, enabled FROM scopes ORDER BY name"#,
  )
  .fetch_all(pool)
  .await?;
  Ok(records)
}

/// Enable or disable a scope. Returns whether a row was updated.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn set_enabled(pool: &sqlx::PgPool, name: &str, enabled: bool) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"UPDATE scopes SET enabled = $2, updated_at = now() WHERE name = $1"#,
    name,
    enabled,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// Delete a scope only when no `user_scopes` entitlement references it.
///
/// Returns `true` when a row was deleted. Deleting a referenced scope would
/// either cascade away entitlements or violate the foreign key, so this is a
/// guarded no-op instead.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn delete_if_unreferenced(pool: &sqlx::PgPool, name: &str) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"DELETE FROM scopes
        WHERE name = $1
          AND NOT EXISTS (SELECT 1 FROM user_scopes WHERE scope_name = $1)"#,
    name,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

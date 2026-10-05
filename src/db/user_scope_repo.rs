//! `user_scopes` entitlement repository.
//!
//! Per-user grants; new users start with none. User-bound token scope is
//! `requested ∩ client-registered ∩ user-entitled ∩ enabled`. This module owns
//! the entitled set; the enabled catalog is `scope_repo`.

use uuid::Uuid;

use crate::error::AppError;

/// Grant a scope to a user. Idempotent: re-granting an existing entitlement is
/// a no-op that preserves the original `granted_at`/`granted_by` audit values.
///
/// # Errors
/// Returns an error when the user or scope does not exist, or on any database
/// failure.
pub async fn entitle(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  scope_name: &str,
  granted_by: Option<Uuid>,
) -> Result<(), AppError> {
  sqlx::query!(
    r#"INSERT INTO user_scopes (user_id, scope_name, granted_at, granted_by)
       VALUES ($1, $2, now(), $3)
       ON CONFLICT (user_id, scope_name) DO NOTHING"#,
    user_id,
    scope_name,
    granted_by,
  )
  .execute(pool)
  .await?;
  Ok(())
}

/// Revoke a scope from a user. Returns whether an entitlement was removed.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn revoke(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  scope_name: &str,
) -> Result<bool, AppError> {
  let result = sqlx::query!(
    r#"DELETE FROM user_scopes WHERE user_id = $1 AND scope_name = $2"#,
    user_id,
    scope_name,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() == 1)
}

/// List a user's entitled scope names, ordered by name.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn list_for_user(pool: &sqlx::PgPool, user_id: Uuid) -> Result<Vec<String>, AppError> {
  let names = sqlx::query_scalar!(
    r#"SELECT scope_name FROM user_scopes
        WHERE user_id = $1 ORDER BY scope_name"#,
    user_id,
  )
  .fetch_all(pool)
  .await?;
  Ok(names)
}

/// Whether a user is entitled to a specific scope.
///
/// # Errors
/// Returns an error on any database failure.
pub async fn is_entitled(
  pool: &sqlx::PgPool,
  user_id: Uuid,
  scope_name: &str,
) -> Result<bool, AppError> {
  let entitled = sqlx::query_scalar!(
    r#"SELECT EXISTS(
         SELECT 1 FROM user_scopes WHERE user_id = $1 AND scope_name = $2
       ) AS "exists!""#,
    user_id,
    scope_name,
  )
  .fetch_one(pool)
  .await?;
  Ok(entitled)
}

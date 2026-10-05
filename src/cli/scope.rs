//! `scope` subcommands and the shared idempotent scope upsert.

use sqlx::{PgPool, Row as _};

use super::context::{CliError, Context, audit};

/// Outcome of an idempotent upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
  /// A new row was inserted.
  Created,
  /// An existing row's mutable fields changed.
  Updated,
  /// The row already matched; nothing changed.
  Unchanged,
}

/// Run a `scope` subcommand.
///
/// # Errors
/// Returns [`CliError`] for invalid names, missing scopes, or database errors.
pub async fn run(context: &Context, command: super::ScopeCommand) -> Result<(), CliError> {
  match command {
    super::ScopeCommand::Create { name, description } => {
      validate(&name)?;
      match upsert(context.pool(), &name, description.as_deref(), true).await? {
        Upsert::Created => println!("created scope {name}"),
        Upsert::Updated => println!("updated scope {name}"),
        Upsert::Unchanged => println!("scope {name} unchanged"),
      }
      audit("scope.create", &name);
      Ok(())
    }
    super::ScopeCommand::List => list(context).await,
    super::ScopeCommand::Enable { name } => set_enabled(context, &name, true).await,
    super::ScopeCommand::Disable { name } => set_enabled(context, &name, false).await,
    super::ScopeCommand::Delete { name } => delete(context, &name).await,
  }
}

/// List the scope catalog.
async fn list(context: &Context) -> Result<(), CliError> {
  let rows = sqlx::query("SELECT name, description, enabled FROM scopes ORDER BY name")
    .fetch_all(context.pool())
    .await?;
  if rows.is_empty() {
    println!("scope catalog is empty");
    return Ok(());
  }
  for row in rows {
    let name: String = row.try_get("name")?;
    let description: String = row.try_get("description")?;
    let enabled: bool = row.try_get("enabled")?;
    let state = if enabled { "enabled" } else { "disabled" };
    println!("{name}\t{state}\t{description}");
  }
  Ok(())
}

/// Enable or disable a scope.
async fn set_enabled(context: &Context, name: &str, enabled: bool) -> Result<(), CliError> {
  let affected = sqlx::query("UPDATE scopes SET enabled = $2, updated_at = now() WHERE name = $1")
    .bind(name)
    .bind(enabled)
    .execute(context.pool())
    .await?
    .rows_affected();
  if affected == 0 {
    return Err(CliError::NotFound(format!("scope {name}")));
  }
  let operation = if enabled {
    "scope.enable"
  } else {
    "scope.disable"
  };
  audit(operation, name);
  println!(
    "{} scope {name}",
    if enabled { "enabled" } else { "disabled" }
  );
  Ok(())
}

/// Delete a scope, or disable it when entitlements reference it.
async fn delete(context: &Context, name: &str) -> Result<(), CliError> {
  let referenced: bool =
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_scopes WHERE scope_name = $1)")
      .bind(name)
      .fetch_one(context.pool())
      .await?;
  if referenced {
    let affected =
      sqlx::query("UPDATE scopes SET enabled = false, updated_at = now() WHERE name = $1")
        .bind(name)
        .execute(context.pool())
        .await?
        .rows_affected();
    if affected == 0 {
      return Err(CliError::NotFound(format!("scope {name}")));
    }
    audit("scope.disable", name);
    println!("scope {name} is referenced; disabled instead of deleted");
    return Ok(());
  }
  let affected = sqlx::query("DELETE FROM scopes WHERE name = $1")
    .bind(name)
    .execute(context.pool())
    .await?
    .rows_affected();
  if affected == 0 {
    return Err(CliError::NotFound(format!("scope {name}")));
  }
  audit("scope.delete", name);
  println!("deleted scope {name}");
  Ok(())
}

/// Validate a scope name against the shared scope-token grammar.
///
/// # Errors
/// Returns [`CliError::Config`] when the name is empty, malformed, or reserved.
pub fn validate(name: &str) -> Result<(), CliError> {
  crate::config::scope::validate_scope_name(name).map_err(CliError::from)
}

/// Idempotently create or update a scope.
///
/// `updated_at` moves only when a mutable field actually changed, so a second
/// identical run is a true no-op.
///
/// # Errors
/// Returns [`CliError::Database`] on failure.
pub async fn upsert(
  pool: &PgPool,
  name: &str,
  description: Option<&str>,
  enabled: bool,
) -> Result<Upsert, CliError> {
  let description = description.unwrap_or_default();
  let row = sqlx::query(
    "INSERT INTO scopes (name, description, enabled, created_at, updated_at)
     VALUES ($1, $2, $3, now(), now())
     ON CONFLICT (name) DO UPDATE
       SET description = EXCLUDED.description,
           enabled = EXCLUDED.enabled,
           updated_at = now()
       WHERE scopes.description IS DISTINCT FROM EXCLUDED.description
          OR scopes.enabled IS DISTINCT FROM EXCLUDED.enabled
     RETURNING (xmax = 0) AS inserted",
  )
  .bind(name)
  .bind(description)
  .bind(enabled)
  .fetch_optional(pool)
  .await?;
  Ok(match row {
    Some(row) if row.try_get::<bool, _>("inserted").unwrap_or(false) => Upsert::Created,
    Some(_) => Upsert::Updated,
    None => Upsert::Unchanged,
  })
}

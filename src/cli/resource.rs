//! `resource-server` subcommands and the shared idempotent catalog upsert.
//!
//! The catalog is the RFC 8707 resource-indicator allowlist. Identifiers match
//! exactly (no normalization, no sub-path, and no wildcard): `identifier` is a
//! public URI, so it is safe to print, but `*` is rejected as a wildcard.

use sqlx::Row as _;

use super::{
  ResourceServerCommand,
  context::{CliError, Context, audit},
  scope::Upsert,
};
use crate::db::resource_repo;

/// Run a `resource-server` subcommand.
///
/// # Errors
/// Returns [`CliError`] for an invalid identifier, a missing row, or a
/// database failure.
pub async fn run(context: &Context, command: ResourceServerCommand) -> Result<(), CliError> {
  match command {
    ResourceServerCommand::Create {
      identifier,
      description,
    } => {
      match upsert(context, &identifier, description.as_deref(), true).await? {
        Upsert::Created => println!("created resource server {identifier}"),
        Upsert::Updated => println!("updated resource server {identifier}"),
        Upsert::Unchanged => println!("resource server {identifier} unchanged"),
      }
      audit("resource_server.create", &identifier);
      Ok(())
    }
    ResourceServerCommand::List => list(context).await,
    ResourceServerCommand::Enable { identifier } => set_enabled(context, &identifier, true).await,
    ResourceServerCommand::Disable { identifier } => set_enabled(context, &identifier, false).await,
    ResourceServerCommand::Delete { identifier } => delete(context, &identifier).await,
  }
}

/// List the resource-server catalog (enabled and disabled).
async fn list(context: &Context) -> Result<(), CliError> {
  let rows = sqlx::query(
    "SELECT identifier, description, enabled FROM resource_servers ORDER BY identifier",
  )
  .fetch_all(context.pool())
  .await?;
  if rows.is_empty() {
    println!("resource server catalog is empty");
    return Ok(());
  }
  for row in rows {
    let identifier: String = row.try_get("identifier")?;
    let description: String = row.try_get("description")?;
    let enabled: bool = row.try_get("enabled")?;
    let state = if enabled { "enabled" } else { "disabled" };
    println!("{identifier}\t{state}\t{description}");
  }
  Ok(())
}

/// Enable or disable a resource server by its exact identifier.
async fn set_enabled(context: &Context, identifier: &str, enabled: bool) -> Result<(), CliError> {
  let affected = if enabled {
    sqlx::query("UPDATE resource_servers SET enabled = true WHERE identifier = $1")
      .bind(identifier)
      .execute(context.pool())
      .await?
      .rows_affected()
  } else {
    u64::from(resource_repo::disable(context.pool(), identifier).await?)
  };
  if affected == 0 {
    return Err(CliError::NotFound(format!("resource server {identifier}")));
  }
  let operation = if enabled {
    "resource_server.enable"
  } else {
    "resource_server.disable"
  };
  audit(operation, identifier);
  println!(
    "{} resource server {identifier}",
    if enabled { "enabled" } else { "disabled" }
  );
  Ok(())
}

/// Delete a resource server by its exact identifier.
async fn delete(context: &Context, identifier: &str) -> Result<(), CliError> {
  let affected = sqlx::query("DELETE FROM resource_servers WHERE identifier = $1")
    .bind(identifier)
    .execute(context.pool())
    .await?
    .rows_affected();
  if affected == 0 {
    return Err(CliError::NotFound(format!("resource server {identifier}")));
  }
  audit("resource_server.delete", identifier);
  println!("deleted resource server {identifier}");
  Ok(())
}

/// Validate an RFC 8707 resource identifier.
///
/// The catalog is fail-closed: the value must be an absolute `https` URI with
/// a host, and an empty identifier, a wildcard `*`, userinfo, a fragment, or a
/// query is rejected so a single row can never stand for an entire origin or a
/// non-fetchable identifier.
///
/// # Errors
/// Returns [`CliError::Input`] for any of the rejected shapes.
pub fn validate(identifier: &str) -> Result<(), CliError> {
  if identifier.trim().is_empty() {
    return Err(CliError::Input(
      "resource identifier must not be empty".to_owned(),
    ));
  }
  if identifier.contains('*') {
    return Err(CliError::Input(
      "resource identifier must not contain a wildcard '*'".to_owned(),
    ));
  }
  let url = reqwest::Url::parse(identifier)
    .map_err(|_| CliError::Input("resource identifier must be an absolute https URI".to_owned()))?;
  if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
    return Err(CliError::Input(
      "resource identifier must be an absolute https URI with a host".to_owned(),
    ));
  }
  if !url.username().is_empty() || url.password().is_some() {
    return Err(CliError::Input(
      "resource identifier must not contain userinfo".to_owned(),
    ));
  }
  if url.fragment().is_some() {
    return Err(CliError::Input(
      "resource identifier must not contain a fragment".to_owned(),
    ));
  }
  if url.query().is_some() {
    return Err(CliError::Input(
      "resource identifier must not contain a query".to_owned(),
    ));
  }
  Ok(())
}

/// Idempotently create or update a resource server, preserving `enabled`.
///
/// A second identical run writes nothing (`Unchanged`), so `config sync` stays
/// a true no-op; an operator-disabled row is never silently re-enabled.
///
/// # Errors
/// Returns [`CliError`] for an invalid identifier or a database failure.
pub async fn upsert(
  context: &Context,
  identifier: &str,
  description: Option<&str>,
  enabled: bool,
) -> Result<Upsert, CliError> {
  validate(identifier)?;
  let description = description.unwrap_or_default();
  let existing =
    sqlx::query("SELECT description, enabled FROM resource_servers WHERE identifier = $1")
      .bind(identifier)
      .fetch_optional(context.pool())
      .await?;
  let Some(row) = existing else {
    resource_repo::upsert(context.pool(), identifier, description).await?;
    if !enabled {
      resource_repo::disable(context.pool(), identifier).await?;
    }
    return Ok(Upsert::Created);
  };
  let stored_description: String = row.try_get("description")?;
  let stored_enabled: bool = row.try_get("enabled")?;
  let mut changed = false;
  if stored_description != description {
    resource_repo::upsert(context.pool(), identifier, description).await?;
    changed = true;
  }
  if !enabled && stored_enabled {
    resource_repo::disable(context.pool(), identifier).await?;
    changed = true;
  }
  Ok(if changed {
    Upsert::Updated
  } else {
    Upsert::Unchanged
  })
}

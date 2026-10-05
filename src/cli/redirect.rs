//! `redirect-uri` and `client` subcommands plus the shared URI upsert.

use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::{
  ClientCommand, RedirectUriCommand,
  context::{CliError, Context, audit},
  scope::Upsert,
};

/// Run a `redirect-uri` subcommand.
///
/// # Errors
/// Returns [`CliError`] for missing URIs, invalid input, or database errors.
pub async fn run_uri(context: &Context, command: RedirectUriCommand) -> Result<(), CliError> {
  match command {
    RedirectUriCommand::Create {
      uri,
      kind,
      description,
    } => {
      match upsert(context.pool(), &uri, &kind, description.as_deref(), true).await? {
        Upsert::Created => println!("created redirect uri {uri}"),
        Upsert::Updated => println!("updated redirect uri {uri}"),
        Upsert::Unchanged => println!("redirect uri {uri} unchanged"),
      }
      audit("redirect_uri.create", &uri);
      Ok(())
    }
    RedirectUriCommand::List => list(context).await,
    RedirectUriCommand::Enable { uri, kind } => set_enabled(context, &uri, &kind, true).await,
    RedirectUriCommand::Disable { uri, kind } => set_enabled(context, &uri, &kind, false).await,
    RedirectUriCommand::Delete { uri, kind } => delete(context, &uri, &kind).await,
  }
}

/// Run a `client` subcommand.
///
/// # Errors
/// Returns [`CliError`] for a missing client/URI or a database error.
pub async fn run_client(context: &Context, command: ClientCommand) -> Result<(), CliError> {
  match command {
    ClientCommand::AttachRedirectUri {
      client_id,
      uri,
      kind,
    } => attach(context, &client_id, &uri, &kind).await,
    ClientCommand::DetachRedirectUri {
      client_id,
      uri,
      kind,
    } => detach(context, &client_id, &uri, &kind).await,
    ClientCommand::RedirectUris { client_id } => list_for_client(context, &client_id).await,
  }
}

async fn list(context: &Context) -> Result<(), CliError> {
  let rows =
    sqlx::query("SELECT uri, kind, description, enabled FROM redirect_uris ORDER BY uri, kind")
      .fetch_all(context.pool())
      .await?;
  if rows.is_empty() {
    println!("redirect uri catalog is empty");
    return Ok(());
  }
  for row in rows {
    let uri: String = row.try_get("uri")?;
    let kind: String = row.try_get("kind")?;
    let description: String = row.try_get("description")?;
    let enabled: bool = row.try_get("enabled")?;
    let state = if enabled { "enabled" } else { "disabled" };
    println!("{uri}\t{kind}\t{state}\t{description}");
  }
  Ok(())
}

async fn set_enabled(
  context: &Context,
  uri: &str,
  kind: &str,
  enabled: bool,
) -> Result<(), CliError> {
  let affected = sqlx::query(
    "UPDATE redirect_uris SET enabled = $3, updated_at = now() WHERE uri = $1 AND kind = $2",
  )
  .bind(uri)
  .bind(kind)
  .bind(enabled)
  .execute(context.pool())
  .await?
  .rows_affected();
  if affected == 0 {
    return Err(CliError::NotFound(format!("redirect uri {uri} ({kind})")));
  }
  let operation = if enabled {
    "redirect_uri.enable"
  } else {
    "redirect_uri.disable"
  };
  audit(operation, uri);
  println!(
    "{} redirect uri {uri} ({kind})",
    if enabled { "enabled" } else { "disabled" }
  );
  Ok(())
}

async fn delete(context: &Context, uri: &str, kind: &str) -> Result<(), CliError> {
  let referenced: bool = sqlx::query_scalar(
    "SELECT EXISTS(
       SELECT 1 FROM client_redirect_uris c
       JOIN redirect_uris r ON r.id = c.redirect_uri_id
       WHERE r.uri = $1 AND r.kind = $2)",
  )
  .bind(uri)
  .bind(kind)
  .fetch_one(context.pool())
  .await?;
  if referenced {
    let affected = sqlx::query(
      "UPDATE redirect_uris SET enabled = false, updated_at = now() \
       WHERE uri = $1 AND kind = $2",
    )
    .bind(uri)
    .bind(kind)
    .execute(context.pool())
    .await?
    .rows_affected();
    if affected == 0 {
      return Err(CliError::NotFound(format!("redirect uri {uri} ({kind})")));
    }
    audit("redirect_uri.disable", uri);
    println!("redirect uri {uri} ({kind}) is attached; disabled instead of deleted");
    return Ok(());
  }
  let affected = sqlx::query("DELETE FROM redirect_uris WHERE uri = $1 AND kind = $2")
    .bind(uri)
    .bind(kind)
    .execute(context.pool())
    .await?
    .rows_affected();
  if affected == 0 {
    return Err(CliError::NotFound(format!("redirect uri {uri} ({kind})")));
  }
  audit("redirect_uri.delete", uri);
  println!("deleted redirect uri {uri} ({kind})");
  Ok(())
}

async fn attach(context: &Context, client_id: &str, uri: &str, kind: &str) -> Result<(), CliError> {
  ensure_client_exists(context, client_id).await?;
  let redirect_id = find_redirect_id(context, uri, kind).await?;
  sqlx::query(
    "INSERT INTO client_redirect_uris (client_id, redirect_uri_id, attached_at)
     VALUES ($1, $2, now())
     ON CONFLICT (client_id, redirect_uri_id) DO NOTHING",
  )
  .bind(client_id)
  .bind(redirect_id)
  .execute(context.pool())
  .await?;
  audit("client.attach_redirect_uri", &format!("{client_id}:{uri}"));
  println!("attached {uri} ({kind}) to {client_id}");
  Ok(())
}

async fn detach(context: &Context, client_id: &str, uri: &str, kind: &str) -> Result<(), CliError> {
  let redirect_id = find_redirect_id(context, uri, kind).await?;
  sqlx::query("DELETE FROM client_redirect_uris WHERE client_id = $1 AND redirect_uri_id = $2")
    .bind(client_id)
    .bind(redirect_id)
    .execute(context.pool())
    .await?;
  audit("client.detach_redirect_uri", &format!("{client_id}:{uri}"));
  println!("detached {uri} ({kind}) from {client_id}");
  Ok(())
}

async fn list_for_client(context: &Context, client_id: &str) -> Result<(), CliError> {
  ensure_client_exists(context, client_id).await?;
  let uris: Vec<(String, String)> = sqlx::query_as(
    "SELECT r.uri, r.kind FROM client_redirect_uris c
       JOIN redirect_uris r ON r.id = c.redirect_uri_id
      WHERE c.client_id = $1
      ORDER BY r.uri, r.kind",
  )
  .bind(client_id)
  .fetch_all(context.pool())
  .await?;
  if uris.is_empty() {
    println!("{client_id} has no attached redirect URIs");
  } else {
    for (uri, kind) in uris {
      println!("{uri}\t{kind}");
    }
  }
  Ok(())
}

/// Idempotently create or update a redirect URI.
///
/// # Errors
/// Returns [`CliError::Database`] on failure.
pub async fn upsert(
  pool: &PgPool,
  uri: &str,
  kind: &str,
  description: Option<&str>,
  enabled: bool,
) -> Result<Upsert, CliError> {
  let description = description.unwrap_or_default();
  let id = Uuid::new_v4();
  let row = sqlx::query(
    "INSERT INTO redirect_uris (id, uri, kind, description, enabled, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, now(), now())
     ON CONFLICT (uri, kind) DO UPDATE
       SET description = EXCLUDED.description,
           enabled = EXCLUDED.enabled,
           updated_at = now()
       WHERE redirect_uris.description IS DISTINCT FROM EXCLUDED.description
          OR redirect_uris.enabled IS DISTINCT FROM EXCLUDED.enabled
     RETURNING (xmax = 0) AS inserted",
  )
  .bind(id)
  .bind(uri)
  .bind(kind)
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

/// Resolve a catalog redirect-URI id by its exact URI and kind.
///
/// # Errors
/// Returns [`CliError::NotFound`] when the URI is not in the catalog.
pub async fn find_redirect_id(context: &Context, uri: &str, kind: &str) -> Result<Uuid, CliError> {
  let id: Option<Uuid> =
    sqlx::query_scalar("SELECT id FROM redirect_uris WHERE uri = $1 AND kind = $2")
      .bind(uri)
      .bind(kind)
      .fetch_optional(context.pool())
      .await?;
  id.ok_or_else(|| CliError::NotFound(format!("redirect uri {uri} ({kind})")))
}

/// Ensure an OAuth client exists.
///
/// # Errors
/// Returns [`CliError::NotFound`] when the client is unknown.
pub async fn ensure_client_exists(context: &Context, client_id: &str) -> Result<(), CliError> {
  let exists: bool =
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE client_id = $1)")
      .bind(client_id)
      .fetch_one(context.pool())
      .await?;
  if exists {
    Ok(())
  } else {
    Err(CliError::NotFound(format!("client {client_id}")))
  }
}

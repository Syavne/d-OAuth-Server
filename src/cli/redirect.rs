//! `redirect-uri` and `client` subcommands plus the shared URI upsert.

use sqlx::Row as _;
use uuid::Uuid;

use super::{
  ClientCommand, RedirectUriCommand,
  context::{CliError, Context, audit},
  scope::Upsert,
};
use crate::{
  crypto::field::blind_index_candidates,
  db::{NewRedirectUri, RedirectKind, UpsertOutcome, redirect_repo},
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
      match upsert(context, &uri, &kind, description.as_deref(), true).await? {
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
  let uris = redirect_repo::list(context.pool(), &context.config().keys, true).await?;
  if uris.is_empty() {
    println!("redirect uri catalog is empty");
    return Ok(());
  }
  for entry in uris {
    let state = if entry.enabled { "enabled" } else { "disabled" };
    println!(
      "{}\t{}\t{}\t{}",
      entry.uri, entry.kind, state, entry.description
    );
  }
  Ok(())
}

async fn set_enabled(
  context: &Context,
  uri: &str,
  kind: &str,
  enabled: bool,
) -> Result<(), CliError> {
  let id = find_redirect_id(context, uri, kind).await?;
  if redirect_repo::set_enabled(context.pool(), &context.config().keys, id, enabled)
    .await?
    .is_none()
  {
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
  let id = find_redirect_id(context, uri, kind).await?;
  if redirect_repo::delete_if_unattached(context.pool(), id).await? {
    audit("redirect_uri.delete", uri);
    println!("deleted redirect uri {uri} ({kind})");
    return Ok(());
  }
  if redirect_repo::set_enabled(context.pool(), &context.config().keys, id, false)
    .await?
    .is_none()
  {
    return Err(CliError::NotFound(format!("redirect uri {uri} ({kind})")));
  }
  audit("redirect_uri.disable", uri);
  println!("redirect uri {uri} ({kind}) is attached; disabled instead of deleted");
  Ok(())
}

async fn attach(context: &Context, client_id: &str, uri: &str, kind: &str) -> Result<(), CliError> {
  ensure_client_exists(context, client_id).await?;
  let redirect_id = find_redirect_id(context, uri, kind).await?;
  redirect_repo::attach(context.pool(), client_id, redirect_id, None).await?;
  audit("client.attach_redirect_uri", &format!("{client_id}:{uri}"));
  println!("attached {uri} ({kind}) to {client_id}");
  Ok(())
}

async fn detach(context: &Context, client_id: &str, uri: &str, kind: &str) -> Result<(), CliError> {
  let redirect_id = find_redirect_id(context, uri, kind).await?;
  redirect_repo::detach(context.pool(), client_id, redirect_id).await?;
  audit("client.detach_redirect_uri", &format!("{client_id}:{uri}"));
  println!("detached {uri} ({kind}) from {client_id}");
  Ok(())
}

async fn list_for_client(context: &Context, client_id: &str) -> Result<(), CliError> {
  ensure_client_exists(context, client_id).await?;
  let uris =
    redirect_repo::list_for_client(context.pool(), &context.config().keys, client_id).await?;
  if uris.is_empty() {
    println!("{client_id} has no attached redirect URIs");
  } else {
    for entry in uris {
      println!("{}\t{}", entry.uri, entry.kind);
    }
  }
  Ok(())
}

/// Idempotently create a catalog redirect URI, or adopt a legacy plaintext row.
///
/// The write routes through [`redirect_repo::upsert`] with the PII key ring and
/// the dual-write flag, so the URI is sealed into `uri_enc` and blind-indexed
/// into `uri_index`. An already-sealed row is left untouched (`Unchanged`),
/// which preserves its `description`/`enabled` and keeps `config sync`
/// idempotent; a declared `enabled` applies only to a freshly created row.
///
/// # Errors
/// Returns [`CliError`] on a repository or database failure.
pub async fn upsert(
  context: &Context,
  uri: &str,
  kind: &str,
  description: Option<&str>,
  enabled: bool,
) -> Result<Upsert, CliError> {
  if !crate::protocol::redirect_repo::is_valid_redirect_scheme(uri) {
    return Err(CliError::Input(
      "redirect URI private-use scheme must contain reverse-DNS dot notation \
       (draft-ietf-oauth-v2-1-16 §2.3.1)"
        .to_owned(),
    ));
  }
  let keys = &context.config().keys;
  if find_existing(context, uri, kind)
    .await?
    .is_some_and(|(_, encrypted)| encrypted)
  {
    return Ok(Upsert::Unchanged);
  }
  let new = NewRedirectUri {
    id: Uuid::new_v4(),
    uri,
    kind: RedirectKind::parse(kind),
    description: description.unwrap_or_default(),
    created_by: None,
  };
  let (row, outcome) =
    redirect_repo::upsert(context.pool(), keys, context.config().pii_dual_write, &new).await?;
  if outcome == UpsertOutcome::Created && !enabled {
    redirect_repo::set_enabled(context.pool(), keys, row.id, false).await?;
  }
  Ok(match outcome {
    UpsertOutcome::Created => Upsert::Created,
    UpsertOutcome::Updated => Upsert::Updated,
  })
}

/// Resolve a catalog redirect-URI id by its exact URI and kind.
///
/// The lookup matches through the keyed blind index (ciphertext rows) with a
/// plaintext fallback for legacy rows whose `uri_index` is still NULL, so a
/// sealed catalog stays resolvable.
///
/// # Errors
/// Returns [`CliError::NotFound`] when the URI is not in the catalog.
pub async fn find_redirect_id(context: &Context, uri: &str, kind: &str) -> Result<Uuid, CliError> {
  find_existing(context, uri, kind)
    .await?
    .map(|(id, _)| id)
    .ok_or_else(|| CliError::NotFound(format!("redirect uri {uri} ({kind})")))
}

/// Resolve a catalog row's id and whether it already carries ciphertext,
/// through the blind-index candidates plus the legacy plaintext fallback.
async fn find_existing(
  context: &Context,
  uri: &str,
  kind: &str,
) -> Result<Option<(Uuid, bool)>, CliError> {
  let candidates = blind_index_candidates(&context.config().keys, uri);
  let row = sqlx::query(
    "SELECT id, (uri_enc IS NOT NULL) AS encrypted FROM redirect_uris \
     WHERE kind = $1 AND (uri_index = ANY($2) OR (uri_enc IS NULL AND uri = $3))",
  )
  .bind(kind)
  .bind(&candidates)
  .bind(uri)
  .fetch_optional(context.pool())
  .await?;
  match row {
    Some(row) => {
      let id: Uuid = row.try_get("id")?;
      let encrypted: bool = row.try_get("encrypted")?;
      Ok(Some((id, encrypted)))
    }
    None => Ok(None),
  }
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

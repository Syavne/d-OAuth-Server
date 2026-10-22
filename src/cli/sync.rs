//! `config sync`: idempotent, declarative apply of the scope catalog, the
//! redirect-URI catalog, per-user entitlements, and client attachments.
//!
//! The file is JSON. A second run of the same file performs zero writes and
//! reports zero changes, which is the idempotency contract.

use std::{fmt, path::Path};

use serde::Deserialize;

use super::{
  context::{CliError, Context, audit},
  redirect, resource, scope,
};
use crate::db::{client_repo, redirect_repo};

/// Top-level declarative file.
#[derive(Debug, Default, Deserialize)]
pub struct SyncFile {
  /// Scope-catalog entries.
  #[serde(default)]
  pub scopes: Vec<ScopeEntry>,
  /// Redirect-URI-catalog entries.
  #[serde(default)]
  pub redirect_uris: Vec<RedirectEntry>,
  /// Resource-server (RFC 8707 resource indicator) catalog entries.
  #[serde(default)]
  pub resource_servers: Vec<ResourceServerEntry>,
  /// Per-user scope entitlements.
  #[serde(default)]
  pub user_scopes: Vec<EntitlementEntry>,
  /// Per-client redirect-URI attachments.
  #[serde(default)]
  pub client_redirect_uris: Vec<AttachmentEntry>,
  /// Per-client access-token-format overrides (operator-only opt-in to JWT).
  #[serde(default)]
  pub client_access_token_formats: Vec<ClientTokenFormatEntry>,
}

/// A declarative scope.
#[derive(Debug, Deserialize)]
pub struct ScopeEntry {
  /// Scope name.
  pub name: String,
  /// Optional description.
  #[serde(default)]
  pub description: Option<String>,
  /// Whether the scope is enabled (default true).
  #[serde(default = "default_true")]
  pub enabled: bool,
}

/// A declarative redirect URI.
#[derive(Debug, Deserialize)]
pub struct RedirectEntry {
  /// Absolute redirect URI.
  pub uri: String,
  /// Catalog kind: `authorize` (default) or `post_logout`.
  #[serde(default = "default_kind")]
  pub kind: String,
  /// Optional description.
  #[serde(default)]
  pub description: Option<String>,
  /// Whether the URI is enabled (default true).
  #[serde(default = "default_true")]
  pub enabled: bool,
}

/// A declarative user entitlement.
#[derive(Debug, Deserialize)]
pub struct EntitlementEntry {
  /// User email.
  pub email: String,
  /// Scope name.
  pub scope: String,
}

/// A declarative resource server (RFC 8707 resource indicator).
#[derive(Debug, Deserialize)]
pub struct ResourceServerEntry {
  /// Exact RFC 8707 resource identifier.
  pub identifier: String,
  /// Optional description.
  #[serde(default)]
  pub description: Option<String>,
  /// Whether the resource server is enabled (default true).
  #[serde(default = "default_true")]
  pub enabled: bool,
}

/// A declarative per-client access-token format.
#[derive(Debug, Deserialize)]
pub struct ClientTokenFormatEntry {
  /// OAuth client identifier.
  pub client_id: String,
  /// Access-token format: `opaque` (default) or `jwt`.
  pub access_token_format: String,
}

/// A declarative client attachment.
#[derive(Debug, Deserialize)]
pub struct AttachmentEntry {
  /// OAuth client identifier.
  pub client_id: String,
  /// Redirect URI from the catalog.
  pub uri: String,
  /// Catalog kind to resolve the URI within: `authorize` (default) or
  /// `post_logout`.
  #[serde(default = "default_kind")]
  pub kind: String,
}

/// Counts of what an apply actually changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
  /// Scopes inserted.
  pub scopes_created: u64,
  /// Scopes updated.
  pub scopes_updated: u64,
  /// Redirect URIs inserted.
  pub redirects_created: u64,
  /// Redirect URIs updated.
  pub redirects_updated: u64,
  /// Resource servers inserted.
  pub resource_servers_created: u64,
  /// Resource servers updated.
  pub resource_servers_updated: u64,
  /// Entitlements inserted.
  pub entitlements_added: u64,
  /// Attachments inserted.
  pub attachments_added: u64,
  /// Client access-token formats changed.
  pub client_formats_set: u64,
}

impl SyncReport {
  /// Whether the apply changed nothing.
  #[must_use]
  pub fn is_noop(&self) -> bool {
    self.scopes_created == 0
      && self.scopes_updated == 0
      && self.redirects_created == 0
      && self.redirects_updated == 0
      && self.resource_servers_created == 0
      && self.resource_servers_updated == 0
      && self.entitlements_added == 0
      && self.attachments_added == 0
      && self.client_formats_set == 0
  }
}

impl fmt::Display for SyncReport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "config sync: scopes +{} ~{}; redirects +{} ~{}; resource_servers +{} ~{}; \
       entitlements +{}; attachments +{}; client_formats {}",
      self.scopes_created,
      self.scopes_updated,
      self.redirects_created,
      self.redirects_updated,
      self.resource_servers_created,
      self.resource_servers_updated,
      self.entitlements_added,
      self.attachments_added,
      self.client_formats_set
    )
  }
}

/// Load and apply a declarative file from the environment configuration.
///
/// # Errors
/// Returns [`CliError`] for an unreadable/invalid file, a missing referenced
/// record, or a database failure.
pub async fn run(path: &Path) -> Result<SyncReport, CliError> {
  let raw = std::fs::read_to_string(path)?;
  let file: SyncFile = serde_json::from_str(&raw)
    .map_err(|error| CliError::Input(format!("invalid sync file: {error}")))?;
  let context = Context::from_env().await?;
  apply(&context, &file).await
}

/// Apply a parsed declarative file idempotently.
///
/// # Errors
/// Returns [`CliError`] for invalid scope names, missing referenced records,
/// or a database failure.
pub async fn apply(context: &Context, file: &SyncFile) -> Result<SyncReport, CliError> {
  let mut report = SyncReport::default();

  for entry in &file.scopes {
    scope::validate(&entry.name)?;
    match scope::upsert(
      context.pool(),
      &entry.name,
      entry.description.as_deref(),
      entry.enabled,
    )
    .await?
    {
      scope::Upsert::Created => report.scopes_created += 1,
      scope::Upsert::Updated => report.scopes_updated += 1,
      scope::Upsert::Unchanged => {}
    }
  }

  for entry in &file.redirect_uris {
    match redirect::upsert(
      context,
      &entry.uri,
      &entry.kind,
      entry.description.as_deref(),
      entry.enabled,
    )
    .await?
    {
      scope::Upsert::Created => report.redirects_created += 1,
      scope::Upsert::Updated => report.redirects_updated += 1,
      scope::Upsert::Unchanged => {}
    }
  }

  for entry in &file.resource_servers {
    match resource::upsert(
      context,
      &entry.identifier,
      entry.description.as_deref(),
      entry.enabled,
    )
    .await?
    {
      scope::Upsert::Created => report.resource_servers_created += 1,
      scope::Upsert::Updated => report.resource_servers_updated += 1,
      scope::Upsert::Unchanged => {}
    }
  }

  for entry in &file.user_scopes {
    let user_id = super::user::find_user_id(context, &entry.email).await?;
    report.entitlements_added += sqlx::query(
      "INSERT INTO user_scopes (user_id, scope_name, granted_at)
       VALUES ($1, $2, now())
       ON CONFLICT (user_id, scope_name) DO NOTHING",
    )
    .bind(user_id)
    .bind(&entry.scope)
    .execute(context.pool())
    .await?
    .rows_affected();
  }

  for entry in &file.client_redirect_uris {
    redirect::ensure_client_exists(context, &entry.client_id).await?;
    let redirect_id = redirect::find_redirect_id(context, &entry.uri, &entry.kind).await?;
    report.attachments_added +=
      u64::from(redirect_repo::attach(context.pool(), &entry.client_id, redirect_id, None).await?);
  }

  for entry in &file.client_access_token_formats {
    if !matches!(entry.access_token_format.as_str(), "opaque" | "jwt") {
      return Err(CliError::Input(format!(
        "invalid access_token_format {} for client {}",
        entry.access_token_format, entry.client_id
      )));
    }
    redirect::ensure_client_exists(context, &entry.client_id).await?;
    if client_repo::set_access_token_format(
      context.pool(),
      &entry.client_id,
      &entry.access_token_format,
    )
    .await?
    {
      report.client_formats_set += 1;
    }
  }

  audit("config.sync", &report.to_string());
  Ok(report)
}

fn default_true() -> bool {
  true
}

fn default_kind() -> String {
  "authorize".to_owned()
}

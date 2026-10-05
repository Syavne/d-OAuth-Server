//! `redirect_uris` catalog + `client_redirect_uris` attachments.
//!
//! URIs are stored normalized-exact; authorize matches strictly against the
//! client's effective attached+enabled set. Dynamic loopback URIs accepted
//! by DCR are upserted here, then attached. Every query is a parameterized
//! `sqlx` macro call, so the schema is checked at compile time and no SQL is
//! ever interpolated.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(test)]
mod tests;

/// The role a catalog URI plays. Both kinds share exact-match validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
  /// The authorization-response callback (carries `code`/`state`).
  Authorize,
  /// A post-logout return target (a bare navigation, no code/state).
  PostLogout,
}

impl RedirectKind {
  /// The stored `kind` discriminator value.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Authorize => "authorize",
      Self::PostLogout => "post_logout",
    }
  }

  /// Parse a stored `kind` value; unknown values fall closed to `Authorize`.
  #[must_use]
  pub fn parse(value: &str) -> Self {
    match value {
      "post_logout" => Self::PostLogout,
      _ => Self::Authorize,
    }
  }
}

/// A catalog redirect URI.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectUri {
  /// Surrogate primary key.
  pub id: Uuid,
  /// Normalized-exact URI, unique per kind in the catalog.
  pub uri: String,
  /// Stored `kind` discriminator; see [`RedirectUri::kind`].
  pub kind: String,
  /// Whether the URI may be used (disabled URIs are invisible to matching).
  pub enabled: bool,
  /// Human-readable description.
  pub description: String,
  /// Admin who created the entry, if known.
  pub created_by: Option<Uuid>,
  /// Row creation timestamp.
  pub created_at: OffsetDateTime,
  /// Row last-update timestamp.
  pub updated_at: OffsetDateTime,
}

impl RedirectUri {
  /// The typed role this URI plays.
  #[must_use]
  pub fn kind(&self) -> RedirectKind {
    RedirectKind::parse(&self.kind)
  }
}

/// Upsert a catalog URI by its normalized-exact value and kind.
///
/// If a row for `(uri, kind)` already exists, it is returned unchanged apart
/// from `updated_at`; the passed `id` is used only when the row is new. This
/// lets DCR register a dynamic loopback URI without resurrecting an
/// admin-disabled entry.
///
/// # Errors
///
/// Returns a database error if the write fails.
pub async fn upsert(
  pool: &PgPool,
  id: Uuid,
  uri: &str,
  kind: RedirectKind,
  description: &str,
  created_by: Option<Uuid>,
) -> Result<RedirectUri, sqlx::Error> {
  sqlx::query_as!(
    RedirectUri,
    "INSERT INTO redirect_uris (id, uri, kind, description, created_by, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, now(), now()) \
     ON CONFLICT (uri, kind) DO UPDATE SET updated_at = now() \
     RETURNING id, uri, kind, enabled, description, created_by, created_at, updated_at",
    id,
    uri,
    kind.as_str(),
    description,
    created_by,
  )
  .fetch_one(pool)
  .await
}

/// List catalog URIs ordered by `uri`, optionally including disabled entries.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn list(pool: &PgPool, include_disabled: bool) -> Result<Vec<RedirectUri>, sqlx::Error> {
  sqlx::query_as!(
    RedirectUri,
    "SELECT id, uri, kind, enabled, description, created_by, created_at, updated_at \
     FROM redirect_uris WHERE ($1 OR enabled = true) ORDER BY uri",
    include_disabled,
  )
  .fetch_all(pool)
  .await
}

/// Enable or disable a catalog URI. Returns the updated row, or `None` if the
/// id is unknown.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn set_enabled(
  pool: &PgPool,
  id: Uuid,
  enabled: bool,
) -> Result<Option<RedirectUri>, sqlx::Error> {
  sqlx::query_as!(
    RedirectUri,
    "UPDATE redirect_uris SET enabled = $2, updated_at = now() WHERE id = $1 \
     RETURNING id, uri, kind, enabled, description, created_by, created_at, updated_at",
    id,
    enabled,
  )
  .fetch_optional(pool)
  .await
}

/// Enable a catalog URI. Returns the updated row, or `None` if unknown.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn enable(pool: &PgPool, id: Uuid) -> Result<Option<RedirectUri>, sqlx::Error> {
  set_enabled(pool, id, true).await
}

/// Disable a catalog URI. Returns the updated row, or `None` if unknown.
///
/// # Errors
///
/// Returns a database error if the update fails.
pub async fn disable(pool: &PgPool, id: Uuid) -> Result<Option<RedirectUri>, sqlx::Error> {
  set_enabled(pool, id, false).await
}

/// Delete a catalog URI only while no client is attached to it.
///
/// The check and the delete are one atomic statement, so a concurrent
/// attachment cannot race the guard. Returns `true` if a row was deleted and
/// `false` if it was attached (or absent).
///
/// # Errors
///
/// Returns a database error if the delete fails.
pub async fn delete_if_unattached(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "DELETE FROM redirect_uris WHERE id = $1 \
       AND NOT EXISTS (SELECT 1 FROM client_redirect_uris WHERE redirect_uri_id = $1)",
    id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

/// Attach a catalog URI to a client. Returns `true` if a new attachment was
/// created, `false` if it was already attached.
///
/// # Errors
///
/// Returns a database error if the write fails (e.g. an unknown client or
/// URI).
pub async fn attach(
  pool: &PgPool,
  client_id: &str,
  redirect_uri_id: Uuid,
  attached_by: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "INSERT INTO client_redirect_uris (client_id, redirect_uri_id, attached_at, attached_by) \
     VALUES ($1, $2, now(), $3) ON CONFLICT (client_id, redirect_uri_id) DO NOTHING",
    client_id,
    redirect_uri_id,
    attached_by,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

/// Detach a catalog URI from a client. Returns `true` if an attachment was
/// removed.
///
/// # Errors
///
/// Returns a database error if the delete fails.
pub async fn detach(
  pool: &PgPool,
  client_id: &str,
  redirect_uri_id: Uuid,
) -> Result<bool, sqlx::Error> {
  let result = sqlx::query!(
    "DELETE FROM client_redirect_uris WHERE client_id = $1 AND redirect_uri_id = $2",
    client_id,
    redirect_uri_id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected() > 0)
}

/// Detach every URI from a client, returning the number removed.
///
/// Used by RFC 7592 PUT to replace a client's attachment set.
///
/// # Errors
///
/// Returns a database error if the delete fails.
pub async fn detach_all(pool: &PgPool, client_id: &str) -> Result<u64, sqlx::Error> {
  let result = sqlx::query!(
    "DELETE FROM client_redirect_uris WHERE client_id = $1",
    client_id,
  )
  .execute(pool)
  .await?;
  Ok(result.rows_affected())
}

/// List every URI attached to a client (enabled or not), ordered by `uri`.
///
/// This is the management view; use [`effective_for_client`] for matching.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn list_for_client(
  pool: &PgPool,
  client_id: &str,
) -> Result<Vec<RedirectUri>, sqlx::Error> {
  sqlx::query_as!(
    RedirectUri,
    "SELECT ru.id, ru.uri, ru.kind, ru.enabled, ru.description, ru.created_by, \
       ru.created_at, ru.updated_at \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 ORDER BY ru.uri",
    client_id,
  )
  .fetch_all(pool)
  .await
}

/// The effective (attached + enabled) authorization-response URIs for a client,
/// ordered by `uri`.
///
/// This is the exact set authorize matching (and RFC 7592 GET serialization)
/// must use. Post-logout URIs are excluded: they are a separate landing kind and
/// must never be accepted as an authorization callback.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn effective_for_client(
  pool: &PgPool,
  client_id: &str,
) -> Result<Vec<RedirectUri>, sqlx::Error> {
  sqlx::query_as!(
    RedirectUri,
    "SELECT ru.id, ru.uri, ru.kind, ru.enabled, ru.description, ru.created_by, \
       ru.created_at, ru.updated_at \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 AND ru.enabled = true AND ru.kind = 'authorize' \
     ORDER BY ru.uri",
    client_id,
  )
  .fetch_all(pool)
  .await
}

/// The client's effective (attached + enabled) post-logout URIs, ordered.
///
/// Used at logout to re-validate that the session's frozen target is still
/// registered for the client before redirecting to it.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn effective_post_logout_for_client(
  pool: &PgPool,
  client_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
  sqlx::query_scalar!(
    "SELECT ru.uri \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 AND ru.enabled = true AND ru.kind = 'post_logout' \
     ORDER BY ru.uri",
    client_id,
  )
  .fetch_all(pool)
  .await
}

/// The client's single effective post-logout URI, if exactly one is registered.
///
/// A post-logout redirect must be unambiguous. Zero registered post-logout URIs
/// yields `None` (no redirect); more than one is also `None`, because choosing
/// arbitrarily would make the logout target nondeterministic. Registration of a
/// second post-logout URI for one client is therefore a configuration error, not
/// a silent last-writer-wins.
///
/// # Errors
///
/// Returns a database error if the query fails.
pub async fn post_logout_for_client(
  pool: &PgPool,
  client_id: &str,
) -> Result<Option<String>, sqlx::Error> {
  let uris: Vec<String> = sqlx::query_scalar!(
    "SELECT ru.uri \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 AND ru.enabled = true AND ru.kind = 'post_logout' \
     ORDER BY ru.uri",
    client_id,
  )
  .fetch_all(pool)
  .await?;
  match uris.as_slice() {
    [only] => Ok(Some(only.clone())),
    _ => Ok(None),
  }
}

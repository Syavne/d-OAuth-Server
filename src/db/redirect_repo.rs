//! `redirect_uris` catalog + `client_redirect_uris` attachments.
//!
//! URIs are stored normalized-exact; authorize matches strictly against the
//! client's effective attached+enabled set. Dynamic loopback URIs accepted
//! by DCR are upserted here, then attached. Every query is a parameterized
//! `sqlx` macro call, so the schema is checked at compile time and no SQL is
//! ever interpolated.
//!
//! The URI itself is PII: it is sealed into `uri_enc` (AES-256-GCM under the
//! PII key chain) and equality-matched through the keyed blind index
//! `uri_index` (`"{kid}:{hex}"`), with a legacy-plaintext fallback for rows
//! whose `uri_index` is still NULL. Plaintext `uri` is written only while
//! `dual_write` holds. Reads never compare decrypted URIs in SQL; result
//! sets are ordered by the decrypted URI in Rust.

use std::fmt;

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::field::{blind_index_active, blind_index_candidates, open_text, seal_text};
use crate::error::AppError;
use crate::keys::KeyRing;

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
///
/// `Debug` redacts `uri`: the rendered form carries `[REDACTED]` so the
/// sealed PII never reaches a log.
#[derive(Clone, PartialEq)]
pub struct RedirectUri {
  /// Surrogate primary key.
  pub id: Uuid,
  /// Normalized-exact URI, unique per kind in the catalog (decrypted).
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

impl fmt::Debug for RedirectUri {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RedirectUri")
      .field("id", &self.id)
      .field("uri", &"[REDACTED]")
      .field("kind", &self.kind)
      .field("enabled", &self.enabled)
      .field("description", &self.description)
      .field("created_by", &self.created_by)
      .field("created_at", &self.created_at)
      .field("updated_at", &self.updated_at)
      .finish()
  }
}

impl RedirectUri {
  /// The typed role this URI plays.
  #[must_use]
  pub fn kind(&self) -> RedirectKind {
    RedirectKind::parse(&self.kind)
  }
}

/// Input for [`upsert`]: the normalized-exact URI plus its catalog identity.
pub struct NewRedirectUri<'a> {
  /// Surrogate id used only when the row is new.
  pub id: Uuid,
  /// Normalized-exact URI to seal and index.
  pub uri: &'a str,
  /// The role the URI plays.
  pub kind: RedirectKind,
  /// Human-readable description, stored only for new rows.
  pub description: &'a str,
  /// Admin creating the entry, if known.
  pub created_by: Option<Uuid>,
}

/// Whether [`upsert`] inserted a row or matched an existing one.
///
/// Mirrors the CLI `redirect::upsert` created-vs-updated distinction (`xmax =
/// 0`): `Created` for a fresh insert, `Updated` for an adopted legacy row, a
/// partial-index conflict winner, or a re-upsert of an existing row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
  /// A new catalog row was inserted.
  Created,
  /// An existing row was matched (and re-sealed) instead.
  Updated,
}

/// Resolve the stored URI: open the ciphertext when present, else use the
/// legacy plaintext. A non-NULL ciphertext that fails to open never falls
/// back to plaintext; a row with neither representation fails closed.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open
/// or when the row carries no usable URI at all.
fn decrypt_stored_uri(
  keys: &KeyRing,
  enc: Option<Vec<u8>>,
  plain: Option<String>,
) -> Result<String, AppError> {
  if let Some(blob) = enc {
    return open_text(keys, &blob).map_err(|_| AppError::PiiDecrypt);
  }
  plain.ok_or(AppError::PiiDecrypt)
}

/// Sealed form of a URI: ciphertext plus its blind indexes.
struct SealedUri {
  /// AES-256-GCM ciphertext of the exact URI.
  enc: Vec<u8>,
  /// Blind index under the active PII key (`"{kid}:{hex}"`).
  index: String,
  /// Blind indexes under every retained PII key, newest first.
  candidates: Vec<String>,
}

/// Seal a URI and derive its blind indexes under `keys`.
///
/// # Errors
///
/// Returns a masked `temporarily_unavailable` error when sealing fails.
fn seal_uri(keys: &KeyRing, uri: &str) -> Result<SealedUri, AppError> {
  Ok(SealedUri {
    enc: seal_text(keys, uri).map_err(AppError::from)?,
    index: blind_index_active(keys, uri),
    candidates: blind_index_candidates(keys, uri),
  })
}

/// Re-seal an existing catalog row matched by the dual predicate (blind-index
/// candidates or legacy plaintext) without touching `description`/`enabled`.
///
/// Returns the decrypted row, or `None` when no row matches.
async fn update_existing(
  pool: &PgPool,
  keys: &KeyRing,
  dual_write: bool,
  new: &NewRedirectUri<'_>,
) -> Result<Option<RedirectUri>, AppError> {
  let kind = new.kind.as_str();
  let sealed = seal_uri(keys, new.uri)?;
  let plain: Option<&str> = if dual_write { Some(new.uri) } else { None };
  let row = sqlx::query!(
    "UPDATE redirect_uris SET uri = $1, uri_enc = $2, uri_index = $3, updated_at = now() \
     WHERE kind = $4 AND (uri_index = ANY($5) OR uri = $6) \
     RETURNING id, uri, kind, enabled, description, created_by, created_at, updated_at, uri_enc",
    plain,
    sealed.enc,
    sealed.index,
    kind,
    &sealed.candidates,
    new.uri,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      Ok(RedirectUri {
        id: row.id,
        uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
        kind: row.kind,
        enabled: row.enabled,
        description: row.description,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .transpose()
}

/// Upsert a catalog URI by its normalized-exact value and kind.
///
/// The URI is sealed into `uri_enc` and blind-indexed into `uri_index`;
/// plaintext `uri` is written only while `dual_write` holds. If a row for
/// `(uri, kind)` already exists — as an indexed row or as a legacy
/// NULL-index row — it is re-sealed in place and returned with
/// [`UpsertOutcome::Updated`] — the passed `id` is used only when the row is
/// new. `description` and `enabled` are never overwritten, so DCR can
/// register a dynamic loopback URI without resurrecting an admin-disabled
/// entry or clobbering its description.
///
/// The write runs in two phases because a legacy row carries a NULL
/// `uri_index` the partial unique index cannot see: first an `UPDATE` over
/// the dual predicate, then an `INSERT` whose conflict target carries the
/// partial-index predicate (`WHERE uri_index IS NOT NULL`, required for
/// index inference — omitting it raises `42P10`). A `23505` from either
/// unique constraint (a lost insert race against the legacy `(uri, kind)`
/// constraint or the indexed one) retries the `UPDATE` against the winner.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a matched row's ciphertext fails to
/// open, a masked error on any other database failure, or a seal failure as
/// `temporarily_unavailable` when PII sealing itself fails.
pub async fn upsert(
  pool: &PgPool,
  keys: &KeyRing,
  dual_write: bool,
  new: &NewRedirectUri<'_>,
) -> Result<(RedirectUri, UpsertOutcome), AppError> {
  let kind = new.kind.as_str();
  let sealed = seal_uri(keys, new.uri)?;
  let plain: Option<&str> = if dual_write { Some(new.uri) } else { None };

  if let Some(row) = update_existing(pool, keys, dual_write, new).await? {
    return Ok((row, UpsertOutcome::Updated));
  }
  let inserted = sqlx::query!(
    "INSERT INTO redirect_uris (id, uri, kind, description, created_by, created_at, updated_at, \
       uri_enc, uri_index) \
     VALUES ($1, $2, $3, $4, $5, now(), now(), $6, $7) \
     ON CONFLICT (uri_index, kind) WHERE uri_index IS NOT NULL \
     DO UPDATE SET updated_at = now() \
     RETURNING id, uri, kind, enabled, description, created_by, created_at, updated_at, uri_enc, \
       (xmax = 0) AS \"inserted!\"",
    new.id,
    plain,
    kind,
    new.description,
    new.created_by,
    sealed.enc,
    sealed.index,
  )
  .fetch_one(pool)
  .await;
  match inserted {
    Ok(row) => {
      let outcome = if row.inserted {
        UpsertOutcome::Created
      } else {
        UpsertOutcome::Updated
      };
      Ok((
        RedirectUri {
          id: row.id,
          uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
          kind: row.kind,
          enabled: row.enabled,
          description: row.description,
          created_by: row.created_by,
          created_at: row.created_at,
          updated_at: row.updated_at,
        },
        outcome,
      ))
    }
    Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
      match update_existing(pool, keys, dual_write, new).await? {
        Some(row) => Ok((row, UpsertOutcome::Updated)),
        None => Err(AppError::server_error()),
      }
    }
    Err(other) => Err(AppError::from(other)),
  }
}

/// List catalog URIs ordered by the decrypted `uri`, optionally including
/// disabled entries.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn list(
  pool: &PgPool,
  keys: &KeyRing,
  include_disabled: bool,
) -> Result<Vec<RedirectUri>, AppError> {
  let rows = sqlx::query!(
    "SELECT id, uri, kind, enabled, description, created_by, created_at, updated_at, uri_enc \
     FROM redirect_uris WHERE ($1 OR enabled = true)",
    include_disabled,
  )
  .fetch_all(pool)
  .await?;
  let mut uris = Vec::with_capacity(rows.len());
  for row in rows {
    uris.push(RedirectUri {
      id: row.id,
      uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
      kind: row.kind,
      enabled: row.enabled,
      description: row.description,
      created_by: row.created_by,
      created_at: row.created_at,
      updated_at: row.updated_at,
    });
  }
  // SQL `ORDER BY uri` is meaningless once plaintext is blanked; sort by the
  // decrypted value instead.
  uris.sort_by(|left, right| left.uri.cmp(&right.uri));
  Ok(uris)
}

/// Enable or disable a catalog URI. Returns the updated row, or `None` if the
/// id is unknown.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when the row's ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn set_enabled(
  pool: &PgPool,
  keys: &KeyRing,
  id: Uuid,
  enabled: bool,
) -> Result<Option<RedirectUri>, AppError> {
  let row = sqlx::query!(
    "UPDATE redirect_uris SET enabled = $2, updated_at = now() WHERE id = $1 \
     RETURNING id, uri, kind, enabled, description, created_by, created_at, updated_at, uri_enc",
    id,
    enabled,
  )
  .fetch_optional(pool)
  .await?;
  row
    .map(|row| {
      Ok(RedirectUri {
        id: row.id,
        uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
        kind: row.kind,
        enabled: row.enabled,
        description: row.description,
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
    })
    .transpose()
}

/// Enable a catalog URI. Returns the updated row, or `None` if unknown.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when the row's ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn enable(
  pool: &PgPool,
  keys: &KeyRing,
  id: Uuid,
) -> Result<Option<RedirectUri>, AppError> {
  set_enabled(pool, keys, id, true).await
}

/// Disable a catalog URI. Returns the updated row, or `None` if unknown.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when the row's ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn disable(
  pool: &PgPool,
  keys: &KeyRing,
  id: Uuid,
) -> Result<Option<RedirectUri>, AppError> {
  set_enabled(pool, keys, id, false).await
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

/// List every URI attached to a client (enabled or not), ordered by the
/// decrypted `uri`.
///
/// This is the management view; use [`effective_for_client`] for matching.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn list_for_client(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<Vec<RedirectUri>, AppError> {
  let rows = sqlx::query!(
    "SELECT ru.id, ru.uri, ru.kind, ru.enabled, ru.description, ru.created_by, \
       ru.created_at, ru.updated_at, ru.uri_enc \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1",
    client_id,
  )
  .fetch_all(pool)
  .await?;
  let mut uris = Vec::with_capacity(rows.len());
  for row in rows {
    uris.push(RedirectUri {
      id: row.id,
      uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
      kind: row.kind,
      enabled: row.enabled,
      description: row.description,
      created_by: row.created_by,
      created_at: row.created_at,
      updated_at: row.updated_at,
    });
  }
  uris.sort_by(|left, right| left.uri.cmp(&right.uri));
  Ok(uris)
}

/// The effective (attached + enabled) authorization-response URIs for a client,
/// ordered by the decrypted `uri`.
///
/// This is the exact set authorize matching (and RFC 7592 GET serialization)
/// must use. Post-logout URIs are excluded: they are a separate landing kind and
/// must never be accepted as an authorization callback.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn effective_for_client(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<Vec<RedirectUri>, AppError> {
  let rows = sqlx::query!(
    "SELECT ru.id, ru.uri, ru.kind, ru.enabled, ru.description, ru.created_by, \
       ru.created_at, ru.updated_at, ru.uri_enc \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 AND ru.enabled = true AND ru.kind = 'authorize'",
    client_id,
  )
  .fetch_all(pool)
  .await?;
  let mut uris = Vec::with_capacity(rows.len());
  for row in rows {
    uris.push(RedirectUri {
      id: row.id,
      uri: decrypt_stored_uri(keys, row.uri_enc, row.uri)?,
      kind: row.kind,
      enabled: row.enabled,
      description: row.description,
      created_by: row.created_by,
      created_at: row.created_at,
      updated_at: row.updated_at,
    });
  }
  uris.sort_by(|left, right| left.uri.cmp(&right.uri));
  Ok(uris)
}

/// The client's effective (attached + enabled) post-logout URIs, ordered by
/// the decrypted value.
///
/// Used at logout to re-validate that the session's frozen target is still
/// registered for the client before redirecting to it.
///
/// # Errors
///
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn effective_post_logout_for_client(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<Vec<String>, AppError> {
  let rows = sqlx::query!(
    "SELECT ru.uri, ru.uri_enc \
     FROM client_redirect_uris AS cru \
     JOIN redirect_uris AS ru ON ru.id = cru.redirect_uri_id \
     WHERE cru.client_id = $1 AND ru.enabled = true AND ru.kind = 'post_logout'",
    client_id,
  )
  .fetch_all(pool)
  .await?;
  let mut uris = Vec::with_capacity(rows.len());
  for row in rows {
    uris.push(decrypt_stored_uri(keys, row.uri_enc, row.uri)?);
  }
  uris.sort();
  Ok(uris)
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
/// Returns [`AppError::PiiDecrypt`] when a stored ciphertext fails to open,
/// or a masked error on any database failure.
pub async fn post_logout_for_client(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
) -> Result<Option<String>, AppError> {
  let uris = effective_post_logout_for_client(pool, keys, client_id).await?;
  match uris.as_slice() {
    [only] => Ok(Some(only.clone())),
    _ => Ok(None),
  }
}

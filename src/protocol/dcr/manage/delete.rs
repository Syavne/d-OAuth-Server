//! RFC 7592 `DELETE /register/{client_id}`: deactivate and revoke.
//!
//! Revocation runs before deactivation: a Redis outage then fails closed
//! with the client still active (nothing half-revoked), while deactivation
//! first would strand live tokens behind a dead client that can no longer
//! be managed. A second `DELETE` with the same token answers `401` — the
//! deactivated row no longer authorizes management.

use super::{ManageContext, ManageError, ManageStores, authorize_manage, revoke};
use crate::db::client_repo;
use crate::error::AppError;

/// Deactivate a managed client and revoke its tokens.
///
/// # Errors
///
/// Returns `401` for a missing token or an unknown (or already deactivated)
/// client, `403` for a token issued to a different client, and a masked
/// store failure when revocation cannot complete.
pub async fn delete_client(
  stores: &mut ManageStores<'_>,
  ctx: &ManageContext<'_>,
  client_id: &str,
  registration_access_token: Option<&str>,
) -> Result<(), ManageError> {
  authorize_manage(
    stores.pool,
    ctx.config,
    client_id,
    registration_access_token,
  )
  .await?;
  revoke::revoke_client_tokens(stores.conn, stores.store, client_id).await?;
  let deactivated = client_repo::deactivate(stores.pool, client_id)
    .await
    .map_err(AppError::from)?;
  if !deactivated {
    return Err(AppError::invalid_client_bearer().into());
  }
  Ok(())
}

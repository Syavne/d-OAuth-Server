//! RFC 7592 `PUT /register/{client_id}`: full metadata replacement.
//!
//! The body is a full [`super::super::RegisterRequest`] validated under the
//! exact registration rules (same defaults: omitted scalars clear, an omitted
//! `redirect_uris` fails as empty). The metadata update allowlist cannot
//! touch identity, secret, issue time, the active flag, or the registration
//! token; attachments are replaced (`detach_all` then attach) only after the
//! metadata row update succeeds. Credential rotation closes the call: the
//! registration token always rotates (the response carries the only copy),
//! and a fresh client secret mints if and only if the resulting method is
//! secret-based.

use super::{ManageContext, ManageError, ManageStores, authorize_manage, respond};
use crate::db::client_repo::{self, ClientMetadata, TokenEndpointAuthMethod};
use crate::db::redirect_repo;
use crate::error::AppError;

/// Full-replace a managed client's metadata, attachments, and credentials.
///
/// Validation precedes every write, so a bad body changes nothing (aside
/// from having presented a valid management token).
///
/// # Errors
///
/// Returns `401` for a missing token or an unknown client, `403` for a
/// token issued to a different client, `invalid_redirect_uri` /
/// `invalid_client_metadata` (`400`) for bad metadata, and a masked store
/// failure otherwise.
pub async fn update_client(
  stores: &mut ManageStores<'_>,
  ctx: &ManageContext<'_>,
  client_id: &str,
  registration_access_token: Option<&str>,
  request: &super::super::RegisterRequest,
) -> Result<super::ManageResponse, ManageError> {
  authorize_manage(
    stores.pool,
    ctx.config,
    client_id,
    registration_access_token,
  )
  .await?;
  let validated = super::super::validate_metadata(stores.pool, request).await?;
  let redirect_ids =
    super::super::resolve_redirects(stores.pool, ctx.config, &validated.redirect_uris).await?;

  let meta = ClientMetadata {
    client_name: validated.client_name.clone(),
    grant_types: validated.grant_types.clone(),
    response_types: vec!["code".to_owned()],
    scope: validated.scope.clone(),
    token_endpoint_auth_method: validated.method.as_str().to_owned(),
    jwks: validated.jwks.clone(),
    jwks_uri: validated.jwks_uri.clone(),
    tls_client_auth_subject_dn: validated.subject_dn.clone(),
    tls_client_auth_cert_thumbprint: None,
    request_uris: validated.request_uris.clone(),
    contacts: validated.contacts.clone(),
    software_id: validated.software_id.clone(),
    dpop_bound_access_tokens: validated.dpop_bound,
  };
  client_repo::update_metadata(
    stores.pool,
    &ctx.config.keys,
    ctx.config.pii_dual_write,
    client_id,
    &meta,
  )
  .await?
  .ok_or_else(AppError::invalid_client_bearer)?;

  redirect_repo::detach_all(stores.pool, client_id)
    .await
    .map_err(AppError::from)?;
  for id in &redirect_ids {
    redirect_repo::attach(stores.pool, client_id, *id, None)
      .await
      .map_err(AppError::from)?;
  }

  let rotated_registration = rotate_registration_token(stores, ctx, client_id).await?;
  let rotated_secret =
    rotate_secret_if_configured(stores, ctx, client_id, validated.method).await?;

  let row = super::active_row(stores.pool, &ctx.config.keys, client_id).await?;
  let effective =
    redirect_repo::effective_for_client(stores.pool, &ctx.config.keys, client_id).await?;
  Ok(respond(
    &row,
    effective.into_iter().map(|uri| uri.uri).collect(),
    rotated_secret,
    Some(rotated_registration),
    &ctx.config.issuer,
  ))
}

/// Mint a fresh registration token and store only its keyed hash.
///
/// # Errors
///
/// Returns a masked failure when minting or persisting fails.
async fn rotate_registration_token(
  stores: &mut ManageStores<'_>,
  ctx: &ManageContext<'_>,
  client_id: &str,
) -> Result<String, ManageError> {
  let raw = crate::crypto::tokens::mint_token().map_err(AppError::internal)?;
  let hash = super::super::keyed_hash(ctx.config, &raw)?;
  client_repo::set_registration_token_hash(stores.pool, client_id, &hash)
    .await
    .map_err(AppError::from)?;
  Ok(raw)
}

/// Mint a fresh client secret when the resulting method is secret-based;
/// any other method receives none (a stale hash from a previous method is
/// then unreachable: authentication dispatches on the stored method).
///
/// # Errors
///
/// Returns a masked failure when minting, hashing, or persisting fails.
async fn rotate_secret_if_configured(
  stores: &mut ManageStores<'_>,
  ctx: &ManageContext<'_>,
  client_id: &str,
  method: TokenEndpointAuthMethod,
) -> Result<Option<String>, ManageError> {
  if !matches!(
    method,
    TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost
  ) {
    return Ok(None);
  }
  let secret = crate::crypto::tokens::mint_token().map_err(AppError::internal)?;
  let hash = super::super::hash_secret(ctx.config, &secret).await?;
  client_repo::rotate_secret_hash(stores.pool, client_id, &hash, None)
    .await
    .map_err(AppError::from)?;
  Ok(Some(secret))
}

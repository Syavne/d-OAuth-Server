//! Approved-grant redemption: binding continuity, scope, and mint.
//!
//! The stored sender binding must be matched by the fresh proofs from this
//! request, the grant is consumed atomically (single redemption), and the
//! scope is recomputed against the approving user's live entitlements
//! before anything is minted.

use uuid::Uuid;

use super::super::super::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService};
use super::{DevicePollError, DeviceTokenResponse, PollState};
use crate::jose::jwt_access::JwtAccessSigner;
use crate::{
  config::GrantKind,
  db::{scope_repo, user_repo, user_scope_repo},
  error::AppError,
  protocol::{
    device::{binding_key, read_binding},
    scope::{ScopeInput, ScopeSet, effective_scope},
  },
  store::{self, device as device_store},
};

/// The approved grant being redeemed: record identity plus fresh proofs.
pub(super) struct Redemption<'x> {
  /// Keyed hash of the device code being redeemed.
  pub(super) device_hash: &'x str,
  /// The polling client row.
  pub(super) client: &'x crate::db::Client,
  /// Public or confidential: selects the constraint matrix.
  pub(super) kind: ClientKind,
  /// Whether a public client must present a DPoP proof: mirrors the
  /// client's `dpop_bound_access_tokens` registration.
  pub(super) dpop_required: bool,
  /// Freshly verified proofs from this poll request.
  pub(super) proofs: SenderProof,
  /// Validated resource audiences (RFC 8707 §2) presented with this poll;
  /// empty means inherit the set pinned at authorization time (§2.2).
  pub(super) aud: &'x [String],
  /// Access-token representation for the minted pair.
  pub(super) token_format: TokenFormat,
  /// JWT signer for `TokenFormat::Jwt` mints.
  pub(super) jwt_signer: Option<JwtAccessSigner>,
}

/// Consume an approved grant exactly once and mint its token pair.
///
/// The stored sender binding must be matched by the fresh proofs from this
/// request, and the scope is recomputed against the approving user's live
/// entitlements before anything is minted.
pub(super) async fn issue_approved(
  state: &mut PollState<'_>,
  redemption: &Redemption<'_>,
) -> Result<DeviceTokenResponse, DevicePollError> {
  let stored = read_binding(state.conn, state.store, redemption.device_hash)
    .await?
    .ok_or_else(AppError::server_error)?;
  if let Some(want) = stored.jkt.as_deref() {
    if redemption.proofs.dpop_jkt.as_deref().unwrap_or("") != want {
      return Err(AppError::invalid_grant("DPoP binding does not match this grant").into());
    }
  } else if redemption.kind == ClientKind::Public && redemption.dpop_required {
    return Err(AppError::server_error().into());
  }
  if let Some(want) = stored.x5t_s256.as_deref()
    && redemption.proofs.mtls_x5t_s256.as_deref().unwrap_or("") != want
  {
    return Err(AppError::invalid_grant("mTLS binding does not match this grant").into());
  }

  let consumed = device_store::consume(state.conn, state.store, redemption.device_hash)
    .await
    .map_err(AppError::from)?
    .ok_or(DevicePollError::ExpiredToken)?;
  match consumed.status {
    device_store::DeviceStatus::Approved => {}
    device_store::DeviceStatus::Denied => return Err(DevicePollError::AccessDenied),
    device_store::DeviceStatus::Pending => {
      return Err(DevicePollError::AuthorizationPending);
    }
  }
  // RFC 8707 §2: the poll's resource set must equal the set pinned at
  // authorization time. RFC 8707 §2.2 / RFC 8628 §3.4: a device client never
  // re-sends `resource`, so an empty presentation inherits `consumed.aud`;
  // an empty pinned set keeps the unchanged no-audience behavior. A mismatch
  // is a grant-binding failure (`invalid_grant`), never `invalid_target`: the
  // request values were already catalog-validated by the token handler.
  //
  // Todo 11 binds the enforced set (`consumed.aud`) through `MintRequest.aud`;
  // nothing is written onto the token record here.
  if !redemption.aud.is_empty()
    && !crate::protocol::params::audience_binds(&consumed.aud, redemption.aud)
  {
    return Err(
      AppError::invalid_grant("resource indicators do not match this device authorization").into(),
    );
  }
  // The device record above is already consumed (single redemption): a JWT
  // redemption with an unbound audience fails here, before the mint, and the
  // client must re-authorize with a `resource`.
  if redemption.token_format == TokenFormat::Jwt && consumed.aud.is_empty() {
    return Err(AppError::invalid_target("jwt access tokens require a resource audience").into());
  }
  if consumed.grant_id.is_empty() || consumed.subject.is_empty() {
    return Err(AppError::server_error().into());
  }

  let effective = approved_scope(state, redemption.client, &consumed).await?;
  let mut tokens = TokenService::new(state.ttl, state.keys).map_err(AppError::internal)?;
  if redemption.token_format == TokenFormat::Jwt {
    let signer = redemption
      .jwt_signer
      .clone()
      .ok_or_else(AppError::server_error)?;
    tokens = tokens.with_jwt_signer(signer);
  }
  let minted = tokens
    .mint(
      state.conn,
      state.store,
      &MintRequest {
        client_id: redemption.client.client_id.clone(),
        client_kind: redemption.kind,
        dpop_required: redemption.dpop_required,
        subject: consumed.subject.clone(),
        scope: effective.clone(),
        access_scope: effective.clone(),
        grant_id: consumed.grant_id.clone(),
        proof: redemption.proofs.clone(),
        aud: consumed.aud.clone(),
        refresh_aud: consumed.aud.clone(),
        format: redemption.token_format,
      },
      state.now_unix,
    )
    .await
    .map_err(AppError::from)?;

  let stale = [
    device_store::poll_key(state.store, redemption.device_hash),
    binding_key(state.store, redemption.device_hash),
  ];
  redis::cmd("DEL")
    .arg(&stale)
    .query_async::<()>(state.conn)
    .await
    .map_err(store::StoreError::Redis)
    .map_err(AppError::from)?;

  Ok(DeviceTokenResponse {
    token_type: if minted.cnf.jkt.is_some() {
      "DPoP".to_owned()
    } else {
      "Bearer".to_owned()
    },
    expires_in: state.ttl.access.as_secs(),
    access_token: minted.access_token,
    refresh_token: minted.refresh_token,
    scope: effective,
  })
}

/// Recompute the effective scope against the approving user's entitlements.
///
/// An explicit request must name only enabled, client-registered, and
/// user-entitled scopes (`invalid_scope` otherwise); an empty request
/// defaults to the client's set narrowed by the catalog and the user.
async fn approved_scope(
  state: &mut PollState<'_>,
  client: &crate::db::Client,
  consumed: &device_store::DeviceRecord,
) -> Result<String, DevicePollError> {
  // The UI records the authenticated session subject, which is the user's
  // email; older records and fixtures carry the user UUID. Resolve either to
  // the entitlement owner and fail closed when the account is not live.
  let user_id = match user_repo::find_by_email(state.pool, state.keys, &consumed.subject).await? {
    Some(user) if user.disabled => {
      return Err(AppError::invalid_grant("the approving user is disabled").into());
    }
    Some(user) => user.id,
    None => Uuid::parse_str(&consumed.subject).map_err(|_| AppError::server_error())?,
  };
  let client_registered =
    ScopeSet::parse(client.scope.trim()).map_err(|_| AppError::server_error())?;
  let enabled_names = scope_repo::list_enabled(state.pool)
    .await?
    .into_iter()
    .map(|record| record.name)
    .collect::<Vec<_>>();
  let enabled = ScopeSet::from_names(&enabled_names).map_err(|_| AppError::server_error())?;
  let entitled = ScopeSet::from_names(&user_scope_repo::list_for_user(state.pool, user_id).await?)
    .map_err(|_| AppError::server_error())?;
  let requested = if consumed.scope.trim().is_empty() {
    None
  } else {
    Some(consumed.scope.as_str())
  };
  let effective = effective_scope(&ScopeInput {
    requested,
    client_registered: &client_registered,
    user_entitled: &entitled,
    enabled: &enabled,
    grant: GrantKind::DeviceCode,
    exchange_allowlist: &ScopeSet::empty(),
  })?;
  Ok(effective.render())
}

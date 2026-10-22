//! Device-code polling grant (RFC 8628 §3.4–§3.5).
//!
//! `POST /token` with
//! `grant_type=urn:ietf:params:oauth:grant-type:device_code` redeems a
//! `device_code` issued by [`crate::protocol::device::authorize_device`].
//! Polling honors the advertised `interval` (a poll sooner than one interval
//! after the previous attempt fails with `slow_down`), reports
//! `authorization_pending` while the user has not decided, `access_denied`
//! after a denial, and `expired_token` once the code is unknown or its TTL
//! has lapsed.
//!
//! On approval the grant is consumed atomically (single redemption), the
//! effective scope is recomputed against the approving user's entitlements,
//! and an access plus refresh pair is minted. The sender-constraint matrix
//! applies unconditionally: public clients must present a freshly verified
//! DPoP proof whose `jkt` matches the binding captured at authorization
//! time, and confidential clients must present the fresh proof matching
//! whatever binding was captured (mTLS and/or DPoP).

mod error;
mod interval;
mod issue;
mod proofs;
#[cfg(test)]
mod tests;

use std::time::Duration;

pub use error::DevicePollError;
use secrecy::SecretString;
use serde::Serialize;
use sqlx::PgPool;

use super::super::TokenFormat;
use super::super::dispatch::require_dpop_binding;
use crate::{
  config::TtlConfig,
  db::TokenEndpointAuthMethod,
  error::AppError,
  protocol::device::{DEVICE_GRANT, hash_token},
  state::RedisConn,
  store::{Store, device as device_store},
  tls::PeerCertificates,
};

/// Everything one device-code poll needs: datastores plus request values.
///
/// The two halves are never varied independently — every helper takes the
/// whole state — so they travel as one struct instead of two parameters.
pub struct PollState<'a> {
  /// Postgres pool for client lookup and scope/entitlement reads.
  pub pool: &'a PgPool,
  /// Redis connection for device records, bindings, and DPoP replay markers.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
  /// Token-pepper ring for keyed code hashes.
  pub keys: &'a crate::keys::KeyRing,
  /// Public issuer URL (no trailing slash); scopes endpoint paths.
  pub issuer: &'a str,
  /// Device-code lifetime (mirrored to the poll sidecar TTL).
  pub device_ttl: Duration,
  /// Minimum interval between two polls of the same device code.
  pub interval: Duration,
  /// Token lifetimes used for the minted pair.
  pub ttl: &'a TtlConfig,
  /// Access-token representation for the minted pair, resolved by the
  /// dispatcher gate (`None` there means the grant never mints).
  pub token_format: TokenFormat,
  /// JWT signer for `TokenFormat::Jwt` mints, built by the dispatcher from
  /// the validated config; attached to the service before minting.
  pub jwt_signer: Option<crate::jose::jwt_access::JwtAccessSigner>,
  /// CIMD resolution settings for a registration-free fallback; `None` when
  /// `config.cimd_enabled` is off.
  pub cimd: Option<crate::protocol::cimd::CimdSettings<'a>>,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// One device-code redemption request at the token endpoint.
pub struct DevicePollInputs<'a> {
  /// The polling client id.
  pub client_id: &'a str,
  /// The `device_code` to redeem.
  pub device_code: &'a str,
  /// Raw `Authorization` header, when present.
  pub basic_header: Option<&'a str>,
  /// `client_secret` form field (body only), when present.
  pub body_secret: Option<SecretString>,
  /// `client_assertion_type` form field, when present.
  pub assertion_type: Option<&'a str>,
  /// `client_assertion` form field, when present.
  pub assertion: Option<&'a str>,
  /// Raw `DPoP` header (proof JWT), when present.
  pub dpop_proof: Option<&'a str>,
  /// Verified peer chain injected by the TLS accept loop, when present.
  pub peer_certs: Option<&'a PeerCertificates>,
  /// Validated resource audiences (RFC 8707 §2) presented with this poll,
  /// sorted and deduped by the token handler; empty when the poll carried no
  /// `resource`. Must equal the set pinned at authorization time (or be
  /// inherited when empty: RFC 8707 §2.2).
  pub aud: &'a [String],
}

/// Successful device-code redemption (RFC 8628 §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceTokenResponse {
  /// Opaque access token (raw; stored only as a keyed hash).
  pub access_token: String,
  /// `DPoP` for sender-bound tokens, `Bearer` otherwise.
  pub token_type: String,
  /// Access-token lifetime, seconds.
  pub expires_in: u64,
  /// Opaque refresh token (raw; stored only as a keyed hash).
  pub refresh_token: String,
  /// Space-joined effective scope actually granted.
  pub scope: String,
}

/// Redeem a device code at the token endpoint (RFC 8628 §3.5).
///
/// The caller authenticates the client, enforces the polling interval, maps
/// the device status onto its RFC error, and — only after approval —
/// consumes the grant exactly once, recomputes the effective scope against
/// the approving user's entitlements, and mints the token pair. Tokens are
/// never issued before approval, and a public client never receives an
/// unbound token.
///
/// # Errors
///
/// Returns [`DevicePollError::AuthorizationPending`] while the user has not
/// decided, [`DevicePollError::SlowDown`] on too-fast polls,
/// [`DevicePollError::AccessDenied`] after a denial,
/// [`DevicePollError::ExpiredToken`] for unknown or lapsed codes, and
/// [`DevicePollError::Protocol`] for client-auth, sender-binding, scope, or
/// store failures.
pub async fn poll_device(
  state: &mut PollState<'_>,
  inputs: &DevicePollInputs<'_>,
) -> Result<DeviceTokenResponse, DevicePollError> {
  if inputs.client_id.trim().is_empty() || inputs.device_code.trim().is_empty() {
    return Err(AppError::invalid_request("client_id and device_code are required").into());
  }
  let used_basic = inputs.basic_header.is_some();
  let unknown_client = || {
    if used_basic {
      AppError::invalid_client_basic()
    } else {
      AppError::invalid_client_non_basic()
    }
  };
  let client = crate::protocol::cimd::resolve_client(
    state.pool,
    state.keys,
    state.conn,
    state.cimd,
    inputs.client_id.trim(),
  )
  .await
  .map_err(AppError::from)?
  .ok_or_else(unknown_client)?;
  let method = client.auth_method().map_err(|_| unknown_client())?;
  if !client.grant_types.iter().any(|grant| grant == DEVICE_GRANT) {
    return Err(AppError::unauthorized_client("client may not use the device grant").into());
  }

  let proofs = proofs::fresh_proofs(state, &client, inputs).await?;
  require_dpop_binding(&client, &proofs)?;

  let device_hash = hash_token(state.keys, inputs.device_code.trim())?;
  let record = device_store::poll(state.conn, state.store, &device_hash)
    .await
    .map_err(AppError::from)?
    .ok_or(DevicePollError::ExpiredToken)?;
  if record.client_id != client.client_id {
    return Err(AppError::invalid_grant("device code was issued to another client").into());
  }
  interval::check_interval(state, &device_hash).await?;

  match record.status {
    device_store::DeviceStatus::Pending => Err(DevicePollError::AuthorizationPending),
    device_store::DeviceStatus::Denied => Err(DevicePollError::AccessDenied),
    device_store::DeviceStatus::Approved => {
      let kind = if method == TokenEndpointAuthMethod::None {
        super::super::ClientKind::Public
      } else {
        super::super::ClientKind::Confidential
      };
      issue::issue_approved(
        state,
        &issue::Redemption {
          device_hash: &device_hash,
          client: &client,
          kind,
          dpop_required: client.dpop_bound_access_tokens,
          proofs,
          aud: inputs.aud,
          token_format: state.token_format,
          jwt_signer: state.jwt_signer.clone(),
        },
      )
      .await
    }
  }
}

//! Client-credentials grant (RFC 6749 §4.4, RFC 9449 §6, RFC 8705 §3).
//!
//! Machine-to-machine issuance: confidential clients only, no resource owner,
//! no refresh token. The caller authenticates the client and verifies the
//! fresh sender proofs (tasks 18/20/21) before this runs; this module enforces
//! the sender-constraint matrix against the client's registered bindings — a
//! DPoP- or mTLS-bound client without a matching freshly verified proof on
//! this request is rejected (`invalid_grant`), and a stored binding alone
//! never mints — then mints an access-only token whose `cnf` carries whatever
//! was proven.
//!
//! Scope is limited by the registry via [`effective_scope`] under
//! [`GrantKind::ClientCredentials`] (no user term); the access token carries
//! an empty subject. The refresh half minted by the service is revoked before
//! returning, so no refresh token is ever issued.

#[cfg(test)]
mod tests;

use serde::Serialize;

use super::super::{ClientKind, Cnf, SenderProof, TokenService};
use crate::{
  config::GrantKind,
  crypto::tokens as crypto_tokens,
  error::AppError,
  protocol::scope::{ScopeInput, ScopeSet, effective_scope},
  state::RedisConn,
  store::Store,
};

/// Grant type for client credentials (RFC 6749 §4.4).
pub const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// Inputs for one client-credentials issuance.
///
/// Client authentication, DPoP verification (RFC 9449), and mTLS leaf
/// verification (RFC 8705) all happen before this runs; `proof` carries only
/// what was freshly verified on this request, while `dpop_bound_jkt` and
/// `mtls_bound_x5t_s256` carry the client's registered bindings (`None` when
/// the client is not bound that way).
pub struct ClientCredentialsInput<'a> {
  /// Authenticated client id.
  pub client_id: &'a str,
  /// Public or confidential: only confidential may use this grant.
  pub client_kind: ClientKind,
  /// Scopes registered to the client.
  pub client_registered: &'a ScopeSet,
  /// Enabled catalog rows, freshly read at issuance.
  pub enabled: &'a ScopeSet,
  /// Raw `scope` parameter, or `None` when omitted.
  pub requested_scope: Option<&'a str>,
  /// Registered DPoP binding (`jkt`), when the client is DPoP-bound.
  pub dpop_bound_jkt: Option<&'a str>,
  /// Registered mTLS binding (`x5t#S256`), when the client is mTLS-bound.
  pub mtls_bound_x5t_s256: Option<&'a str>,
  /// Freshly verified proofs for this request.
  pub proof: &'a SenderProof,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// An issued client-credentials access token.
///
/// There is deliberately no `refresh_token` field: the service-minted refresh
/// half is revoked before returning, so no refresh token can leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientCredentialsTokens {
  /// Raw access token (return to the caller once; never stored).
  pub access_token: String,
  /// Storage identity of the access token.
  pub access_hash: String,
  /// `DPoP` when `jkt`-bound, else `Bearer`.
  pub token_type: String,
  /// Access-token lifetime, seconds.
  pub expires_in: u64,
  /// Canonical issued scope.
  pub scope: String,
  /// Recorded sender constraint propagated from the fresh proofs.
  pub cnf: Cnf,
  /// Grant chain the new token joins (for revocation wiring).
  pub grant_id: String,
  /// Access-token expiry (Unix seconds).
  pub access_expires_at: i64,
}

/// Issue a client-credentials access token: enforce the confidential-only and
/// sender-constraint gates, narrow the scope, then mint access-only.
///
/// # Errors
///
/// Returns `invalid_client` for a public client, `invalid_grant` when a
/// sender-constrained client presents no (or a stale) proof, `invalid_scope`
/// for scope violations, and `server_error` for store failures.
pub async fn issue_client_credentials(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  input: &ClientCredentialsInput<'_>,
) -> Result<ClientCredentialsTokens, AppError> {
  if input.client_id.trim().is_empty() {
    return Err(AppError::invalid_request("client_id is required"));
  }
  if input.client_kind == ClientKind::Public {
    return Err(AppError::invalid_client_non_basic());
  }
  require_binding(
    input.dpop_bound_jkt,
    input.proof.dpop_jkt.as_deref(),
    "DPoP proof is required for this client",
  )?;
  require_binding(
    input.mtls_bound_x5t_s256,
    input.proof.mtls_x5t_s256.as_deref(),
    "mTLS proof is required for this client",
  )?;

  let issued = effective_scope(&ScopeInput {
    requested: input.requested_scope,
    client_registered: input.client_registered,
    user_entitled: &ScopeSet::empty(),
    enabled: input.enabled,
    grant: GrantKind::ClientCredentials,
    exchange_allowlist: &ScopeSet::empty(),
  })?;

  let grant_id = crypto_tokens::mint_token().map_err(AppError::internal)?;
  let minted = service
    .mint(
      conn,
      store,
      &super::super::MintRequest {
        client_id: input.client_id.trim().to_owned(),
        client_kind: ClientKind::Confidential,
        subject: String::new(),
        scope: issued.render(),
        grant_id: grant_id.clone(),
        proof: input.proof.clone(),
      },
      input.now_unix,
    )
    .await
    .map_err(AppError::from)?;
  service
    .revoke_token(conn, store, &minted.refresh_token)
    .await
    .map_err(AppError::from)?;

  let token_type = if minted.cnf.jkt.is_some() {
    "DPoP".to_owned()
  } else {
    "Bearer".to_owned()
  };
  Ok(ClientCredentialsTokens {
    access_token: minted.access_token,
    access_hash: minted.access_hash,
    token_type,
    expires_in: service.access_ttl().as_secs(),
    scope: issued.render(),
    cnf: minted.cnf,
    grant_id,
    access_expires_at: minted.access_expires_at,
  })
}

/// Require the fresh proof to equal the registered binding, when bound.
///
/// An unbound client (`None` or empty binding) passes unconstrained; a bound
/// client passes only when this request carried a freshly verified proof for
/// the same key. Absence and staleness both fail closed as `invalid_grant`.
fn require_binding(
  bound: Option<&str>,
  proven: Option<&str>,
  why: &'static str,
) -> Result<(), AppError> {
  let want = bound.unwrap_or("").trim();
  if want.is_empty() {
    return Ok(());
  }
  if proven.unwrap_or("").trim() == want {
    Ok(())
  } else {
    Err(AppError::invalid_grant(why))
  }
}

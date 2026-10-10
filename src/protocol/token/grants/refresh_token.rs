//! Refresh-token rotation grant (RFC 9700 §2.2.2/§4.14; RFC 9449 §5–§6).
//!
//! The caller authenticates the client (task 18) and verifies the sender
//! proofs fresh on this request (tasks 20/21) before calling [`refresh`];
//! this grant matches those proofs against the stored `cnf` binding, narrows
//! the scope, mints the replacement pair, and rotates atomically through
//! [`TokenService::rotate`] (task-12 Lua compare-and-set with tombstone and
//! request-id mapping).
//!
//! Ordering is the whole contract: the new raw pair is minted server-side
//! FIRST (barrier deferred to the rotation, which covers the pre-mint writes
//! on the same connection), keyed by the deterministic `rotation_request_id`,
//! and only then is the Lua script invoked. A barrier failure after the
//! originating write applied resolves to the minted pair
//! (`RotatedUnbarriered`, returned as-is); a lost post-`EXEC` reply is
//! recovered by re-reading the request-id mapping (same hashes, never a
//! double rotation, still rejected without cascading); only a tombstone with
//! no valid mapping triggers the grant-cascade reuse path. A retry that hits
//! a live mapping is rejected WITHOUT cascading: the raw tokens of the first
//! rotation are unrecoverable from hashes alone, so the retry cannot be
//! served, but the grant family is left intact.

#[cfg(test)]
mod tests;

use super::super::{ClientKind, Cnf, MintRequest, MintedTokens, SenderProof, TokenService};
use crate::{
  db::{
    user_repo::{self, SubjectAccountStatus},
    user_scope_repo,
  },
  error::AppError,
  keys::KeyRing,
  protocol::scope::{ScopeSet, narrow_on_refresh},
  state::RedisConn,
  store::{
    Store,
    grants::revoke_by_token_hash,
    tokens::{AccessRecord, RefreshRecord, RotateOutcome, RotationInput},
  },
};

/// `grant_type` value for refresh-token rotation (RFC 6749 §6).
pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";

/// Inputs for one refresh-token rotation call.
pub struct RefreshInput<'a> {
  /// Authenticated client id (must own the presented token).
  pub client_id: &'a str,
  /// Public or confidential: selects the `cnf` matrix on the new token.
  pub client_kind: ClientKind,
  /// Raw presented refresh token.
  pub refresh_token: &'a str,
  /// Raw `scope` parameter, or `None` when omitted (keeps the grant scope).
  pub requested_scope: Option<&'a str>,
  /// Freshly verified proofs for this request (never a stored binding).
  pub proof: &'a SenderProof,
  /// Enabled catalog rows, freshly read at issuance.
  pub enabled: &'a ScopeSet,
  /// Current scopes registered to the authenticated client (fresh parse of
  /// the client's `scope` at issuance).
  pub client_registered: &'a ScopeSet,
  /// Current user entitlements. [`refresh_with_subject_check`] replaces this
  /// with a fresh Postgres read for real users; direct [`refresh`] callers
  /// (Redis-only tests) supply the term themselves.
  pub user_entitled: &'a ScopeSet,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// A rotated token pair: raw values plus response shaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshedTokens {
  /// Raw access token (return to the caller once; never stored).
  pub access_token: String,
  /// Raw refresh token (return to the caller once; never stored).
  pub refresh_token: String,
  /// Space-joined effective scope actually granted.
  pub scope: String,
  /// `DPoP` for sender-bound tokens, `Bearer` otherwise.
  pub token_type: String,
  /// Access-token lifetime, seconds.
  pub expires_in: u64,
  /// Grant chain the rotated pair joins (unchanged across rotations).
  pub grant_id: String,
}

/// Datastore handles for the use-time disabled-user re-check in
/// [`refresh_with_subject_check`]. `refresh` itself stays Redis-only so its
/// existing callers keep compiling; the dispatcher must prefer the checked
/// entry point (see the note there).
pub struct RefreshUserStores<'a> {
  /// Postgres pool for the `users.disabled` lookup.
  pub pool: &'a sqlx::PgPool,
  /// Versioned PII keys for the email blind-index lookup.
  pub keys: &'a KeyRing,
}

/// Rotate with a fail-closed use-time disabled-user re-check and fresh
/// entitlement enforcement.
///
/// The presented refresh token is located first; when its non-empty subject
/// resolves to a disabled user the grant is rejected with `invalid_grant`
/// BEFORE anything is minted or rotated, so the presented token stays live
/// for a retry after re-enable. Otherwise the current user entitlements are
/// read fresh from Postgres (a subject that maps to no user — empty
/// client-credentials subjects, synthetic principals — carries no user term)
/// and the rotation narrows against the current `client_registered`,
/// `user_entitled`, and `enabled` sets, so a revoked entitlement or a removed
/// client scope drops out on refresh instead of surviving for the token's
/// whole lifetime. The disabled check preserves unknown-token,
/// tombstone-cascade, and proof-check behavior. A datastore failure propagates
/// as an error.
///
/// # Errors
///
/// Returns `invalid_grant` for a disabled subject, plus every error
/// [`refresh`] can return.
pub async fn refresh_with_subject_check(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  users: &RefreshUserStores<'_>,
  input: &RefreshInput<'_>,
) -> Result<RefreshedTokens, AppError> {
  let raw = input.refresh_token.trim();
  let found = if raw.is_empty() {
    None
  } else {
    service
      .find_refresh(conn, store, raw)
      .await
      .map_err(AppError::from)?
  };
  let Some(found) = found else {
    return refresh(conn, store, service, input).await;
  };
  if !found.record.subject.trim().is_empty()
    && matches!(
      user_repo::subject_account_status(users.pool, users.keys, &found.record.subject).await?,
      SubjectAccountStatus::Disabled
    )
  {
    return Err(AppError::invalid_grant("account is disabled"));
  }
  let entitled =
    match user_repo::subject_user_id(users.pool, users.keys, &found.record.subject).await? {
      Some(id) => ScopeSet::from_names(&user_scope_repo::list_for_user(users.pool, id).await?)?,
      None => ScopeSet::parse(&found.record.scope).map_err(|_| AppError::server_error())?,
    };
  let fresh = RefreshInput {
    client_id: input.client_id,
    client_kind: input.client_kind,
    refresh_token: input.refresh_token,
    requested_scope: input.requested_scope,
    proof: input.proof,
    enabled: input.enabled,
    client_registered: input.client_registered,
    user_entitled: &entitled,
    now_unix: input.now_unix,
  };
  refresh(conn, store, service, &fresh).await
}

/// Rotate a refresh token: fresh proof-of-possession, scope narrowing, then
/// mint-first atomic rotation with tombstone reuse detection.
///
/// The stored `cnf` alone never mints: every bound component must equal its
/// freshly verified counterpart. Scope may only narrow (`invalid_scope`
/// otherwise). The replacement pair is minted BEFORE the Lua script runs
/// (barrier deferred to the rotation, which gates the response), so every
/// non-`Rotated`/`RotatedUnbarriered` outcome revokes the orphaned pre-mint.
/// A barrier failure after the originating write applied returns the minted
/// pair as tokens instead of locking out; a mapping replay still discards
/// the orphans and rejects without cascading.
///
/// # Errors
///
/// Returns `invalid_request` for a missing client or token, `invalid_grant`
/// for an unknown, foreign, already-rotated, or proof-mismatched token (reuse
/// additionally cascade-revokes the grant family), `invalid_scope` for scope
/// widening, and `server_error`/`temporarily_unavailable` for store failures.
pub async fn refresh(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  input: &RefreshInput<'_>,
) -> Result<RefreshedTokens, AppError> {
  let client_id = input.client_id.trim();
  let raw = input.refresh_token.trim();
  if client_id.is_empty() || raw.is_empty() {
    return Err(AppError::invalid_request(
      "client_id and refresh_token are required",
    ));
  }
  let found = match service
    .find_refresh(conn, store, raw)
    .await
    .map_err(AppError::from)?
  {
    Some(found) => found,
    None => return unknown_or_tombstoned(conn, store, service, raw).await,
  };
  if found.record.client_id != client_id {
    return Err(AppError::invalid_grant(
      "refresh token was issued to another client",
    ));
  }
  check_proofs(input.client_kind, &found.record.cnf, input.proof)?;
  let previous = ScopeSet::parse(&found.record.scope).map_err(|_| AppError::server_error())?;
  // An empty subject is a client-credentials-style principal with no user
  // term; the previous grant itself stands in so only the client and catalog
  // sets narrow.
  let user_term = if found.record.subject.trim().is_empty() {
    &previous
  } else {
    input.user_entitled
  };
  let narrowed = narrow_on_refresh(
    &previous,
    input.requested_scope,
    input.enabled,
    input.client_registered,
    user_term,
  )?;
  let minted = service
    .mint_for_rotation(
      conn,
      store,
      &MintRequest {
        client_id: client_id.to_owned(),
        client_kind: input.client_kind,
        subject: found.record.subject.clone(),
        scope: narrowed.render(),
        grant_id: found.record.grant_id.clone(),
        proof: input.proof.clone(),
      },
      input.now_unix,
    )
    .await
    .map_err(AppError::from)?;
  let request_id = service
    .request_id_for(&found.hash)
    .map_err(AppError::from)?;
  let cnf_json = minted.cnf.to_storage().map_err(AppError::from)?;
  let rotation = RotationInput {
    old_refresh_hash: found.hash.clone(),
    expected_client_id: client_id.to_owned(),
    new_refresh_hash: minted.refresh_hash.clone(),
    new_access_hash: minted.access_hash.clone(),
    new_refresh: RefreshRecord {
      client_id: client_id.to_owned(),
      grant_id: found.record.grant_id.clone(),
      scope: narrowed.render(),
      subject: found.record.subject.clone(),
      cnf: cnf_json.clone(),
    },
    new_access: AccessRecord {
      client_id: client_id.to_owned(),
      grant_id: found.record.grant_id.clone(),
      scope: narrowed.render(),
      subject: found.record.subject.clone(),
      cnf: cnf_json,
    },
    new_refresh_ttl: service.refresh_ttl(),
    new_access_ttl: service.access_ttl(),
    request_id: Some(request_id),
  };
  match service
    .rotate(conn, store, &rotation)
    .await
    .map_err(AppError::from)?
  {
    RotateOutcome::Rotated { .. } | RotateOutcome::RotatedUnbarriered { .. } => Ok(response(
      service,
      &minted,
      &narrowed,
      &found.record.grant_id,
    )),
    RotateOutcome::Replay { .. } => {
      discard_orphan(conn, store, service, &minted).await?;
      Err(AppError::invalid_grant("refresh token was already rotated"))
    }
    RotateOutcome::Reused { .. } => {
      discard_orphan(conn, store, service, &minted).await?;
      Err(AppError::invalid_grant("refresh token reuse detected"))
    }
    RotateOutcome::Absent | RotateOutcome::Mismatch => {
      discard_orphan(conn, store, service, &minted).await?;
      Err(AppError::invalid_grant("refresh token is invalid"))
    }
  }
}

/// Reject an unknown refresh token; when the raw value resolves to a rotation
/// tombstone, cascade-revoke the grant family first.
async fn unknown_or_tombstoned(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  raw: &str,
) -> Result<RefreshedTokens, AppError> {
  if let Some(target) = service
    .consume_tombstone(conn, store, raw)
    .await
    .map_err(AppError::from)?
  {
    revoke_by_token_hash(conn, store, &target)
      .await
      .map_err(AppError::from)?;
  }
  Err(AppError::invalid_grant("refresh token is invalid"))
}

/// Match freshly verified proofs against the stored `cnf` binding.
///
/// At least one proof must be present on this request, and every bound
/// component of the stored claim must equal its fresh counterpart. A public
/// grant always carries a `jkt` (mint-enforced); its absence here is a
/// fail-closed invariant violation.
fn check_proofs(kind: ClientKind, stored: &str, proof: &SenderProof) -> Result<(), AppError> {
  let bound = Cnf::parse_storage(stored).map_err(AppError::from)?;
  let jkt = proof.dpop_jkt.clone().filter(|value| !value.is_empty());
  let x5t = proof
    .mtls_x5t_s256
    .clone()
    .filter(|value| !value.is_empty());
  if jkt.is_none() && x5t.is_none() {
    return Err(AppError::invalid_grant(
      "refresh requires a freshly verified proof of possession",
    ));
  }
  if let Some(want) = bound.jkt.as_deref() {
    if jkt.as_deref() != Some(want) {
      return Err(AppError::invalid_grant(
        "DPoP binding does not match this grant",
      ));
    }
  } else if kind == ClientKind::Public {
    return Err(AppError::server_error());
  }
  if let Some(want) = bound.x5t_s256.as_deref()
    && x5t.as_deref() != Some(want)
  {
    return Err(AppError::invalid_grant(
      "mTLS binding does not match this grant",
    ));
  }
  Ok(())
}

/// Revoke the orphaned pre-mint pair after a non-`Rotated` outcome.
///
/// The mint stored both records before the script ran; leaving them live
/// would fork the grant chain. On the reuse path the cascade already wiped
/// the grant, so these deletes are no-ops there.
async fn discard_orphan(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  minted: &MintedTokens,
) -> Result<(), AppError> {
  service
    .revoke_token(conn, store, &minted.refresh_token)
    .await
    .map_err(AppError::from)?;
  service
    .revoke_token(conn, store, &minted.access_token)
    .await
    .map_err(AppError::from)?;
  Ok(())
}

/// Shape a successful rotation response from the minted pair.
fn response(
  service: &TokenService,
  minted: &MintedTokens,
  scope: &ScopeSet,
  grant_id: &str,
) -> RefreshedTokens {
  RefreshedTokens {
    access_token: minted.access_token.clone(),
    refresh_token: minted.refresh_token.clone(),
    scope: scope.render(),
    token_type: if minted.cnf.jkt.is_some() {
      "DPoP".to_owned()
    } else {
      "Bearer".to_owned()
    },
    expires_in: service.access_ttl().as_secs(),
    grant_id: grant_id.to_owned(),
  }
}

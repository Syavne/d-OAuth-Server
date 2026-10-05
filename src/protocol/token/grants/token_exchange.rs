//! Token-exchange grant with policy (RFC 8693 §2-§3).
//!
//! The caller is already authenticated by task 18 before this runs. The
//! exchange additionally requires a freshly verified proof-of-possession on
//! this request ([`SenderProof`]); when the `subject_token` is
//! sender-constrained, that proof must match the SUBJECT token's `cnf`, not
//! merely the caller's. A stored binding alone never mints.
//!
//! Scope is pinned to
//! `subject.scope ∩ caller-registered ∩ subject-user-entitled ∩ enabled ∩
//! allowlist`; an explicit request naming a scope the subject token does not
//! hold is rejected (no widening). Chained exchanges are rejected: a subject
//! token that already carries an [`ActClaim`] sidecar is not exchangeable.
//! No refresh token is ever issued: the service-minted refresh half is
//! revoked before returning.

#[cfg(test)]
mod tests;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::super::{ClientKind, Cnf, MintRequest, SenderProof, TokenService};
use crate::{
  config::{GrantKind, TokenExchangeRule},
  crypto::tokens as crypto_tokens,
  error::AppError,
  protocol::scope::{ScopeInput, ScopeSet, effective_scope},
  state::RedisConn,
  store::{Store, StoreError, durability_barrier, tokens as low},
};

/// Grant-type URN for token exchange (RFC 8693 §2.1).
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The only supported `subject_token_type` / `actor_token_type`.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Suffix for the `act` sidecar key hanging off an access-token record key.
const ACT_KEY_SUFFIX: &str = ":act";

/// The `act` (actor) claim bound to an exchanged token (RFC 8693 §4.1).
///
/// `sub` names the party the new token acts as: the subject token's client.
/// Stored as a JSON sidecar (task-29 precedent) so the frozen task-12 record
/// shape is untouched; introspection (task 36) reads it via [`read_act`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
  /// The subject token's client: the party being impersonated/delegated.
  pub sub: String,
}

/// Inputs for one token-exchange call.
pub struct ExchangeInput<'a> {
  /// Authenticated caller client id.
  pub caller_client_id: &'a str,
  /// Public or confidential: selects the `cnf` matrix on the new token.
  pub caller_kind: ClientKind,
  /// Scopes registered to the caller client.
  pub caller_registered: &'a ScopeSet,
  /// Raw subject token.
  pub subject_token: &'a str,
  /// `subject_token_type` URN (must be the access-token URN).
  pub subject_token_type: &'a str,
  /// Raw actor token, when present (validated live, never copied).
  pub actor_token: Option<&'a str>,
  /// `actor_token_type` URN, when an actor token is present.
  pub actor_token_type: Option<&'a str>,
  /// `requested_token_type` URN, when present.
  pub requested_token_type: Option<&'a str>,
  /// Raw `scope` parameter, or `None` when omitted.
  pub requested_scope: Option<&'a str>,
  /// Scopes the subject token's user is entitled to.
  pub subject_user_entitled: &'a ScopeSet,
  /// Enabled catalog rows, freshly read at issuance.
  pub enabled: &'a ScopeSet,
  /// Whether the deployment enables token exchange at all.
  pub allow_exchange: bool,
  /// Configured `(caller, subject, scopes)` policy.
  pub allowlist: &'a [TokenExchangeRule],
  /// Freshly verified proofs for this request.
  pub proof: &'a SenderProof,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// An exchanged access token: raw value plus its response shaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangedTokens {
  /// Raw access token (return to the caller once; never stored).
  pub access_token: String,
  /// Storage identity of the access token.
  pub access_hash: String,
  /// Canonical issued scope.
  pub scope: String,
  /// Resource-owner subject carried over from the subject token.
  pub subject: String,
  /// Recorded sender constraint on the new token.
  pub cnf: Cnf,
  /// The `act` claim bound into the sidecar.
  pub act: ActClaim,
  /// `token_type` response member: `DPoP` when `jkt`-bound, else `Bearer`.
  pub token_type: String,
  /// Grant chain the new token joins (for revocation wiring).
  pub grant_id: String,
  /// Access-token expiry (Unix seconds).
  pub access_expires_at: i64,
}

/// Exchange TTL: half the service access TTL (floored at one second), so an
/// exchanged token always outlives nothing it was derived from.
#[must_use]
pub fn exchange_ttl(service: &TokenService) -> Duration {
  service
    .access_ttl()
    .checked_div(2)
    .unwrap_or(Duration::from_secs(1))
    .max(Duration::from_secs(1))
}

/// Sidecar key holding the [`ActClaim`] JSON for an access-token hash.
#[must_use]
pub fn act_key(store: &Store, access_hash: &str) -> String {
  format!("{}{ACT_KEY_SUFFIX}", store.access_key(access_hash))
}

/// Read the [`ActClaim`] sidecar for an access-token hash, if any.
///
/// Task 36 (introspection) reads the `act` of an exchanged token through
/// this; [`exchange`] uses it to reject chained exchanges.
///
/// # Errors
///
/// Returns the store failure, or `server_error` when the sidecar is corrupt.
pub async fn read_act(
  conn: &mut RedisConn,
  store: &Store,
  access_hash: &str,
) -> Result<Option<ActClaim>, AppError> {
  let key = act_key(store, access_hash);
  let raw: Option<String> = redis::cmd("GET")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  raw
    .map(|value| serde_json::from_str(&value).map_err(|_| AppError::server_error()))
    .transpose()
}

/// Perform a token exchange: policy-check, then mint an access-only token.
///
/// The refresh half minted by the service is revoked before returning, so no
/// refresh token is ever issued.
///
/// # Errors
///
/// Returns `invalid_request` for unsupported token types, `invalid_scope`
/// for scope violations, `invalid_grant` for policy/proof failures, and
/// `server_error` for store corruption.
pub async fn exchange(
  conn: &mut RedisConn,
  store: &Store,
  service: &TokenService,
  input: &ExchangeInput<'_>,
) -> Result<ExchangedTokens, AppError> {
  if !input.allow_exchange {
    return Err(AppError::invalid_grant("token exchange is not enabled"));
  }
  if input.subject_token_type != TOKEN_TYPE_ACCESS_TOKEN {
    return Err(AppError::invalid_request("unsupported subject_token_type"));
  }
  if let Some(actor_type) = input.actor_token_type
    && actor_type != TOKEN_TYPE_ACCESS_TOKEN
  {
    return Err(AppError::invalid_request("unsupported actor_token_type"));
  }
  if let Some(requested_type) = input.requested_token_type
    && requested_type != TOKEN_TYPE_ACCESS_TOKEN
  {
    return Err(AppError::invalid_request(
      "unsupported requested_token_type",
    ));
  }
  let proof_jkt = input
    .proof
    .dpop_jkt
    .clone()
    .filter(|value| !value.is_empty());
  let proof_x5t = input
    .proof
    .mtls_x5t_s256
    .clone()
    .filter(|value| !value.is_empty());
  if proof_jkt.is_none() && proof_x5t.is_none() {
    return Err(AppError::invalid_grant(
      "exchange requires a freshly verified proof of possession",
    ));
  }

  let subject = service
    .find_access(conn, store, input.subject_token)
    .await
    .map_err(AppError::from)?;
  let subject = subject.ok_or_else(|| AppError::invalid_grant("subject token is invalid"))?;
  if let Some(actor_raw) = input.actor_token {
    let actor = service
      .find_access(conn, store, actor_raw)
      .await
      .map_err(AppError::from)?;
    if actor.is_none() {
      return Err(AppError::invalid_grant("actor token is invalid"));
    }
  }
  if read_act(conn, store, &subject.hash).await?.is_some() {
    return Err(AppError::invalid_grant(
      "chained token exchange is not permitted",
    ));
  }

  let subject_cnf = Cnf::parse_storage(&subject.record.cnf).map_err(AppError::from)?;
  if let Some(bound) = subject_cnf.jkt.as_deref()
    && proof_jkt.as_deref() != Some(bound)
  {
    return Err(AppError::invalid_grant(
      "proof does not match the subject token binding",
    ));
  }
  if let Some(bound) = subject_cnf.x5t_s256.as_deref()
    && proof_x5t.as_deref() != Some(bound)
  {
    return Err(AppError::invalid_grant(
      "proof does not match the subject token binding",
    ));
  }

  let rule = input
    .allowlist
    .iter()
    .find(|rule| rule.caller == input.caller_client_id && rule.subject == subject.record.client_id)
    .ok_or_else(|| AppError::invalid_grant("exchange is not allowlisted for this pair"))?;
  let rule_scopes = ScopeSet::from_names(&rule.scopes).map_err(|_| AppError::server_error())?;
  let exchange_allowlist = rule_scopes.intersect(input.subject_user_entitled);

  let subject_scopes =
    ScopeSet::parse(&subject.record.scope).map_err(|_| AppError::server_error())?;
  if let Some(raw) = input.requested_scope {
    let requested = ScopeSet::parse(raw)?;
    if !requested.is_subset_of(&subject_scopes) {
      return Err(AppError::invalid_scope(
        "requested scope exceeds the subject token",
      ));
    }
  }
  let issued = effective_scope(&ScopeInput {
    requested: input.requested_scope,
    client_registered: input.caller_registered,
    user_entitled: input.subject_user_entitled,
    enabled: input.enabled,
    grant: GrantKind::TokenExchange,
    exchange_allowlist: &exchange_allowlist,
  })?;
  let issued = issued.intersect(&subject_scopes);

  let grant_id = crypto_tokens::mint_token().map_err(AppError::internal)?;
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: input.caller_client_id.to_owned(),
        client_kind: input.caller_kind,
        subject: subject.record.subject.clone(),
        scope: issued.render(),
        grant_id,
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

  let ttl = exchange_ttl(service);
  let grant_id = minted_grant_of(conn, store, &minted.access_hash).await?;
  let record = low::AccessRecord {
    client_id: input.caller_client_id.to_owned(),
    grant_id: grant_id.clone(),
    scope: issued.render(),
    subject: subject.record.subject.clone(),
    cnf: minted.cnf.to_storage().map_err(AppError::from)?,
  };
  low::put_access(conn, store, &minted.access_hash, &record, ttl)
    .await
    .map_err(AppError::from)?;

  let act = ActClaim {
    sub: subject.record.client_id.clone(),
  };
  let act_raw = serde_json::to_string(&act).map_err(AppError::internal)?;
  let key = act_key(store, &minted.access_hash);
  let _: () = redis::cmd("SET")
    .arg(&key)
    .arg(&act_raw)
    .arg("PX")
    .arg(ttl.as_millis() as u64)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  durability_barrier(conn, store)
    .await
    .map_err(AppError::from)?;

  let token_type = if minted.cnf.jkt.is_some() {
    "DPoP".to_owned()
  } else {
    "Bearer".to_owned()
  };
  Ok(ExchangedTokens {
    access_token: minted.access_token,
    access_hash: minted.access_hash,
    scope: issued.render(),
    subject: subject.record.subject,
    cnf: minted.cnf,
    act,
    token_type,
    grant_id,
    access_expires_at: input.now_unix.saturating_add(ttl.as_secs() as i64),
  })
}

/// Recover the grant id the service minted into, via the stored record.
async fn minted_grant_of(
  conn: &mut RedisConn,
  store: &Store,
  access_hash: &str,
) -> Result<String, AppError> {
  let record = low::get_access(conn, store, access_hash)
    .await
    .map_err(AppError::from)?;
  record.map_or_else(
    || Err(AppError::server_error()),
    |record| Ok(record.grant_id),
  )
}

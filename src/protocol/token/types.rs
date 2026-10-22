//! Token-service vocabulary: errors, client kinds, proofs, and claims.
//!
//! The sender-constraint matrix lives here ([`resolve_cnf`]): DPoP is
//! mandatory for a public client only when it is DPoP-bound
//! (`dpop_bound_access_tokens=true`); an unbound public client is
//! Bearer-capable. Confidential clients record mTLS (`cnf.x5t#S256`) and/or
//! DPoP when proven; an unconstrained confidential grant carries an empty
//! `cnf`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{crypto::tokens as crypto_tokens, error::AppError, store::StoreError};

/// How a client's access tokens are represented to resource servers.
///
/// `Opaque` is the default: a random token whose keyed hash names the record.
/// `Jwt` is the opt-in RFC 9068 profile (Todo 26): the access token returned
/// to the client is a signed `at+jwt`, while the refresh half stays an opaque
/// token (rotation semantics unchanged). The type lives here so `dispatch`
/// and `service` share one decision without a module cycle; `dispatch`
/// re-exports it so Todo 25's `require_token_format` call sites keep
/// compiling. Token exchange never mints `Jwt` (fail-closed `act` never).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFormat {
  /// Opaque bearer token; the JWT stack is never touched.
  Opaque,
  /// RFC 9068 JWT access token; requires the global switch and key material.
  Jwt,
}

/// Fail-closed token-service failures.
#[derive(Debug, thiserror::Error)]
pub enum TokenServiceError {
  /// A public client tried to mint without a DPoP binding.
  #[error("public clients require a DPoP-bound token")]
  MissingDpopBinding,
  /// No token pepper is configured.
  #[error("no token pepper configured")]
  NoPepper,
  /// A stored confirmation claim did not parse.
  #[error("stored confirmation claim is malformed")]
  MalformedCnf,
  /// The operating-system RNG failed.
  #[error("token randomness unavailable")]
  Randomness(#[from] crypto_tokens::TokenError),
  /// A store operation failed.
  #[error("token store failure")]
  Store(#[from] StoreError),
  /// A `Jwt` mint ran without an attached signer (the dispatcher guarantees
  /// one; fail closed instead of minting opaque).
  #[error("no JWT signer configured for a jwt mint")]
  JwtSignerMissing,
  /// JWT signing or claim construction failed (keys are validated at load,
  /// so this is unreachable in practice; fail closed).
  #[error("JWT minting failed")]
  Jwt(#[from] crate::jose::jwt_access::JwtError),
  /// A `Jwt` mint ran with an empty audience: RFC 9068 `aud` is mandatory,
  /// so a JWT access token without a requested RFC 8707 resource is
  /// rejected before signing or writing anything.
  #[error("jwt access tokens require a resource audience")]
  EmptyAudience,
}

impl From<TokenServiceError> for AppError {
  /// Map a service failure onto the RFC error model: a missing public-client
  /// binding is the caller's `invalid_grant`; store failures reuse the store
  /// mapping (fail closed); a JWT signing/deployment failure is the fail-closed
  /// `503`; everything else is masked as `server_error`.
  fn from(error: TokenServiceError) -> Self {
    match error {
      TokenServiceError::MissingDpopBinding => {
        Self::invalid_grant("public clients require a DPoP-bound token")
      }
      TokenServiceError::EmptyAudience => {
        Self::invalid_target("jwt access tokens require a resource audience")
      }
      TokenServiceError::Store(inner) => Self::from(inner),
      TokenServiceError::JwtSignerMissing | TokenServiceError::Jwt(_) => {
        Self::temporarily_unavailable()
      }
      other => Self::internal(other),
    }
  }
}

/// Whether the client authenticates as public or confidential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
  /// No client secret: DPoP is mandatory only for a DPoP-bound client;
  /// unbound public clients use Bearer.
  Public,
  /// Authenticated client: mTLS and/or DPoP are recorded when proven.
  Confidential,
}

/// Freshly verified sender proofs for one mint call.
///
/// Verification itself belongs to tasks 20/21; the service only records what
/// was proven on this request. A stored binding alone never mints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderProof {
  /// Verified DPoP key thumbprint (`jkt`), if a proof was verified.
  pub dpop_jkt: Option<String>,
  /// Verified mTLS leaf thumbprint (`x5t#S256`), if mTLS was presented.
  pub mtls_x5t_s256: Option<String>,
}

impl SenderProof {
  /// No proof was verified on this request.
  #[must_use]
  pub fn none() -> Self {
    Self::default()
  }
}

/// The `cnf` confirmation claim bound into issued tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
  /// DPoP key thumbprint, when DPoP was proven.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub jkt: Option<String>,
  /// mTLS leaf thumbprint, when mTLS was proven.
  #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
  pub x5t_s256: Option<String>,
}

impl Cnf {
  /// Whether any sender constraint is bound.
  #[must_use]
  pub fn is_bound(&self) -> bool {
    self.jkt.is_some() || self.x5t_s256.is_some()
  }

  /// Render for storage: empty string when unconstrained, else JSON.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::MalformedCnf`] when serialization fails.
  pub fn to_storage(&self) -> Result<String, TokenServiceError> {
    if !self.is_bound() {
      return Ok(String::new());
    }
    serde_json::to_string(self).map_err(|_| TokenServiceError::MalformedCnf)
  }

  /// Parse [`Cnf::to_storage`] output.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::MalformedCnf`] for non-empty, non-JSON input.
  pub fn parse_storage(raw: &str) -> Result<Self, TokenServiceError> {
    if raw.is_empty() {
      return Ok(Self::default());
    }
    serde_json::from_str(raw).map_err(|_| TokenServiceError::MalformedCnf)
  }
}

/// Apply the sender-constraint matrix to one mint call.
///
/// A public client registers its DPoP posture per client: a DPoP-bound client
/// (`dpop_required`) must present a `jkt`, while an unbound public client
/// mints a `Bearer` token when no proof was verified (a presented proof is
/// still recorded). Empty proof strings count as absent.
///
/// # Errors
///
/// Returns [`TokenServiceError::MissingDpopBinding`] for a DPoP-bound public
/// client without a `jkt`.
pub(super) fn resolve_cnf(
  kind: ClientKind,
  proof: &SenderProof,
  dpop_required: bool,
) -> Result<Cnf, TokenServiceError> {
  let jkt = proof.dpop_jkt.clone().filter(|value| !value.is_empty());
  let x5t_s256 = proof
    .mtls_x5t_s256
    .clone()
    .filter(|value| !value.is_empty());
  match kind {
    ClientKind::Public if dpop_required => match jkt {
      Some(jkt) => Ok(Cnf {
        jkt: Some(jkt),
        x5t_s256,
      }),
      None => Err(TokenServiceError::MissingDpopBinding),
    },
    ClientKind::Public => Ok(Cnf { jkt, x5t_s256 }),
    ClientKind::Confidential => Ok(Cnf { jkt, x5t_s256 }),
  }
}

/// Inputs for one mint call.
///
/// Resource audiences (RFC 8707 §2) travel as a pair: [`MintRequest::aud`]
/// binds the ACCESS token while [`MintRequest::refresh_aud`] binds the
/// REFRESH token and the grant-chain record. The two are equal on every first
/// issuance; they diverge only on a narrowed refresh rotation, where RFC 8707
/// §2.2 keeps the refresh token bound to the full original grant set while
/// the access token narrows (an omitted `resource` defaults to that full
/// set, NOT to §3's empty set). `mint_inner` writes each half to its record,
/// so the rotation script — which commits the [`RotationInput`] records
/// verbatim and never rewrites the grant record — preserves the full binding
/// while the access token narrows.
///
/// Scope travels as the same kind of pair: [`MintRequest::scope`] is the
/// REFRESH/grant scope (the retained set, re-checked against the current
/// catalog, client registration, and entitlements), while
/// [`MintRequest::access_scope`] is the ACCESS scope (the narrowed subset on
/// an explicit `scope` request, else equal to `scope`). The JWT `scope`
/// claim and the stored access record bind `access_scope`; the refresh and
/// grant records bind `scope`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
  /// Client the tokens are issued to.
  pub client_id: String,
  /// Public or confidential: selects the constraint matrix.
  pub client_kind: ClientKind,
  /// Whether a public client must present a DPoP proof: mirrors the
  /// client's `dpop_bound_access_tokens` registration (unbound public
  /// clients mint `Bearer` tokens). Ignored for confidential clients.
  pub dpop_required: bool,
  /// Resource-owner subject, empty for client-credentials tokens.
  pub subject: String,
  /// Space-joined scope: the REFRESH/grant scope (retained set).
  pub scope: String,
  /// Space-joined ACCESS scope: the narrowed subset on an explicit `scope`
  /// request, else equal to [`MintRequest::scope`]. Binds the JWT `scope`
  /// claim and the stored access record.
  pub access_scope: String,
  /// Grant chain the tokens join.
  pub grant_id: String,
  /// Freshly verified proofs for this request.
  pub proof: SenderProof,
  /// Resource audiences (RFC 8707 §2) bound into the ACCESS token record.
  pub aud: Vec<String>,
  /// Resource audiences bound into the REFRESH token record and the
  /// grant-chain record: the full original grant set, even when `aud` is a
  /// narrowed refresh subset.
  pub refresh_aud: Vec<String>,
  /// Access-token representation for this mint: `Opaque` reproduces today's
  /// behavior byte-for-byte (records plus grant membership, no marker, no
  /// JWT); `Jwt` returns a signed RFC 9068 `at+jwt` whose `aud` claim takes
  /// [`MintRequest::aud`] (the narrowed access set, never `refresh_aud`)
  /// while the refresh half stays opaque.
  pub format: TokenFormat,
}

/// Freshly minted pair: raw tokens (return to the caller once) plus their
/// hash-at-rest identities and validity window.
///
/// `Debug` redacts the raw tokens (lengths only) and prints the storage
/// identities, following the [`crate::protocol::code::IssuedCode`] pattern.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedTokens {
  /// Raw access token (never stored).
  pub access_token: String,
  /// Raw refresh token (never stored).
  pub refresh_token: String,
  /// Storage identity of the access token.
  pub access_hash: String,
  /// Storage identity of the refresh token.
  pub refresh_hash: String,
  /// Recorded sender constraint.
  pub cnf: Cnf,
  /// Issuance time (Unix seconds, caller clock).
  pub issued_at: i64,
  /// Access-token expiry (Unix seconds).
  pub access_expires_at: i64,
  /// Refresh-token expiry (Unix seconds).
  pub refresh_expires_at: i64,
}

impl MintedTokens {
  /// The `jti` hash when this mint produced a JWT access token: the access
  /// identity is the grant-set member `jwt:<jti-hash>` (never a pepper
  /// hash), so stripping the prefix recovers the marker key material.
  /// `None` for opaque mints, whose identity is a pepper hash.
  #[must_use]
  pub fn jwt_jti_hash(&self) -> Option<&str> {
    self.access_hash.strip_prefix("jwt:")
  }
}

impl fmt::Debug for MintedTokens {
  /// Redacted [`fmt::Debug`]: raw tokens never reach logs or errors, only
  /// their lengths plus the hash-at-rest identities.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("MintedTokens")
      .field("access_token", &"[REDACTED]")
      .field("access_token_len", &self.access_token.len())
      .field("refresh_token", &"[REDACTED]")
      .field("refresh_token_len", &self.refresh_token.len())
      .field("access_hash", &self.access_hash)
      .field("refresh_hash", &self.refresh_hash)
      .field("cnf", &self.cnf)
      .field("issued_at", &self.issued_at)
      .field("access_expires_at", &self.access_expires_at)
      .field("refresh_expires_at", &self.refresh_expires_at)
      .finish()
  }
}

/// A located access token plus its hash-at-rest identity.
#[derive(Clone, PartialEq, Eq)]
pub struct FoundAccess {
  /// The stored record.
  pub record: crate::store::tokens::AccessRecord,
  /// Storage identity the raw token resolved to.
  pub hash: String,
  /// Pepper label (`v<N>`) that produced the match.
  pub key_label: String,
}

impl fmt::Debug for FoundAccess {
  /// Locked [`fmt::Debug`]: the struct carries no raw token, only the stored
  /// record plus its hash-at-rest identity and pepper label. Transitive: the
  /// record's derived `Debug` holds identifiers only (see
  /// [`crate::store::tokens::AccessRecord`]), so nothing secret formats here.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FoundAccess")
      .field("record", &self.record)
      .field("hash", &self.hash)
      .field("key_label", &self.key_label)
      .finish()
  }
}

/// A located refresh token plus its hash-at-rest identity.
#[derive(Clone, PartialEq, Eq)]
pub struct FoundRefresh {
  /// The stored record.
  pub record: crate::store::tokens::RefreshRecord,
  /// Storage identity the raw token resolved to.
  pub hash: String,
  /// Pepper label (`v<N>`) that produced the match.
  pub key_label: String,
}

impl fmt::Debug for FoundRefresh {
  /// Locked [`fmt::Debug`]: the struct carries no raw token, only the stored
  /// record plus its hash-at-rest identity and pepper label. Transitive: the
  /// record's derived `Debug` holds identifiers only (see
  /// [`crate::store::tokens::RefreshRecord`]), so nothing secret formats here.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FoundRefresh")
      .field("record", &self.record)
      .field("hash", &self.hash)
      .field("key_label", &self.key_label)
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use axum::http::StatusCode;

  use super::TokenServiceError;
  use crate::{error::AppError, jose::jwt_access::JwtError};

  /// A missing signer or a signing failure is a deployment/dependency failure:
  /// it must fail closed with `503`, never a masked `500`.
  #[test]
  fn jwt_service_failures_map_to_503() {
    let missing = AppError::from(TokenServiceError::JwtSignerMissing);
    assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
    let signing = AppError::from(TokenServiceError::Jwt(JwtError::NoSigningKey));
    assert_eq!(signing.status(), StatusCode::SERVICE_UNAVAILABLE);
  }
}

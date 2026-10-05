//! Token-service vocabulary: errors, client kinds, proofs, and claims.
//!
//! The sender-constraint matrix lives here ([`resolve_cnf`]): public clients
//! REQUIRE DPoP (`cnf.jkt`) — absence is a hard error, never "if present".
//! Confidential clients record mTLS (`cnf.x5t#S256`) and/or DPoP, both when
//! both were proven; an unconstrained confidential grant carries an empty
//! `cnf`.

use serde::{Deserialize, Serialize};

use crate::{crypto::tokens as crypto_tokens, error::AppError, store::StoreError};

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
}

impl From<TokenServiceError> for AppError {
  /// Map a service failure onto the RFC error model: a missing public-client
  /// binding is the caller's `invalid_grant`; store failures reuse the store
  /// mapping (fail closed); everything else is masked as `server_error`.
  fn from(error: TokenServiceError) -> Self {
    match error {
      TokenServiceError::MissingDpopBinding => {
        Self::invalid_grant("public clients require a DPoP-bound token")
      }
      TokenServiceError::Store(inner) => Self::from(inner),
      other => Self::internal(other),
    }
  }
}

/// Whether the client authenticates as public or confidential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
  /// No client secret: DPoP binding is mandatory.
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
/// # Errors
///
/// Returns [`TokenServiceError::MissingDpopBinding`] for a public client
/// without a `jkt`. Empty proof strings count as absent.
pub(super) fn resolve_cnf(kind: ClientKind, proof: &SenderProof) -> Result<Cnf, TokenServiceError> {
  let jkt = proof.dpop_jkt.clone().filter(|value| !value.is_empty());
  let x5t_s256 = proof
    .mtls_x5t_s256
    .clone()
    .filter(|value| !value.is_empty());
  match kind {
    ClientKind::Public => match jkt {
      Some(jkt) => Ok(Cnf {
        jkt: Some(jkt),
        x5t_s256,
      }),
      None => Err(TokenServiceError::MissingDpopBinding),
    },
    ClientKind::Confidential => Ok(Cnf { jkt, x5t_s256 }),
  }
}

/// Inputs for one mint call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
  /// Client the tokens are issued to.
  pub client_id: String,
  /// Public or confidential: selects the constraint matrix.
  pub client_kind: ClientKind,
  /// Resource-owner subject, empty for client-credentials tokens.
  pub subject: String,
  /// Space-joined scope.
  pub scope: String,
  /// Grant chain the tokens join.
  pub grant_id: String,
  /// Freshly verified proofs for this request.
  pub proof: SenderProof,
}

/// Freshly minted pair: raw tokens (return to the caller once) plus their
/// hash-at-rest identities and validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A located access token plus its hash-at-rest identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundAccess {
  /// The stored record.
  pub record: crate::store::tokens::AccessRecord,
  /// Storage identity the raw token resolved to.
  pub hash: String,
  /// Pepper label (`v<N>`) that produced the match.
  pub key_label: String,
}

/// A located refresh token plus its hash-at-rest identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundRefresh {
  /// The stored record.
  pub record: crate::store::tokens::RefreshRecord,
  /// Storage identity the raw token resolved to.
  pub hash: String,
  /// Pepper label (`v<N>`) that produced the match.
  pub key_label: String,
}

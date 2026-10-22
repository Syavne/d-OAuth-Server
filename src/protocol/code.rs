//! Authorization-code issuance and success redirect (RFC 9700 §4.5.3, RFC 9207).
//!
//! The consent stage (task 26) hands an approved post-entitlement scope set to
//! [`CodeIssuer::issue`], which mints a 256-bit code via
//! [`crypto::tokens::mint_token`](crate::crypto::tokens::mint_token), persists
//! only its versioned keyed hash through [`store::codes`](crate::store::codes)
//! with a TTL capped at [`CODE_TTL_CAP`], and returns the success redirect
//! carrying `code`, `state`, and `iss` (RFC 9207). No tokens appear in the
//! redirect; the raw code never touches storage or logs.
//!
//! Field mapping onto the task-12 [`CodeRecord`](crate::store::codes::CodeRecord):
//! `user_id` → `subject`, `dpop_jkt` → `cnf` (REQUIRED for public clients;
//! empty only for unconstrained confidential grants), `method` is invariantly
//! `S256` (non-S256 challenges are rejected before issuance, so no column is
//! needed). GAP (filed in `.omo/evidence/task-27-rust-oauth21-server.md`):
//! `CodeRecord` has no `auth_time`/`iss` columns, so those values are echoed
//! (`iss` in the redirect) but not persisted; extending the record is owned by
//! task 12 once it is free, and the redemption handler (task 31) must source
//! `auth_time` from the session/pending record until then.

use std::{fmt, time::Duration};

use secrecy::ExposeSecret;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
  config::TtlConfig,
  crypto::{pkce::CHALLENGE_LEN, tokens as crypto_tokens},
  error::AppError,
  keys::KeyRing,
  protocol::scope::ScopeSet,
  state::RedisConn,
  store::{Store, StoreError, codes},
};

/// Hard ceiling on the authorization-code lifetime (plan: TTL 60 s).
pub const CODE_TTL_CAP: Duration = Duration::from_secs(60);

/// Whether the code is issued to a public or a confidential client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeClientKind {
  /// No client secret: a verified DPoP `jkt` is mandatory only when the
  /// client is DPoP-bound; unbound public clients use Bearer.
  Public,
  /// Authenticated client: the DPoP `jkt` is recorded when proven.
  Confidential,
}

/// Inputs for one code issuance (all values already validated upstream).
#[derive(Debug, Clone, Copy)]
pub struct CodeIssueRequest<'a> {
  /// Client the code is issued to (exact match at redemption).
  pub client_id: &'a str,
  /// Public or confidential: selects the DPoP matrix.
  pub client_kind: CodeClientKind,
  /// Whether a public client must present a DPoP proof: mirrors the
  /// client's `dpop_bound_access_tokens` registration (unbound public
  /// clients are issued bearer-capable codes). Ignored for confidential.
  pub dpop_required: bool,
  /// Resource-owner subject the code is authorized for.
  pub user_id: &'a str,
  /// Redirect URI the code is bound to.
  pub redirect_uri: &'a str,
  /// Post-entitlement set approved at consent (never the raw request).
  pub approved_scope: &'a ScopeSet,
  /// Scopes the user is entitled to; approval must be a subset.
  pub user_entitled: &'a ScopeSet,
  /// S256 `code_challenge` the later code grant is bound to.
  pub code_challenge: &'a str,
  /// Verified DPoP key thumbprint; REQUIRED for public clients.
  pub dpop_jkt: Option<&'a str>,
  /// `state` value to echo in the success redirect, if supplied.
  pub state: Option<&'a str>,
  /// Validated resource audiences (RFC 8707) pinned from the pending
  /// request; empty when the authorize request was unbound.
  pub aud: &'a [String],
  /// Server issuer echoed as the RFC 9207 `iss` parameter.
  pub issuer: &'a str,
}

/// A freshly issued code: the raw code (return once) plus its redirect.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCode {
  /// Raw 256-bit code (base64url, never stored or logged).
  pub code: String,
  /// Success redirect: `{redirect_uri}?code=…&state=…&iss=…` (302 target).
  pub location: String,
  /// Storage identity: the versioned keyed hash under which the record sits.
  pub code_hash: String,
  /// Grant chain the code opens.
  pub grant_id: String,
  /// Code lifetime (capped at [`CODE_TTL_CAP`]).
  pub expires_in: Duration,
}

impl fmt::Debug for IssuedCode {
  /// Redacted [`fmt::Debug`]: the raw code never reaches logs or errors.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("IssuedCode")
      .field("code", &"[redacted]")
      .field("location", &"[redacted]")
      .field("code_hash", &self.code_hash)
      .field("grant_id", &self.grant_id)
      .field("expires_in", &self.expires_in)
      .finish()
  }
}

/// Fail-closed code-issuance failures.
#[derive(Debug, thiserror::Error)]
pub enum CodeIssueError {
  /// A public client tried to issue without a DPoP binding.
  #[error("public clients require a DPoP-bound code")]
  MissingDpopBinding,
  /// The approved scope exceeds the user's entitlement.
  #[error("approved scope exceeds user entitlement")]
  UnentitledScope,
  /// The `code_challenge` is malformed (S256 shape required).
  #[error("malformed code_challenge")]
  BadChallenge,
  /// No token pepper is configured.
  #[error("no token pepper configured")]
  NoPepper,
  /// The operating-system RNG failed.
  #[error("code randomness unavailable")]
  Randomness(#[from] crypto_tokens::TokenError),
  /// A store operation failed.
  #[error("code store failure")]
  Store(#[from] StoreError),
}

impl From<CodeIssueError> for AppError {
  /// Map issuance failures onto the RFC error model: caller faults become
  /// `invalid_grant`/`invalid_scope`/`invalid_request`; store failures reuse
  /// the store mapping (fail closed); the rest is masked as `server_error`.
  fn from(error: CodeIssueError) -> Self {
    match error {
      CodeIssueError::MissingDpopBinding => {
        Self::invalid_grant("public clients require a DPoP-bound code")
      }
      CodeIssueError::UnentitledScope => {
        Self::invalid_scope("approved scope exceeds user entitlement")
      }
      CodeIssueError::BadChallenge => Self::invalid_request("malformed code_challenge"),
      CodeIssueError::Store(inner) => Self::from(inner),
      other => Self::internal(other),
    }
  }
}

/// One retained pepper generation, newest-first.
///
/// The raw pepper never reaches `Debug`: only the generation, label, and
/// material length are printed (the [`KeyRing`] ids-only pattern).
#[derive(Clone)]
struct PepperKey {
  /// Verbatim generation for [`crypto_tokens::token_hash`].
  generation: crypto_tokens::KeyId,
  /// String label (`v<N>`) for audit.
  label: String,
  /// Raw pepper bytes, wiped on drop.
  secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PepperKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("PepperKey")
      .field("generation", &self.generation)
      .field("label", &self.label)
      .field("secret", &"[REDACTED]")
      .field("secret_len", &self.secret.len())
      .finish()
  }
}

/// Authorization-code minting plus hash-at-rest persistence.
///
/// `Debug` prints the lifetime plus the retained pepper ids and material
/// lengths only, never raw pepper bytes.
#[derive(Clone)]
pub struct CodeIssuer {
  /// Code lifetime, capped at [`CODE_TTL_CAP`] at construction.
  ttl: Duration,
  /// Retained peppers, newest-first, bounded by
  /// [`crypto_tokens::MAX_RETAINED_KEYS`].
  keys: Vec<PepperKey>,
}

impl fmt::Debug for CodeIssuer {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let key_labels: Vec<&str> = self.keys.iter().map(|key| key.label.as_str()).collect();
    let secret_lens: Vec<usize> = self.keys.iter().map(|key| key.secret.len()).collect();
    f.debug_struct("CodeIssuer")
      .field("ttl", &self.ttl)
      .field("key_labels", &key_labels)
      .field("secret", &"[REDACTED]")
      .field("secret_lens", &secret_lens)
      .finish()
  }
}

impl CodeIssuer {
  /// Build an issuer from the validated TTLs and key ring.
  ///
  /// # Errors
  ///
  /// Returns [`CodeIssueError::NoPepper`] when the ring holds no pepper.
  pub fn new(ttl: &TtlConfig, ring: &KeyRing) -> Result<Self, CodeIssueError> {
    let mut keys = Vec::new();
    for (id, secret) in ring
      .peppers_newest_first()
      .take(crypto_tokens::MAX_RETAINED_KEYS)
    {
      keys.push(PepperKey {
        generation: crypto_tokens::KeyId::new(id.as_str()),
        label: id.as_str().to_owned(),
        secret: Zeroizing::new(secret.expose_secret().as_bytes().to_vec()),
      });
    }
    if keys.is_empty() {
      return Err(CodeIssueError::NoPepper);
    }
    Ok(Self {
      ttl: ttl.code.min(CODE_TTL_CAP),
      keys,
    })
  }

  /// The code lifetime this issuer stores under.
  #[must_use]
  pub const fn ttl(&self) -> Duration {
    self.ttl
  }

  /// Mint a code, persist only its keyed hash, build the success redirect.
  ///
  /// # Errors
  ///
  /// Returns [`CodeIssueError::BadChallenge`] for a malformed challenge,
  /// [`CodeIssueError::UnentitledScope`] when approval exceeds entitlement,
  /// [`CodeIssueError::MissingDpopBinding`] for a public client without a
  /// `jkt`, or the crypto/store failure.
  pub async fn issue(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    request: &CodeIssueRequest<'_>,
  ) -> Result<IssuedCode, CodeIssueError> {
    check_challenge_shape(request.code_challenge)?;
    if !request.approved_scope.is_subset_of(request.user_entitled) {
      return Err(CodeIssueError::UnentitledScope);
    }
    let cnf = resolve_cnf(request.client_kind, request.dpop_jkt, request.dpop_required)?;
    let raw = crypto_tokens::mint_token()?;
    let active = self.keys.first().ok_or(CodeIssueError::NoPepper)?;
    let code_hash = crypto_tokens::token_hash(&active.generation, active.secret.as_slice(), &raw)
      .to_storage_string();
    let grant_id = Uuid::new_v4().to_string();
    let record = codes::CodeRecord {
      client_id: request.client_id.to_owned(),
      redirect_uri: request.redirect_uri.to_owned(),
      scope: request.approved_scope.render(),
      code_challenge: request.code_challenge.to_owned(),
      subject: request.user_id.to_owned(),
      grant_id: grant_id.clone(),
      cnf,
      aud: request.aud.to_vec(),
    };
    codes::issue(conn, store, &code_hash, &record, self.ttl).await?;
    let location = success_redirect(request.redirect_uri, &raw, request.state, request.issuer);
    Ok(IssuedCode {
      code: raw,
      location,
      code_hash,
      grant_id,
      expires_in: self.ttl,
    })
  }
}

/// Apply the DPoP matrix: DPoP-bound public clients REQUIRE a `jkt`;
/// unbound public clients are issued bearer-capable codes (an empty `cnf`);
/// confidential clients record the `jkt` when proven, else stay unconstrained.
fn resolve_cnf(
  kind: CodeClientKind,
  jkt: Option<&str>,
  dpop_required: bool,
) -> Result<String, CodeIssueError> {
  let bound = jkt.filter(|value| !value.is_empty());
  match kind {
    CodeClientKind::Public if dpop_required => bound
      .map(str::to_owned)
      .ok_or(CodeIssueError::MissingDpopBinding),
    CodeClientKind::Public => Ok(bound.unwrap_or_default().to_owned()),
    CodeClientKind::Confidential => Ok(bound.unwrap_or_default().to_owned()),
  }
}

/// Check the S256 challenge shape (43 base64url characters, no verifier yet).
fn check_challenge_shape(challenge: &str) -> Result<(), CodeIssueError> {
  let well_formed = challenge.len() == CHALLENGE_LEN
    && challenge
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
  if well_formed {
    Ok(())
  } else {
    Err(CodeIssueError::BadChallenge)
  }
}

/// Build the success redirect: `code` + optional `state` + RFC 9207 `iss`.
fn success_redirect(redirect_uri: &str, code: &str, state: Option<&str>, issuer: &str) -> String {
  let separator = if redirect_uri.contains('?') { '&' } else { '?' };
  let mut location = String::with_capacity(redirect_uri.len() + code.len() + 160);
  location.push_str(redirect_uri);
  location.push(separator);
  location.push_str("code=");
  push_percent_encoded(&mut location, code);
  if let Some(state) = state {
    location.push_str("&state=");
    push_percent_encoded(&mut location, state);
  }
  location.push_str("&iss=");
  push_percent_encoded(&mut location, issuer);
  location
}

/// Append `text` percent-encoded (unreserved characters pass through).
fn push_percent_encoded(out: &mut String, text: &str) {
  const HEX: &[u8; 16] = b"0123456789ABCDEF";
  for byte in text.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(byte as char);
    } else {
      out.push('%');
      out.push(HEX[usize::from(byte >> 4)] as char);
      out.push(HEX[usize::from(byte & 0x0F)] as char);
    }
  }
}

#[cfg(test)]
mod tests;

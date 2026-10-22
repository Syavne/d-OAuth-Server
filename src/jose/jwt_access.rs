//! JWT access tokens: a profile subset of RFC 9068 minted by this AS.
//!
//! The AS signs access tokens with the configured [`JwtSigningKey`] (current
//! key signs, `jwt_signing_previous_keys` verify only) when the
//! `jwt_access_tokens_enabled` kill-switch is on. JOSE header carries `kid`
//! plus `typ: "at+jwt"` (RFC 9068 §2.1, §4); claims carry `iss`/`sub`/`aud`/
//! `scope`/`exp`/`iat`/`jti`/`client_id` (`client_id` is REQUIRED, §2.2),
//! optional `cnf` (§2.2) and optional `act` (RFC 8693 §4.1, carried only when
//! an exchange delegated authority).
//!
//! This is a profile subset, not full RFC 9068 conformance: no claim beyond
//! the set above is emitted or required, and resource-server validation
//! beyond `aud` containment is out of scope.
//!
//! Verification is fail-closed: the header `alg` must equal the configured
//! algorithm (never trusted from the token), `typ` must be exactly `at+jwt`,
//! `kid` must name the current or a previous key, and `iss`/`exp`/`aud` are
//! enforced with zero clock-skew leeway (matching `jar::verify`). A token is
//! additionally live only while its `jwt:<jti-hash>` allowlist marker exists
//! and its subject account is not disabled.
//!
//! Key material never appears in [`fmt::Debug`], [`JwtError`], or logs.

#[cfg(test)]
mod tests;

use std::fmt;

use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
  config::{Config, JwtPublicJwk, JwtSigningAlg, JwtSigningKey},
  db::user_repo::{SubjectAccountStatus, subject_account_status},
  keys::{KeyId, KeyRing},
  protocol::token::Cnf,
  state::RedisConn,
  store::{self, Store},
};

/// Required JOSE header `typ` for AS-minted access tokens (RFC 9068 §2.1).
pub const JWT_TYP: &str = "at+jwt";

/// `exp`/`iat` clock-skew leeway in seconds. Zero: strict expiry, matching
/// `jar::verify`; the access-token TTL is short, so no grace is granted.
const LEEWAY_SECS: u64 = 0;

/// Access-token claims: the RFC 9068 §2.2 profile subset this AS emits.
///
/// `scope` is the space-joined granted scope; `aud` is always an array (this
/// AS never emits the string form). `sub` is empty for client-credentials
/// tokens. `client_id` is REQUIRED (§2.2): a token without it is malformed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
  /// Token issuer: the AS `issuer`.
  pub iss: String,
  /// Token subject: the user email/user-id, or empty for client-credentials.
  pub sub: String,
  /// Intended audiences (RFC 8707 resource indicators at mint).
  pub aud: Vec<String>,
  /// Space-joined granted scope.
  pub scope: String,
  /// Expiry, seconds since the Unix epoch.
  pub exp: i64,
  /// Issued-at, seconds since the Unix epoch.
  pub iat: i64,
  /// Unique token id (allowlist marker key material, hashed at rest).
  pub jti: String,
  /// The client the token was issued to (REQUIRED, RFC 9068 §2.2).
  pub client_id: String,
  /// Sender-constraint confirmation, absent for unbound bearer tokens.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cnf: Option<Cnf>,
  /// Delegation actor (RFC 8693 §4.1), present only on exchanged tokens.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub act: Option<ActClaim>,
}

/// The `act` (actor) claim on an exchanged access token (RFC 8693 §4.1).
///
/// `sub` names the party the token acts as. The exchange grant stores the
/// same shape as a sidecar; the JWT carries it inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
  /// The subject token's client: the impersonated/delegated party.
  pub sub: String,
}

impl fmt::Debug for JwtClaims {
  /// Locked [`fmt::Debug`]: the raw `sub` (PII) and `jti` (allowlist key
  /// material) are redacted; the remaining members are public identifiers.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("JwtClaims")
      .field("iss", &self.iss)
      .field("sub", &"[REDACTED]")
      .field("aud", &self.aud)
      .field("scope", &self.scope)
      .field("exp", &self.exp)
      .field("iat", &self.iat)
      .field("jti", &"[REDACTED]")
      .field("client_id", &self.client_id)
      .field("cnf", &self.cnf)
      .field("act", &self.act)
      .finish()
  }
}

/// A verified access token: signature, claims, marker, and account checks all
/// passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwt {
  /// The verified claim set.
  pub claims: JwtClaims,
}

/// Typed access-token verification failures. Variants carry no token, key, or
/// claim bytes: only the failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JwtError {
  /// JOSE header `typ` is not `at+jwt`.
  #[error("access token has an unexpected JOSE header type")]
  WrongTyp,
  /// JOSE header `alg` is not the configured algorithm.
  #[error("access token uses an unexpected JOSE algorithm")]
  WrongAlg,
  /// JOSE header `kid` names no current or previous key.
  #[error("access token key id is unknown")]
  UnknownKid,
  /// The signature does not verify under the selected key.
  #[error("access token signature is invalid")]
  Signature,
  /// `exp` is in the past (zero leeway).
  #[error("access token is expired")]
  Expired,
  /// `iss` does not equal the configured issuer.
  #[error("access token issuer is unexpected")]
  WrongIssuer,
  /// `aud` lacks a required audience value.
  #[error("access token audience is insufficient")]
  WrongAudience,
  /// The token is not a well-formed JWT for this claim shape.
  #[error("access token is malformed")]
  Malformed,
  /// The `jwt:<jti-hash>` allowlist marker is absent (revoked or purged).
  #[error("access token allowlist marker is absent")]
  MarkerAbsent,
  /// The subject maps to a disabled account.
  #[error("access token subject is disabled")]
  SubjectDisabled,
  /// No JWT signing key is configured.
  #[error("no JWT signing key is configured")]
  NoSigningKey,
  /// Signing a token failed (keys are validated at load; unreachable).
  #[error("access token signing failed")]
  Encode,
  /// Redis or Postgres was unavailable; the token stays unusable.
  #[error("token verification backend is unavailable")]
  Backend,
}

/// The AS access-token signer: the current signing key plus verify-only
/// previous keys selected by header `kid`.
///
/// `Debug` prints `kid`/`alg`/public coordinates only; key material is
/// redacted by [`JwtSigningKey`]'s own `Debug`.
#[derive(Clone)]
pub struct JwtAccessSigner {
  issuer: String,
  alg: JwtSigningAlg,
  current: JwtSigningKey,
  previous: Vec<JwtSigningKey>,
}

impl JwtAccessSigner {
  /// Build the signer from the validated [`Config`]: the active
  /// `jwt_signing_key` signs, every `jwt_signing_previous_keys` entry verifies
  /// only. All keys share the configured `jwt_access_token_signing_alg`.
  ///
  /// # Errors
  ///
  /// Returns [`JwtError::NoSigningKey`] when no active key is configured.
  pub fn from_config(config: &Config) -> Result<Self, JwtError> {
    let current = config
      .jwt_signing_key
      .clone()
      .ok_or(JwtError::NoSigningKey)?;
    Ok(Self::new(
      config.issuer.clone(),
      current,
      config.jwt_signing_previous_keys.clone(),
    ))
  }

  /// Build a signer from parts: `issuer` the tokens assert, `current` the
  /// signing key, `previous` the verify-only rotated-out keys.
  #[must_use]
  pub fn new(issuer: String, current: JwtSigningKey, previous: Vec<JwtSigningKey>) -> Self {
    let alg = current.alg();
    Self {
      issuer,
      alg,
      current,
      previous,
    }
  }

  /// The algorithm this signer mints and verifies under.
  #[must_use]
  pub fn algorithm(&self) -> Algorithm {
    self.alg.algorithm()
  }

  /// The issuer minted tokens assert (RFC 9068 §2.2 `iss`).
  #[must_use]
  pub fn issuer(&self) -> &str {
    &self.issuer
  }

  /// The current key first, then every retained verify-only key, each with
  /// its `kid`, algorithm, and public JWK coordinates (RFC 7517 §4/§5).
  /// Ordering is the configured order and therefore deterministic.
  pub fn public_keys(&self) -> impl Iterator<Item = (&KeyId, JwtSigningAlg, &JwtPublicJwk)> {
    std::iter::once((
      self.current.kid(),
      self.current.alg(),
      self.current.public_jwk(),
    ))
    .chain(
      self
        .previous
        .iter()
        .map(|key| (key.kid(), key.alg(), key.public_jwk())),
    )
  }

  /// Mint an access token: JOSE header `kid` + `typ: "at+jwt"` + the
  /// configured `alg` (never `none`, never HS, never caller-chosen).
  ///
  /// # Errors
  ///
  /// Returns [`JwtError::Encode`] when JOSE encoding fails.
  pub fn sign(&self, claims: &JwtClaims) -> Result<String, JwtError> {
    let mut header = Header::new(self.algorithm());
    header.kid = Some(self.current.kid().as_str().to_owned());
    header.typ = Some(JWT_TYP.to_owned());
    encode(&header, claims, self.current.encoding_key()).map_err(|_| JwtError::Encode)
  }

  /// Verify signature and claims without touching Redis or Postgres.
  ///
  /// Checks, in order: `typ == "at+jwt"`, `alg` equals the configured
  /// algorithm, `kid` selects the current or a previous key (unknown `kid`
  /// fails with no fallback), signature, `iss`, `exp` (zero leeway), then
  /// `aud` containment: when `expected_aud` is non-empty every expected value
  /// must appear in the token `aud` (the same containment semantics the
  /// audience-binding grants use). An empty `expected_aud` skips the check.
  ///
  /// Marker and account liveness are NOT checked here; use [`Self::verify_live`].
  ///
  /// # Errors
  ///
  /// Returns the matching [`JwtError`] class for the first failing check.
  pub fn verify(
    &self,
    token: &str,
    expected_aud: Option<&[String]>,
  ) -> Result<VerifiedJwt, JwtError> {
    let header = decode_header(token).map_err(|_| JwtError::Malformed)?;
    if header.typ.as_deref() != Some(JWT_TYP) {
      return Err(JwtError::WrongTyp);
    }
    if header.alg != self.algorithm() {
      return Err(JwtError::WrongAlg);
    }
    let kid = header.kid.as_deref().ok_or(JwtError::UnknownKid)?;
    let key = self
      .current
      .kid()
      .as_str()
      .eq(kid)
      .then_some(&self.current)
      .or_else(|| {
        self
          .previous
          .iter()
          .find(|candidate| candidate.kid().as_str() == kid)
      })
      .ok_or(JwtError::UnknownKid)?;
    let mut validation = Validation::new(self.algorithm());
    validation.set_issuer(&[self.issuer.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation.leeway = LEEWAY_SECS;
    validation.validate_exp = true;
    // The library audience gate stays off: `aud` containment against the
    // caller-supplied expected set is enforced manually below, so an empty
    // `expected_aud` skips the check instead of failing it.
    validation.validate_aud = false;
    let claims = decode::<JwtClaims>(token, key.decoding_key(), &validation)
      .map_err(|error| {
        use jsonwebtoken::errors::ErrorKind as Kind;
        match error.kind() {
          Kind::ExpiredSignature => JwtError::Expired,
          Kind::InvalidIssuer => JwtError::WrongIssuer,
          Kind::InvalidSignature => JwtError::Signature,
          Kind::InvalidAlgorithm => JwtError::WrongAlg,
          _ => JwtError::Malformed,
        }
      })?
      .claims;
    if let Some(expected) = expected_aud {
      let missing = expected
        .iter()
        .any(|value| !claims.aud.iter().any(|got| got == value));
      if missing {
        return Err(JwtError::WrongAudience);
      }
    }
    Ok(VerifiedJwt { claims })
  }

  /// Full liveness verification: [`Self::verify`] plus the strict allowlist
  /// marker (marker + grant membership, [`marker_live_strict`]) and the
  /// disabled-subject re-check (same `subject_account_status` call
  /// introspection uses).
  ///
  /// # Errors
  ///
  /// Returns [`JwtError::MarkerAbsent`] when the `jwt:<jti-hash>` marker hash
  /// does not exist, [`JwtError::SubjectDisabled`] when `sub` maps to a
  /// disabled account, [`JwtError::Backend`] on a Redis/Postgres outage, or
  /// the [`Self::verify`] class for a signature/claim failure.
  pub async fn verify_live(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    pool: &sqlx::PgPool,
    keys: &KeyRing,
    token: &str,
    expected_aud: Option<&[String]>,
  ) -> Result<VerifiedJwt, JwtError> {
    let verified = self.verify(token, expected_aud)?;
    if !marker_live_strict(conn, store, &jti_hash(&verified.claims.jti)).await? {
      return Err(JwtError::MarkerAbsent);
    }
    if !subject_active(pool, keys, &verified.claims.sub).await? {
      return Err(JwtError::SubjectDisabled);
    }
    Ok(verified)
  }
}

impl fmt::Debug for JwtAccessSigner {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("JwtAccessSigner")
      .field("issuer", &self.issuer)
      .field("alg", &self.alg)
      .field("current_kid", &self.current.kid())
      .field("current_public", self.current.public_jwk())
      .field(
        "previous",
        &self
          .previous
          .iter()
          .map(|key| (key.kid(), key.public_jwk()))
          .collect::<Vec<_>>(),
      )
      .finish()
  }
}

/// Whether the presented token has JWT shape: three non-empty dot-separated
/// base64url segments (`<b64url>.<b64url>.<b64url>`).
///
/// Opaque tokens are fixed-length base64url-no-pad with no dots (see the
/// `is_well_formed_token` gate in [`crate::protocol::token::TokenService`],
/// which rejects any dotted value before hashing or Redis work), so the dot
/// test discriminates the two families without consulting the store. Shape
/// alone never authorizes anything: both the revocation and the introspection
/// JWT paths still verify signature plus `iss` and enforce ownership before
/// acting.
#[must_use]
pub fn is_jwt_shape(token: &str) -> bool {
  let mut segments = token.split('.');
  let shaped = matches!(
    (segments.next(), segments.next(), segments.next(), segments.next()),
    (Some(first), Some(second), Some(third), None)
      if !first.is_empty() && !second.is_empty() && !third.is_empty()
  );
  shaped
    && token
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Hash a `jti` for its allowlist marker key: the store's existing SHA-256
/// helper, the same convention `dpop`/`client_auth` use for `jti` replay
/// markers. Never the raw `jti`.
#[must_use]
pub fn jti_hash(jti: &str) -> String {
  store::sha256_hex(jti.as_bytes())
}

/// Whether the `jwt:<jti-hash>` allowlist marker hash exists. Absent means
/// revoked, expired, or purged (`user disable`): the token is unusable.
///
/// # Errors
///
/// Returns [`JwtError::Backend`] when Redis is unavailable (fail closed).
pub async fn marker_live(
  conn: &mut RedisConn,
  store: &Store,
  jti_hash: &str,
) -> Result<bool, JwtError> {
  let key = store.jwt_marker_key(jti_hash);
  let present: bool = redis::cmd("EXISTS")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(|_| JwtError::Backend)?;
  Ok(present)
}

/// Whether the `jwt:<jti-hash>` marker is bound to a live grant member.
///
/// Strict allowlist liveness (Todo 26 race rule, RFC 9068 §4): the marker
/// hash must exist AND the `jwt:<jti-hash>` member must still sit in the
/// grant's token set named by the marker's own `grant_id` field. The atomic
/// mint writes marker and membership in one script, so a fresh mint is
/// strictly live; a marker written late (after a cascade revoke wiped the
/// set, or after `discard_orphan` removed the member) reports inactive even
/// though the marker hash itself exists. The marker-only [`marker_live`]
/// stays untouched for the Todo 24 callers; Todo 27 (cascade marker purge)
/// and Todo 29 (introspection) consume this bound check.
///
/// # Errors
///
/// Returns [`JwtError::Backend`] when Redis is unavailable (fail closed: a
/// missing marker or membership reports `Ok(false)`, never an error).
pub async fn marker_live_strict(
  conn: &mut RedisConn,
  store: &Store,
  jti_hash: &str,
) -> Result<bool, JwtError> {
  let key = store.jwt_marker_key(jti_hash);
  let flat: Vec<String> = redis::cmd("HGETALL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(|_| JwtError::Backend)?;
  if flat.is_empty() {
    return Ok(false);
  }
  let mut grant_id = "";
  let mut fields = flat.as_slice();
  while let [field, value, rest @ ..] = fields {
    if field == "grant_id" {
      grant_id = value;
    }
    fields = rest;
  }
  if grant_id.is_empty() {
    return Ok(false);
  }
  let member = format!("jwt:{jti_hash}");
  let bound: bool = redis::cmd("SISMEMBER")
    .arg(store.grant_tokens_key(grant_id))
    .arg(&member)
    .query_async(conn)
    .await
    .map_err(|_| JwtError::Backend)?;
  Ok(bound)
}

/// Whether the token subject is live: an empty subject (client-credentials)
/// and unmapped subjects stay live; a subject mapping to a disabled account
/// does not. Same `subject_account_status` call introspection uses.
///
/// # Errors
///
/// Returns [`JwtError::Backend`] on a database failure (fail closed: the
/// caller must treat the token as unusable, never as active).
pub async fn subject_active(
  pool: &sqlx::PgPool,
  keys: &KeyRing,
  subject: &str,
) -> Result<bool, JwtError> {
  if subject.trim().is_empty() {
    return Ok(true);
  }
  match subject_account_status(pool, keys, subject)
    .await
    .map_err(|_| JwtError::Backend)?
  {
    SubjectAccountStatus::Disabled => Ok(false),
    SubjectAccountStatus::Enabled | SubjectAccountStatus::Unmapped => Ok(true),
  }
}

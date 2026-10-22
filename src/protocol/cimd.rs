//! Client ID Metadata Documents (CIMD) — fetch, validate, and cache.
//!
//! A registration-free client identifies itself with an `https://` URL as its
//! `client_id`; the authorization server fetches that URL and validates the
//! returned JSON document before treating it as client metadata. This module
//! owns the fetch and the strict validation rules; the request-path wiring
//! (authorize/token/client auth) lives in the callers.
//!
//! Strict rules (CIMD draft §4.1/§5/§8.6/§8.7):
//!
//! - The document URL is fetched through the single guarded fetcher
//!   [`ssrf::fetch_guarded_bytes_with`]: `https` only, no redirects, special-
//!   use/private/loopback targets rejected, the configured timeout, and the
//!   configured byte cap.
//! - The response MUST be a JSON object whose `client_id` is byte-for-byte the
//!   fetched URL.
//! - `token_endpoint_auth_method` MUST be `none` (the default when absent) or
//!   `private_key_jwt`. Every shared-secret and mTLS method is rejected
//!   (CIMD §4.1: metadata documents describe clients that cannot hold a
//!   shared secret).
//! - `private_key_jwt` REQUIRES an INLINE `jwks` object with a non-empty
//!   `keys` array. A document that supplies only `jwks_uri` is rejected: the
//!   decision here is inline-only so client authentication never triggers a
//!   second network fetch on the token path.
//! - `redirect_uris` MUST be a non-empty array. Every URI must be `https`, or
//!   plaintext `http` to an RFC 8252 §7.3 loopback host (`127.0.0.1`, `[::1]`,
//!   and `localhost` only while `allow_localhost` is set). The checks delegate
//!   to [`redirect_repo::match_redirect_uri`] so CIMD and registered clients
//!   share exactly one loopback rule. Wildcards are never accepted.
//! - `scope` MUST be a subset of the enabled catalog and `grant_types` a
//!   subset of `{authorization_code, refresh_token}`.
//!
//! A validated document is cached for 15 minutes under `{state}` as
//! `cimd:<sha256(url)>`. The cache stores the raw document; it is revalidated
//! on every read so a scope disabled during the TTL takes effect immediately.
//!
//! This module never writes an `/register` row and never consumes an initial
//! access token; it only resolves metadata.

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_principal;

use std::{collections::HashSet, sync::LazyLock, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
  db::{client_repo, scope_repo},
  error::AppError,
  keys::KeyRing,
  protocol::{
    redirect_repo::{self, RedirectDecision},
    ssrf,
  },
  state::RedisConn,
  store::{StoreError, sha256_hex},
};

/// How long a validated CIMD document stays cached (seconds).
const CACHE_TTL_SECS: u64 = 15 * 60;

/// How long a fetch failure stays negatively cached (seconds).
const NEG_CACHE_TTL_SECS: u64 = 30;

/// How long a fresh-fetch validation failure stays short-cached (seconds).
/// This is a single-flight completion marker: it stops every waiter from
/// re-fetching a deterministically invalid document, while a corrected
/// document is seen within this short window.
const INVALID_CACHE_TTL_SECS: u64 = 2;

/// Extra lifetime on the single-flight lock beyond the fetch budget: the
/// elected fetcher finishes its bounded fetch and cache write inside this.
const LOCK_TTL_MARGIN: Duration = Duration::from_secs(1);

/// Extra wait beyond the fetch budget before a waiter tries to acquire the
/// lock itself: longer than [`LOCK_TTL_MARGIN`] so an abandoned lock expires.
const LOCK_WAIT_MARGIN: Duration = Duration::from_millis(1_500);

/// Waiter poll interval for the positive and negative cache.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Grant types a CIMD client may declare (CIMD §4.1; no device or
/// client-credentials grants in a registration-free document).
const ALLOWED_GRANTS: [&str; 2] = ["authorization_code", "refresh_token"];

/// A CIMD document as returned by the `client_id` URL.
///
/// Unknown members are ignored, so a document may carry additional metadata
/// (logos, contacts, policy URIs) without failing validation. Only the members
/// the server acts on are modeled here.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CimdDocument {
  /// The client identifier; MUST equal the fetched URL.
  pub client_id: String,
  /// Registered redirect URIs.
  pub redirect_uris: Vec<String>,
  /// Token-endpoint authentication method (`none` when absent).
  #[serde(default)]
  pub token_endpoint_auth_method: Option<String>,
  /// Requested grant types (default `["authorization_code"]`).
  #[serde(default)]
  pub grant_types: Option<Vec<String>>,
  /// Space-delimited scope bound for the client.
  #[serde(default)]
  pub scope: Option<String>,
  /// Inline JWKS (required for `private_key_jwt`).
  #[serde(default)]
  pub jwks: Option<serde_json::Value>,
  /// Remote JWKS URI. Rejected: inline-only by decision (no second fetch).
  #[serde(default)]
  pub jwks_uri: Option<String>,
  /// Human-readable client name.
  #[serde(default)]
  pub client_name: Option<String>,
  /// Whether the client opts into DPoP-bound access tokens.
  #[serde(default)]
  pub dpop_bound_access_tokens: Option<bool>,
}

/// Client authentication method accepted from a CIMD document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CimdAuthMethod {
  /// Public client (the registration-free default).
  None,
  /// `private_key_jwt` with an inline JWKS.
  PrivateKeyJwt,
}

impl CimdAuthMethod {
  /// The wire value stored in the synthetic client's
  /// `token_endpoint_auth_method`.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::None => "none",
      Self::PrivateKeyJwt => "private_key_jwt",
    }
  }
}

/// The validated subset of a CIMD document, ready for request handling.
#[derive(Debug, Clone)]
pub struct ValidatedCimd {
  /// The client identifier (equals the fetched URL).
  pub client_id: String,
  /// Redirect URIs declared by the document.
  pub redirect_uris: Vec<String>,
  /// Accepted client authentication method.
  pub token_endpoint_auth_method: CimdAuthMethod,
  /// Deduplicated grant types.
  pub grant_types: Vec<String>,
  /// Space-joined scope, already checked against the enabled catalog.
  pub scope: String,
  /// Inline JWKS for `private_key_jwt`, if any.
  pub jwks: Option<serde_json::Value>,
  /// Human-readable client name.
  pub client_name: Option<String>,
  /// Whether the client opts into DPoP-bound access tokens.
  pub dpop_bound_access_tokens: bool,
}

impl ValidatedCimd {
  /// Materialize the registration-free principal as a synthetic
  /// [`client_repo::Client`] so every existing code path works unchanged.
  ///
  /// Field mapping: `client_id` is the document URL; the auth method, grant
  /// allowlist, scope bound, DPoP flag, and inline `jwks` come from the
  /// validated document; secrets, mTLS pins, `jwks_uri`, pre-registered
  /// `request_uris`, contacts, and PII are empty; `access_token_format` is
  /// always `opaque` (a document can never opt into JWT); the row is active
  /// with fresh timestamps and a random surrogate id. No row is written: the
  /// value is in-memory only, and the next resolution revalidates the cached
  /// document, so a scope or catalog change takes effect immediately.
  #[must_use]
  pub fn to_client(&self) -> client_repo::Client {
    let now = time::OffsetDateTime::now_utc();
    client_repo::Client {
      id: uuid::Uuid::new_v4(),
      client_id: self.client_id.clone(),
      client_secret_expires_at: None,
      client_id_issued_at: now,
      client_name: self
        .client_name
        .clone()
        .unwrap_or_else(|| self.client_id.clone()),
      grant_types: self.grant_types.clone(),
      response_types: vec!["code".to_owned()],
      scope: self.scope.clone(),
      token_endpoint_auth_method: self.token_endpoint_auth_method.as_str().to_owned(),
      jwks: self.jwks.clone(),
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: self.dpop_bound_access_tokens,
      access_token_format: "opaque".to_owned(),
      active: true,
      created_at: now,
      updated_at: now,
    }
  }
}

/// Per-fetch limits from the validated configuration.
#[derive(Debug, Clone, Copy)]
pub struct CimdLimits {
  /// Maximum accepted document size in bytes (`cimd_max_bytes`).
  pub max_bytes: usize,
  /// Total fetch budget (`cimd_fetch_timeout`).
  pub timeout: Duration,
}

/// Validation inputs resolved by the caller (keeps this module pure).
pub struct CimdValidation<'a> {
  /// Every enabled scope name (`scope_repo::list_enabled`).
  pub enabled_scopes: &'a HashSet<String>,
  /// Config `allow_localhost_redirect`: whether the host `localhost` joins
  /// the RFC 8252 §7.3 loopback exception.
  pub allow_localhost: bool,
}

/// Fail-closed CIMD failures.
///
/// Validation failures map to `invalid_client_metadata` (or
/// `invalid_redirect_uri` for a bad redirect set) via [`From<CimdError>`].
#[derive(Debug, thiserror::Error)]
pub enum CimdError {
  /// The guarded fetch failed (policy, DNS, status, timeout, or size cap).
  #[error("client metadata document fetch failed")]
  Fetch,
  /// The fetched body was not JSON or not the expected document shape.
  #[error("client metadata document is not valid JSON")]
  InvalidJson,
  /// The document `client_id` does not equal the fetched URL.
  #[error("client metadata document client_id does not match its URL")]
  ClientIdMismatch,
  /// `token_endpoint_auth_method` was absent-with-invalid-value or a
  /// shared-secret/mTLS method.
  #[error("unsupported token_endpoint_auth_method")]
  UnsupportedAuthMethod,
  /// `private_key_jwt` was declared without an inline JWKS.
  #[error("private_key_jwt requires an inline jwks")]
  JwksRequired,
  /// The document supplied `jwks_uri`; inline-only by decision.
  #[error("jwks_uri is not allowed in a client metadata document")]
  JwksUriNotAllowed,
  /// A redirect URI was missing, wildcarded, non-https, or non-loopback
  /// plaintext `http`.
  #[error("invalid redirect_uris")]
  InvalidRedirectUri,
  /// A grant type outside `{authorization_code, refresh_token}`.
  #[error("unsupported grant_type")]
  UnsupportedGrantType,
  /// A scope token is not in the enabled catalog.
  #[error("scope is not a subset of the enabled catalog")]
  UnknownScope,
  /// The cache or scope catalog could not be read (fail closed, `503`).
  #[error("client metadata backend failure")]
  Backend(#[source] AppError),
  /// The registered-row lookup failed. Pass-through: the inner error is
  /// returned unchanged so typed row failures (e.g. a corrupt sealed PII
  /// field surfacing as `PiiDecrypt`) are never flattened into a `503`.
  /// A database outage still surfaces as `temporarily_unavailable` through
  /// the existing `From<sqlx::Error> for AppError`.
  #[error("client row lookup failed")]
  Lookup(#[source] AppError),
}

impl From<CimdError> for AppError {
  /// Map a CIMD failure to a client-safe OAuth error. Bad redirects use
  /// `invalid_redirect_uri`; every other validation failure uses
  /// `invalid_client_metadata`; a dependency failure is a fail-closed `503`.
  /// No document contents or fetch internals are included.
  fn from(error: CimdError) -> Self {
    match error {
      CimdError::InvalidRedirectUri => {
        Self::invalid_redirect_uri("invalid redirect_uri in client metadata document")
      }
      CimdError::Backend(_) => Self::temporarily_unavailable(),
      CimdError::Lookup(inner) => inner,
      CimdError::Fetch
      | CimdError::InvalidJson
      | CimdError::ClientIdMismatch
      | CimdError::UnsupportedAuthMethod
      | CimdError::JwksRequired
      | CimdError::JwksUriNotAllowed
      | CimdError::UnsupportedGrantType
      | CimdError::UnknownScope => {
        Self::invalid_client_metadata("invalid client metadata document")
      }
    }
  }
}

/// The cache key for a validated document: `{state}`-prefixed
/// `cimd:<sha256(url)>`.
///
/// `token_prefix` is the configured token keyspace prefix (which carries the
/// `{state}` hash tag); the key therefore never lands in the `{rl}` keyspace.
#[must_use]
pub fn cache_key(token_prefix: &str, client_id_url: &str) -> String {
  format!(
    "{token_prefix}cimd:{}",
    sha256_hex(client_id_url.as_bytes())
  )
}

/// The negative cache key for origin-level fetch failures: `{state}`-prefixed
/// `cimd:neg:<sha256(url)>`, same prefix/hash conventions as [`cache_key`].
/// The raw URL is never stored.
#[must_use]
pub fn negative_cache_key(token_prefix: &str, client_id_url: &str) -> String {
  format!(
    "{token_prefix}cimd:neg:{}",
    sha256_hex(client_id_url.as_bytes())
  )
}

/// The short cache key for a fresh-fetch validation failure:
/// `{state}`-prefixed `cimd:invalid:<sha256(url)>`.
#[must_use]
pub fn invalid_cache_key(token_prefix: &str, client_id_url: &str) -> String {
  format!(
    "{token_prefix}cimd:invalid:{}",
    sha256_hex(client_id_url.as_bytes())
  )
}

/// Per-request CIMD resolution settings for a client-auth consumer.
///
/// `None` at a call site means CIMD is disabled there (`config.cimd_enabled`
/// is off): an `https://` `client_id` with no registered row keeps the
/// existing unknown-client behavior. `Some` enables the registered-row-wins
/// fallback for that consumer.
#[derive(Debug, Clone, Copy)]
pub struct CimdSettings<'a> {
  /// Token keyspace prefix carrying the `{state}` hash tag, for the
  /// `cimd:<sha256(url)>` document cache.
  pub token_prefix: &'a str,
  /// Maximum accepted document size (`config.cimd_max_bytes`).
  pub max_bytes: usize,
  /// Total fetch budget (`config.cimd_fetch_timeout`).
  pub timeout: Duration,
  /// Config `allow_localhost_redirect`: whether the host `localhost` joins
  /// the RFC 8252 §7.3 loopback exception.
  pub allow_localhost: bool,
}

/// The single client-principal resolution for every client-auth consumer
/// (token dispatch, `client_auth`, `/revoke`, `/introspect`, authorize/JAR,
/// PAR, device poll).
///
/// A registered row always wins: when `find_by_client_id_any_state` names a
/// row — including a row whose `client_id` happens to be an `https://` URL —
/// an active row is returned and an inactive row resolves to `None` (no fetch,
/// so deactivation cannot be bypassed). Otherwise, when `settings` is
/// `Some` and the id parses as `https://`, the document is resolved through
/// [`resolve_with_catalog`] (cache, else guarded fetch + strict validation)
/// and materialized via [`ValidatedCimd::to_client`]. Any other id, or a
/// disabled feature, resolves to `None` so the caller keeps its existing
/// unknown-client error.
///
/// Only `none` and `private_key_jwt` documents can resolve here: validation
/// rejects every shared-secret and mTLS method before a principal exists
/// (CIMD draft §4.1), and a `private_key_jwt` document resolves only with an
/// inline `jwks` (no second fetch on the auth path).
///
/// # Errors
///
/// Returns the [`CimdError`] of a failed fetch or validation (mapped by the
/// caller per [`From<CimdError>`]: `invalid_client_metadata`,
/// `invalid_redirect_uri`, or fail-closed `503`), a pass-through
/// [`CimdError::Lookup`] preserving the row lookup's own error, or a
/// [`CimdError::Backend`] when the scope catalog or the cache fails.
pub async fn resolve_client(
  pool: &PgPool,
  keys: &KeyRing,
  conn: &mut RedisConn,
  settings: Option<CimdSettings<'_>>,
  client_id: &str,
) -> Result<Option<client_repo::Client>, CimdError> {
  let row = client_repo::find_by_client_id_any_state(pool, keys, client_id)
    .await
    .map_err(CimdError::Lookup)?;
  if let Some(client) = row {
    if client.active {
      return Ok(Some(client));
    }
    // A disabled row is dead: the caller keeps its unknown-client error
    // and no document is fetched, so deactivation cannot be bypassed.
    return Ok(None);
  }
  let Some(settings) = settings else {
    return Ok(None);
  };
  // CIMD draft §3: only an `https://` URL names a metadata document.
  if !client_id.starts_with("https://") {
    return Ok(None);
  }
  let limits = CimdLimits {
    max_bytes: settings.max_bytes,
    timeout: settings.timeout,
  };
  let validated = resolve_with_catalog(
    conn,
    settings.token_prefix,
    pool,
    client_id,
    settings.allow_localhost,
    limits,
  )
  .await?;
  Ok(Some(validated.to_client()))
}
/// Fetch a CIMD document by URL through the guarded fetcher.
///
/// Uses exactly one fetcher ([`ssrf::fetch_guarded_bytes_with`]): `https`
/// only, no redirects, special-use/private addresses rejected, `limits`
/// enforced. Non-success statuses and oversize bodies fail closed as
/// [`CimdError::Fetch`].
///
/// # Errors
///
/// Returns [`CimdError::Fetch`] on any guard/fetch/status/size failure and
/// [`CimdError::InvalidJson`] when the body is not a document-shaped JSON
/// object.
pub async fn fetch_document(
  client_id_url: &str,
  limits: CimdLimits,
) -> Result<CimdDocument, CimdError> {
  let bytes = ssrf::fetch_guarded_bytes_with(client_id_url, limits.max_bytes, limits.timeout)
    .await
    .map_err(|_| CimdError::Fetch)?;
  serde_json::from_slice(&bytes).map_err(|_| CimdError::InvalidJson)
}

/// Validate a document against the strict CIMD rules.
///
/// # Errors
///
/// Returns the specific [`CimdError`] for the first violated rule. The
/// checks are ordered cheapest/most-specific first: identifier echo, auth
/// method and JWKS policy, redirect set, scope subset, grant subset.
pub fn validate_document(
  client_id_url: &str,
  document: &CimdDocument,
  validation: &CimdValidation<'_>,
) -> Result<ValidatedCimd, CimdError> {
  // CIMD §4.1: the document must identify itself as the URL it was fetched
  // from, exactly. No normalization is performed.
  if document.client_id != client_id_url {
    return Err(CimdError::ClientIdMismatch);
  }

  // CIMD §4.1: only registration-free-safe methods. Absent defaults to
  // `none`; shared-secret and mTLS methods are rejected.
  let token_endpoint_auth_method = match document.token_endpoint_auth_method.as_deref() {
    None | Some("none") => CimdAuthMethod::None,
    Some("private_key_jwt") => CimdAuthMethod::PrivateKeyJwt,
    Some(_) => return Err(CimdError::UnsupportedAuthMethod),
  };

  // Inline-only decision: never fetch a second URL on the auth path.
  if document.jwks_uri.is_some() {
    return Err(CimdError::JwksUriNotAllowed);
  }
  let jwks = match token_endpoint_auth_method {
    CimdAuthMethod::PrivateKeyJwt => {
      let Some(value) = document.jwks.as_ref() else {
        return Err(CimdError::JwksRequired);
      };
      validate_jwks_shape(value)?;
      Some(value.clone())
    }
    CimdAuthMethod::None => None,
  };

  validate_redirect_uris(&document.redirect_uris, validation.allow_localhost)?;

  let scope = validate_scope(document.scope.as_deref(), validation.enabled_scopes)?;
  let grant_types = validate_grants(document.grant_types.as_ref())?;

  Ok(ValidatedCimd {
    client_id: document.client_id.clone(),
    redirect_uris: document.redirect_uris.clone(),
    token_endpoint_auth_method,
    grant_types,
    scope,
    jwks,
    client_name: document.client_name.clone(),
    dpop_bound_access_tokens: document.dpop_bound_access_tokens.unwrap_or(false),
  })
}

/// Fetch and validate in one step (no cache).
///
/// # Errors
///
/// Returns a fetch, parse, or validation [`CimdError`].
pub async fn fetch_and_validate(
  client_id_url: &str,
  validation: &CimdValidation<'_>,
  limits: CimdLimits,
) -> Result<ValidatedCimd, CimdError> {
  let document = fetch_document(client_id_url, limits).await?;
  validate_document(client_id_url, &document, validation)
}

/// Resolve a CIMD client: negative-cache hit fails fast, else cache hit,
/// else one elected fetcher plus waiters.
///
/// An origin-level fetch failure (`Fetch`/`InvalidJson`) is negatively cached
/// for 30 seconds under `cimd:neg:<sha256(url)>`. A fresh-fetch validation
/// failure is short-cached for [`INVALID_CACHE_TTL_SECS`] under
/// `cimd:invalid:<sha256(url)>` as a single-flight completion marker, so a
/// corrected document is seen within that short window; a validation failure
/// on a cached document writes no marker. A cached document is revalidated so
/// catalog changes are honored during the 15-minute TTL. If the cache write
/// after a successful validation fails, the validated document is still
/// served (uncached).
///
/// Concurrent misses for the same URL elect exactly one fetcher through a
/// `{state}` Redis lock (`cimd:lock:<sha256(url)>`, TTL = the fetch budget plus
/// [`LOCK_TTL_MARGIN`]). The other requests poll the positive and negative
/// caches for up to the fetch budget plus [`LOCK_WAIT_MARGIN`], then try once
/// more to acquire the lock; if it is still held they fail closed with
/// [`CimdError::Fetch`]. A holder's `release_lock` is a compare-and-delete, and
/// the lock TTL bounds a crashed holder.
///
/// `token_prefix` must carry the `{state}` hash tag.
///
/// # Errors
///
/// Returns any fetch/parse/validation [`CimdError`], or
/// [`CimdError::Backend`] when Redis cannot be read or written (fail closed).
pub async fn resolve(
  conn: &mut RedisConn,
  token_prefix: &str,
  client_id_url: &str,
  validation: &CimdValidation<'_>,
  limits: CimdLimits,
) -> Result<ValidatedCimd, CimdError> {
  let key = cache_key(token_prefix, client_id_url);
  let neg_key = negative_cache_key(token_prefix, client_id_url);
  let invalid_key = invalid_cache_key(token_prefix, client_id_url);
  let lock = lock_key(token_prefix, client_id_url);
  if is_negatively_cached(conn, &neg_key).await? {
    return Err(CimdError::Fetch);
  }
  if let Some(document) = get_cached(conn, &key).await? {
    return validate_document(client_id_url, &document, validation);
  }
  if is_invalid_cached(conn, &invalid_key).await? {
    return Err(CimdError::Fetch);
  }

  let ttl_ms = lock_ttl_ms(limits);
  if let Some(token) = acquire_lock(conn, &lock, ttl_ms).await? {
    let result = resolve_under_lock(
      conn,
      &key,
      &neg_key,
      &invalid_key,
      client_id_url,
      validation,
      limits,
    )
    .await;
    // Best effort: a missed release is bounded by the lock TTL.
    let _ = release_lock(conn, &lock, &token).await;
    return result;
  }

  let deadline = tokio::time::Instant::now()
    .checked_add(limits.timeout)
    .and_then(|instant| instant.checked_add(LOCK_WAIT_MARGIN))
    .unwrap_or_else(tokio::time::Instant::now);
  loop {
    if is_negatively_cached(conn, &neg_key).await? {
      return Err(CimdError::Fetch);
    }
    if let Some(document) = get_cached(conn, &key).await? {
      return validate_document(client_id_url, &document, validation);
    }
    if is_invalid_cached(conn, &invalid_key).await? {
      return Err(CimdError::Fetch);
    }
    // A holder that failed validation releases without a cache entry; stop
    // waiting as soon as the lock is gone and try to elect the next fetcher.
    let lock_present: bool = redis::cmd("EXISTS")
      .arg(&lock)
      .query_async(conn)
      .await
      .map_err(cache_backend)?;
    if !lock_present {
      break;
    }
    let now = tokio::time::Instant::now();
    if now >= deadline {
      break;
    }
    let left = deadline.saturating_duration_since(now);
    tokio::time::sleep(left.min(LOCK_POLL_INTERVAL)).await;
  }

  if let Some(token) = acquire_lock(conn, &lock, ttl_ms).await? {
    let result = resolve_under_lock(
      conn,
      &key,
      &neg_key,
      &invalid_key,
      client_id_url,
      validation,
      limits,
    )
    .await;
    let _ = release_lock(conn, &lock, &token).await;
    return result;
  }
  Err(CimdError::Fetch)
}

/// The lock-held path: re-check the caches (another holder may have just
/// published), then fetch, validate, and cache.
async fn resolve_under_lock(
  conn: &mut RedisConn,
  key: &str,
  neg_key: &str,
  invalid_key: &str,
  client_id_url: &str,
  validation: &CimdValidation<'_>,
  limits: CimdLimits,
) -> Result<ValidatedCimd, CimdError> {
  if is_negatively_cached(conn, neg_key).await? {
    return Err(CimdError::Fetch);
  }
  if let Some(document) = get_cached(conn, key).await? {
    return validate_document(client_id_url, &document, validation);
  }
  if is_invalid_cached(conn, invalid_key).await? {
    return Err(CimdError::Fetch);
  }
  let document = match fetch_document(client_id_url, limits).await {
    Ok(document) => document,
    Err(error @ (CimdError::Fetch | CimdError::InvalidJson)) => {
      put_negative(conn, neg_key).await?;
      return Err(error);
    }
    Err(error) => return Err(error),
  };
  let validated = match validate_document(client_id_url, &document, validation) {
    Ok(validated) => validated,
    Err(error) => {
      if put_invalid(conn, invalid_key).await.is_err() {
        tracing::warn!("cimd invalid-document marker write failed");
      }
      return Err(error);
    }
  };
  if put_cached(conn, key, &document).await.is_err() {
    tracing::warn!("cimd cache population failed after validation");
  }
  Ok(validated)
}

/// The single-flight lock key: `{state}`-prefixed, hash of the URL, never the
/// raw URL.
fn lock_key(token_prefix: &str, client_id_url: &str) -> String {
  format!(
    "{token_prefix}cimd:lock:{}",
    sha256_hex(client_id_url.as_bytes())
  )
}

/// Lock lifetime in milliseconds: the fetch budget plus a scheduling margin.
fn lock_ttl_ms(limits: CimdLimits) -> u64 {
  u64::try_from(limits.timeout.saturating_add(LOCK_TTL_MARGIN).as_millis()).unwrap_or(u64::MAX)
}

/// Acquire the single-flight lock with `SET NX PX`. The random token is the
/// compare-and-delete value; `None` means another request holds it.
async fn acquire_lock(
  conn: &mut RedisConn,
  key: &str,
  ttl_ms: u64,
) -> Result<Option<String>, CimdError> {
  let token = crate::crypto::tokens::mint_token()
    .map_err(|_| CimdError::Backend(AppError::temporarily_unavailable()))?;
  let acquired: Option<String> = redis::cmd("SET")
    .arg(key)
    .arg(&token)
    .arg("NX")
    .arg("PX")
    .arg(ttl_ms)
    .query_async(conn)
    .await
    .map_err(cache_backend)?;
  Ok(acquired.map(|_| token))
}

/// Compare-and-delete the single-flight lock, so a holder whose TTL expired
/// cannot release a successor's lock.
static RELEASE_LOCK: LazyLock<redis::Script> = LazyLock::new(|| {
  redis::Script::new(
    "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
  )
});

/// Release the lock only when it still holds `token`.
async fn release_lock(conn: &mut RedisConn, key: &str, token: &str) -> Result<(), CimdError> {
  let mut invocation = RELEASE_LOCK.prepare_invoke();
  invocation.key(key);
  invocation.arg(token);
  let _: i64 = invocation.invoke_async(conn).await.map_err(cache_backend)?;
  Ok(())
}

/// Resolve a CIMD client while loading the enabled scope catalog from
/// Postgres. Convenience wrapper for request handlers.
///
/// # Errors
///
/// Returns [`CimdError::Backend`] when the catalog read fails, plus every
/// [`resolve`] failure.
pub async fn resolve_with_catalog(
  conn: &mut RedisConn,
  token_prefix: &str,
  pool: &PgPool,
  client_id_url: &str,
  allow_localhost: bool,
  limits: CimdLimits,
) -> Result<ValidatedCimd, CimdError> {
  let enabled_scopes: HashSet<String> = scope_repo::list_enabled(pool)
    .await
    .map_err(CimdError::Backend)?
    .into_iter()
    .map(|record| record.name)
    .collect();
  resolve(
    conn,
    token_prefix,
    client_id_url,
    &CimdValidation {
      enabled_scopes: &enabled_scopes,
      allow_localhost,
    },
    limits,
  )
  .await
}

/// Read a cached document. Malformed cache entries are deleted and treated as
/// a miss; a Redis failure is fail-closed [`CimdError::Backend`].
async fn get_cached(conn: &mut RedisConn, key: &str) -> Result<Option<CimdDocument>, CimdError> {
  let raw: Option<String> = redis::cmd("GET")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(cache_backend)?;
  let Some(raw) = raw else {
    return Ok(None);
  };
  match serde_json::from_str(&raw) {
    Ok(document) => Ok(Some(document)),
    Err(_) => {
      // A corrupt entry is not trusted: drop it and fetch afresh.
      let _: Result<i64, _> = redis::cmd("DEL").arg(key).query_async(conn).await;
      Ok(None)
    }
  }
}

/// Whether an origin-level fetch failure is negatively cached. A Redis
/// failure is fail-closed [`CimdError::Backend`].
async fn is_negatively_cached(conn: &mut RedisConn, neg_key: &str) -> Result<bool, CimdError> {
  let present: bool = redis::cmd("EXISTS")
    .arg(neg_key)
    .query_async(conn)
    .await
    .map_err(cache_backend)?;
  Ok(present)
}

/// Record an origin-level fetch failure for [`NEG_CACHE_TTL_SECS`]. A Redis
/// failure is fail-closed [`CimdError::Backend`].
async fn put_negative(conn: &mut RedisConn, neg_key: &str) -> Result<(), CimdError> {
  redis::cmd("SET")
    .arg(neg_key)
    .arg("1")
    .arg("EX")
    .arg(NEG_CACHE_TTL_SECS)
    .query_async::<()>(conn)
    .await
    .map_err(cache_backend)
}

/// Whether a fresh-fetch validation failure is short-cached. A Redis failure
/// is fail-closed [`CimdError::Backend`].
async fn is_invalid_cached(conn: &mut RedisConn, invalid_key: &str) -> Result<bool, CimdError> {
  let present: bool = redis::cmd("EXISTS")
    .arg(invalid_key)
    .query_async(conn)
    .await
    .map_err(cache_backend)?;
  Ok(present)
}

/// Record a fresh-fetch validation failure for [`INVALID_CACHE_TTL_SECS`].
async fn put_invalid(conn: &mut RedisConn, invalid_key: &str) -> Result<(), CimdError> {
  redis::cmd("SET")
    .arg(invalid_key)
    .arg("1")
    .arg("EX")
    .arg(INVALID_CACHE_TTL_SECS)
    .query_async::<()>(conn)
    .await
    .map_err(cache_backend)
}

/// Cache a validated document for [`CACHE_TTL_SECS`].
async fn put_cached(
  conn: &mut RedisConn,
  key: &str,
  document: &CimdDocument,
) -> Result<(), CimdError> {
  let payload = serde_json::to_string(document).map_err(|_| CimdError::InvalidJson)?;
  redis::cmd("SET")
    .arg(key)
    .arg(payload)
    .arg("EX")
    .arg(CACHE_TTL_SECS)
    .query_async::<()>(conn)
    .await
    .map_err(cache_backend)
}

/// Map a Redis error to a fail-closed backend error.
fn cache_backend(error: redis::RedisError) -> CimdError {
  CimdError::Backend(StoreError::Redis(error).into())
}

/// Redirect URIs are `https`, or plaintext `http` only for an RFC 8252 §7.3
/// loopback host. The loopback decision (including `localhost` behind
/// `allow_localhost`) reuses [`redirect_repo::match_redirect_uri`] so CIMD and
/// registered clients can never disagree. Wildcards are rejected outright.
fn validate_redirect_uris(uris: &[String], allow_localhost: bool) -> Result<(), CimdError> {
  if uris.is_empty() {
    return Err(CimdError::InvalidRedirectUri);
  }
  for uri in uris {
    if uri.contains('*') {
      return Err(CimdError::InvalidRedirectUri);
    }
    let parsed = reqwest::Url::parse(uri).map_err(|_| CimdError::InvalidRedirectUri)?;
    if !matches!(parsed.scheme(), "https" | "http")
      || parsed.host_str().is_none_or(str::is_empty)
      || !parsed.username().is_empty()
      || parsed.password().is_some()
    {
      return Err(CimdError::InvalidRedirectUri);
    }
    // `match_redirect_uri` is the single source of truth for the loopback
    // exception and rejects plaintext `http` for every non-loopback host.
    if redirect_repo::match_redirect_uri(uris, uri, allow_localhost) == RedirectDecision::Reject {
      return Err(CimdError::InvalidRedirectUri);
    }
  }
  Ok(())
}

/// Check every requested scope token against the enabled catalog.
fn validate_scope(
  scope: Option<&str>,
  enabled_scopes: &HashSet<String>,
) -> Result<String, CimdError> {
  let mut accepted = Vec::new();
  for token in scope.unwrap_or_default().split_whitespace() {
    if !enabled_scopes.contains(token) {
      return Err(CimdError::UnknownScope);
    }
    accepted.push(token);
  }
  Ok(accepted.join(" "))
}

/// Require a non-empty grant set, each member in [`ALLOWED_GRANTS`]; default
/// to `["authorization_code"]` when absent. Duplicates collapse in first-seen
/// order.
fn validate_grants(grants: Option<&Vec<String>>) -> Result<Vec<String>, CimdError> {
  let requested: &[String] = grants.map_or(&[], Vec::as_slice);
  if grants.is_some() && requested.is_empty() {
    return Err(CimdError::UnsupportedGrantType);
  }
  let source: Vec<String> = if requested.is_empty() {
    vec!["authorization_code".to_owned()]
  } else {
    requested.to_vec()
  };
  let mut seen = HashSet::with_capacity(source.len());
  let mut out = Vec::with_capacity(source.len());
  for grant in source {
    if !ALLOWED_GRANTS.contains(&grant.as_str()) {
      return Err(CimdError::UnsupportedGrantType);
    }
    if seen.insert(grant.clone()) {
      out.push(grant);
    }
  }
  Ok(out)
}

/// Require an inline JWKS document to carry a non-empty `keys` array. Mirrors
/// the DCR shape check; signature validation belongs to the assertion
/// verifier.
fn validate_jwks_shape(value: &serde_json::Value) -> Result<(), CimdError> {
  let has_keys = value
    .get("keys")
    .and_then(|keys| keys.as_array())
    .is_some_and(|keys| !keys.is_empty());
  if has_keys {
    Ok(())
  } else {
    Err(CimdError::JwksRequired)
  }
}

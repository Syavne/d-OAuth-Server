//! Dynamic client registration (RFC 7591 §2/§3.1/§3.2).
//!
//! `POST /register` mints a client for a caller holding an unexpired initial
//! access token with remaining uses, or — only when
//! `allow_open_registration` is set — for an anonymous caller inside a
//! fixed-window Redis budget (the router's rate-limit layer in task 40 is the
//! primary throttle; the in-handler budget here is defense in depth).
//! Confidential clients must bind a token sender-constraint (mTLS or DPoP);
//! `private_key_jwt` alone never satisfies it. Secrets leave this module
//! exactly once (the 201 body) and persist only as Argon2id hashes; the
//! registration access token persists only as a keyed hash on the client row
//! so management (task 39) survives a Redis loss.
//!
//! `jwks_uri` values are fetched only through the SSRF guard
//! (`protocol::ssrf`); inline `jwks` is preferred. RFC 7592 management
//! (`GET`/`PUT`/`DELETE /register/{id}`) lives in [`manage`].

#[cfg(test)]
mod tests;

pub mod manage;

use std::collections::HashSet;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::{Config, DcrRedirectPolicy};
use crate::crypto::secret as secret_crypto;
use crate::crypto::tokens as tokens_crypto;
use crate::db::client_repo::{self, NewClient, TokenEndpointAuthMethod};
use crate::db::{redirect_repo, scope_repo};
use crate::error::AppError;
use crate::protocol::ssrf;
use crate::state::{AppState, RedisConn};
use crate::store::{Store, ratelimit};

/// Anonymous-registration fixed-window bucket (hashed before keying).
const ANON_REGISTER_BUCKET: &str = "dcr-anon-register";
/// Upper bound on `client_name` length.
const MAX_CLIENT_NAME_LEN: usize = 256;
/// Grant types this server can register (RFC 7591; no `client_credentials`).
const SUPPORTED_GRANTS: [&str; 3] = [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code",
];
/// Description stored on catalog rows created for dynamic URIs.
const DYNAMIC_REDIRECT_DESCRIPTION: &str = "dynamic client registration";

/// Datastore handles needed by [`register_client`].
pub struct RegisterStores<'a> {
  /// Postgres pool for the client row, catalog reads, and attachments.
  pub pool: &'a PgPool,
  /// Redis connection for the IAT consume and the anonymous budget.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
}

/// Request-scoped registration inputs.
pub struct RegisterContext<'a> {
  /// Validated runtime configuration (issuer, policies, peppers, budgets).
  pub config: &'a Config,
  /// Current time for issued-at stamps.
  pub now: OffsetDateTime,
}

/// RFC 7591 §2 registration request body.
///
/// Unknown fields are ignored; client-asserted secrets, ids, or timestamps
/// are never honored (the server mints every credential it returns).
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
  /// Requested redirect URIs (required, non-empty).
  pub redirect_uris: Option<Vec<String>>,
  /// Human-readable client name.
  pub client_name: Option<String>,
  /// Token-endpoint auth method (default `client_secret_basic`).
  pub token_endpoint_auth_method: Option<String>,
  /// Requested grant types (default `["authorization_code"]`).
  pub grant_types: Option<Vec<String>>,
  /// Requested response types (default `["code"]`; only `code` registers).
  pub response_types: Option<Vec<String>>,
  /// Space-delimited requested scope (subset of the enabled catalog).
  pub scope: Option<String>,
  /// Inline JWKS document (XOR `jwks_uri`).
  pub jwks: Option<serde_json::Value>,
  /// Remote JWKS URI (XOR `jwks`; fetched only through the SSRF guard).
  pub jwks_uri: Option<String>,
  /// RFC 8705 mTLS subject DN (requires `tls_client_auth`).
  pub tls_client_auth_subject_dn: Option<String>,
  /// DPoP binding signal (RFC 9449): the client opts into DPoP-bound tokens.
  pub dpop_bound_access_tokens: Option<bool>,
  /// Contact addresses, stored verbatim.
  pub contacts: Option<serde_json::Value>,
  /// Software identifier, stored verbatim.
  pub software_id: Option<String>,
}

/// RFC 7591 §3.2.1 registration response (HTTP 201).
///
/// `client_secret` appears only for secret-issued confidential clients and is
/// never persisted or returned again; `registration_access_token` is shown
/// exactly once (only its keyed hash is stored).
#[derive(Debug, Clone, Serialize)]
pub struct RegisterResponse {
  /// The minted public client identifier.
  pub client_id: String,
  /// The minted client secret (secret-issued confidential clients only).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_secret: Option<String>,
  /// When the minted secret expires, if it does.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub client_secret_expires_at: Option<i64>,
  /// The RFC 7592 management token, shown exactly once.
  pub registration_access_token: String,
  /// The RFC 7592 management URI for this client.
  pub registration_client_uri: String,
  /// Effective attached redirect URIs.
  pub redirect_uris: Vec<String>,
  /// Registered client name.
  pub client_name: String,
  /// Registered token-endpoint authentication method.
  pub token_endpoint_auth_method: String,
  /// Registered grant types.
  pub grant_types: Vec<String>,
  /// Registered response types.
  pub response_types: Vec<String>,
  /// Registered scope string.
  pub scope: String,
  /// Registered inline JWKS, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jwks: Option<serde_json::Value>,
  /// Registered JWKS URI, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jwks_uri: Option<String>,
  /// Registered mTLS subject DN, if any.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tls_client_auth_subject_dn: Option<String>,
  /// Whether the client registered DPoP-bound tokens.
  pub dpop_bound_access_tokens: bool,
  /// When the client identifier was issued (unix seconds).
  pub client_id_issued_at: i64,
}

/// Validated registration ready to persist.
struct ValidatedRegistration {
  method: TokenEndpointAuthMethod,
  grant_types: Vec<String>,
  scope: String,
  client_name: String,
  jwks: Option<serde_json::Value>,
  jwks_uri: Option<String>,
  subject_dn: Option<String>,
  dpop_bound: bool,
  contacts: Option<serde_json::Value>,
  software_id: Option<String>,
  redirect_uris: Vec<String>,
}

/// Axum entry point for `POST /register` (mounted by the router in task 40).
///
/// # Errors
///
/// Returns `invalid_client` (401 + `WWW-Authenticate: Bearer`) for a missing
/// or invalid initial access token, `invalid_redirect_uri` /
/// `invalid_client_metadata` (400) for bad metadata, `temporarily_unavailable`
/// (503) when an anonymous budget is exhausted or a dependency fails closed,
/// and `server_error` (500, masked) for unexpected internal failures.
pub async fn register_handler(
  State(state): State<AppState>,
  headers: HeaderMap,
  Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
  let token = bearer_token(&headers);
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let mut stores = RegisterStores {
    pool: &state.pool,
    conn: &mut conn,
    store: &store,
  };
  let ctx = RegisterContext {
    config: &state.config,
    now: state.clock.now(),
  };
  let response = register_client(&mut stores, &ctx, token, &request).await?;
  Ok((StatusCode::CREATED, Json(response)))
}

/// Register a client: authorize the caller, validate metadata, persist the
/// row (secret and registration token as hashes only), attach redirects.
///
/// A spent initial-access use is burned even when later validation fails: a
/// use authorizes one registration call, not one successful call.
///
/// # Errors
///
/// Returns the same errors as [`register_handler`].
pub async fn register_client(
  stores: &mut RegisterStores<'_>,
  ctx: &RegisterContext<'_>,
  initial_access_token: Option<&str>,
  request: &RegisterRequest,
) -> Result<RegisterResponse, AppError> {
  authorize_caller(stores, ctx.config, initial_access_token).await?;
  let validated = validate_metadata(stores.pool, request).await?;
  let redirect_ids = resolve_redirects(stores.pool, ctx.config, &validated.redirect_uris).await?;

  let client_id = tokens_crypto::mint_token().map_err(AppError::internal)?;
  let registration_token = tokens_crypto::mint_token().map_err(AppError::internal)?;
  let registration_hash = keyed_hash(ctx.config, &registration_token)?;
  let secret_hash = match validated.method {
    TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost => {
      let secret = tokens_crypto::mint_token().map_err(AppError::internal)?;
      let hash = hash_secret(ctx.config, &secret).await?;
      Some((secret, hash))
    }
    TokenEndpointAuthMethod::None
    | TokenEndpointAuthMethod::PrivateKeyJwt
    | TokenEndpointAuthMethod::TlsClientAuth
    | TokenEndpointAuthMethod::SelfSignedTlsClientAuth => None,
  };

  let new = NewClient {
    id: Uuid::new_v4(),
    client_id: client_id.clone(),
    client_secret_hash: secret_hash.as_ref().map(|(_, hash)| hash.clone()),
    client_secret_expires_at: None,
    client_name: validated.client_name.clone(),
    grant_types: validated.grant_types.clone(),
    response_types: vec!["code".to_owned()],
    scope: validated.scope.clone(),
    token_endpoint_auth_method: validated.method.as_str().to_owned(),
    jwks: validated.jwks.clone(),
    jwks_uri: validated.jwks_uri.clone(),
    tls_client_auth_subject_dn: validated.subject_dn.clone(),
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: validated.contacts.clone(),
    software_id: validated.software_id.clone(),
    dpop_bound_access_tokens: validated.dpop_bound,
    registration_access_token_hash: Some(registration_hash),
  };
  let row = client_repo::insert(stores.pool, &new).await?;

  for id in &redirect_ids {
    redirect_repo::attach(stores.pool, &client_id, *id, None).await?;
  }

  Ok(RegisterResponse {
    client_id: row.client_id,
    client_secret: secret_hash.map(|(secret, _)| secret),
    client_secret_expires_at: None,
    registration_access_token: registration_token,
    registration_client_uri: format!("{}/register/{client_id}", ctx.config.issuer),
    redirect_uris: validated.redirect_uris.clone(),
    client_name: row.client_name,
    token_endpoint_auth_method: validated.method.as_str().to_owned(),
    grant_types: validated.grant_types,
    response_types: vec!["code".to_owned()],
    scope: validated.scope,
    jwks: validated.jwks,
    jwks_uri: validated.jwks_uri,
    tls_client_auth_subject_dn: validated.subject_dn,
    dpop_bound_access_tokens: validated.dpop_bound,
    client_id_issued_at: ctx.now.unix_timestamp(),
  })
}

/// Authorize a registration call: spend one use of a valid initial access
/// token, or — only under `allow_open_registration` — spend from the
/// anonymous fixed-window budget.
async fn authorize_caller(
  stores: &mut RegisterStores<'_>,
  config: &Config,
  initial_access_token: Option<&str>,
) -> Result<(), AppError> {
  if let Some(token) = initial_access_token {
    let hash = keyed_hash(config, token)?;
    match crate::store::dcr::consume_one_use(stores.conn, stores.store, &hash).await? {
      Some(_) => Ok(()),
      None => Err(AppError::invalid_client_bearer()),
    }
  } else if config.allow_open_registration {
    match ratelimit::check_and_incr(
      stores.conn,
      stores.store,
      ANON_REGISTER_BUCKET,
      config.rate_limit.window,
      u64::from(config.rate_limit.per_ip),
    )
    .await
    {
      Ok(decision) if decision.allowed => Ok(()),
      Ok(_) => Err(AppError::temporarily_unavailable()),
      Err(error) => Err(AppError::from(error)),
    }
  } else {
    Err(AppError::invalid_client_bearer())
  }
}

/// Validate every metadata field except redirects: auth method, grants and
/// their compatibility with the method, response types, scope subset, the
/// `jwks`/`jwks_uri` exclusive-or, mTLS fields, and — for confidential
/// clients — the mandatory sender-constraint binding.
async fn validate_metadata(
  pool: &PgPool,
  request: &RegisterRequest,
) -> Result<ValidatedRegistration, AppError> {
  let method = match request.token_endpoint_auth_method.as_deref() {
    None => TokenEndpointAuthMethod::ClientSecretBasic,
    Some(value) => TokenEndpointAuthMethod::try_from(value)
      .map_err(|_| AppError::invalid_client_metadata("unsupported token_endpoint_auth_method"))?,
  };

  let grant_types = dedupe_strings(
    request
      .grant_types
      .clone()
      .unwrap_or_else(|| vec!["authorization_code".to_owned()]),
  );
  if grant_types.is_empty() {
    return Err(AppError::invalid_client_metadata(
      "grant_types must not be empty",
    ));
  }
  for grant in &grant_types {
    if !SUPPORTED_GRANTS.contains(&grant.as_str()) {
      return Err(AppError::invalid_client_metadata("unsupported grant type"));
    }
  }

  let response_types = request
    .response_types
    .clone()
    .unwrap_or_else(|| vec!["code".to_owned()]);
  if response_types.is_empty() || response_types.iter().any(|kind| kind != "code") {
    return Err(AppError::invalid_client_metadata(
      "only response_types [\"code\"] is supported",
    ));
  }

  let scope = validate_scope(pool, request.scope.as_deref()).await?;

  if request.jwks.is_some() && request.jwks_uri.is_some() {
    return Err(AppError::invalid_client_metadata(
      "jwks and jwks_uri are mutually exclusive",
    ));
  }
  let jwks = match request.jwks.as_ref() {
    Some(value) => {
      validate_jwks_shape(value)?;
      Some(value.clone())
    }
    None => None,
  };
  let jwks_uri = match request.jwks_uri.as_deref() {
    Some(uri) => {
      let fetched = fetch_jwks_uri(uri).await?;
      Some((uri.to_owned(), fetched))
    }
    None => None,
  };

  if matches!(method, TokenEndpointAuthMethod::PrivateKeyJwt)
    && jwks.is_none()
    && jwks_uri.is_none()
  {
    return Err(AppError::invalid_client_metadata(
      "private_key_jwt requires jwks or jwks_uri",
    ));
  }
  if matches!(method, TokenEndpointAuthMethod::SelfSignedTlsClientAuth)
    && jwks.is_none()
    && jwks_uri.is_none()
  {
    return Err(AppError::invalid_client_metadata(
      "self_signed_tls_client_auth requires jwks or jwks_uri",
    ));
  }

  let subject_dn = match request.tls_client_auth_subject_dn.as_deref() {
    Some(dn) if dn.trim().is_empty() => {
      return Err(AppError::invalid_client_metadata(
        "tls_client_auth_subject_dn must not be empty",
      ));
    }
    Some(dn) => {
      if !matches!(method, TokenEndpointAuthMethod::TlsClientAuth) {
        return Err(AppError::invalid_client_metadata(
          "tls_client_auth_subject_dn requires tls_client_auth",
        ));
      }
      Some(dn.trim().to_owned())
    }
    None => None,
  };
  if matches!(method, TokenEndpointAuthMethod::TlsClientAuth) && subject_dn.is_none() {
    return Err(AppError::invalid_client_metadata(
      "tls_client_auth requires tls_client_auth_subject_dn",
    ));
  }

  let dpop_bound = request.dpop_bound_access_tokens.unwrap_or(false);
  let confidential = !matches!(method, TokenEndpointAuthMethod::None);
  let mtls_bound = matches!(
    method,
    TokenEndpointAuthMethod::TlsClientAuth | TokenEndpointAuthMethod::SelfSignedTlsClientAuth
  );
  if confidential && !(mtls_bound || dpop_bound) {
    return Err(AppError::invalid_client_metadata(
      "confidential clients must register a sender-constraint binding \
       (tls_client_auth, self_signed_tls_client_auth, or dpop_bound_access_tokens)",
    ));
  }

  let client_name = request.client_name.clone().unwrap_or_default();
  if client_name.len() > MAX_CLIENT_NAME_LEN {
    return Err(AppError::invalid_client_metadata("client_name is too long"));
  }

  let redirect_uris = request.redirect_uris.clone().unwrap_or_default();
  if redirect_uris.is_empty() {
    return Err(AppError::invalid_redirect_uri(
      "redirect_uris must not be empty",
    ));
  }

  Ok(ValidatedRegistration {
    method,
    grant_types,
    scope,
    client_name,
    jwks: jwks.or_else(|| jwks_uri.as_ref().map(|(_, fetched)| fetched.clone())),
    jwks_uri: jwks_uri.map(|(uri, _)| uri),
    subject_dn,
    dpop_bound,
    contacts: request.contacts.clone(),
    software_id: request.software_id.clone(),
    redirect_uris,
  })
}

/// Check the requested scope string against the enabled catalog: every token
/// must be an enabled scope.
async fn validate_scope(pool: &PgPool, scope: Option<&str>) -> Result<String, AppError> {
  let requested: Vec<&str> = scope.unwrap_or_default().split_whitespace().collect();
  if requested.is_empty() {
    return Ok(String::new());
  }
  let enabled: HashSet<String> = scope_repo::list_enabled(pool)
    .await?
    .into_iter()
    .map(|record| record.name)
    .collect();
  for token in &requested {
    if !enabled.contains(*token) {
      return Err(AppError::invalid_client_metadata("unknown scope"));
    }
  }
  Ok(requested.join(" "))
}

/// Resolve requested redirects to catalog ids: catalog hits attach directly;
/// anything else follows `dcr_redirect_policy` (`open` and dynamic loopback
/// URIs are upserted into the catalog, then attached). An upsert that lands
/// on an admin-disabled row is rejected rather than resurrected.
async fn resolve_redirects(
  pool: &PgPool,
  config: &Config,
  redirect_uris: &[String],
) -> Result<Vec<Uuid>, AppError> {
  let catalog = redirect_repo::list(pool, false).await?;
  let mut ids = Vec::with_capacity(redirect_uris.len());
  for uri in redirect_uris {
    if let Some(hit) = catalog.iter().find(|row| row.uri == *uri) {
      ids.push(hit.id);
      continue;
    }
    match config.dcr_redirect_policy {
      DcrRedirectPolicy::Catalog => {
        return Err(AppError::invalid_redirect_uri(
          "redirect URI is not in the catalog",
        ));
      }
      DcrRedirectPolicy::CatalogLoopback => {
        if !is_loopback_uri(uri) {
          return Err(AppError::invalid_redirect_uri(
            "redirect URI is not in the catalog or a loopback URI",
          ));
        }
      }
      DcrRedirectPolicy::Open => {
        if !has_valid_scheme(uri) {
          return Err(AppError::invalid_redirect_uri(
            "redirect URI is not a valid absolute URI",
          ));
        }
      }
    }
    let row = redirect_repo::upsert(
      pool,
      Uuid::new_v4(),
      uri,
      redirect_repo::RedirectKind::Authorize,
      DYNAMIC_REDIRECT_DESCRIPTION,
      None,
    )
    .await?;
    if !row.enabled {
      return Err(AppError::invalid_redirect_uri(
        "redirect URI is disabled by the administrator",
      ));
    }
    ids.push(row.id);
  }
  Ok(ids)
}

/// Whether `uri` is an RFC 8252 §7.3 loopback URI: plaintext `http` to a
/// loopback literal (`127.0.0.1` or `[::1]`, any port) with no userinfo,
/// query, or fragment. `localhost` is never loopback here.
fn is_loopback_uri(uri: &str) -> bool {
  let (before_fragment, fragment) = match uri.split_once('#') {
    Some((before, fragment)) => (before, Some(fragment)),
    None => (uri, None),
  };
  if fragment.is_some() {
    return false;
  }
  let (before_query, query) = match before_fragment.split_once('?') {
    Some((before, query)) => (before, Some(query)),
    None => (before_fragment, None),
  };
  if query.is_some() {
    return false;
  }
  let rest = match strip_scheme_prefix(before_query, "http") {
    Some(rest) => rest,
    None => return false,
  };
  let after_slashes = match rest.strip_prefix("//") {
    Some(after) => after,
    None => return false,
  };
  let authority = match after_slashes.find('/') {
    Some(index) => &after_slashes[..index],
    None => after_slashes,
  };
  if authority.contains('@') {
    return false;
  }
  if let Some(inner) = authority.strip_prefix('[') {
    match inner.find(']') {
      Some(close) => {
        &inner[..close] == "::1"
          && (inner.len() == close + 1 || inner.as_bytes().get(close + 1) == Some(&b':'))
      }
      None => false,
    }
  } else {
    match authority.split_once(':') {
      Some((host, _)) => host == "127.0.0.1",
      None => authority == "127.0.0.1",
    }
  }
}

/// Whether `uri` is absolute with a valid RFC 3986 §3.1 scheme and a
/// non-empty remainder without whitespace.
fn has_valid_scheme(uri: &str) -> bool {
  let Some((scheme, rest)) = uri.split_once(':') else {
    return false;
  };
  let mut chars = scheme.chars();
  match chars.next() {
    Some(first) if first.is_ascii_alphabetic() => {}
    _ => return false,
  }
  if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
    return false;
  }
  !rest.is_empty() && !rest.chars().any(char::is_whitespace)
}

/// Strip a case-insensitive `scheme:` prefix without ever slicing at a
/// non-character boundary.
fn strip_scheme_prefix<'a>(uri: &'a str, scheme: &str) -> Option<&'a str> {
  let head = uri.get(..scheme.len())?;
  if !head.eq_ignore_ascii_case(scheme) {
    return None;
  }
  uri.get(scheme.len()..)?.strip_prefix(':')
}

/// Require an inline JWKS document to carry a non-empty `keys` array.
/// Signature and key-use validation belong to the assertion/mTLS verifiers.
fn validate_jwks_shape(value: &serde_json::Value) -> Result<(), AppError> {
  let has_keys = value
    .get("keys")
    .and_then(|keys| keys.as_array())
    .is_some_and(|keys| !keys.is_empty());
  if has_keys {
    Ok(())
  } else {
    Err(AppError::invalid_client_metadata(
      "jwks must contain a non-empty keys array",
    ))
  }
}

/// Fetch a `jwks_uri` document through the SSRF guard and require the same
/// JWKS shape as an inline document. Guard/fetch failures are fail-closed
/// and report no fetch internals to the client.
async fn fetch_jwks_uri(uri: &str) -> Result<serde_json::Value, AppError> {
  let bytes = ssrf::fetch_guarded_bytes(uri)
    .await
    .map_err(|_| AppError::invalid_client_metadata("jwks_uri fetch failed"))?;
  let document: serde_json::Value = serde_json::from_slice(&bytes)
    .map_err(|_| AppError::invalid_client_metadata("jwks_uri did not return JSON"))?;
  validate_jwks_shape(&document)?;
  Ok(document)
}

/// Random 256-bit client secrets are hashed with Argon2id off the async
/// worker; only the PHC string is stored.
async fn hash_secret(config: &Config, secret: &str) -> Result<String, AppError> {
  let params = secret_crypto::Argon2Params::new(
    config.argon2.memory_kib,
    config.argon2.iterations,
    config.argon2.parallelism,
    32,
  )
  .map_err(AppError::internal)?;
  let owned = secret.to_owned();
  tokio::task::spawn_blocking(move || secret_crypto::hash_secret(&owned, &params))
    .await
    .map_err(AppError::internal)?
    .map_err(AppError::internal)
}

/// Keyed token hash for at-rest storage under the active pepper — the same
/// scheme the CLI uses when issuing initial access tokens, so registration
/// validates exactly what issuance stored.
fn keyed_hash(config: &Config, token: &str) -> Result<String, AppError> {
  let (key_id, pepper) = config
    .keys
    .active_pepper()
    .ok_or_else(AppError::server_error)?;
  let generation = key_id
    .as_str()
    .trim_start_matches('v')
    .parse::<u32>()
    .unwrap_or(1);
  let hash = tokens_crypto::token_hash(
    &tokens_crypto::KeyId::new(generation),
    pepper.expose_secret().as_bytes(),
    token,
  );
  Ok(hash.to_storage_string())
}

/// Extract a Bearer token from an `Authorization` header, if well-formed.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
  let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
  let token = value.strip_prefix("Bearer ")?.trim();
  if token.is_empty() { None } else { Some(token) }
}

/// Deduplicate strings preserving first-seen order.
fn dedupe_strings(values: Vec<String>) -> Vec<String> {
  let mut seen = HashSet::with_capacity(values.len());
  let mut out = Vec::with_capacity(values.len());
  for value in values {
    if seen.insert(value.clone()) {
      out.push(value);
    }
  }
  out
}

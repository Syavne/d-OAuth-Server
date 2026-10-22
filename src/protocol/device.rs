//! Device authorization endpoint (RFC 8628 §3.1–§3.2).
//!
//! `POST /device_authorization` issues a `device_code`/`user_code` pair for
//! public and confidential clients. Public clients (`none`) authenticate with
//! `client_id` only, exactly as RFC 8628 intends, but MUST present a valid
//! DPoP proof: the verified `jkt` is the sender-constraint binding a public
//! client later needs at polling time, and issuance without it would mint an
//! unbound grant. Confidential clients authenticate as usual through
//! [`client_auth`](super::client_auth); an mTLS-authenticated client binds
//! its `x5t#S256`, and any client presenting a DPoP proof additionally binds
//! its `jkt`.
//!
//! The sender binding rides a sidecar key (`<device-key>:cnf`, same `{state}`
//! hash slot, same TTL) because `store::device::DeviceRecord` (task 12) has
//! no binding field and that module is owned by another task. Polling
//! (task 34) reads it back through [`read_binding`].
//!
//! Raw codes never touch storage: both keys are versioned keyed hashes under
//! the active token pepper. The user code is 8 Crockford-style characters
//! (`XXXX-XXXX` on the wire) with a bounded collision retry.

#[cfg(test)]
mod tests;

use std::time::Duration;

use axum::{Extension, extract::State, http::HeaderMap};
use rand::{TryRng as _, rngs::SysRng};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::client_auth::{self, AuthContext, AuthStores, ClientAuthRequest};
use crate::{
  crypto::tokens::{self},
  db::{Client, TokenEndpointAuthMethod, client_repo},
  error::AppError,
  jose::dpop::{DpopRequest, verify_dpop},
  protocol::mtls,
  state::{AppState, RedisConn},
  store::{self, Store},
  tls::PeerCertificates,
};

/// Grant value a client must be registered for to use this endpoint.
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Polling interval advertised to devices (RFC 8628 §3.2), seconds.
pub const DEVICE_INTERVAL_SECS: u64 = 5;
/// User-code entropy characters, in display form.
pub const USER_CODE_LEN: usize = 8;
/// Crockford-style alphabet without `I`, `L`, `O`, `0`, or `1`.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Collision retries when a fresh user code hashes onto a live one.
const MAX_USER_CODE_ATTEMPTS: u32 = 3;

/// Form fields accepted at `POST /device_authorization`.
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationForm {
  /// The requesting client (public) or the authenticated client id.
  pub client_id: String,
  /// Optional space-delimited scope request.
  #[serde(default)]
  pub scope: Option<String>,
  /// `client_secret_post` secret (body only, never the query).
  #[serde(default)]
  pub client_secret: Option<String>,
  /// `client_assertion_type` for `private_key_jwt`.
  #[serde(default)]
  pub client_assertion_type: Option<String>,
  /// `client_assertion` for `private_key_jwt`.
  #[serde(default)]
  pub client_assertion: Option<String>,
}

impl DeviceAuthorizationForm {
  /// Fields the extractor recognizes: a repeat of any of these is a
  /// duplicate-field rejection. Unknown fields (including a repeated
  /// `resource`) are silently absorbed, as `serde_urlencoded` absorbed them.
  const KNOWN_FIELDS: [&str; 5] = [
    "client_id",
    "scope",
    "client_secret",
    "client_assertion_type",
    "client_assertion",
  ];

  /// Build the form from a strict single-valued map (the `Bytes` extractor
  /// replacement for `Form<DeviceAuthorizationForm>`). A missing
  /// `client_id` is `None` so the handler renders the extractor's 400,
  /// never a core error.
  fn from_map(map: &std::collections::HashMap<String, String>) -> Option<Self> {
    let client_id = map.get("client_id").cloned()?;
    Some(Self {
      client_id,
      scope: map.get("scope").cloned(),
      client_secret: map.get("client_secret").cloned(),
      client_assertion_type: map.get("client_assertion_type").cloned(),
      client_assertion: map.get("client_assertion").cloned(),
    })
  }
}

/// Successful `POST /device_authorization` body (RFC 8628 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceAuthorizationResponse {
  /// Opaque device code the device polls with (task 34).
  pub device_code: String,
  /// Human-readable code rendered as `XXXX-XXXX`.
  pub user_code: String,
  /// Verification page URL for manual entry.
  pub verification_uri: String,
  /// Verification URL with the user code pre-filled.
  pub verification_uri_complete: String,
  /// Device-code lifetime, seconds (mirrors the store TTL).
  pub expires_in: u64,
  /// Minimum polling interval, seconds.
  pub interval: u64,
}

/// Everything the endpoint needs beyond shared state, borrowed from the HTTP
/// layer so the core stays callable without a router.
pub struct DeviceHttpInputs<'a> {
  /// `client_id` form field.
  pub client_id: &'a str,
  /// `scope` form field, when present.
  pub scope: Option<&'a str>,
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
  /// Repeated `resource` indicators (RFC 8707) in wire order, captured from
  /// the raw body by the `Bytes` extractor (see `protocol::params`).
  pub resource: &'a [String],
  /// Verified peer chain injected by the TLS accept loop, when present.
  pub peer_certs: Option<&'a PeerCertificates>,
}

/// Datastore handles needed by [`authorize_device`].
pub struct DeviceStores<'a> {
  /// Postgres pool for client lookup and secret verification.
  pub pool: &'a PgPool,
  /// Redis connection for device records and DPoP replay markers.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
  /// Token-pepper ring for keyed code hashes and CSRF HMACs.
  pub keys: &'a crate::keys::KeyRing,
}

/// Request-scoped issuance inputs.
pub struct DeviceContext<'a> {
  /// Public issuer URL (no trailing slash); scopes endpoint paths.
  pub issuer: &'a str,
  /// Device-code lifetime (mirrored to the store TTL and `expires_in`).
  pub device_ttl: Duration,
  /// Current time as seconds since the Unix epoch (DPoP freshness).
  pub now_unix: i64,
  /// Config `resource_indicators_enabled`: off + any `resource` present is
  /// `invalid_target` (fail-closed, no silent drop).
  pub resource_indicators_enabled: bool,
}
/// Sender-constraint binding captured at authorization time.
///
/// Serialized as the `cnf` object polling (task 34) enforces: `jkt` for
/// DPoP-bound clients, `x5t#S256` for mTLS-bound ones, both when both were
/// proven. Absent entirely only for unconstrained confidential clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
  /// DPoP key thumbprint, when a proof was verified.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub jkt: Option<String>,
  /// mTLS leaf thumbprint, when the client authenticated with mTLS.
  #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
  pub x5t_s256: Option<String>,
}

/// Sidecar key holding the [`DeviceBinding`] JSON for a device hash.
///
/// Derived from the device record key, so it shares the `{state}` hash slot
/// and expires alongside the record itself.
#[must_use]
pub fn binding_key(store: &Store, device_hash: &str) -> String {
  format!("{}:cnf", store.device_key(device_hash))
}

/// Versioned keyed hash of a raw code, for use as a store key.
///
/// Mirrors the CLI hashing convention: the active key id is preserved verbatim,
/// so rotated peppers keep distinct storage strings.
pub fn hash_token(keys: &crate::keys::KeyRing, token: &str) -> Result<String, AppError> {
  let (id, pepper) = keys.active_pepper().ok_or_else(AppError::server_error)?;
  Ok(
    tokens::token_hash(
      &tokens::KeyId::new(id.as_str()),
      pepper.expose_secret().as_bytes(),
      token,
    )
    .to_storage_string(),
  )
}

/// Normalize a presented user code: uppercase, drop separators.
///
/// Comparison always runs on this form, so `abcd-efgh`, `ABCD EFGH`, and
/// `abcdefgh` address the same record.
#[must_use]
pub fn normalize_user_code(raw: &str) -> String {
  raw
    .to_ascii_uppercase()
    .chars()
    .filter(|c| *c != '-' && *c != ' ')
    .collect()
}

/// Whether a normalized user code has the issuance shape.
#[must_use]
pub fn is_well_formed_user_code(normalized: &str) -> bool {
  normalized.len() == USER_CODE_LEN && normalized.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))
}

/// Read the sender binding stored at authorization time.
///
/// `Ok(None)` when the device record (and its sidecar) is gone; a malformed
/// sidecar is a server defect, never a client error.
pub async fn read_binding(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
) -> Result<Option<DeviceBinding>, AppError> {
  let raw: Option<String> = redis::cmd("GET")
    .arg(binding_key(store, device_hash))
    .query_async(conn)
    .await
    .map_err(store::StoreError::Redis)?;
  raw
    .map(|json| serde_json::from_str(&json).map_err(|_| AppError::server_error()))
    .transpose()
}

/// Issue a device authorization: authenticate the client, capture its sender
/// binding, and store the hashed code pair with the configured device TTL.
///
/// Public clients authenticate with `client_id` alone plus a mandatory DPoP
/// proof; confidential clients authenticate as usual. Failures never reveal
/// whether a `client_id` exists.
///
/// # Errors
///
/// Returns `invalid_client` for unknown clients or failed authentication,
/// `invalid_dpop_proof` when a required or presented proof is bad,
/// `invalid_scope` for an unparsable or over-registered scope request,
/// `unauthorized_client` when the client may not use the device grant, and a
/// masked `5xx` when randomness or either datastore fails.
pub async fn authorize_device(
  stores: &mut DeviceStores<'_>,
  ctx: &DeviceContext<'_>,
  inputs: &DeviceHttpInputs<'_>,
) -> Result<DeviceAuthorizationResponse, AppError> {
  if inputs.client_id.trim().is_empty() {
    return Err(AppError::invalid_request("client_id is required"));
  }
  // Resource indicators (RFC 8707) validate fail-closed before any state is
  // written: off + present is `invalid_target`, and every value must be an
  // absolute `https` URI with an exact enabled-catalog match.
  let aud = crate::protocol::params::validate_resources(
    stores.pool,
    ctx.resource_indicators_enabled,
    inputs.resource,
  )
  .await?;
  let used_basic = inputs.basic_header.is_some();
  let unknown_client = || {
    if used_basic {
      AppError::invalid_client_basic()
    } else {
      AppError::invalid_client_non_basic()
    }
  };
  let client = client_repo::find_active_by_client_id(stores.pool, stores.keys, inputs.client_id)
    .await?
    .ok_or_else(unknown_client)?;
  let method = client.auth_method().map_err(|_| unknown_client())?;

  let htu = format!("{}/device_authorization", ctx.issuer);
  let dpop_jkt = match inputs.dpop_proof {
    Some(proof) => Some(
      verify_dpop(
        stores.conn,
        stores.store,
        &DpopRequest {
          proof: Some(proof),
          htm: "POST",
          htu: &htu,
          access_token: None,
          now_unix: ctx.now_unix,
        },
      )
      .await?
      .jkt,
    ),
    None => None,
  };

  let binding = match method {
    TokenEndpointAuthMethod::None => {
      if inputs.basic_header.is_some() || inputs.body_secret.is_some() || inputs.assertion.is_some()
      {
        return Err(AppError::invalid_client_non_basic());
      }
      DeviceBinding {
        jkt: dpop_jkt.filter(|jkt| !jkt.is_empty()),
        x5t_s256: None,
      }
    }
    TokenEndpointAuthMethod::ClientSecretBasic
    | TokenEndpointAuthMethod::ClientSecretPost
    | TokenEndpointAuthMethod::PrivateKeyJwt => {
      authenticate_confidential(stores, ctx, &client, inputs).await?;
      DeviceBinding {
        jkt: dpop_jkt.filter(|jkt| !jkt.is_empty()),
        x5t_s256: None,
      }
    }
    TokenEndpointAuthMethod::TlsClientAuth | TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
      let leaf = inputs.peer_certs.and_then(|chain| chain.chain().first());
      let cnf = mtls::authenticate(stores.pool, stores.keys, &client, leaf)
        .await
        .map_err(mtls::MtlsError::into_app_error)?;
      DeviceBinding {
        jkt: dpop_jkt.filter(|jkt| !jkt.is_empty()),
        x5t_s256: Some(cnf.x5t_s256),
      }
    }
  };

  // A DPoP-bound public client with no DPoP binding would mint an unbound
  // grant: the sender-constraint matrix forbids it, so issuance fails here,
  // before any state is written. Unbound public clients start bearer-capable
  // device flows.
  if method == TokenEndpointAuthMethod::None
    && binding.jkt.is_none()
    && client.dpop_bound_access_tokens
  {
    return Err(AppError::invalid_dpop_proof("DPoP proof is required"));
  }

  if !client.grant_types.iter().any(|g| g == DEVICE_GRANT) {
    return Err(AppError::unauthorized_client(
      "client may not use the device authorization grant",
    ));
  }
  let scope = checked_scope(&client, inputs.scope)?;

  let device_code = tokens::mint_token().map_err(AppError::internal)?;
  let device_hash = hash_token(stores.keys, &device_code)?;
  let (user_code, user_hash) =
    mint_unique_user_code(stores.conn, stores.store, stores.keys, &mut SysRng).await?;

  let record = store::device::DeviceRecord {
    client_id: client.client_id.clone(),
    scope,
    status: store::device::DeviceStatus::Pending,
    subject: String::new(),
    grant_id: String::new(),
    aud,
  };
  store::device::put(
    stores.conn,
    stores.store,
    &device_hash,
    &user_hash,
    &record,
    ctx.device_ttl,
  )
  .await?;
  put_binding(
    stores.conn,
    &binding_key(stores.store, &device_hash),
    &binding,
    ctx.device_ttl,
  )
  .await?;

  let verification_uri = format!("{}/device", ctx.issuer);
  Ok(DeviceAuthorizationResponse {
    device_code,
    verification_uri_complete: format!("{verification_uri}?user_code={user_code}"),
    verification_uri,
    user_code,
    expires_in: ctx.device_ttl.as_secs(),
    interval: DEVICE_INTERVAL_SECS,
  })
}

/// Authenticate a secret/assertion client through the shared dispatch.
///
/// The returned row is discarded: the pre-lookup above already owns the
/// client record, and this call exists only for its proof.
async fn authenticate_confidential(
  stores: &mut DeviceStores<'_>,
  ctx: &DeviceContext<'_>,
  client: &Client,
  inputs: &DeviceHttpInputs<'_>,
) -> Result<(), AppError> {
  let endpoint = client_auth::token_endpoint(ctx.issuer);
  let request = ClientAuthRequest {
    basic_header: inputs.basic_header,
    client_id: Some(client.client_id.as_str()),
    body_secret: inputs.body_secret.clone(),
    assertion_type: inputs.assertion_type,
    assertion: inputs.assertion,
    peer_certs: inputs.peer_certs,
  };
  let mut auth = AuthStores {
    pool: stores.pool,
    keys: stores.keys,
    conn: &mut *stores.conn,
    store: stores.store,
  };
  let auth_ctx = AuthContext {
    token_endpoint: endpoint.as_str(),
    now: time::OffsetDateTime::from_unix_timestamp(ctx.now_unix)
      .unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
    // The device-authorization endpoint serves registered clients only: a
    // CIMD document can never declare the device grant, so no fallback.
    cimd: None,
  };
  client_auth::authenticate_client(&mut auth, &auth_ctx, &request).await?;
  Ok(())
}

/// Validate the requested scope: syntax-checked, and a subset of the
/// client's registered scope when one is requested.
fn checked_scope(client: &Client, requested: Option<&str>) -> Result<String, AppError> {
  let asked = requested.unwrap_or("").trim();
  if asked.is_empty() {
    return Ok(String::new());
  }
  let want = crate::protocol::scope::ScopeSet::parse(asked)?;
  let registered = crate::protocol::scope::ScopeSet::parse(client.scope.trim())
    .map_err(|_| AppError::server_error())?;
  if !want.is_subset_of(&registered) {
    return Err(AppError::invalid_scope(
      "requested scope exceeds the client registration",
    ));
  }
  Ok(want.render())
}

/// Mint a fresh user code whose hash is not already live.
async fn mint_unique_user_code(
  conn: &mut RedisConn,
  store: &Store,
  keys: &crate::keys::KeyRing,
  rng: &mut SysRng,
) -> Result<(String, String), AppError> {
  for _ in 0..MAX_USER_CODE_ATTEMPTS {
    let mut raw = [0u8; USER_CODE_LEN];
    rng
      .try_fill_bytes(&mut raw)
      .map_err(|_| AppError::temporarily_unavailable())?;
    let code: String = raw
      .iter()
      .map(|b| char::from(USER_CODE_ALPHABET[usize::from(*b) % USER_CODE_ALPHABET.len()]))
      .collect();
    let hash = hash_token(keys, &code)?;
    let live: bool = store::device::resolve_user_code(conn, store, &hash)
      .await?
      .is_some();
    if !live {
      return Ok((display_user_code(&code), hash));
    }
  }
  Err(AppError::temporarily_unavailable())
}

/// Render the canonical code as the hyphenated wire form.
#[must_use]
pub fn display_user_code(code: &str) -> String {
  format!("{}-{}", &code[..4], &code[4..])
}

/// Store the sender binding under its sidecar key with the record TTL.
async fn put_binding(
  conn: &mut RedisConn,
  key: &str,
  binding: &DeviceBinding,
  ttl: Duration,
) -> Result<(), AppError> {
  let json = serde_json::to_string(binding).map_err(|_| AppError::server_error())?;
  redis::cmd("SET")
    .arg(key)
    .arg(json)
    .arg("PX")
    .arg(ttl.as_millis() as u64)
    .query_async::<()>(conn)
    .await
    .map_err(store::StoreError::Redis)?;
  Ok(())
}

/// Axum handler for `POST /device_authorization` (wired by task 40).
///
/// Thin glue: `Bytes` + a manual parse replaces `Form<...>` (the extractor
/// consumed the raw body, hiding repeats), then delegates to
/// [`authorize_device`]. The explicit content-type gate preserves the 415
/// `Form` rendered (`Bytes` never fails on content-type), a malformed body
/// or a repeated known field is the same 400, and the repeated `resource`
/// indicator (RFC 8707) is captured in order by
/// `params::repeated_values`.
pub async fn handler(
  State(state): State<AppState>,
  peer_certs: Option<Extension<PeerCertificates>>,
  headers: HeaderMap,
  body: axum::body::Bytes,
) -> axum::response::Response {
  use axum::response::IntoResponse as _;
  if let Err(reject) = crate::protocol::params::require_form_content_type(&headers) {
    return reject.into_response();
  }
  let pairs = match crate::protocol::params::form_pairs(&body) {
    Ok(pairs) => pairs,
    Err(reject) => return reject.into_response(),
  };
  if crate::protocol::params::has_duplicate_field(&pairs, &DeviceAuthorizationForm::KNOWN_FIELDS) {
    return (
      axum::http::StatusCode::BAD_REQUEST,
      "Failed to deserialize form",
    )
      .into_response();
  }
  let map = crate::protocol::params::single_valued_map(&pairs);
  let Some(form) = DeviceAuthorizationForm::from_map(&map) else {
    return (
      axum::http::StatusCode::BAD_REQUEST,
      "Failed to deserialize form",
    )
      .into_response();
  };
  let text = match crate::protocol::params::form_text(&body) {
    Ok(text) => text,
    Err(reject) => return reject.into_response(),
  };
  let resources =
    crate::protocol::params::repeated_values(text, crate::protocol::params::RESOURCE_PARAM);
  let dpop_proof = headers.get("dpop").and_then(|value| value.to_str().ok());
  let basic_header = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok());
  let inputs = DeviceHttpInputs {
    client_id: form.client_id.as_str(),
    scope: form.scope.as_deref(),
    basic_header,
    body_secret: form.client_secret.map(SecretString::from),
    assertion_type: form.client_assertion_type.as_deref(),
    assertion: form.client_assertion.as_deref(),
    dpop_proof,
    resource: &resources,
    peer_certs: peer_certs.as_deref(),
  };
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let mut stores = DeviceStores {
    pool: &state.pool,
    conn: &mut conn,
    store: &store,
    keys: &state.keys,
  };
  let ctx = DeviceContext {
    issuer: &state.config.issuer,
    device_ttl: state.config.ttl.device,
    now_unix: state.clock.now().unix_timestamp(),
    resource_indicators_enabled: state.config.resource_indicators_enabled,
  };
  match authorize_device(&mut stores, &ctx, &inputs).await {
    Ok(response) => axum::Json(response).into_response(),
    Err(error) => error.into_response(),
  }
}

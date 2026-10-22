//! Client authentication dispatch.
//!
//! `client_secret_basic` (RFC 6749 §2.3.1, 401 + `WWW-Authenticate` on
//! failure), `client_secret_post`, `none` (public clients only),
//! `private_key_jwt` (RFC 7523, see [`assertion`]), and `tls_client_auth` /
//! `self_signed_tls_client_auth` (RFC 8705, matching owned by task 21).
//!
//! The caller builds [`ClientAuthRequest`] from the `Authorization` header
//! and the form body ONLY: a secret taken from the query string must never
//! be placed here. Unknown clients, absent credentials on a confidential
//! client, and a presented method that differs from the registered
//! `token_endpoint_auth_method` all collapse to `invalid_client` without
//! revealing which check failed.

pub mod assertion;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_containers;

use secrecy::{ExposeSecret, SecretString};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::{
  db::client_repo::ClientRepoError,
  db::{Client, TokenEndpointAuthMethod, client_repo},
  error::AppError,
  keys::KeyRing,
  protocol::{cimd, mtls},
  state::RedisConn,
  store::Store,
  tls::PeerCertificates,
};

/// Exact `client_assertion_type` value for `private_key_jwt` (RFC 7523 §2.2).
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Canonical token endpoint URL for a given issuer.
///
/// `aud` in a `private_key_jwt` assertion must equal exactly this value.
/// Tasks 31-39 (token handlers) and task 40 (router) must use this helper so
/// issuance and verification can never disagree.
#[must_use]
pub fn token_endpoint(issuer: &str) -> String {
  format!("{issuer}/token")
}

/// Decoded HTTP Basic credentials.
///
/// The secret is a [`SecretString`] so a `Debug` print can never leak it.
#[derive(Debug, Clone)]
pub struct BasicCredentials {
  /// The claimed `client_id` (never empty).
  pub client_id: String,
  /// The presented `client_secret`.
  pub secret: SecretString,
}

/// Decode an `Authorization` header of the form `Basic <base64>`.
///
/// Returns `None` when the scheme is absent, the payload is not valid
/// base64, there is no `:` separator, or the `client_id` is empty. The
/// secret keeps everything after the first `:` (it may itself contain
/// colons). No percent-decoding is applied: ids/secrets are matched
/// exactly, failing closed on exotic characters.
#[must_use]
pub fn parse_basic_header(value: &str) -> Option<BasicCredentials> {
  use base64::Engine as _;

  let encoded = value.strip_prefix("Basic ")?;
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(encoded.trim())
    .ok()?;
  let text = core::str::from_utf8(&decoded).ok()?;
  let (client_id, secret) = text.split_once(':')?;
  if client_id.is_empty() {
    return None;
  }
  Some(BasicCredentials {
    client_id: client_id.to_owned(),
    secret: SecretString::from(secret),
  })
}

/// Whether a client secret is expired: `Some(past) <= now` rejects.
///
/// A client with no expiry (`None`) never expires on this check.
#[must_use]
pub fn is_secret_expired(expires_at: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
  expires_at.is_some_and(|at| at <= now)
}

/// Presented client credentials for one token request.
///
/// Populate ONLY from the `Authorization` header and the parsed form body.
/// A `client_secret` observed in the query string must be dropped, never
/// placed in `body_secret`.
#[derive(Debug)]
pub struct ClientAuthRequest<'a> {
  /// Raw `Authorization` header value, when present.
  pub basic_header: Option<&'a str>,
  /// `client_id` from the form body, when present.
  pub client_id: Option<&'a str>,
  /// `client_secret` from the form body ONLY (never the query), when present.
  pub body_secret: Option<SecretString>,
  /// `client_assertion_type` from the form body, when present.
  pub assertion_type: Option<&'a str>,
  /// `client_assertion` from the form body, when present.
  pub assertion: Option<&'a str>,
  /// Peer certificate chain injected by the TLS accept loop, when present.
  pub peer_certs: Option<&'a PeerCertificates>,
}

/// An authenticated client: the registered row plus the method that proved it.
///
/// A `None` method marks a public client; the grant handlers (tasks 31-35)
/// must still demand PKCE and a DPoP proof at token time before minting.
#[derive(Debug)]
pub struct AuthenticatedClient {
  /// The active registered client row.
  pub client: Client,
  /// The method that authenticated this request.
  pub method: TokenEndpointAuthMethod,
}

/// Datastore handles needed by [`authenticate_client`].
pub struct AuthStores<'a> {
  /// Postgres pool for client lookup and secret verification.
  pub pool: &'a PgPool,
  /// Versioned PII keys for the encrypted client lookup.
  pub keys: &'a KeyRing,
  /// Redis connection for the assertion `jti` replay store.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs for the replay store.
  pub store: &'a Store,
}

/// Request-scoped authentication inputs.
pub struct AuthContext<'a> {
  /// Canonical token endpoint URL (`aud` must equal this exactly).
  pub token_endpoint: &'a str,
  /// Current time for secret-expiry enforcement.
  pub now: OffsetDateTime,
  /// CIMD resolution settings for a registration-free fallback; `None` when
  /// `config.cimd_enabled` is off, so an `https://` `client_id` with no
  /// registered row keeps the existing unknown-client behavior.
  pub cimd: Option<cimd::CimdSettings<'a>>,
}

/// Authenticate a token-request client.
///
/// Exactly one credential style may be presented (RFC 6749 §2.3: servers
/// must not accept more than one method per request). Failures map to
/// `invalid_client`: `401` + `WWW-Authenticate` when Basic was attempted,
/// `400` otherwise.
///
/// # Errors
///
/// Returns `invalid_client` for unknown/inactive clients, method mismatch,
/// expired or wrong secrets, bad assertions, replayed `jti` values, and
/// missing mTLS chains; returns an internal error only when a datastore
/// itself fails.
pub async fn authenticate_client(
  stores: &mut AuthStores<'_>,
  ctx: &AuthContext<'_>,
  req: &ClientAuthRequest<'_>,
) -> Result<AuthenticatedClient, AppError> {
  let mut methods = 0u8;
  if req.basic_header.is_some() {
    methods += 1;
  }
  if req.body_secret.is_some() {
    methods += 1;
  }
  if req.assertion.is_some() {
    methods += 1;
  }
  if methods > 1 {
    return Err(invalid_client_for(req.basic_header.is_some()));
  }

  if let Some(header) = req.basic_header {
    let Some(creds) = parse_basic_header(header) else {
      return Err(invalid_client_for(true));
    };
    if let Some(body_id) = req.client_id
      && body_id != creds.client_id
    {
      return Err(invalid_client_for(true));
    }
    let client = lookup_client(stores, ctx.cimd, &creds.client_id, true).await?;
    require_method(&client, TokenEndpointAuthMethod::ClientSecretBasic, true)?;
    authenticate_secret(
      stores.pool,
      &client,
      creds.secret.expose_secret(),
      ctx.now,
      true,
    )
    .await
  } else if let Some(secret) = req.body_secret.as_ref() {
    let Some(client_id) = req.client_id else {
      return Err(invalid_client_for(false));
    };
    let client = lookup_client(stores, ctx.cimd, client_id, false).await?;
    require_method(&client, TokenEndpointAuthMethod::ClientSecretPost, false)?;
    authenticate_secret(stores.pool, &client, secret.expose_secret(), ctx.now, false).await
  } else if let Some(assertion_str) = req.assertion {
    if req.assertion_type != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) {
      return Err(invalid_client_for(false));
    }
    let client_id = match (req.client_id, assertion::unverified_iss(assertion_str)) {
      (Some(id), Some(iss)) if id != iss => return Err(invalid_client_for(false)),
      (Some(id), _) => id.to_owned(),
      (None, Some(iss)) => iss,
      (None, None) => return Err(invalid_client_for(false)),
    };
    let client = lookup_client(stores, ctx.cimd, &client_id, false).await?;
    require_method(&client, TokenEndpointAuthMethod::PrivateKeyJwt, false)?;
    assertion::authenticate(stores, &client, assertion_str, ctx).await
  } else if let Some(client_id) = req.client_id {
    let client = lookup_client(stores, ctx.cimd, client_id, false).await?;
    match client.auth_method() {
      Ok(TokenEndpointAuthMethod::None) => Ok(AuthenticatedClient {
        client,
        method: TokenEndpointAuthMethod::None,
      }),
      Ok(
        TokenEndpointAuthMethod::TlsClientAuth | TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
      ) => authenticate_tls(stores.pool, stores.keys, &client, req.peer_certs).await,
      Ok(_) | Err(_) => Err(invalid_client_for(false)),
    }
  } else {
    Err(invalid_client_for(false))
  }
}

/// `invalid_client` with the status selected by whether Basic was attempted.
fn invalid_client_for(used_basic: bool) -> AppError {
  if used_basic {
    AppError::invalid_client_basic()
  } else {
    AppError::invalid_client_non_basic()
  }
}

/// Load the client principal: a registered row wins, else a validated CIMD
/// document materialized as a synthetic client (CIMD draft §3/§4.1), else
/// `invalid_client` (never reveal whether the id exists).
///
/// A CIMD fetch or validation failure maps per [`cimd::CimdError`]
/// (`invalid_client_metadata`, `invalid_redirect_uri`, or fail-closed `503`),
/// not to `invalid_client`: the id named a document, but the document itself
/// is unusable.
async fn lookup_client(
  stores: &mut AuthStores<'_>,
  cimd: Option<cimd::CimdSettings<'_>>,
  client_id: &str,
  used_basic: bool,
) -> Result<Client, AppError> {
  match cimd::resolve_client(stores.pool, stores.keys, stores.conn, cimd, client_id).await {
    Ok(Some(client)) => Ok(client),
    Ok(None) => Err(invalid_client_for(used_basic)),
    Err(error) => Err(AppError::from(error)),
  }
}

/// The presented method must equal the registered one; `none` on a
/// confidential client (and any secret/assertion on a `none` client, which
/// cannot reach here) is rejected.
fn require_method(
  client: &Client,
  presented: TokenEndpointAuthMethod,
  used_basic: bool,
) -> Result<(), AppError> {
  match client.auth_method() {
    Ok(registered) if registered == presented => Ok(()),
    Ok(_) | Err(_) => Err(invalid_client_for(used_basic)),
  }
}

/// Enforce `client_secret_expires_at`, then verify the secret hash.
///
/// An expired secret is rejected even when the presented value is correct.
async fn authenticate_secret(
  pool: &PgPool,
  client: &Client,
  presented: &str,
  now: OffsetDateTime,
  used_basic: bool,
) -> Result<AuthenticatedClient, AppError> {
  if is_secret_expired(client.client_secret_expires_at, now) {
    return Err(invalid_client_for(used_basic));
  }
  let method = client
    .auth_method()
    .map_err(|_| invalid_client_for(used_basic))?;
  match client_repo::verify_secret(pool, &client.client_id, presented).await {
    Ok(Some(true)) => Ok(AuthenticatedClient {
      client: client.clone(),
      method,
    }),
    Ok(Some(false) | None) => Err(invalid_client_for(used_basic)),
    Err(ClientRepoError::UnknownAuthMethod(_)) => Err(invalid_client_for(used_basic)),
    Err(ClientRepoError::Database(error)) => Err(AppError::from(error)),
    Err(ClientRepoError::Secret(error)) => Err(AppError::internal(error)),
    Err(ClientRepoError::Task(error)) => Err(AppError::internal(error)),
  }
}

/// mTLS client authentication (RFC 8705 §2).
///
/// Reads the verified chain injected as [`PeerCertificates`] by the custom
/// accept loop and delegates certificate-to-client matching (thumbprint
/// pinning, subject-DN) to [`crate::protocol::mtls::authenticate`]. A missing
/// or unregistered certificate fails closed as `invalid_client`.
async fn authenticate_tls(
  pool: &PgPool,
  keys: &KeyRing,
  client: &Client,
  peer_certs: Option<&PeerCertificates>,
) -> Result<AuthenticatedClient, AppError> {
  let method = client
    .auth_method()
    .map_err(|_| AppError::invalid_client_non_basic())?;
  let leaf = peer_certs.and_then(|certs| certs.chain().first());
  mtls::authenticate(pool, keys, client, leaf)
    .await
    .map_err(mtls::MtlsError::into_app_error)?;
  Ok(AuthenticatedClient {
    client: client.clone(),
    method,
  })
}

//! `POST /token` grant dispatcher (RFC 6749 §5, RFC 8693 §2, RFC 9449 §6).
//!
//! Parses the form once, authenticates the client through the shared
//! [`client_auth`] dispatch (or delegates to the grants that authenticate
//! themselves), verifies the fresh sender proof, dispatches on `grant_type`,
//! and shapes the RFC 6749 §5.1 JSON response. Unknown grant types fail
//! closed with `unsupported_grant_type`.
//!
//! The per-grant branches live in [`grants`]; this module owns the HTTP
//! contract, the request-scoped handles, and the shared authentication and
//! proof helpers.

mod grants;

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::grants::device_code::DevicePollError;
use super::{ClientKind, SenderProof, TokenService};
use crate::{
  db::{TokenEndpointAuthMethod, client_repo, scope_repo},
  error::AppError,
  jose::dpop::{DpopRequest, verify_dpop},
  protocol::{
    client_auth::{self, AuthContext, AuthStores, ClientAuthRequest},
    mtls,
    scope::ScopeSet,
  },
  state::{AppState, RedisConn},
  store::Store,
  tls::PeerCertificates,
};

/// `POST /token` request form (RFC 6749 §4 plus every extension this server
/// supports). All fields are optional here: each grant validates its own
/// required members and answers `invalid_request` when one is missing.
#[derive(Debug, Default, Deserialize)]
pub struct TokenForm {
  /// The grant being exercised.
  pub grant_type: Option<String>,
  /// Authorization code (authorization-code grant).
  pub code: Option<String>,
  /// Redirect URI bound to the code (authorization-code grant).
  pub redirect_uri: Option<String>,
  /// PKCE verifier (authorization-code grant).
  pub code_verifier: Option<String>,
  /// Refresh token (refresh-token grant).
  pub refresh_token: Option<String>,
  /// Client identifier, from the form body.
  pub client_id: Option<String>,
  /// Client secret, from the form body only.
  pub client_secret: Option<String>,
  /// Requested scope, or `None` to keep the grant's scope.
  pub scope: Option<String>,
  /// Device code (device-code grant).
  pub device_code: Option<String>,
  /// Subject token (token-exchange grant).
  pub subject_token: Option<String>,
  /// Subject token type URN (token-exchange grant).
  pub subject_token_type: Option<String>,
  /// Actor token (token-exchange grant).
  pub actor_token: Option<String>,
  /// Actor token type URN (token-exchange grant).
  pub actor_token_type: Option<String>,
  /// Requested token type URN (token-exchange grant).
  pub requested_token_type: Option<String>,
  /// Token type hint (accepted for RFC 7009/7662 parity; never trusted).
  pub token_type_hint: Option<String>,
  /// `private_key_jwt` assertion type.
  pub client_assertion_type: Option<String>,
  /// `private_key_jwt` assertion.
  pub client_assertion: Option<String>,
}

/// RFC 6749 §5.1 token response plus the RFC 8693 §2.2.1
/// `issued_token_type` member. Optional members are omitted, never null.
#[derive(Debug, Serialize)]
struct TokenResponseBody {
  /// Opaque access token.
  access_token: String,
  /// `DPoP` or `Bearer`.
  token_type: String,
  /// Access-token lifetime, seconds.
  expires_in: u64,
  /// Opaque refresh token, absent for grants that issue none.
  #[serde(skip_serializing_if = "Option::is_none")]
  refresh_token: Option<String>,
  /// Space-joined effective scope.
  scope: String,
  /// Token-exchange result type, absent for every other grant.
  #[serde(skip_serializing_if = "Option::is_none")]
  issued_token_type: Option<String>,
}

/// Token-endpoint failure: the RFC 6749 error model plus the RFC 8628 §3.5
/// polling codes.
enum TokenError {
  /// A protocol or dependency failure with its own status.
  OAuth(AppError),
  /// A device-polling failure (`authorization_pending`, `slow_down`, ...).
  Device(DevicePollError),
}

impl From<AppError> for TokenError {
  fn from(error: AppError) -> Self {
    Self::OAuth(error)
  }
}

impl From<DevicePollError> for TokenError {
  fn from(error: DevicePollError) -> Self {
    Self::Device(error)
  }
}

impl IntoResponse for TokenError {
  fn into_response(self) -> Response {
    match self {
      Self::OAuth(error) => error.into_response(),
      Self::Device(error) => error.into_response(),
    }
  }
}

/// Request-scoped handles shared by every grant branch.
struct Dispatch<'a> {
  /// Shared application state.
  state: &'a AppState,
  /// Redis connection for codes, tokens, proofs, and replay markers.
  conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  store: &'a Store,
  /// Request headers (Basic credentials, `DPoP` proof).
  headers: &'a HeaderMap,
  /// Parsed form body.
  form: &'a TokenForm,
  /// Verified peer chain injected by the TLS accept loop, when present.
  peer_certs: Option<&'a PeerCertificates>,
  /// Current time as seconds since the Unix epoch.
  now_unix: i64,
}

impl Dispatch<'_> {
  /// Authenticate the token-request client through the shared dispatch.
  async fn authenticate(&mut self) -> Result<client_auth::AuthenticatedClient, AppError> {
    let endpoint = client_auth::token_endpoint(&self.state.config.issuer);
    let request = ClientAuthRequest {
      basic_header: basic_header(self.headers),
      client_id: self.form.client_id.as_deref(),
      body_secret: self.form.client_secret.clone().map(SecretString::from),
      assertion_type: self.form.client_assertion_type.as_deref(),
      assertion: self.form.client_assertion.as_deref(),
      peer_certs: self.peer_certs,
    };
    let mut stores = AuthStores {
      pool: &self.state.pool,
      conn: &mut *self.conn,
      store: self.store,
    };
    let ctx = AuthContext {
      token_endpoint: &endpoint,
      now: self.state.clock.now(),
    };
    client_auth::authenticate_client(&mut stores, &ctx, &request).await
  }

  /// Verify this request's fresh sender proofs (DPoP `jkt`, mTLS `x5t#S256`).
  async fn sender_proof(&mut self, client: &client_repo::Client) -> Result<SenderProof, AppError> {
    let htu = client_auth::token_endpoint(&self.state.config.issuer);
    let dpop_jkt = match dpop_proof(self.headers) {
      Some(proof) => Some(
        verify_dpop(
          &mut *self.conn,
          self.store,
          &DpopRequest {
            proof: Some(proof),
            htm: "POST",
            htu: &htu,
            access_token: None,
            now_unix: self.now_unix,
          },
        )
        .await?
        .jkt,
      ),
      None => None,
    };
    let mtls_x5t_s256 = match client.auth_method() {
      Ok(
        TokenEndpointAuthMethod::TlsClientAuth | TokenEndpointAuthMethod::SelfSignedTlsClientAuth,
      ) => {
        let leaf = self.peer_certs.and_then(|certs| certs.chain().first());
        Some(
          mtls::authenticate(&self.state.pool, client, leaf)
            .await
            .map_err(mtls::MtlsError::into_app_error)?
            .x5t_s256,
        )
      }
      _ => None,
    };
    Ok(SenderProof {
      dpop_jkt,
      mtls_x5t_s256,
    })
  }
}

/// The raw `Authorization` header, when present and UTF-8.
fn basic_header(headers: &HeaderMap) -> Option<&str> {
  headers
    .get(header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
}

/// The raw `DPoP` proof header, when present and UTF-8.
fn dpop_proof(headers: &HeaderMap) -> Option<&str> {
  headers.get("dpop").and_then(|value| value.to_str().ok())
}

/// Public vs confidential: the sender-constraint matrix selector.
fn client_kind(client: &client_repo::Client) -> Result<ClientKind, AppError> {
  match client.auth_method() {
    Ok(TokenEndpointAuthMethod::None) => Ok(ClientKind::Public),
    Ok(_) => Ok(ClientKind::Confidential),
    Err(_) => Err(AppError::invalid_client_non_basic()),
  }
}

/// The client must be registered for the grant it is exercising.
fn require_grant(client: &client_repo::Client, grant: &str) -> Result<(), AppError> {
  if client
    .grant_types
    .iter()
    .any(|registered| registered == grant)
  {
    Ok(())
  } else {
    Err(AppError::unauthorized_client(
      "client may not use this grant",
    ))
  }
}

/// A client registered for DPoP-bound tokens must present a fresh proof.
///
/// Shared with the grants that authenticate their client internally
/// (`authorization_code`, `device_code`) so the registration flag is enforced
/// on every token-time path, not only the dispatcher-authenticated ones.
pub(super) fn require_dpop_binding(
  client: &client_repo::Client,
  proof: &SenderProof,
) -> Result<(), AppError> {
  let proven = proof.dpop_jkt.as_deref().is_some_and(|jkt| !jkt.is_empty());
  if client.dpop_bound_access_tokens && !proven {
    Err(AppError::invalid_grant(
      "DPoP proof is required for this client",
    ))
  } else {
    Ok(())
  }
}

/// The enabled scope catalog as a set.
async fn enabled_scopes(pool: &PgPool) -> Result<ScopeSet, AppError> {
  let names: Vec<String> = scope_repo::list_enabled(pool)
    .await?
    .into_iter()
    .map(|row| row.name)
    .collect();
  ScopeSet::from_names(&names)
}

/// Build the token service from the validated TTLs and key ring.
fn token_service(state: &AppState) -> Result<TokenService, AppError> {
  TokenService::new(&state.config.ttl, &state.keys).map_err(AppError::from)
}

/// `POST /token`: the five-grant dispatcher.
///
/// # Errors
///
/// Returns the RFC 6749 §5.2 error for the failing grant (or the RFC 8628
/// §3.5 polling code), always with the correct HTTP status.
pub async fn handler(
  State(state): State<AppState>,
  peer_certs: Option<Extension<PeerCertificates>>,
  headers: HeaderMap,
  form: axum::Form<TokenForm>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let now_unix = state.clock.now().unix_timestamp();
  let mut dispatch = Dispatch {
    state: &state,
    conn: &mut conn,
    store: &store,
    headers: &headers,
    form: &form,
    peer_certs: peer_certs.as_deref(),
    now_unix,
  };
  match grants::dispatch_grant(&mut dispatch).await {
    Ok(body) => token_response(body),
    Err(error) => error.into_response(),
  }
}

/// Shape a success response: JSON plus the RFC 6749 §5.1 no-store headers.
fn token_response(body: TokenResponseBody) -> Response {
  let mut response = Json(body).into_response();
  response
    .headers_mut()
    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
  response
    .headers_mut()
    .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
  response
}

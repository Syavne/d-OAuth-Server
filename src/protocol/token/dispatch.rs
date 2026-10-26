//! `POST /token` grant dispatcher (RFC 6749 §5, RFC 8693 §2, RFC 9449 §6).
//!
//! Parses the form once, authenticates the client through the shared
//! [`client_auth`] dispatch (or delegates to the grants that authenticate
//! themselves), verifies the fresh sender proof, dispatches on `grant_type`,
//! and shapes the RFC 6749 §5.1 JSON response. A missing `grant_type` is
//! `invalid_request`; an unknown one fails closed with `unsupported_grant_type`.
//!
//! The per-grant branches live in [`grants`]; this module owns the HTTP
//! contract, the request-scoped handles, and the shared authentication and
//! proof helpers.

mod grants;

use axum::Json;
use axum::extract::{Extension, RawForm, State};
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
  jose::{
    dpop::{DpopRequest, verify_dpop},
    jwt_access::JwtAccessSigner,
  },
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

impl TokenForm {
  /// Fields the extractor recognizes: a repeat of any of these is the
  /// duplicate-field rejection (mapped to `invalid_request`, per RFC 6749
  /// §5.2 "includes a parameter more than once"). Unknown fields (including
  /// a repeated `resource`) are silently absorbed, as `serde_urlencoded`
  /// absorbed them.
  const KNOWN_FIELDS: [&str; 17] = [
    "grant_type",
    "code",
    "redirect_uri",
    "code_verifier",
    "refresh_token",
    "client_id",
    "client_secret",
    "scope",
    "device_code",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "requested_token_type",
    "token_type_hint",
    "client_assertion_type",
    "client_assertion",
  ];

  /// Build the form from a strict single-valued map (the `Bytes` extractor
  /// replacement for `Form<TokenForm>`). Every member is optional: each
  /// grant validates its own required members.
  fn from_map(map: &std::collections::HashMap<String, String>) -> Self {
    Self {
      grant_type: map.get("grant_type").cloned(),
      code: map.get("code").cloned(),
      redirect_uri: map.get("redirect_uri").cloned(),
      code_verifier: map.get("code_verifier").cloned(),
      refresh_token: map.get("refresh_token").cloned(),
      client_id: map.get("client_id").cloned(),
      client_secret: map.get("client_secret").cloned(),
      scope: map.get("scope").cloned(),
      device_code: map.get("device_code").cloned(),
      subject_token: map.get("subject_token").cloned(),
      subject_token_type: map.get("subject_token_type").cloned(),
      actor_token: map.get("actor_token").cloned(),
      actor_token_type: map.get("actor_token_type").cloned(),
      requested_token_type: map.get("requested_token_type").cloned(),
      token_type_hint: map.get("token_type_hint").cloned(),
      client_assertion_type: map.get("client_assertion_type").cloned(),
      client_assertion: map.get("client_assertion").cloned(),
    }
  }
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
  /// Raw repeated `resource` values (RFC 8707) from this token request, in
  /// wire order; empty when the request carried no `resource`. Each grant
  /// validates this set against the catalog AFTER authenticating the client,
  /// so an unauthenticated caller observes `invalid_client` first.
  resources: &'a [String],
  /// CIMD resolution settings for a registration-free fallback; `None` when
  /// `config.cimd_enabled` is off.
  cimd: Option<crate::protocol::cimd::CimdSettings<'a>>,
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
      keys: &self.state.keys,
      conn: &mut *self.conn,
      store: self.store,
    };
    let ctx = AuthContext {
      token_endpoint: &endpoint,
      now: self.state.clock.now(),
      cimd: self.cimd.clone(),
    };
    client_auth::authenticate_client(&mut stores, &ctx, &request).await
  }

  /// Enforce this client's access-token format on a minting path.
  ///
  /// `opaque` returns without constructing the JWT signer or reading any key
  /// material; a `jwt` client whose global switch is off (or any unrecognized
  /// stored value) fails closed with `temporarily_unavailable` (503).
  fn require_token_format(&self, client: &client_repo::Client) -> Result<TokenFormat, AppError> {
    resolve_token_format(
      &client.access_token_format,
      self.state.config.jwt_access_tokens_enabled,
    )
  }

  /// Apply the format gate to a grant that authenticates inside its own
  /// module (`authorization_code`, `device_code`), and report the resolved
  /// format for the mint call.
  ///
  /// Before delegation the dispatcher only knows a candidate presenter id. An
  /// unknown or inactive client, or a structurally inconsistent Basic/body
  /// pair, is left to the grant's existing `invalid_client` path so error
  /// precedence does not change (`Ok(None)`: the grant never mints). A
  /// client the dispatcher can name is gated first, so a `jwt` client with
  /// the global switch off never reaches minting (and never burns a code or
  /// a device poll). A registration-free CIMD id resolves to `Ok(None)` here
  /// and to `Opaque` at the call site: the synthetic principal is always
  /// `opaque` by construction (a document can never opt into JWT), so no
  /// format gate is skipped.
  async fn gate_candidate_client_format(
    &self,
    client_id: Option<String>,
  ) -> Result<Option<TokenFormat>, AppError> {
    let Some(client_id) = client_id else {
      return Ok(None);
    };
    let Some(client) =
      client_repo::find_active_by_client_id(&self.state.pool, &self.state.keys, &client_id).await?
    else {
      return Ok(None);
    };
    self.require_token_format(&client).map(Some)
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
          mtls::authenticate(&self.state.pool, &self.state.keys, client, leaf)
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

/// Re-exported from [`super::types`], where the decision type lives so both
/// this dispatcher and [`super::service`] share it without a module cycle.
pub use super::types::TokenFormat;

/// Resolve a client's stored `access_token_format` to a [`TokenFormat`].
///
/// `opaque` is the default and never consults the JWT stack. RFC 9068 §2 makes
/// JWT access tokens an opt-in profile the authorization server decides per
/// client; §4 ties issuance to signing-key material, so a `jwt` client is
/// accepted only while the operator's global `jwt_access_tokens_enabled`
/// switch is on. When that switch is off — or the stored value is unknown
/// (corruption or a future value) — the request fails closed with
/// `temporarily_unavailable` (HTTP 503): the client asked for a token shape
/// this deployment cannot mint, so there is no silent opaque fallback and no
/// partial token. It is deliberately not `server_error` (HTTP 500), which
/// would retract the fail-closed dependency contract, and not a 4xx, which
/// would blame the client for a deployment state.
fn resolve_token_format(
  stored: &str,
  jwt_access_tokens_enabled: bool,
) -> Result<TokenFormat, AppError> {
  match stored {
    "opaque" => Ok(TokenFormat::Opaque),
    "jwt" if jwt_access_tokens_enabled => Ok(TokenFormat::Jwt),
    "jwt" => Err(AppError::temporarily_unavailable()),
    _ => Err(AppError::temporarily_unavailable()),
  }
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

/// Build the JWT signer for a `Jwt` mint from the validated config: the
/// active `jwt_signing_key` signs, previous keys verify only. Fail-closed
/// `temporarily_unavailable` when no key is configured (the format gate
/// guarantees this is unreachable in practice): never a 500, and the typed
/// [`crate::jose::jwt_access::JwtError`] carries no key material.
fn jwt_signer(state: &AppState) -> Result<JwtAccessSigner, AppError> {
  JwtAccessSigner::from_config(&state.config).map_err(|_| AppError::temporarily_unavailable())
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
  body: RawForm,
) -> Response {
  // `RawForm` gates the content type BEFORE `Bytes` buffering, so a wrong
  // content type is rejected 415 without reading the (up to 2 MiB) body.
  // The explicit exact-MIME gate below is the second check: `RawForm` uses a
  // case-sensitive prefix match, so it accepts e.g.
  // `application/x-www-form-urlencodedevil`, which the exact gate rejects.
  let body = body.0;
  // `RawForm` + a manual parse replaces `Result<Form<TokenForm>, FormRejection>`:
  // the extractor consumed the raw body, hiding repeats. The explicit
  // exact-MIME gate below is the second content-type check (see above); any
  // other transport failure keeps the documented `invalid_request` mapping
  // ("includes a parameter more than once"). The repeated `resource`
  // indicator (RFC 8707) is captured in order by `params::values_of` and
  // carried raw on the dispatcher: each grant validates it against the
  // catalog AFTER authenticating the client, so an unauthenticated caller
  // observes `invalid_client` before any catalog error.
  if let Err(reject) = crate::protocol::params::require_form_content_type(&headers) {
    return reject.into_response();
  }
  let malformed = || {
    AppError::invalid_request(
      "the request body is malformed or includes a parameter more than once",
    )
  };
  let text = match std::str::from_utf8(&body) {
    Ok(text) => text,
    Err(_) => return TokenError::from(malformed()).into_response(),
  };
  let pairs = match crate::protocol::params::parse_pairs(text) {
    Ok(pairs) => pairs,
    Err(_) => return TokenError::from(malformed()).into_response(),
  };
  if crate::protocol::params::has_duplicate_field(&pairs, &TokenForm::KNOWN_FIELDS) {
    return TokenError::from(malformed()).into_response();
  }
  let map = crate::protocol::params::single_valued_map(&pairs);
  let form = TokenForm::from_map(&map);
  let resources =
    crate::protocol::params::values_of(&pairs, crate::protocol::params::RESOURCE_PARAM);
  // RFC 8707 resource indicators do not apply to RFC 8693 token exchange;
  // reject the parameter BEFORE the catalog lookup so a bogus value cannot
  // surface `invalid_target` from a grant that must answer `invalid_request`.
  if form.grant_type.as_deref()
    == Some(crate::protocol::token::grants::token_exchange::GRANT_TYPE_TOKEN_EXCHANGE)
    && !resources.is_empty()
  {
    return TokenError::from(AppError::invalid_request(
      "resource is not supported by token-exchange",
    ))
    .into_response();
  }
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
    resources: &resources,
    cimd: state
      .config
      .cimd_enabled
      .then(|| crate::protocol::cimd::CimdSettings {
        token_prefix: &state.config.redis.token_key_prefix,
        max_bytes: state.config.cimd_max_bytes,
        timeout: state.config.cimd_fetch_timeout,
        allow_localhost: state.config.allow_localhost_redirect,
        fetcher: state.cimd_fetcher.clone(),
      }),
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

#[cfg(test)]
mod tests {
  use axum::http::StatusCode;

  use super::{TokenFormat, resolve_token_format};

  #[test]
  fn unknown_format_fails_closed_503() {
    let unknown = resolve_token_format("bogus", true)
      .err()
      .map(|error| error.status());
    assert_eq!(unknown, Some(StatusCode::SERVICE_UNAVAILABLE));
    let jwt_off = resolve_token_format("jwt", false)
      .err()
      .map(|error| error.status());
    assert_eq!(jwt_off, Some(StatusCode::SERVICE_UNAVAILABLE));
    assert!(matches!(
      resolve_token_format("opaque", false),
      Ok(TokenFormat::Opaque)
    ));
    assert!(matches!(
      resolve_token_format("opaque", true),
      Ok(TokenFormat::Opaque)
    ));
    assert!(matches!(
      resolve_token_format("jwt", true),
      Ok(TokenFormat::Jwt)
    ));
  }
}

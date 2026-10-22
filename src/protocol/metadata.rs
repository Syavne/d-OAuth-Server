//! Authorization-server metadata (RFC 8414).
//!
//! `GET /.well-known/oauth-authorization-server` returns the AS document. The
//! only server-state-dependent member is `scopes_supported`: it is read from
//! the enabled `scopes` table (the single source of truth, populated at runtime
//! via `config sync` / `scope create`) on every request. The catalog is mutated
//! out of process by the CLI, so an in-process cache could not be invalidated
//! across replicas; a per-request read makes a mutation visible immediately with
//! no restart. When Postgres is unavailable the endpoint fails closed with `503
//! temporarily_unavailable` rather than advertising an unknown scope list.
//!
//! The JWT access-token feature adds two conditional members: `jwks_uri`
//! (RFC 8414 §2), pointing at `GET /jwks.json`, and
//! `access_token_signing_alg_values_supported` (RFC 9068 §2.1), whose list is
//! exactly the configured `jwt_access_token_signing_alg`. Both are ABSENT
//! unless `jwt_access_tokens_enabled` is set, so a client never sees a key or
//! an algorithm the signer would not honor. There is no RSA branch: the
//! signer produces `ES256` or `EdDSA` only.
//!
//! `code_challenge_methods_supported` advertises `S256` only; `plain` is
//! never offered.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{config::JwtSigningAlg, db::scope_repo, error::AppError, state::AppState};

/// The five grant types this server supports (RFC 6749, RFC 8628, RFC 8693).
pub const GRANT_TYPES_SUPPORTED: [&str; 5] = [
  "authorization_code",
  "refresh_token",
  "client_credentials",
  "urn:ietf:params:oauth:grant-type:device_code",
  "urn:ietf:params:oauth:grant-type:token-exchange",
];

/// Client-authentication methods accepted at the token endpoint.
///
/// `none` covers public clients; `tls_client_auth` and
/// `self_signed_tls_client_auth` are the RFC 8705 mTLS methods.
pub const TOKEN_AUTH_METHODS: [&str; 6] = [
  "client_secret_basic",
  "client_secret_post",
  "none",
  "private_key_jwt",
  "tls_client_auth",
  "self_signed_tls_client_auth",
];

/// Methods accepted at the revocation endpoint (RFC 7009). Public clients may
/// revoke their own tokens, so `none` is included.
pub const REVOCATION_AUTH_METHODS: [&str; 6] = TOKEN_AUTH_METHODS;

/// Methods accepted at the introspection endpoint (RFC 7662). Introspection
/// requires an authenticated caller, so `none` is not offered.
pub const INTROSPECTION_AUTH_METHODS: [&str; 5] = [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "tls_client_auth",
  "self_signed_tls_client_auth",
];

/// JWS algorithms accepted for `private_key_jwt` client assertions
/// (`token_endpoint_auth_signing_alg_values_supported`); kept in sync with
/// `protocol::client_auth::assertion::ALLOWED_ALGS`.
pub const CLIENT_ASSERTION_SIGNING_ALG_VALUES: [&str; 4] = ["ES256", "EdDSA", "RS256", "PS256"];

/// JWS algorithms accepted for DPoP proofs (`dpop_signing_alg_values_supported`).
pub const DPOP_SIGNING_ALG_VALUES: [&str; 3] = ["ES256", "EdDSA", "RS256"];

/// RFC 8414 authorization-server metadata document.
#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
  /// Public issuer identifier.
  pub issuer: String,
  /// Authorization endpoint.
  pub authorization_endpoint: String,
  /// Token endpoint.
  pub token_endpoint: String,
  /// Dynamic client-registration endpoint.
  pub registration_endpoint: String,
  /// Token-introspection endpoint.
  pub introspection_endpoint: String,
  /// Token-revocation endpoint.
  pub revocation_endpoint: String,
  /// Pushed authorization request endpoint.
  pub pushed_authorization_request_endpoint: String,
  /// Device authorization endpoint.
  pub device_authorization_endpoint: String,
  /// Response types supported (code only).
  pub response_types_supported: [&'static str; 1],
  /// Grant types supported.
  pub grant_types_supported: [&'static str; 5],
  /// Token-endpoint client-authentication methods.
  pub token_endpoint_auth_methods_supported: [&'static str; 6],
  /// Signing algorithms for `private_key_jwt` client assertions.
  pub token_endpoint_auth_signing_alg_values_supported: [&'static str; 4],
  /// Introspection-endpoint client-authentication methods.
  pub introspection_endpoint_auth_methods_supported: [&'static str; 5],
  /// Revocation-endpoint client-authentication methods.
  pub revocation_endpoint_auth_methods_supported: [&'static str; 6],
  /// PKCE code-challenge methods (`S256` only; `plain` is never offered).
  pub code_challenge_methods_supported: [&'static str; 1],
  /// DPoP proof signing algorithms.
  pub dpop_signing_alg_values_supported: [&'static str; 3],
  /// Whether mTLS-bound access tokens are supported (RFC 8705).
  pub tls_client_certificate_bound_access_tokens: bool,
  /// Whether the `iss` authorization-response parameter is supported (RFC 9207).
  pub authorization_response_iss_parameter_supported: bool,
  /// Enabled scope catalog (single source of truth: the `scopes` table).
  pub scopes_supported: Vec<String>,
  /// RFC 9728 §4 resource identifiers this AS can mint tokens for. Omitted
  /// unless `protected_resources_enabled` is set. `resource_metadata` is a
  /// resource-server `WWW-Authenticate` parameter (§5.1), never an AS member.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub protected_resources: Option<Vec<String>>,
  /// Whether the RFC 8707 `resource` request parameter is honored.
  ///
  /// A vetted LOCAL EXTENSION: RFC 8707 registers only the `resource`
  /// parameter (RFC 8707 §5.1) and the `invalid_target` error (§5.2); it
  /// defines no authorization-server metadata member. The member is emitted
  /// as `true` only when `resource_indicators_enabled` is set and is ABSENT
  /// (not `false`) otherwise, so a client never sees a capability the server
  /// would reject with `invalid_target`.
  #[serde(skip_serializing_if = "std::ops::Not::not")]
  pub resource_indicators_supported: bool,
  /// Whether a `client_id` URL may name a Client ID Metadata Document.
  ///
  /// The CIMD draft's "Authorization Server Metadata" section
  /// (`draft-ietf-oauth-client-id-metadata-document-02` §6) registers this
  /// Boolean in the RFC 8414 metadata document; it is emitted as `true` only
  /// when `cimd_enabled` is set and is ABSENT (not `false`) otherwise. Client
  /// interoperability requires it TOGETHER with `none` in
  /// [`Self::token_endpoint_auth_methods_supported`]: mainstream MCP clients
  /// select CIMD only when both are present (the CIMD client is a public
  /// client unless its document publishes a key, §4.1).
  #[serde(skip_serializing_if = "std::ops::Not::not")]
  pub client_id_metadata_document_supported: bool,
  /// Public JWK Set (RFC 7517 §5) for verifying the AS's own signed access
  /// tokens (RFC 9068 §4). Omitted unless `jwt_access_tokens_enabled` is set.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jwks_uri: Option<String>,
  /// JWS algorithms the access-token signer can produce (RFC 9068 §2.1).
  ///
  /// Exactly the configured `jwt_access_token_signing_alg` (`ES256` or
  /// `EdDSA`), never a broader list: the signer has no RSA branch, so
  /// advertising `RS256` would name an algorithm no key can produce. Omitted
  /// unless `jwt_access_tokens_enabled` is set.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub access_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl AuthorizationServerMetadata {
  /// Build the document for `issuer` with the given enabled scope catalog.
  ///
  /// `issuer` is validated elsewhere to be absolute `https` with no trailing
  /// slash, so endpoint paths append directly.
  #[must_use]
  pub fn for_issuer(
    issuer: &str,
    scopes_supported: Vec<String>,
    protected_resources: Option<Vec<String>>,
    resource_indicators_supported: bool,
    client_id_metadata_document_supported: bool,
    jwt_signing_alg: Option<JwtSigningAlg>,
  ) -> Self {
    let jwks_uri = jwt_signing_alg.map(|_| endpoint(issuer, "/jwks.json"));
    let access_token_signing_alg_values_supported =
      jwt_signing_alg.map(|alg| vec![alg.as_str().to_owned()]);
    Self {
      issuer: issuer.to_owned(),
      authorization_endpoint: endpoint(issuer, "/authorize"),
      token_endpoint: endpoint(issuer, "/token"),
      registration_endpoint: endpoint(issuer, "/register"),
      introspection_endpoint: endpoint(issuer, "/introspect"),
      revocation_endpoint: endpoint(issuer, "/revoke"),
      pushed_authorization_request_endpoint: endpoint(issuer, "/par"),
      device_authorization_endpoint: endpoint(issuer, "/device_authorization"),
      response_types_supported: ["code"],
      grant_types_supported: GRANT_TYPES_SUPPORTED,
      token_endpoint_auth_methods_supported: TOKEN_AUTH_METHODS,
      token_endpoint_auth_signing_alg_values_supported: CLIENT_ASSERTION_SIGNING_ALG_VALUES,
      introspection_endpoint_auth_methods_supported: INTROSPECTION_AUTH_METHODS,
      revocation_endpoint_auth_methods_supported: REVOCATION_AUTH_METHODS,
      code_challenge_methods_supported: ["S256"],
      dpop_signing_alg_values_supported: DPOP_SIGNING_ALG_VALUES,
      tls_client_certificate_bound_access_tokens: true,
      authorization_response_iss_parameter_supported: true,
      scopes_supported,
      protected_resources,
      resource_indicators_supported,
      client_id_metadata_document_supported,
      jwks_uri,
      access_token_signing_alg_values_supported,
    }
  }
}

/// Append an endpoint path to the (trailing-slash-free) issuer.
fn endpoint(issuer: &str, path: &str) -> String {
  format!("{issuer}{path}")
}

/// `GET /.well-known/oauth-authorization-server`.
///
/// # Errors
/// Returns `503 temporarily_unavailable` when Postgres is unreachable and the
/// enabled scope list cannot be read.
pub async fn metadata(
  State(state): State<AppState>,
) -> Result<Json<AuthorizationServerMetadata>, AppError> {
  let rows = scope_repo::list_enabled(&state.pool).await?;
  let mut scopes: Vec<String> = rows.into_iter().map(|row| row.name).collect();
  scopes.sort();
  let protected_resources = state
    .config
    .protected_resources_enabled
    .then(|| state.config.protected_resource_ids.clone());
  let jwt_signing_alg = state
    .config
    .jwt_access_tokens_enabled
    .then_some(state.config.jwt_access_token_signing_alg);
  Ok(Json(AuthorizationServerMetadata::for_issuer(
    &state.config.issuer,
    scopes,
    protected_resources,
    state.config.resource_indicators_enabled,
    state.config.cimd_enabled,
    jwt_signing_alg,
  )))
}

#[cfg(test)]
mod tests;

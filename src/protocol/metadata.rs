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
//! No `jwks_uri`: the AS signs nothing (there is no AS JWT-signing key), and
//! `code_challenge_methods_supported` advertises `S256` only — `plain` is
//! never offered.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{db::scope_repo, error::AppError, state::AppState};

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

/// JWS algorithms accepted for `private_key_jwt` assertions and DPoP proofs.
pub const SIGNING_ALG_VALUES: [&str; 3] = ["ES256", "EdDSA", "RS256"];

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
  pub token_endpoint_auth_signing_alg_values_supported: [&'static str; 3],
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
}

impl AuthorizationServerMetadata {
  /// Build the document for `issuer` with the given enabled scope catalog.
  ///
  /// `issuer` is validated elsewhere to be absolute `https` with no trailing
  /// slash, so endpoint paths append directly.
  #[must_use]
  pub fn for_issuer(issuer: &str, scopes_supported: Vec<String>) -> Self {
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
      token_endpoint_auth_signing_alg_values_supported: SIGNING_ALG_VALUES,
      introspection_endpoint_auth_methods_supported: INTROSPECTION_AUTH_METHODS,
      revocation_endpoint_auth_methods_supported: REVOCATION_AUTH_METHODS,
      code_challenge_methods_supported: ["S256"],
      dpop_signing_alg_values_supported: SIGNING_ALG_VALUES,
      tls_client_certificate_bound_access_tokens: true,
      authorization_response_iss_parameter_supported: true,
      scopes_supported,
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
  Ok(Json(AuthorizationServerMetadata::for_issuer(
    &state.config.issuer,
    scopes,
  )))
}

#[cfg(test)]
mod tests;

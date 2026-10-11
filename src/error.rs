//! RFC error model and HTTP responses.
//!
//! `AppError` maps OAuth 2.1, DPoP (RFC 9449 §9), and JAR (RFC 9101 §5)
//! error codes onto the correct HTTP status and a JSON body of the shape
//! `{"error": "...", "error_description": "..."}`.
//!
//! `invalid_client` renders `401 Unauthorized` with a `WWW-Authenticate`
//! challenge when the client used HTTP Basic, and `400 Bad Request`
//! otherwise (RFC 6749 §5.2). Internal failures collapse to `server_error`
//! with a generic description, so database text, backtraces, or secrets can
//! never reach a client.

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// `WWW-Authenticate` challenge advertised for a failed HTTP Basic attempt.
const BASIC_CHALLENGE: &str = "Basic realm=\"oauth\"";

/// `WWW-Authenticate` challenge advertised for a failed Bearer token attempt
/// (RFC 6750 §3, DCR initial/registration access tokens).
const BEARER_CHALLENGE: &str = "Bearer realm=\"oauth\"";

/// `Retry-After` value (seconds) sent with `temporarily_unavailable`.
const RETRY_AFTER_SECS: &str = "1";

/// An RFC OAuth error code understood by this authorization server.
///
/// Codes are grouped by the endpoint that can emit them: authorization
/// endpoint (`invalid_request`, `unauthorized_client`, `access_denied`,
/// `unsupported_response_type`, `invalid_scope`, `server_error`,
/// `temporarily_unavailable`), token endpoint (the authorization set plus
/// `invalid_client`, `invalid_grant`, `unsupported_grant_type`,
/// `invalid_target`), DPoP (RFC 9449: `invalid_dpop_proof`), JAR
/// (RFC 9101: `invalid_request_object`), and dynamic client registration
/// (RFC 7591: `invalid_redirect_uri`, `invalid_client_metadata`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthErrorCode {
  /// The request is malformed or missing a required parameter.
  InvalidRequest,
  /// The client may not use this grant or response type.
  UnauthorizedClient,
  /// The resource owner or authorization server denied the request.
  AccessDenied,
  /// The authorization server does not support this response type.
  UnsupportedResponseType,
  /// The requested scope is invalid, unknown, or malformed.
  InvalidScope,
  /// An unexpected server-side condition prevented fulfillment.
  ServerError,
  /// The server is temporarily overloaded or under maintenance.
  TemporarilyUnavailable,
  /// Client authentication failed.
  InvalidClient,
  /// The supplied grant or refresh token is invalid.
  InvalidGrant,
  /// The grant type is not supported by the server.
  UnsupportedGrantType,
  /// The requested resource target is invalid or unsupported.
  InvalidTarget,
  /// The DPoP proof is invalid (RFC 9449 §9).
  InvalidDpopProof,
  /// The JAR request object is invalid (RFC 9101 §5).
  InvalidRequestObject,
  /// A requested redirect URI is invalid (RFC 7591 §3.2.2).
  InvalidRedirectUri,
  /// Client metadata is invalid (RFC 7591 §3.2.2).
  InvalidClientMetadata,
}

impl OAuthErrorCode {
  /// The wire value of this error code (the `error` member).
  #[must_use]
  pub fn as_str(self) -> &'static str {
    match self {
      Self::InvalidRequest => "invalid_request",
      Self::UnauthorizedClient => "unauthorized_client",
      Self::AccessDenied => "access_denied",
      Self::UnsupportedResponseType => "unsupported_response_type",
      Self::InvalidScope => "invalid_scope",
      Self::ServerError => "server_error",
      Self::TemporarilyUnavailable => "temporarily_unavailable",
      Self::InvalidClient => "invalid_client",
      Self::InvalidGrant => "invalid_grant",
      Self::UnsupportedGrantType => "unsupported_grant_type",
      Self::InvalidTarget => "invalid_target",
      Self::InvalidDpopProof => "invalid_dpop_proof",
      Self::InvalidRequestObject => "invalid_request_object",
      Self::InvalidRedirectUri => "invalid_redirect_uri",
      Self::InvalidClientMetadata => "invalid_client_metadata",
    }
  }

  /// The standard, client-safe description for this code.
  ///
  /// These strings are fixed and contain no request-specific data.
  #[must_use]
  pub fn default_description(self) -> &'static str {
    match self {
      Self::InvalidRequest => {
        "The request is missing a required parameter, includes an invalid parameter value, \
         includes a parameter more than once, or is otherwise malformed."
      }
      Self::UnauthorizedClient => {
        "The client is not authorized to request an authorization code using this method."
      }
      Self::AccessDenied => "The resource owner or authorization server denied the request.",
      Self::UnsupportedResponseType => {
        "The authorization server does not support obtaining an authorization code using this \
         method."
      }
      Self::InvalidScope => "The requested scope is invalid, unknown, or malformed.",
      Self::ServerError => {
        "The authorization server encountered an unexpected condition that prevented it from \
         fulfilling the request."
      }
      Self::TemporarilyUnavailable => {
        "The authorization server is currently unable to handle the request due to a temporary \
         overloading or maintenance of the server."
      }
      Self::InvalidClient => {
        "Client authentication failed (for example, unknown client, no client authentication \
         included, or unsupported authentication method)."
      }
      Self::InvalidGrant => {
        "The provided authorization grant or refresh token is invalid, expired, revoked, does \
         not match the redirection URI used in the authorization request, or was issued to \
         another client."
      }
      Self::UnsupportedGrantType => {
        "The authorization grant type is not supported by the authorization server."
      }
      Self::InvalidTarget => {
        "The requested resource is invalid, unknown, malformed, or otherwise not supported by \
         the authorization server."
      }
      Self::InvalidDpopProof => "The DPoP proof is invalid.",
      Self::InvalidRequestObject => "The request object is invalid.",
      Self::InvalidRedirectUri => "The requested redirect URI is invalid.",
      Self::InvalidClientMetadata => "The client metadata is invalid.",
    }
  }
}

impl fmt::Display for OAuthErrorCode {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

/// How a client presented its credentials, which selects the HTTP status
/// used for an `invalid_client` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthMethod {
  /// Credentials came from the request body, or none were presented.
  #[default]
  NonBasic,
  /// Credentials came from the `Authorization: Basic` header.
  Basic,
  /// A Bearer token (DCR initial or registration access token) was presented.
  Bearer,
}

/// An error that can be rendered as an OAuth error response or masked as an
/// internal server failure.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
  /// A protocol error that is safe to render to the client.
  #[error("{code}: {description}")]
  OAuth {
    /// The RFC error code.
    code: OAuthErrorCode,
    /// A client-safe human-readable description.
    description: Cow<'static, str>,
    /// How the client authenticated; selects the `invalid_client` status.
    client_auth: ClientAuthMethod,
  },
  /// An internal failure; the cause is never rendered to the client.
  #[error("internal server error")]
  Internal {
    /// Underlying cause, retained for server-side logging only.
    #[source]
    source: Box<dyn StdError + Send + Sync>,
  },
  /// A unique email collided (pre-check or `ux_users_email[_index]` 23505).
  ///
  /// Payload-free by construction (unit variant): no email ever reaches a
  /// log, a metric label, or an HTTP body through this variant.
  #[error("duplicate email")]
  DuplicateEmail,
  /// A stored PII ciphertext failed to open (tampered or corrupt).
  ///
  /// Fail-closed `temporarily_unavailable` (503), distinguishable from a
  /// database-outage 503 by the variant. Payload-free by construction.
  #[error("PII field cannot be decrypted")]
  PiiDecrypt,
  /// A client mTLS identity collided (pre-check or `ux_oauth_clients_tls_*`
  /// 23505).
  ///
  /// Payload-free by construction (unit variant): no DN or thumbprint value
  /// ever reaches a log, a metric label, or an HTTP body through this variant.
  #[error("duplicate client identity")]
  DuplicateClientIdentity,
}

impl AppError {
  /// Build a protocol error from a code and an explicit, client-safe
  /// description.
  ///
  /// Callers MUST NOT pass tokens, secrets, or raw dependency errors here.
  #[must_use]
  pub fn new(code: OAuthErrorCode, description: impl Into<Cow<'static, str>>) -> Self {
    Self::OAuth {
      code,
      description: description.into(),
      client_auth: ClientAuthMethod::NonBasic,
    }
  }

  /// Build a protocol error using the code's standard RFC description.
  #[must_use]
  pub fn from_code(code: OAuthErrorCode) -> Self {
    Self::new(code, code.default_description())
  }

  /// `invalid_request` (authorize and token endpoints).
  #[must_use]
  pub fn invalid_request(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidRequest, description)
  }

  /// `unauthorized_client` (authorize and token endpoints).
  #[must_use]
  pub fn unauthorized_client(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::UnauthorizedClient, description)
  }

  /// `access_denied` (authorize endpoint).
  #[must_use]
  pub fn access_denied(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::AccessDenied, description)
  }

  /// `unsupported_response_type` (authorize endpoint).
  #[must_use]
  pub fn unsupported_response_type(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::UnsupportedResponseType, description)
  }

  /// `invalid_scope` (authorize and token endpoints).
  #[must_use]
  pub fn invalid_scope(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidScope, description)
  }

  /// `server_error`, rendered as `500 Internal Server Error`.
  #[must_use]
  pub fn server_error() -> Self {
    Self::from_code(OAuthErrorCode::ServerError)
  }

  /// `temporarily_unavailable`, rendered as `503 Service Unavailable` with a
  /// `Retry-After` header (fail-closed dependency policy).
  #[must_use]
  pub fn temporarily_unavailable() -> Self {
    Self::from_code(OAuthErrorCode::TemporarilyUnavailable)
  }

  /// `invalid_client`, with the status selected by how the client
  /// authenticated.
  #[must_use]
  pub fn invalid_client(client_auth: ClientAuthMethod) -> Self {
    Self::OAuth {
      code: OAuthErrorCode::InvalidClient,
      description: Cow::Borrowed(OAuthErrorCode::InvalidClient.default_description()),
      client_auth,
    }
  }

  /// `invalid_client` after HTTP Basic authentication (`401` +
  /// `WWW-Authenticate`).
  #[must_use]
  pub fn invalid_client_basic() -> Self {
    Self::invalid_client(ClientAuthMethod::Basic)
  }

  /// `invalid_client` without HTTP Basic authentication (`400`).
  #[must_use]
  pub fn invalid_client_non_basic() -> Self {
    Self::invalid_client(ClientAuthMethod::NonBasic)
  }

  /// `invalid_client` after a Bearer token authentication attempt (`401` +
  /// `WWW-Authenticate: Bearer`).
  #[must_use]
  pub fn invalid_client_bearer() -> Self {
    Self::invalid_client(ClientAuthMethod::Bearer)
  }

  /// `invalid_redirect_uri` (dynamic client registration, RFC 7591 §3.2.2).
  #[must_use]
  pub fn invalid_redirect_uri(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidRedirectUri, description)
  }

  /// `invalid_client_metadata` (dynamic client registration, RFC 7591 §3.2.2).
  #[must_use]
  pub fn invalid_client_metadata(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidClientMetadata, description)
  }

  /// `invalid_grant` (token endpoint).
  #[must_use]
  pub fn invalid_grant(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidGrant, description)
  }

  /// `unsupported_grant_type` (token endpoint).
  #[must_use]
  pub fn unsupported_grant_type(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::UnsupportedGrantType, description)
  }

  /// `invalid_target` (token endpoint, resource indicators).
  #[must_use]
  pub fn invalid_target(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidTarget, description)
  }

  /// `invalid_dpop_proof` (RFC 9449 §9).
  #[must_use]
  pub fn invalid_dpop_proof(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidDpopProof, description)
  }

  /// `invalid_request_object` (RFC 9101 §5).
  #[must_use]
  pub fn invalid_request_object(description: impl Into<Cow<'static, str>>) -> Self {
    Self::new(OAuthErrorCode::InvalidRequestObject, description)
  }

  /// Wrap an internal failure. The source is kept for logging but is never
  /// serialized; the client only sees `server_error` with a generic
  /// description.
  #[must_use]
  pub fn internal<E>(source: E) -> Self
  where
    E: StdError + Send + Sync + 'static,
  {
    Self::Internal {
      source: Box::new(source),
    }
  }

  /// The RFC error code this error renders as. Internal failures map to
  /// `server_error`; a duplicate email maps to `invalid_request`, a duplicate
  /// client mTLS identity maps to `invalid_client_metadata`, and a PII
  /// decrypt failure maps to `temporarily_unavailable`.
  #[must_use]
  pub fn code(&self) -> OAuthErrorCode {
    match self {
      Self::OAuth { code, .. } => *code,
      Self::DuplicateEmail => OAuthErrorCode::InvalidRequest,
      Self::DuplicateClientIdentity => OAuthErrorCode::InvalidClientMetadata,
      Self::PiiDecrypt => OAuthErrorCode::TemporarilyUnavailable,
      Self::Internal { .. } => OAuthErrorCode::ServerError,
    }
  }

  /// The HTTP status this error renders as.
  #[must_use]
  pub fn status(&self) -> StatusCode {
    match self {
      Self::OAuth {
        code, client_auth, ..
      } => status_for(*code, *client_auth),
      Self::DuplicateEmail => {
        status_for(OAuthErrorCode::InvalidRequest, ClientAuthMethod::NonBasic)
      }
      Self::DuplicateClientIdentity => status_for(
        OAuthErrorCode::InvalidClientMetadata,
        ClientAuthMethod::NonBasic,
      ),
      Self::PiiDecrypt => status_for(
        OAuthErrorCode::TemporarilyUnavailable,
        ClientAuthMethod::NonBasic,
      ),
      Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }

  /// The client-safe description this error renders as.
  #[must_use]
  pub fn description(&self) -> &str {
    match self {
      Self::OAuth { description, .. } => description,
      Self::DuplicateEmail => "The email address is already in use.",
      Self::DuplicateClientIdentity => OAuthErrorCode::InvalidClientMetadata.default_description(),
      Self::PiiDecrypt => OAuthErrorCode::TemporarilyUnavailable.default_description(),
      Self::Internal { .. } => OAuthErrorCode::ServerError.default_description(),
    }
  }
}

/// Map an error code (and, for `invalid_client`, the auth method) to an HTTP
/// status.
fn status_for(code: OAuthErrorCode, client_auth: ClientAuthMethod) -> StatusCode {
  match (code, client_auth) {
    (OAuthErrorCode::InvalidClient, ClientAuthMethod::Basic)
    | (OAuthErrorCode::InvalidClient, ClientAuthMethod::Bearer) => StatusCode::UNAUTHORIZED,
    (OAuthErrorCode::ServerError, _) => StatusCode::INTERNAL_SERVER_ERROR,
    (OAuthErrorCode::TemporarilyUnavailable, _) => StatusCode::SERVICE_UNAVAILABLE,
    _ => StatusCode::BAD_REQUEST,
  }
}

/// The JSON error body: `{error, error_description}`.
#[derive(Debug, Serialize)]
struct OAuthErrorBody<'a> {
  error: &'a str,
  error_description: &'a str,
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let (code, description, client_auth) = match self {
      Self::OAuth {
        code,
        description,
        client_auth,
      } => (code, description, client_auth),
      // Payload-free typed errors render fixed codes and descriptions.
      Self::DuplicateEmail => (
        OAuthErrorCode::InvalidRequest,
        Cow::Borrowed("The email address is already in use."),
        ClientAuthMethod::NonBasic,
      ),
      Self::DuplicateClientIdentity => (
        OAuthErrorCode::InvalidClientMetadata,
        Cow::Borrowed(OAuthErrorCode::InvalidClientMetadata.default_description()),
        ClientAuthMethod::NonBasic,
      ),
      Self::PiiDecrypt => (
        OAuthErrorCode::TemporarilyUnavailable,
        Cow::Borrowed(OAuthErrorCode::TemporarilyUnavailable.default_description()),
        ClientAuthMethod::NonBasic,
      ),
      // Mask every internal failure: generic code + generic description.
      Self::Internal { .. } => (
        OAuthErrorCode::ServerError,
        Cow::Borrowed(OAuthErrorCode::ServerError.default_description()),
        ClientAuthMethod::NonBasic,
      ),
    };

    let body = OAuthErrorBody {
      error: code.as_str(),
      error_description: description.as_ref(),
    };
    let mut response = (status_for(code, client_auth), Json(body)).into_response();
    response
      .headers_mut()
      .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
      .headers_mut()
      .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    if code == OAuthErrorCode::InvalidClient && client_auth == ClientAuthMethod::Basic {
      response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(BASIC_CHALLENGE),
      );
    }
    if code == OAuthErrorCode::InvalidClient && client_auth == ClientAuthMethod::Bearer {
      response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(BEARER_CHALLENGE),
      );
    }
    if code == OAuthErrorCode::TemporarilyUnavailable {
      response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(RETRY_AFTER_SECS),
      );
    }

    response
  }
}

impl From<sqlx::Error> for AppError {
  /// Map a database error to a client-safe error: connectivity failures
  /// (pool timeout/close, transport I/O, and an outage SQLSTATE such as a
  /// server shutdown mid-query) render `503 temporarily_unavailable` (fail
  /// closed, matching the Redis mapping); a unique violation on the
  /// user-email constraints renders the payload-free [`AppError::DuplicateEmail`];
  /// a unique violation on any client mTLS identity constraint (legacy
  /// plaintext or blind-index) renders the payload-free
  /// [`AppError::DuplicateClientIdentity`]; every other genuine query or
  /// logic failure stays a masked `server_error` that never leaks database text.
  fn from(source: sqlx::Error) -> Self {
    match source {
      sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
        Self::temporarily_unavailable()
      }
      sqlx::Error::Database(db) if is_dependency_outage(db.code().as_deref()) => {
        Self::temporarily_unavailable()
      }
      sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23505")
          && matches!(
            db.constraint(),
            Some("ux_users_email") | Some("ux_users_email_index")
          ) =>
      {
        Self::DuplicateEmail
      }
      sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23505")
          && matches!(
            db.constraint(),
            Some("ux_oauth_clients_tls_subject_dn")
              | Some("ux_oauth_clients_tls_cert_thumbprint")
              | Some("ux_oauth_clients_tls_subject_dn_index")
              | Some("ux_oauth_clients_tls_cert_thumbprint_index")
          ) =>
      {
        Self::DuplicateClientIdentity
      }
      other => Self::internal(other),
    }
  }
}

/// SQLSTATE codes proving the Postgres dependency is transiently unavailable
/// (a failover, restart, or shutdown) rather than the statement being wrong.
/// These must fail closed as `503 temporarily_unavailable`, never a masked
/// `500`, matching the connectivity arms above and the Redis transient class.
///
/// - class `08` — Connection Exception (`08000`, `08003`, `08006`, `08P01`, …)
/// - `57P01` admin_shutdown, `57P02` crash_shutdown, `57P03` cannot_connect_now,
///   `57P04` database_dropped
/// - `53300` too_many_connections
fn is_dependency_outage(code: Option<&str>) -> bool {
  let Some(code) = code else {
    return false;
  };
  code.starts_with("08")
    || matches!(code, "57P01" | "57P02" | "57P03" | "57P04" | "53300")
}

impl From<crate::crypto::field::FieldError> for AppError {
  /// Map a PII field failure fail-closed: a blob that fails to open becomes
  /// the distinguishable [`AppError::PiiDecrypt`] (503); a seal or RNG
  /// failure becomes generic `temporarily_unavailable` (503). Neither carries
  /// plaintext or key material.
  fn from(error: crate::crypto::field::FieldError) -> Self {
    match error {
      crate::crypto::field::FieldError::Decrypt => Self::PiiDecrypt,
      crate::crypto::field::FieldError::Encrypt
      | crate::crypto::field::FieldError::UnavailableRandomness => Self::temporarily_unavailable(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::Bytes;
  use axum::http::{HeaderMap, header};
  use http_body_util::BodyExt as _;
  use serde_json::Value;

  /// Drive an `AppError` through `IntoResponse` and collect its status,
  /// headers, and parsed JSON body.
  async fn render(err: AppError) -> (StatusCode, HeaderMap, Value) {
    let response = err.into_response();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = match response.into_body().collect().await {
      Ok(collected) => collected.to_bytes(),
      Err(_) => Bytes::new(),
    };
    let body = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
  }

  /// Every error body forbids caching (RFC 6749 §5.1, draft-16 §3.2.3).
  #[tokio::test]
  async fn error_responses_are_not_cacheable() {
    let (_, headers, _) = render(AppError::invalid_request("nope")).await;
    let value = |name: header::HeaderName| {
      headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
    };
    assert_eq!(value(header::CACHE_CONTROL), "no-store");
    assert_eq!(value(header::PRAGMA), "no-cache");
  }

  #[tokio::test]
  async fn error_response_codes_and_statuses() {
    let cases: [(AppError, OAuthErrorCode, StatusCode); 14] = [
      (
        AppError::invalid_request("bad request"),
        OAuthErrorCode::InvalidRequest,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::unauthorized_client("not allowed"),
        OAuthErrorCode::UnauthorizedClient,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::access_denied("denied"),
        OAuthErrorCode::AccessDenied,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::unsupported_response_type("unsupported"),
        OAuthErrorCode::UnsupportedResponseType,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::invalid_scope("bad scope"),
        OAuthErrorCode::InvalidScope,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::server_error(),
        OAuthErrorCode::ServerError,
        StatusCode::INTERNAL_SERVER_ERROR,
      ),
      (
        AppError::temporarily_unavailable(),
        OAuthErrorCode::TemporarilyUnavailable,
        StatusCode::SERVICE_UNAVAILABLE,
      ),
      (
        AppError::invalid_client_non_basic(),
        OAuthErrorCode::InvalidClient,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::invalid_client_basic(),
        OAuthErrorCode::InvalidClient,
        StatusCode::UNAUTHORIZED,
      ),
      (
        AppError::invalid_grant("bad grant"),
        OAuthErrorCode::InvalidGrant,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::unsupported_grant_type("bad grant type"),
        OAuthErrorCode::UnsupportedGrantType,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::invalid_target("bad target"),
        OAuthErrorCode::InvalidTarget,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::invalid_dpop_proof("bad proof"),
        OAuthErrorCode::InvalidDpopProof,
        StatusCode::BAD_REQUEST,
      ),
      (
        AppError::invalid_request_object("bad object"),
        OAuthErrorCode::InvalidRequestObject,
        StatusCode::BAD_REQUEST,
      ),
    ];

    for (err, code, status) in cases {
      assert_eq!(err.code(), code, "code mismatch (expected {code})");
      assert_eq!(
        err.status(),
        status,
        "in-memory status mismatch (code {code})"
      );

      let (rendered, _headers, body) = render(err).await;
      assert_eq!(rendered, status, "rendered status mismatch (code {code})");
      assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some(code.as_str())
      );
      assert!(
        body
          .get("error_description")
          .and_then(|value| value.as_str())
          .is_some(),
        "error_description missing (code {code})"
      );
    }
  }

  #[tokio::test]
  async fn error_response_invalid_client_basic_sets_www_authenticate() {
    let (status, headers, body) = render(AppError::invalid_client_basic()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
      headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok()),
      Some(BASIC_CHALLENGE)
    );
    assert_eq!(
      body.get("error").and_then(|value| value.as_str()),
      Some("invalid_client")
    );
  }

  #[tokio::test]
  async fn error_response_invalid_client_non_basic_is_400() {
    let (status, headers, body) = render(AppError::invalid_client_non_basic()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
      body.get("error").and_then(|value| value.as_str()),
      Some("invalid_client")
    );
  }

  #[tokio::test]
  async fn error_response_temporarily_unavailable_sets_retry_after() {
    let (status, headers, body) = render(AppError::temporarily_unavailable()).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
      headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok()),
      Some(RETRY_AFTER_SECS)
    );
    assert_eq!(
      body.get("error").and_then(|value| value.as_str()),
      Some("temporarily_unavailable")
    );
  }

  #[tokio::test]
  async fn error_response_internal_sqlx_masks_db_detail() {
    let marker = "pg-secret-marked-detail-7d3a";
    let err = AppError::from(sqlx::Error::Protocol(marker.to_owned()));

    assert_eq!(err.code(), OAuthErrorCode::ServerError);
    assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let (status, _headers, body) = render(err).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
      body.get("error").and_then(|value| value.as_str()),
      Some("server_error")
    );
    assert!(
      body
        .get("error_description")
        .and_then(|value| value.as_str())
        .is_some()
    );

    let rendered = body.to_string();
    assert!(!rendered.contains(marker), "DB detail leaked: {rendered}");
    assert!(
      !rendered.to_ascii_lowercase().contains("protocol"),
      "dependency error text leaked: {rendered}"
    );
  }

  #[tokio::test]
  async fn error_sqlx_connectivity_maps_to_503() {
    let cases = [
      sqlx::Error::PoolTimedOut,
      sqlx::Error::PoolClosed,
      sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "refused",
      )),
    ];

    for source in cases {
      let err = AppError::from(source);
      assert_eq!(err.code(), OAuthErrorCode::TemporarilyUnavailable);
      assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);

      let (status, headers, body) = render(err).await;
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert_eq!(
        headers
          .get(header::RETRY_AFTER)
          .and_then(|value| value.to_str().ok()),
        Some(RETRY_AFTER_SECS)
      );
      assert_eq!(
        body.get("error").and_then(|value| value.as_str()),
        Some("temporarily_unavailable")
      );
    }
  }

  #[test]
  fn sqlx_outage_sqlstate_classification() {
    for code in [
      "08000", "08003", "08006", "08P01", "57P01", "57P02", "57P03", "57P04", "53300",
    ] {
      assert!(is_dependency_outage(Some(code)), "{code} must be an outage");
    }
    for code in ["23505", "42P01", "42601", "28P01", "57014", "40001"] {
      assert!(
        !is_dependency_outage(Some(code)),
        "{code} must not be an outage"
      );
    }
    assert!(!is_dependency_outage(None));
  }

  #[tokio::test]
  async fn error_response_invalid_client_snapshot() {
    let (status, headers, body) = render(AppError::invalid_client_basic()).await;
    let challenge = headers
      .get(header::WWW_AUTHENTICATE)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();

    let snapshot = serde_json::json!({
      "status": status.as_u16(),
      "www_authenticate": challenge,
      "body": body,
    });

    // The rendered response must never carry secret material.
    assert!(!snapshot.to_string().to_ascii_lowercase().contains("secret"));

    // `insta`'s `json` feature is not enabled in this workspace (and
    // `Cargo.toml` is out of scope for this task), so the snapshot is stored
    // as pretty-printed JSON via the always-available `assert_snapshot!`.
    let rendered_snapshot = serde_json::to_string_pretty(&snapshot).unwrap_or_default();
    insta::with_settings!({ prepend_module_to_snapshot => false }, {
      insta::assert_snapshot!("error_invalid_client", rendered_snapshot);
    });
  }
}

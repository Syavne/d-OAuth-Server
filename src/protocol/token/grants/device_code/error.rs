//! RFC 8628 §3.5 polling errors with exact wire codes.
//!
//! `authorization_pending`, `slow_down`, and `expired_token` have no
//! counterpart in [`AppError`](crate::error::AppError), so this grant carries
//! its own error type rendering those codes with HTTP 400.

use axum::{
  Json,
  http::StatusCode,
  response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::error::AppError;

/// Device-polling failures: the RFC 8628 §3.5 codes plus protocol errors.
#[derive(Debug)]
pub enum DevicePollError {
  /// The user has not approved or denied the request yet.
  AuthorizationPending,
  /// The device polled faster than `interval`; back off before retrying.
  SlowDown {
    /// Whole seconds the device should wait before polling again.
    retry_after_secs: u64,
  },
  /// The user denied the request.
  AccessDenied,
  /// The device code is unknown or its TTL has lapsed.
  ExpiredToken,
  /// Any other token-endpoint failure (client auth, binding, scope, store).
  Protocol(AppError),
}

impl From<AppError> for DevicePollError {
  fn from(error: AppError) -> Self {
    Self::Protocol(error)
  }
}

impl DevicePollError {
  /// The exact wire `error` code for this failure.
  #[must_use]
  pub fn code(&self) -> &'static str {
    match self {
      Self::AuthorizationPending => "authorization_pending",
      Self::SlowDown { .. } => "slow_down",
      Self::AccessDenied => "access_denied",
      Self::ExpiredToken => "expired_token",
      Self::Protocol(error) => match error {
        AppError::OAuth { code, .. } => code.as_str(),
        AppError::Internal { .. } => "server_error",
      },
    }
  }

  /// The HTTP status for this failure (400 for every polling code).
  #[must_use]
  pub fn status(&self) -> StatusCode {
    match self {
      Self::Protocol(error) => error.status(),
      Self::AuthorizationPending
      | Self::SlowDown { .. }
      | Self::AccessDenied
      | Self::ExpiredToken => StatusCode::BAD_REQUEST,
    }
  }
}

/// The JSON error body: `{error, error_description}`.
#[derive(Debug, Serialize)]
struct DevicePollErrorBody<'a> {
  error: &'a str,
  error_description: &'a str,
}

impl IntoResponse for DevicePollError {
  fn into_response(self) -> Response {
    let description: &str = match &self {
      Self::AuthorizationPending => "The authorization request is still pending.",
      Self::SlowDown { .. } => "Polling too frequently; increase the polling interval.",
      Self::AccessDenied => "The resource owner denied the request.",
      Self::ExpiredToken => "The device code has expired or is unknown.",
      Self::Protocol(error) => error.description(),
    };
    let body = DevicePollErrorBody {
      error: self.code(),
      error_description: description,
    };
    (self.status(), Json(body)).into_response()
  }
}

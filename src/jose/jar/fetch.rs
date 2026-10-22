//! SSRF-guarded fetch for pre-registered `request_uri` values.
//!
//! Delegates to the shared [`crate::protocol::ssrf`] guard (`https`-only,
//! no redirects, DNS-validated and connection-pinned targets, success
//! statuses only) and then enforces the request-object body cap of
//! [`MAX_REQUEST_OBJECT_BYTES`] with a UTF-8 requirement.

use super::MAX_REQUEST_OBJECT_BYTES;
use crate::{
  error::AppError,
  protocol::ssrf::{self, SsrfError},
};

/// Fetch a pre-registered request object behind the SSRF guard.
///
/// # Errors
///
/// Returns `invalid_request_object` for any policy violation or fetch
/// failure; never surfaces transport detail.
pub(crate) async fn fetch_request_object(uri: &str) -> Result<String, AppError> {
  let bytes = ssrf::fetch_guarded_bytes(uri)
    .await
    .map_err(map_ssrf_error)?;
  decode_request_object(&bytes)
}

/// Map a shared-guard failure to `invalid_request_object` without leaking
/// transport detail; an over-limit body keeps the too-large message.
fn map_ssrf_error(error: SsrfError) -> AppError {
  match error {
    SsrfError::TooLarge => AppError::invalid_request_object("request_uri response is too large"),
    _ => AppError::invalid_request_object("request_uri fetch failed"),
  }
}

/// Enforce the 64 KiB request-object cap and the UTF-8 requirement on an
/// already-guarded response body.
fn decode_request_object(bytes: &[u8]) -> Result<String, AppError> {
  if bytes.len() > MAX_REQUEST_OBJECT_BYTES {
    return Err(AppError::invalid_request_object(
      "request_uri response is too large",
    ));
  }
  String::from_utf8(bytes.to_vec())
    .map_err(|_| AppError::invalid_request_object("request_uri body is not UTF-8"))
}

#[cfg(test)]
mod tests {
  use super::decode_request_object;
  use crate::jose::jar::MAX_REQUEST_OBJECT_BYTES;

  #[test]
  fn jar_fetch_decode_rejects_body_over_64kib() {
    let oversize = vec![b'a'; MAX_REQUEST_OBJECT_BYTES + 1];
    assert!(decode_request_object(&oversize).is_err());
  }

  #[test]
  fn jar_fetch_decode_rejects_non_utf8_body() {
    assert!(decode_request_object(&[0xff, 0xfe, 0x00]).is_err());
  }

  #[test]
  fn jar_fetch_decode_accepts_valid_body() {
    let body = "header.payload.signature";
    assert!(decode_request_object(body.as_bytes()).is_ok());
  }
}

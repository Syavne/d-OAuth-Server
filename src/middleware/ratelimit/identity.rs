//! Request identity for rate limiting: peer IP and `client_id`, both hashed.
//!
//! The raw identity never becomes key material — [`counter_key`] hashes it —
//! and `client_id` is recovered from the query string or, for form posts, a
//! buffered-and-restored body so the downstream handler still sees it.

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use sha2::{Digest, Sha256};

/// Largest form body buffered to recover a `client_id`; anything larger is
/// left untouched and simply yields no client identity.
const MAX_FORM_BYTES: usize = 64 * 1024;

/// The peer address recorded by axum's `ConnectInfo` (present whenever the
/// listener is served with `into_make_service_with_connect_info`).
pub(super) fn peer_ip(request: &Request<Body>) -> Option<IpAddr> {
  request
    .extensions()
    .get::<ConnectInfo<SocketAddr>>()
    .map(|info| info.0.ip())
}

/// Recover a `client_id` from the query string, or (for form posts) the body.
///
/// A form body is buffered and restored so the handler still sees it; a body
/// that cannot be read yields `None` (the IP bucket still applies).
pub(super) async fn extract_client_id(request: &mut Request<Body>) -> Option<String> {
  if let Some(client_id) = query_param(request.uri().query(), "client_id") {
    return Some(client_id);
  }
  let is_form = request
    .headers()
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
  if !is_form {
    return None;
  }
  let body = std::mem::replace(request.body_mut(), Body::empty());
  let bytes = axum::body::to_bytes(body, MAX_FORM_BYTES).await.ok()?;
  let client_id = std::str::from_utf8(&bytes)
    .ok()
    .and_then(|text| find_param(text, "client_id"));
  *request.body_mut() = Body::from(bytes);
  client_id
}

/// `{prefix}{kind}:{sha256-hex}` — the raw identity never reaches Redis.
pub(super) fn counter_key(prefix: &str, kind: &str, raw: &str) -> String {
  format!("{prefix}{kind}:{}", sha256_hex(raw.as_bytes()))
}

/// Lowercase hex of the SHA-256 digest.
fn sha256_hex(input: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let digest = Sha256::digest(input);
  let mut out = String::with_capacity(digest.len() * 2);
  for byte in digest {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

/// First value of `name` in a `&`-separated query or form string.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
  query.and_then(|query| find_param(query, name))
}

/// Parse `key=value` pairs (percent- and `+`-decoded) and return the first
/// value whose key matches `name`.
fn find_param(input: &str, name: &str) -> Option<String> {
  input.split('&').find_map(|pair| {
    let (key, value) = pair.split_once('=')?;
    (decode_component(key) == name).then(|| decode_component(value))
  })
}

/// Minimal `application/x-www-form-urlencoded` component decoder.
fn decode_component(raw: &str) -> String {
  let bytes = raw.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    match bytes[index] {
      b'+' => {
        out.push(b' ');
        index += 1;
      }
      b'%' if index + 2 < bytes.len() => {
        match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
          (Some(high), Some(low)) => {
            out.push(high * 16 + low);
            index += 3;
          }
          _ => {
            out.push(b'%');
            index += 1;
          }
        }
      }
      byte => {
        out.push(byte);
        index += 1;
      }
    }
  }
  String::from_utf8_lossy(&out).into_owned()
}

/// Hexadecimal digit value, or `None` for a non-hex byte.
fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

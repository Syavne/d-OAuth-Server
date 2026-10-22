//! Repeated `resource` parsing + RFC 8707 validation (task 7).
//!
//! Every entry point decodes into a single-valued map (`Query<HashMap>` on
//! `/authorize`, `Form<HashMap>` on `/par`, `TokenForm` on `/token`,
//! `IntrospectForm` on `/introspect`, `DeviceAuthorizationForm` on
//! `/device_authorization`), and each extractor CONSUMES the raw query/body —
//! so a raw parse requires switching the extractor (`RawQuery` + `Bytes` with
//! a manual struct parse) at all five endpoints. A helper alone cannot see
//! the raw input after `Form`/`Query` runs.
//!
//! This module owns the shared half of that surgery:
//!
//! - [`parse_pairs`] / [`single_valued_map`] — the strict urlencoded parse
//!   (last-wins, mirroring `serde_urlencoded`'s `HashMap` absorption).
//! - [`repeated_values`] — the ONE helper capturing repeated `resource`
//!   values in order from a raw query/body string.
//! - [`require_form_content_type`] / [`form_pairs`] / [`query_pairs`] — the
//!   transport contract the `Form`/`Query` extractors used to enforce
//!   (415 on a non-urlencoded body, 400 on malformed input), so the
//!   extractor switch is behavior-preserving. `Bytes` never fails on
//!   content-type, hence the explicit gate.
//! - [`has_duplicate_field`] — mirrors serde's duplicate-field rejection for
//!   struct forms. NOTE (do not misreport): a repeated `resource` is
//!   silently absorbed for struct forms (`TokenForm`, `IntrospectForm`,
//!   `DeviceAuthorizationForm` carry no `resource` member and no
//!   `deny_unknown_fields`), NOT rejected by `serde_urlencoded` — only a
//!   repeated KNOWN field errors.
//! - [`validate_resources`] — fail-closed RFC 8707 validation.
//! - [`audience_binds`] — the ONE order-insensitive, constant-time audience
//!   comparison shared by every grant that binds a pinned resource set.
//!
//! Resource policy (stricter than RFC 8707 §2, which only SHOULD-NOTs a query
//! component): every value must be an absolute `https` URI and must exactly
//! match an enabled `resource_servers` row (`resource_repo::find_enabled`).
//! There is no loopback exception for audiences (unlike redirect URIs under
//! RFC 8252 §7.3), values are never delimiter-joined (a comma-bearing URI
//! would collide — the validated set is pinned as a sorted deduped
//! `Vec<String>`), scopes are never widened, and when the
//! `resource_indicators_enabled` flag is off any `resource` present is
//! `invalid_target` (fail-closed, no silent drop).

use std::{
  collections::{HashMap, HashSet},
  fmt,
};

use axum::http::{HeaderMap, StatusCode, header};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;

use crate::{db::resource_repo, error::AppError};

/// RFC 8707 indicator parameter name.
pub const RESOURCE_PARAM: &str = "resource";

/// Urlencoded parse failure.
///
/// Decoding itself mirrors `serde_urlencoded` and is infallible (a bare `%`
/// stays literal, non-UTF-8 decodes lossily), so this type is retained for
/// the [`parse_pairs`] signature rather than constructed on any current
/// decoding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamsError;

impl fmt::Display for ParamsError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("malformed urlencoded input")
  }
}

impl std::error::Error for ParamsError {}

/// Decode one `application/x-www-form-urlencoded` component (`+` is a space).
///
/// Percent-decoding mirrors `serde_urlencoded` observable behavior so
/// malformed encodings reach typed validation and fail closed downstream
/// (`unsupported_grant_type` / `invalid_client` / `invalid_scope`) instead
/// of failing the parse: a `%` NOT followed by two hex digits stays a
/// literal `%` (only `%<hex><hex>` decodes), and non-UTF-8 bytes decode
/// lossily (`U+FFFD` replacement).
fn decode_component(raw: &str) -> String {
  let bytes = raw.as_bytes();
  let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    match bytes[index] {
      b'+' => {
        out.push(b' ');
        index += 1;
      }
      b'%' => {
        match (
          bytes.get(index + 1).copied().and_then(hex_value),
          bytes.get(index + 2).copied().and_then(hex_value),
        ) {
          (Some(high), Some(low)) => {
            out.push(high << 4 | low);
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

/// One percent-encoded hex digit.
fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

/// Strictly parse raw urlencoded input into ordered pairs.
///
/// A segment without `=` carries an empty value (mirroring
/// `serde_urlencoded`); empty segments are skipped. Decoding itself is
/// lossy and infallible (see [`decode_component`]): a malformed `%`
/// escape stays literal and non-UTF-8 decodes with replacement, so odd
/// encodings reach typed validation downstream instead of failing the
/// parse. [`ParamsError`] is retained for the signature; callers map it
/// onto the same 400 the `Form`/`Query` extractors rendered.
pub fn parse_pairs(raw: &str) -> Result<Vec<(String, String)>, ParamsError> {
  if raw.is_empty() {
    return Ok(Vec::new());
  }
  let mut pairs = Vec::new();
  for segment in raw.split('&') {
    if segment.is_empty() {
      continue;
    }
    let (name, value) = match segment.split_once('=') {
      Some((name, value)) => (name, value),
      None => (segment, ""),
    };
    pairs.push((decode_component(name), decode_component(value)));
  }
  Ok(pairs)
}

/// Collapse ordered pairs into a single-valued map, last-wins.
///
/// This mirrors `serde_urlencoded`'s `HashMap` absorption exactly: a
/// repeated parameter (including a repeated `resource`) is silently
/// absorbed, never rejected.
#[must_use]
pub fn single_valued_map(pairs: &[(String, String)]) -> HashMap<String, String> {
  let mut map = HashMap::with_capacity(pairs.len());
  for (name, value) in pairs {
    map.insert(name.clone(), value.clone());
  }
  map
}

/// Capture every `name` value in order from a raw query/body string.
///
/// This is the ONE helper for the query/body endpoints (JAR arrays are
/// handled out-of-band by the merge carrier, never by this function).
/// Infallible by design: handlers run the strict [`parse_pairs`] first for
/// error mapping and only call this on input that already parsed, so an
/// undecodable segment is skipped as unreachable rather than erroring.
#[must_use]
pub fn repeated_values(raw: &str, name: &str) -> Vec<String> {
  match parse_pairs(raw) {
    Ok(pairs) => pairs
      .into_iter()
      .filter_map(|(key, value)| (key == name).then_some(value))
      .collect(),
    Err(ParamsError) => Vec::new(),
  }
}

/// Whether any KNOWN field repeats — mirrors serde's duplicate-field
/// rejection for struct forms (`TokenForm`, `IntrospectForm`,
/// `DeviceAuthorizationForm`).
///
/// Unknown fields are ignored entirely (no `deny_unknown_fields`), so a
/// repeated `resource` — unknown to every struct form — is silently
/// absorbed here, exactly as `serde_urlencoded` absorbed it.
#[must_use]
pub fn has_duplicate_field(pairs: &[(String, String)], known: &[&str]) -> bool {
  let mut seen: HashSet<&str> = HashSet::with_capacity(pairs.len());
  for (name, _) in pairs {
    if known.contains(&name.as_str()) && !seen.insert(name.as_str()) {
      return true;
    }
  }
  false
}

/// Transport rejection: a small status + body pair the handlers render with
/// `IntoResponse`, mirroring the axum extractor's status class and body.
pub type TransportRejection = (StatusCode, &'static str);

/// Reject a non-urlencoded body with 415, mirroring axum's
/// `InvalidFormContentType` (`Bytes` never fails on content-type, so the
/// extractor switch needs this explicit gate to preserve the contract).
///
/// # Errors
///
/// Returns the 415 rejection when the `Content-Type` is missing or is not
/// `application/x-www-form-urlencoded` (an optional `;charset=…` suffix is
/// accepted, as axum did).
pub fn require_form_content_type(headers: &HeaderMap) -> Result<(), TransportRejection> {
  let urlencoded = headers
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(';').next())
    .is_some_and(|mime| {
      mime
        .trim()
        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    });
  if urlencoded {
    Ok(())
  } else {
    Err((
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "Form requests must have `Content-Type: application/x-www-form-urlencoded`",
    ))
  }
}

/// Borrow a request body as text, mirroring `Form`'s 400
/// (`FailedToDeserializeForm`) on non-UTF-8 input.
///
/// Handlers use this before [`parse_pairs`] + [`repeated_values`] so the
/// raw text stays available for the repeated-value capture.
///
/// # Errors
///
/// Returns the 400 rejection when the body is not UTF-8.
pub fn form_text(body: &[u8]) -> Result<&str, TransportRejection> {
  std::str::from_utf8(body).map_err(|_| (StatusCode::BAD_REQUEST, "Failed to deserialize form"))
}

/// Strict urlencoded pairs from a request body, mirroring `Form`'s 400
/// (`FailedToDeserializeForm`) on non-UTF-8 or malformed input.
///
/// # Errors
///
/// Returns the 400 rejection when the body is not strict urlencoded input.
pub fn form_pairs(body: &[u8]) -> Result<Vec<(String, String)>, TransportRejection> {
  let text = form_text(body)?;
  parse_pairs(text).map_err(|_| (StatusCode::BAD_REQUEST, "Failed to deserialize form"))
}

/// Strict urlencoded pairs from a query string, mirroring `Query`'s 400
/// (`FailedToDeserializeQueryString`) on malformed input.
///
/// # Errors
///
/// Returns the 400 rejection when the query is not strict urlencoded input.
pub fn query_pairs(raw: Option<&str>) -> Result<Vec<(String, String)>, TransportRejection> {
  parse_pairs(raw.unwrap_or("")).map_err(|_| {
    (
      StatusCode::BAD_REQUEST,
      "Failed to deserialize query string",
    )
  })
}

/// Validate resource indicators fail-closed (RFC 8707 §2).
///
/// An empty input pins an empty set without touching the catalog. Otherwise
/// the flag must be on (off + any `resource` present is `invalid_target`,
/// never a silent drop), every value must be an absolute `https` URI — no
/// loopback exception applies to audiences — and must exactly match an
/// enabled `resource_servers` row. Returns the sorted deduped set for
/// pinning into `PendingAuth.aud` / PAR / code / device records; values are
/// never delimiter-joined and scopes are never widened here.
///
/// # Errors
///
/// Returns `invalid_target` for a disabled flag, a non-`https` or relative
/// value, or an unknown/disabled catalog entry; a database outage propagates
/// as the fail-closed `503`.
pub async fn validate_resources(
  pool: &PgPool,
  enabled: bool,
  values: &[String],
) -> Result<Vec<String>, AppError> {
  if values.is_empty() {
    return Ok(Vec::new());
  }
  if !enabled {
    return Err(AppError::invalid_target(
      "resource indicators are not enabled",
    ));
  }
  let mut aud = Vec::with_capacity(values.len());
  for value in values {
    let absolute_https = reqwest::Url::parse(value)
      .ok()
      .filter(|url| url.scheme() == "https" && url.has_host())
      .is_some();
    if !absolute_https {
      return Err(AppError::invalid_target(
        "resource must be an absolute https URI",
      ));
    }
    let known = resource_repo::find_enabled(pool, value).await?.is_some();
    if !known {
      return Err(AppError::invalid_target(
        "unknown or disabled resource server",
      ));
    }
    aud.push(value.clone());
  }
  aud.sort();
  aud.dedup();
  Ok(aud)
}

/// Whether a grant's pinned audience and the presented set are identical.
///
/// RFC 8707 §2 requires a token request to present the same resource set the
/// authorization request bound to the grant. Comparison is order-insensitive
/// (both sides are sorted and deduped here; the store contract already sorts,
/// this defends it) and fail-closed for every cardinality change. Members are
/// hashed with SHA-256 and compared through [`subtle::ConstantTimeEq`] without
/// a per-member early exit. Lengths and set membership are public metadata for
/// RFC 8707 audiences, so the cardinality gate is not secret-dependent.
pub(crate) fn audience_binds(pinned: &[String], presented: &[String]) -> bool {
  let pinned = normalized_audience(pinned);
  let presented = normalized_audience(presented);
  if pinned.len() != presented.len() {
    return false;
  }
  let mut equal = subtle::Choice::from(1u8);
  for (left, right) in pinned.iter().zip(presented.iter()) {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    equal &= left.as_slice().ct_eq(right.as_slice());
  }
  bool::from(equal)
}

/// Sorted, deduped view of an audience set.
fn normalized_audience(values: &[String]) -> Vec<&str> {
  let mut normalized: Vec<&str> = values.iter().map(String::as_str).collect();
  normalized.sort_unstable();
  normalized.dedup();
  normalized
}

#[cfg(test)]
mod tests;

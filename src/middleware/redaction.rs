//! Secret redaction for anything that reaches a log sink.
//!
//! Central policy for the whole crate: authorization material is identified by
//! name and replaced with [`REDACTED`] before it can ever be serialized into a
//! structured log line. Header names are matched case-insensitively with `-`
//! normalized to `_` so `DPoP` and `code-verifier` are covered alongside their
//! canonical spellings.
//!
//! This module never mutates the live request; it only produces redacted
//! projections for logging.

use axum::http::{HeaderMap, Uri};
use serde_json::Value;

/// Replacement marker written in place of any sensitive value.
pub const REDACTED: &str = "[REDACTED]";

/// Field names that are always redacted, compared after normalization.
const SENSITIVE_FIELDS: &[&str] = &[
  "authorization",
  "cookie",
  "dpop",
  "code",
  "token",
  "client_secret",
  "code_verifier",
  "password",
];

/// Whether a header/body/query key holds secret material.
///
/// The match is on the normalized (trimmed, lowercased, `-`→`_`) key: an exact
/// member of [`SENSITIVE_FIELDS`], or any key ending in `_token`, `_secret`, or
/// `_password`. `code_challenge` deliberately stays visible — RFC 9449 makes it
/// public, unlike `code_verifier`.
#[must_use]
pub fn is_sensitive(key: &str) -> bool {
  let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
  if normalized.is_empty() {
    return false;
  }
  SENSITIVE_FIELDS.contains(&normalized.as_str())
    || normalized.ends_with("_token")
    || normalized.ends_with("_secret")
    || normalized.ends_with("_password")
    || normalized.contains("secret")
}

/// Redacted projection of every header, safe to log as a map.
#[must_use]
pub fn redact_headers(headers: &HeaderMap) -> Vec<(String, String)> {
  headers
    .iter()
    .map(|(name, value)| {
      let key = name.as_str().to_ascii_lowercase();
      let rendered = if is_sensitive(&key) {
        REDACTED.to_owned()
      } else {
        value
          .to_str()
          .map(|text| text.to_owned())
          .unwrap_or_else(|_| "<non-utf8>".to_owned())
      };
      (key, rendered)
    })
    .collect()
}

/// Redacted headers rendered as a JSON object string (never fails).
#[must_use]
pub fn redact_headers_json(headers: &HeaderMap) -> String {
  let entries = redact_headers(headers);
  let object: serde_json::Map<String, Value> = entries
    .into_iter()
    .map(|(key, value)| (key, Value::String(value)))
    .collect();
  serde_json::to_string(&object).unwrap_or_else(|_| "{}".to_owned())
}

/// Recursively replace every sensitive field in a JSON value.
pub fn redact_json(value: &mut Value) {
  match value {
    Value::Object(map) => {
      for (key, entry) in map.iter_mut() {
        if is_sensitive(key) {
          *entry = Value::String(REDACTED.to_owned());
        } else {
          redact_json(entry);
        }
      }
    }
    Value::Array(items) => {
      for item in items {
        redact_json(item);
      }
    }
    _ => {}
  }
}

/// Redact an `application/x-www-form-urlencoded` body, preserving shape.
#[must_use]
pub fn redact_form(body: &str) -> String {
  body
    .split('&')
    .map(redact_pair)
    .collect::<Vec<_>>()
    .join("&")
}

/// Redact the query string of a URI, keeping the path intact.
#[must_use]
pub fn redact_uri(uri: &Uri) -> String {
  match uri.query() {
    None => uri.path().to_owned(),
    Some(query) => {
      let redacted = query
        .split('&')
        .map(redact_pair)
        .collect::<Vec<_>>()
        .join("&");
      format!("{}?{}", uri.path(), redacted)
    }
  }
}

/// Redact one `key=value` pair; keys without `=` are passed through.
fn redact_pair(pair: &str) -> String {
  match pair.split_once('=') {
    Some((key, _value)) if is_sensitive(key) => format!("{key}={REDACTED}"),
    _ => pair.to_owned(),
  }
}

#[cfg(test)]
mod redaction_tests {
  use super::*;
  use axum::http::{HeaderName, HeaderValue};
  use serde_json::json;

  #[test]
  fn redaction_header_map_masks_authorization_cookie_and_dpop() {
    let mut headers = HeaderMap::new();
    headers.insert(
      HeaderName::from_static("authorization"),
      HeaderValue::from_static("Bearer top-secret"),
    );
    headers.insert(
      HeaderName::from_static("cookie"),
      HeaderValue::from_static("session=abc"),
    );
    headers.insert(
      HeaderName::from_static("dpop"),
      HeaderValue::from_static("proof"),
    );
    headers.insert(
      HeaderName::from_static("accept"),
      HeaderValue::from_static("application/json"),
    );

    let redacted = redact_headers(&headers);
    let map: std::collections::HashMap<_, _> = redacted.into_iter().collect();

    assert_eq!(map.get("authorization").map(String::as_str), Some(REDACTED));
    assert_eq!(map.get("cookie").map(String::as_str), Some(REDACTED));
    assert_eq!(map.get("dpop").map(String::as_str), Some(REDACTED));
    assert_eq!(
      map.get("accept").map(String::as_str),
      Some("application/json")
    );
  }

  #[test]
  fn redaction_json_masks_nested_secrets_but_keeps_code_challenge() {
    let mut value = json!({
      "client_id": "public-client",
      "client_secret": "shh",
      "refresh_token": "rotated",
      "code_challenge": "public-challenge",
      "nested": { "code_verifier": "private", "state": "keep-me" }
    });

    redact_json(&mut value);

    assert_eq!(value["client_id"], json!("public-client"));
    assert_eq!(value["client_secret"], json!(REDACTED));
    assert_eq!(value["refresh_token"], json!(REDACTED));
    assert_eq!(value["code_challenge"], json!("public-challenge"));
    assert_eq!(value["nested"]["code_verifier"], json!(REDACTED));
    assert_eq!(value["nested"]["state"], json!("keep-me"));
  }

  #[test]
  fn redaction_form_and_query_mask_code_and_tokens() {
    assert_eq!(
      redact_form("grant_type=authorization_code&code=abc123&client_id=web"),
      format!("grant_type=authorization_code&code={REDACTED}&client_id=web")
    );

    let uri: Uri = "/authorize?code=abc123&client_id=web&state=s1"
      .parse()
      .unwrap_or_else(|_| Uri::from_static("/"));
    assert_eq!(
      redact_uri(&uri),
      format!("/authorize?code={REDACTED}&client_id=web&state=s1")
    );
  }

  #[test]
  fn redaction_sensitivity_policy_covers_headers_and_derivatives() {
    for key in SENSITIVE_FIELDS {
      assert!(is_sensitive(key), "{key} must be sensitive");
    }
    assert!(is_sensitive("DPoP"));
    assert!(is_sensitive("code-verifier"));
    assert!(is_sensitive("access_token"));
    assert!(is_sensitive("REFRESH_SECRET"));
    assert!(!is_sensitive("code_challenge"));
    assert!(!is_sensitive("client_id"));
    assert!(!is_sensitive(""));
  }
}

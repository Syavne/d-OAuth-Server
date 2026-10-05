//! RFC 9101 §5.2 claim merge: verified claims overlay the query.
//!
//! A claim repeating a query parameter with a different value is a
//! conflict and rejects the request; an identical repeat is accepted.
//! `request`/`request_uri` members inside the object, and a `client_id`
//! member disagreeing with `iss`, are rejected outright so parameters
//! cannot be smuggled past the query binding.

use std::collections::HashMap;

use serde_json::Value;

use crate::error::AppError;

/// JWT claims that carry JOSE semantics and never become authorize params.
const JWT_METADATA_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "nbf", "iat", "jti"];

/// Merge verified claims over the query parameters (RFC 9101 §5.2).
///
/// # Errors
///
/// Returns `invalid_request_object` on any conflict or forbidden member.
pub(crate) fn merge_claims(
  query: &HashMap<String, String>,
  claims: &serde_json::Map<String, Value>,
  client_id: &str,
) -> Result<HashMap<String, String>, AppError> {
  if let Some(Value::String(claimed)) = claims.get("client_id") {
    if claimed != client_id {
      return Err(AppError::invalid_request_object(
        "request object client_id disagrees with iss",
      ));
    }
  } else if claims.contains_key("client_id") {
    return Err(AppError::invalid_request_object(
      "request object client_id must be a string",
    ));
  }
  let mut merged = query.clone();
  for (name, value) in claims {
    if name == "request" || name == "request_uri" {
      return Err(AppError::invalid_request_object(
        "request object must not contain request or request_uri",
      ));
    }
    if JWT_METADATA_CLAIMS.contains(&name.as_str()) {
      continue;
    }
    let rendered = claim_to_string(value)?;
    match merged.get(name) {
      Some(seen) if seen != &rendered => {
        return Err(AppError::invalid_request_object(
          "request object conflicts with a query parameter",
        ));
      }
      _ => {
        merged.insert(name.clone(), rendered);
      }
    }
  }
  Ok(merged)
}

/// Render one claim value as an authorize parameter string.
fn claim_to_string(value: &Value) -> Result<String, AppError> {
  match value {
    Value::String(text) => Ok(text.clone()),
    Value::Number(number) => Ok(number.to_string()),
    Value::Bool(flag) => Ok(flag.to_string()),
    Value::Array(_) | Value::Object(_) => serde_json::to_string(value)
      .map_err(|_| AppError::invalid_request_object("request object claim is not renderable")),
    Value::Null => Err(AppError::invalid_request_object(
      "request object claim must not be null",
    )),
  }
}

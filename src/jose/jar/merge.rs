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
/// The repeated `resource` indicator (RFC 8707) is carried OUT-OF-BAND in
/// [`MergedClaims::resource`]: a `Value::Array` maps to one element per
/// entry and a plain `Value::String` to a single element (any other shape,
/// including `null`, is `invalid_request_object`). Values are never
/// delimiter-joined, so a comma-bearing URI cannot collide. The merged map
/// never carries a `resource` key — a single-valued map cannot hold repeats,
/// and the old `claim_to_string` collapse of an array into one JSON string
/// must never become an audience.
///
/// A `resource` present in BOTH the query map and the claims is
/// `invalid_request_object`: the single-valued query side cannot represent
/// repeats, so a cross-transport duplication is unresolvable fail-closed —
/// the client puts the indicator in exactly one transport.
///
/// # Errors
///
/// Returns `invalid_request_object` on any conflict or forbidden member.
pub(crate) fn merge_claims(
  query: &HashMap<String, String>,
  claims: &serde_json::Map<String, Value>,
  client_id: &str,
) -> Result<MergedClaims, AppError> {
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
  merged.remove("resource");
  let query_had_resource = query.contains_key("resource");
  let mut resource = Vec::new();
  for (name, value) in claims {
    if name == "request" || name == "request_uri" {
      return Err(AppError::invalid_request_object(
        "request object must not contain request or request_uri",
      ));
    }
    if JWT_METADATA_CLAIMS.contains(&name.as_str()) {
      continue;
    }
    if name == "resource" {
      resource = jar_resources(value)?;
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
  if query_had_resource && claims.contains_key("resource") {
    return Err(AppError::invalid_request_object(
      "request object repeats a resource indicator present in the query",
    ));
  }
  Ok(MergedClaims {
    params: merged,
    resource,
  })
}

/// Merged authorize parameters: the single-valued map plus the repeated
/// `resource` indicator carried out-of-band (see [`merge_claims`]).
pub struct MergedClaims {
  /// Effective single-valued parameters (never carries `resource`).
  pub params: HashMap<String, String>,
  /// Repeated `resource` values from a JAR `resource` claim, in order.
  pub resource: Vec<String>,
}

/// Extract a JAR `resource` claim out-of-band: an array maps to one element
/// per entry, a plain string to a single element; anything else (including
/// `null`) is `invalid_request_object`.
fn jar_resources(value: &Value) -> Result<Vec<String>, AppError> {
  match value {
    Value::String(text) => Ok(vec![text.clone()]),
    Value::Array(items) => items
      .iter()
      .map(|item| match item {
        Value::String(text) => Ok(text.clone()),
        _ => Err(AppError::invalid_request_object(
          "request object resource array must contain only strings",
        )),
      })
      .collect(),
    _ => Err(AppError::invalid_request_object(
      "request object resource must be a string or an array of strings",
    )),
  }
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

#[cfg(test)]
mod tests {
  use super::merge_claims;

  /// A JAR `resource` JSON array survives the merge out-of-band: one element
  /// per entry, in order, and never as a joined string in the params map.
  #[test]
  fn jar_resource_array_survives_request_object() -> Result<(), String> {
    let query = std::collections::HashMap::from([("client_id".to_owned(), "client-a".to_owned())]);
    let mut claims = serde_json::Map::new();
    claims.insert(
      "client_id".to_owned(),
      serde_json::Value::String("client-a".to_owned()),
    );
    claims.insert(
      "resource".to_owned(),
      serde_json::json!(["https://b.example.test/", "https://a.example.test/",]),
    );
    let merged = merge_claims(&query, &claims, "client-a")
      .map_err(|error| format!("array resource must merge: {}", error.code()))?;
    if merged.resource
      != vec![
        "https://b.example.test/".to_owned(),
        "https://a.example.test/".to_owned(),
      ]
    {
      return Err(format!(
        "array resource lost or reordered: {:?}",
        merged.resource
      ));
    }
    if merged.params.contains_key("resource") {
      return Err("merged params must never carry resource".to_owned());
    }
    // A plain string is a single element.
    let mut single = serde_json::Map::new();
    single.insert(
      "client_id".to_owned(),
      serde_json::Value::String("client-a".to_owned()),
    );
    single.insert(
      "resource".to_owned(),
      serde_json::Value::String("https://a.example.test/".to_owned()),
    );
    let merged = merge_claims(&query, &single, "client-a")
      .map_err(|error| format!("string resource must merge: {}", error.code()))?;
    if merged.resource != vec!["https://a.example.test/".to_owned()] {
      return Err(format!("string resource lost: {:?}", merged.resource));
    }
    // A non-string array member, a non-string claim, and a null are rejected.
    for bad in [
      serde_json::json!([7]),
      serde_json::json!({"aud": "x"}),
      serde_json::Value::Null,
    ] {
      let mut claims = serde_json::Map::new();
      claims.insert(
        "client_id".to_owned(),
        serde_json::Value::String("client-a".to_owned()),
      );
      claims.insert("resource".to_owned(), bad);
      if merge_claims(&query, &claims, "client-a").is_ok() {
        return Err("non-string resource must be invalid_request_object".to_owned());
      }
    }
    // A `resource` in both the query and the claims is unresolvable
    // fail-closed: the single-valued side cannot represent repeats.
    let both_query = std::collections::HashMap::from([
      ("client_id".to_owned(), "client-a".to_owned()),
      ("resource".to_owned(), "https://a.example.test/".to_owned()),
    ]);
    if merge_claims(&both_query, &single, "client-a").is_ok() {
      return Err("duplicated resource across transports must be rejected".to_owned());
    }
    Ok(())
  }
}

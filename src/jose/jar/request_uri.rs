//! `request_uri` resolution: PAR URNs or pre-registered URIs.
//!
//! A PAR-issued URN is consumed one-time from the PAR store and bound to
//! the presenting client; any other URI must exactly match the client's
//! registered `request_uris` and is then fetched behind the SSRF guard.
//! Arbitrary URIs are never fetched.

use std::collections::HashMap;

use serde_json::Value;

use super::merge::merge_claims;
use super::verify::verify_request_object;
use super::{PAR_REQUEST_URI_PREFIX, fetch::fetch_request_object, merge::MergedClaims};
use crate::{
  db::client_repo::Client,
  error::AppError,
  state::RedisConn,
  store::{Store, par},
};

/// Resolve a `request_uri`: PAR URN or pre-registered URI.
///
/// # Errors
///
/// Returns `invalid_request` for PAR misuse and `invalid_request_object`
/// for unknown, unfetchable, or invalid referenced objects.
pub(crate) async fn resolve_uri(
  conn: &mut RedisConn,
  store: &Store,
  client: &Client,
  issuer: &str,
  query: &HashMap<String, String>,
  uri: &str,
) -> Result<MergedClaims, AppError> {
  if let Some(id) = uri.strip_prefix(PAR_REQUEST_URI_PREFIX) {
    return resolve_par(conn, store, client, query, id).await;
  }
  if !is_registered_request_uri(client, uri) {
    return Err(AppError::invalid_request_object(
      "request_uri is neither PAR-issued nor pre-registered",
    ));
  }
  let body = fetch_request_object(uri).await?;
  let claims = verify_request_object(client, issuer, &body)?;
  merge_claims(query, &claims, &client.client_id)
}

/// Whether `uri` is exactly one of the client's pre-registered JAR
/// `request_uris` (no normalization: fail closed on any deviation).
fn is_registered_request_uri(client: &Client, uri: &str) -> bool {
  match client.request_uris {
    Some(Value::Array(ref items)) => items.iter().any(|item| item.as_str() == Some(uri)),
    _ => false,
  }
}

/// Consume a PAR-issued `request_uri` one-time, bound to `client`.
///
/// The expected client travels inside the consume script: a foreign presenter
/// observes `Mismatched` and the victim record survives for its owner, so a
/// cross-client presentation can never burn the single-use value.
///
/// # Errors
///
/// Returns `invalid_request` for an empty, unknown, consumed, or
/// foreign-client id, and a masked `server_error` when the stored record
/// does not parse.
async fn resolve_par(
  conn: &mut RedisConn,
  store: &Store,
  client: &Client,
  query: &HashMap<String, String>,
  id: &str,
) -> Result<MergedClaims, AppError> {
  if id.is_empty() {
    return Err(AppError::invalid_request("request_uri is malformed"));
  }
  let record = match par::consume_bound(conn, store, id, client.client_id.as_str()).await? {
    par::ConsumeOutcome::Consumed(record) => record,
    par::ConsumeOutcome::Mismatched => {
      return Err(AppError::invalid_request(
        "request_uri was issued to a different client",
      ));
    }
    par::ConsumeOutcome::Absent => {
      return Err(AppError::invalid_request(
        "request_uri is unknown, expired, or already used",
      ));
    }
  };
  let stored: Value = serde_json::from_str(&record.request).map_err(AppError::internal)?;
  let Some(object) = stored.as_object() else {
    return Err(AppError::internal(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "stored PAR record is not a JSON object",
    )));
  };
  // The PAR-pinned audience rides out-of-band (record `aud`, validated at
  // push and re-validated by the authorize caller); the stored JSON object
  // itself carries no `resource` (stripped at push, stripped by the merge).
  let mut merged = merge_claims(query, object, &client.client_id)?;
  merged.resource = record.aud;
  Ok(merged)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn fixture(request_uris: Option<Value>) -> Client {
    Client {
      id: uuid::Uuid::nil(),
      client_id: "jar-fixture".to_owned(),
      client_secret_expires_at: None,
      client_id_issued_at: time::OffsetDateTime::UNIX_EPOCH,
      client_name: "JAR Fixture".to_owned(),
      grant_types: Vec::new(),
      response_types: Vec::new(),
      scope: String::new(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      access_token_format: "opaque".to_owned(),
      active: true,
      created_at: time::OffsetDateTime::UNIX_EPOCH,
      updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
  }

  #[test]
  fn jar_preregistered_request_uri_matches_decrypted_set() {
    let uri = "https://client.example.test/req.jwt";
    let client = fixture(Some(serde_json::json!([uri])));
    assert!(is_registered_request_uri(&client, uri));
    assert!(!is_registered_request_uri(
      &client,
      "https://evil.example.test/req.jwt"
    ));
    assert!(!is_registered_request_uri(
      &client,
      "https://client.example.test/req.jwt/extra"
    ));
    assert!(!is_registered_request_uri(&fixture(None), uri));
  }
}

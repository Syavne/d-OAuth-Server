//! `request_uri` resolution: PAR URNs or pre-registered URIs.
//!
//! A PAR-issued URN is consumed one-time from the PAR store and bound to
//! the presenting client; any other URI must exactly match the client's
//! registered `request_uris` and is then fetched behind the SSRF guard.
//! Arbitrary URIs are never fetched.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
  db::client_repo::Client,
  error::AppError,
  state::RedisConn,
  store::{Store, par},
};

use super::verify::verify_request_object;
use super::{PAR_REQUEST_URI_PREFIX, fetch::fetch_request_object, merge::merge_claims};

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
) -> Result<HashMap<String, String>, AppError> {
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
) -> Result<HashMap<String, String>, AppError> {
  if id.is_empty() {
    return Err(AppError::invalid_request("request_uri is malformed"));
  }
  let record = par::consume(conn, store, id).await?;
  let Some(record) = record else {
    return Err(AppError::invalid_request(
      "request_uri is unknown, expired, or already used",
    ));
  };
  if record.client_id != client.client_id {
    return Err(AppError::invalid_request(
      "request_uri was issued to a different client",
    ));
  }
  let stored: Value = serde_json::from_str(&record.request).map_err(AppError::internal)?;
  let Some(object) = stored.as_object() else {
    return Err(AppError::internal(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "stored PAR record is not a JSON object",
    )));
  };
  merge_claims(query, object, &client.client_id)
}

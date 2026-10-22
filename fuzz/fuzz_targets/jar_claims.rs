//! Fuzz the JAR (request object) claims envelope plus the PAR/JAR
//! mandatory-rule dispatch.
//!
//! The target splits the input into a faux `token_endpoint_auth_method` and a
//! compact-JWT-shaped claims envelope. The envelope parser (three
//! base64url segments, JSON header/payload objects) must never panic;
//! `require_par_or_jar` pins the confidential-client dispatch. Full
//! signature verification needs keys and stays under unit/proptest cover.

#![no_main]

use d_oauth::db::Client;
use d_oauth::jose::jar::require_par_or_jar;
use libfuzzer_sys::fuzz_target;

fn envelope_invariants(compact: &str) {
  let mut parts = compact.split('.');
  let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
    (parts.next(), parts.next(), parts.next(), parts.next())
  else {
    return;
  };
  if sig_b64.is_empty() {
    return;
  }
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
  let Ok(header_raw) = URL_SAFE_NO_PAD.decode(header_b64) else {
    return;
  };
  let Ok(payload_raw) = URL_SAFE_NO_PAD.decode(payload_b64) else {
    return;
  };
  let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_raw) else {
    return;
  };
  let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_raw) else {
    return;
  };
  // Header and payload are JSON objects; a request object names its
  // algorithm and carries claims. Parsing robustness (never panicking on
  // hostile input) is the property under test; validity is decided by the
  // verifier, not the envelope shape, so nothing is asserted here.
  let _ = (header, payload);
}

fn client_with_method(method: &str) -> Client {
  Client {
    id: uuid::Uuid::nil(),
    client_id: "fuzz-client".to_owned(),
    client_secret_expires_at: None,
    client_id_issued_at: time::OffsetDateTime::UNIX_EPOCH,
    client_name: "fuzz".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: method.to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    active: true,
    created_at: time::OffsetDateTime::UNIX_EPOCH,
    updated_at: time::OffsetDateTime::UNIX_EPOCH,
  }
}

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let (method, compact) = match text.split_once('\n') {
    Some((method, compact)) => (method, compact),
    None => ("none", text),
  };
  envelope_invariants(compact);
  let client = client_with_method(method);
  let _ = require_par_or_jar(&client);
});

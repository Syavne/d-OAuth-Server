//! Fuzz client-ID metadata document (CIMD) validation.
//!
//! [`validate_document`] is pure: it enforces the `client_id` echo, the
//! registration-free auth methods, inline-only JWKS, the wildcard-free
//! redirect set, the enabled-scope subset, and the grant allowlist without a
//! fetch, Postgres, or Redis. The input is a first selector byte
//! (`allow_localhost`), one `client_id` line, then a JSON document. An accepted
//! document must echo its identifier, contain no wildcard redirect, and grant
//! only the two registration-free grants.

#![no_main]

use std::collections::HashSet;

use d_oauth::protocol::cimd::{CimdDocument, CimdValidation, validate_document};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Some((flag, rest)) = data.split_first() else {
    return;
  };
  let Ok(text) = core::str::from_utf8(rest) else {
    return;
  };
  let Some((client_id, json)) = text.split_once('\n') else {
    return;
  };
  let Ok(document) = serde_json::from_str::<CimdDocument>(json) else {
    return;
  };
  let scopes: HashSet<String> = ["read", "write"]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
  let validation = CimdValidation {
    enabled_scopes: &scopes,
    allow_localhost: *flag % 2 == 1,
  };
  let Ok(validated) = validate_document(client_id, &document, &validation) else {
    return;
  };
  // Accepted documents echo the URL they were validated under.
  assert_eq!(validated.client_id, client_id);
  // No wildcard ever survives the redirect allowlist.
  assert!(
    validated.redirect_uris.iter().all(|uri| !uri.contains('*')),
    "accepted document kept a wildcard redirect"
  );
  // Only the registration-free grants survive.
  assert!(
    validated
      .grant_types
      .iter()
      .all(|grant| grant == "authorization_code" || grant == "refresh_token"),
    "accepted document kept a non-CIMD grant"
  );
});

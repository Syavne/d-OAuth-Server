//! Fuzz JOSE assertion verification (`private_key_jwt`, RFC 7523).
//!
//! The assertion and the client JWKS document are both hostile input:
//! [`validate_assertion`] parses the compact-JWT envelope, enforces the
//! asymmetric `alg` allowlist, refuses `jku`/`x5u` fetch directives, pins a
//! single `kid` candidate, and checks `iss`/`sub`/`aud`/`exp`/`jti` — all
//! without I/O (the JWKS document is passed in, so no `jwks_uri` fetch and
//! no replay store). [`unverified_iss`] reads only the envelope's `iss` for
//! client lookup. Neither must ever panic; the `jti` replay claim itself
//! needs Redis and stays under unit cover.

#![no_main]

use d_oauth::protocol::client_auth::assertion::{unverified_iss, validate_assertion};
use libfuzzer_sys::fuzz_target;

/// Pinned clock for the assertion window: a fixed instant, never the wall
/// clock, so the harness is deterministic and hermetic.
fn now() -> time::OffsetDateTime {
  match time::OffsetDateTime::from_unix_timestamp(1_700_000_000) {
    Ok(instant) => instant,
    Err(_) => time::OffsetDateTime::UNIX_EPOCH,
  }
}

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let mut lines = text.split('\n');
  let (Some(assertion), Some(jwks_text), Some(client_id), Some(token_endpoint)) =
    (lines.next(), lines.next(), lines.next(), lines.next())
  else {
    return;
  };
  let Ok(jwks_doc) = serde_json::from_str::<serde_json::Value>(jwks_text) else {
    return;
  };
  let _ = unverified_iss(assertion);
  let _ = validate_assertion(assertion, &jwks_doc, client_id, token_endpoint, now());
});

//! Fuzz dynamic client registration JSON (`RegisterRequest` deserialization).
//!
//! The DCR body must never panic the deserializer on any input; unknown
//! fields are ignored and client-asserted secrets are never honored (the
//! server mints every credential it returns).

#![no_main]

use d_oauth::protocol::dcr::RegisterRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
    return;
  };
  let Ok(request) = serde_json::from_value::<RegisterRequest>(value) else {
    return;
  };
  // Deserialization accepted the body; the request carries no server-minted
  // credential surface (`client_secret`, ids, timestamps are absent by type).
  let _ = request.redirect_uris.is_some() || request.scope.is_some();
});

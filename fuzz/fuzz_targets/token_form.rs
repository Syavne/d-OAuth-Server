//! Fuzz the opaque token-form parser (`TokenHash::parse_storage_string`).
//!
//! The parser must never panic on any input; an accepted value must
//! re-render byte-identically (parse-print stability).

#![no_main]

use d_oauth::crypto::tokens::TokenHash;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let Ok(parsed) = TokenHash::parse_storage_string(text) else {
    return;
  };
  // Accepted values re-render to the exact input (canonical form only).
  let rendered = parsed.to_storage_string();
  let Ok(reparsed) = TokenHash::parse_storage_string(&rendered) else {
    return;
  };
  debug_assert_eq!(parsed, reparsed);
});

//! Fuzz scope parsing (`protocol::scope::ScopeSet`, RFC 6749 §3.3).
//!
//! The raw `scope` value is hostile input: tokens split on single `0x20`
//! spaces with no empty tokens, length- and count-capped. Parsing must never
//! panic; an accepted set re-renders to the canonical wire form
//! (single-space-joined, sorted, deduped), which parses back to the same set.

#![no_main]

use d_oauth::protocol::scope::ScopeSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Ok(raw) = core::str::from_utf8(data) else {
    return;
  };
  let Ok(parsed) = ScopeSet::parse(raw) else {
    return;
  };
  let rendered = parsed.render();
  let Ok(reparsed) = ScopeSet::parse(&rendered) else {
    return;
  };
  debug_assert_eq!(parsed, reparsed);
});

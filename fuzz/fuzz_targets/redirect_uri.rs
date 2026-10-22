//! Fuzz `redirect_uri` matching (`protocol::redirect_repo`, RFC 3986 §6.2.1
//! plus the RFC 8252 §7.3 loopback exception).
//!
//! Both the requested URI (first input line) and the registered catalog set
//! (following lines, capped) are hostile input: the matcher must never panic,
//! never fall back to prefix/wildcard comparison, and only report `Exact`
//! for a character-for-character member of the registered set.

#![no_main]

use d_oauth::protocol::redirect_repo::{RedirectDecision, match_redirect_uri};
use libfuzzer_sys::fuzz_target;

/// Maximum registered URIs taken from one input; matching is linear, so the
/// cap keeps a single execution bounded.
const MAX_REGISTERED: usize = 8;

fuzz_target!(|data: &[u8]| {
  let Ok(text) = core::str::from_utf8(data) else {
    return;
  };
  let mut lines = text.split('\n');
  let Some(requested) = lines.next() else {
    return;
  };
  let registered: Vec<&str> = lines.take(MAX_REGISTERED).collect();
  // Flag off is the default policy; flag on additionally admits the exact
  // host `localhost` as a loopback host. Both must hold the same invariants.
  let decision = match_redirect_uri(&registered, requested, false);
  let localhost_decision = match_redirect_uri(&registered, requested, true);
  // An empty catalog can never match.
  if registered.is_empty() {
    debug_assert_eq!(decision, RedirectDecision::Reject);
    debug_assert_eq!(localhost_decision, RedirectDecision::Reject);
  }
  // `Exact` fires only for a character-for-character registered member.
  for decision in [decision, localhost_decision] {
    if decision == RedirectDecision::Exact {
      debug_assert!(registered.contains(&requested));
    }
  }
});

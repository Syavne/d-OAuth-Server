//! Fuzz the wire-form helpers (`protocol::params`).
//!
//! [`parse_pairs`] is lossy but infallible on malformed percent escapes and
//! non-UTF-8, so it must never panic on any input. Once accepted, the ordered
//! pairs feed [`values_of`] (wire order) and [`single_valued_map`] (last-wins);
//! [`has_duplicate_field`] reports a repeat only for a known field.

#![no_main]

use d_oauth::protocol::params::{has_duplicate_field, parse_pairs, single_valued_map, values_of};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Ok(raw) = core::str::from_utf8(data) else {
    return;
  };
  let Ok(pairs) = parse_pairs(raw) else {
    return;
  };

  // One pair per non-empty segment, in wire order.
  let segments = raw.split('&').filter(|segment| !segment.is_empty()).count();
  assert_eq!(pairs.len(), segments, "parse_pairs dropped or added a pair");

  // Distinct names in first-occurrence order.
  let mut names: Vec<&str> = Vec::new();
  for (name, _) in &pairs {
    if !names.contains(&name.as_str()) {
      names.push(name);
    }
  }

  let map = single_valued_map(&pairs);
  assert_eq!(map.len(), names.len(), "map lost a distinct name");
  for name in &names {
    let values = values_of(&pairs, name);
    assert!(!values.is_empty(), "known name produced no value");
    // Last-wins: the map carries the final occurrence.
    assert_eq!(
      map.get(*name),
      values.last(),
      "map did not keep the last value"
    );
  }

  // A repeat is reported exactly when a known name occurs twice or more.
  let expected = names.iter().any(|name| values_of(&pairs, name).len() > 1);
  assert_eq!(
    has_duplicate_field(&pairs, &names),
    expected,
    "duplicate detection disagreed with the wire pairs"
  );
});

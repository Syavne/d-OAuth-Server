//! `test(proptest_scope)` — scope-parser property suite (task 42).
//!
//! Pure properties over `protocol::scope::ScopeSet::parse`: the parser never
//! panics, rejects only with `invalid_scope`, accepts the RFC 6749
//! scope-token alphabet, enforces the count cap, and refuses empty tokens.
//! Test bodies use `prop_assert!` (no `unwrap`/`expect`/`panic` anywhere).

use d_oauth::{
  error::{AppError, OAuthErrorCode},
  protocol::scope::{MAX_SCOPE_COUNT, ScopeSet},
};
use proptest::prelude::*;

fn is_invalid_scope<T>(result: Result<T, AppError>) -> bool {
  matches!(
    result,
    Err(AppError::OAuth {
      code: OAuthErrorCode::InvalidScope,
      ..
    })
  )
}

proptest! {
  #[test]
  fn scope_parse_never_panics_and_rejects_only_invalid_scope(raw in "\\PC*") {
    match ScopeSet::parse(&raw) {
      Ok(set) => {
        // An accepted value renders to a form that re-parses identically.
        let rendered = set.render();
        match ScopeSet::parse(&rendered) {
          Ok(again) => {
            prop_assert_eq!(set.render(), again.render());
            prop_assert!(again.is_subset_of(&set));
          }
          Err(_) => prop_assert!(false, "rendered form must re-parse"),
        }
      }
      Err(error) => prop_assert!(
        matches!(
          error,
          AppError::OAuth {
            code: OAuthErrorCode::InvalidScope,
            ..
          }
        ),
        "parser must reject only with invalid_scope"
      ),
    }
  }

  #[test]
  fn scope_parse_accepts_the_token_alphabet(words in proptest::collection::vec("[!-~&&[^\"\\\\]]{1,16}", 1..8)) {
    // `%x21 / %x23-5B / %x5D-7E`: printable ASCII except space, `"`, `\`.
    let raw = words.join(" ");
    match ScopeSet::parse(&raw) {
      Ok(set) => {
        prop_assert_eq!(set.render(), {
          let mut sorted = words.clone();
          sorted.sort();
          sorted.dedup();
          sorted.join(" ")
        });
      }
      Err(_) => prop_assert!(false, "alphabet words must parse: {:?}", raw),
    }
  }

  #[test]
  fn scope_parse_rejects_empty_tokens(words in proptest::collection::vec("[a-z]{1,8}", 2..6)) {
    // Joining with a double space always leaves an empty token.
    let doubled = words.join("  ");
    prop_assert!(is_invalid_scope(ScopeSet::parse(&doubled)));
    // A leading space always leaves an empty token.
    let leading = format!(" {}", words.join(" "));
    prop_assert!(is_invalid_scope(ScopeSet::parse(&leading)));
  }

  #[test]
  fn scope_parse_enforces_the_count_cap(extra in 1..8_usize) {
    let many: Vec<String> = (0..MAX_SCOPE_COUNT + extra).map(|i| format!("s{i}")).collect();
    prop_assert!(is_invalid_scope(ScopeSet::from_names(&many)));
  }
}

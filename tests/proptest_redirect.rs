//! `test(proptest_redirect)` — redirect-matcher property suite (task 42).
//!
//! Pure properties over `protocol::redirect_repo::match_redirect_uri`
//! (RFC 3986 §6.2.1 Simple String Comparison + RFC 8252 §7.3 loopback):
//! exact self-match, empty-set rejection, `Exact` implies membership,
//! `Loopback` implies a loopback request shape, and `Exact` outranks
//! `Loopback`. No `unwrap`/`expect`/`panic` anywhere.

use d_oauth::protocol::redirect_repo::{RedirectDecision, match_redirect_uri};
use proptest::prelude::*;

/// Well-formed registered redirect URIs (no userinfo/query/fragment).
///
/// The dots are regex-escaped: an unescaped `.` would generate arbitrary
/// characters (including `?`/`#`/`@`), producing registrations the matcher
/// must fail closed on instead of matching.
fn registered_uri() -> impl Strategy<Value = String> {
  (
    "https://client\\.example\\.test/cb/[a-z0-9]{0,8}",
    "[a-z0-9]{0,6}",
  )
    .prop_map(|(base, tail)| {
      if tail.is_empty() {
        base
      } else {
        format!("{base}/{tail}")
      }
    })
}

/// Whether `requested` has the loopback request shape the matcher demands:
/// `http` scheme (any ASCII case), loopback-literal host, no userinfo,
/// query, or fragment (mirrors `parse_uri` + the §7.3 arm, not its code).
fn is_loopback_shaped(requested: &str) -> bool {
  let Some((scheme, rest)) = requested.split_once(':') else {
    return false;
  };
  if !scheme.eq_ignore_ascii_case("http") || !rest.starts_with("//") {
    return false;
  }
  let authority = &rest[2..];
  let host = authority.split([':', '/']).next().unwrap_or("");
  if host != "127.0.0.1" && host != "[::1]" {
    return false;
  }
  !requested.contains(['?', '#', '@'])
}

proptest! {
  #[test]
  fn redirect_exact_self_match(uri in registered_uri()) {
    prop_assert_eq!(
      match_redirect_uri(std::slice::from_ref(&uri), &uri),
      RedirectDecision::Exact
    );
  }

  #[test]
  fn redirect_empty_set_always_rejects(requested in "\\PC*") {
    let empty: Vec<String> = vec![];
    prop_assert_eq!(
      match_redirect_uri(&empty, &requested),
      RedirectDecision::Reject
    );
  }

  #[test]
  fn redirect_exact_implies_membership(
    registered in proptest::collection::vec(registered_uri(), 0..4),
    requested in "\\PC*",
  ) {
    if match_redirect_uri(&registered, &requested) == RedirectDecision::Exact {
      prop_assert!(registered.iter().any(|candidate| candidate == &requested));
    }
  }

  #[test]
  fn redirect_loopback_implies_loopback_request_shape(
    registered in proptest::collection::vec(registered_uri(), 0..4),
    requested in "\\PC*",
  ) {
    if match_redirect_uri(&registered, &requested) == RedirectDecision::Loopback {
      prop_assert!(
        is_loopback_shaped(&requested),
        "loopback match needs a loopback request: {:?}",
        requested
      );
    }
  }

  #[test]
  fn redirect_exact_outranks_loopback(port in 1024..65535_u16, path in "[a-z]{1,8}") {
    let loopback_reg = "http://127.0.0.1/cb".to_owned();
    let exact = format!("https://client.example.test/{path}");
    let requested_loopback = format!("http://127.0.0.1:{port}/cb");
    // The exact registration wins when it matches byte-for-byte, even with
    // a loopback candidate that would also match its own request shape.
    prop_assert_eq!(
      match_redirect_uri(&[loopback_reg.clone(), exact.clone()], &exact),
      RedirectDecision::Exact
    );
    // And the loopback arm still fires for the port-flexible request.
    prop_assert_eq!(
      match_redirect_uri(&[loopback_reg, exact], &requested_loopback),
      RedirectDecision::Loopback
    );
  }
}

//! Tests for `redirect_uri` matching (RFC 3986 §6.2.1 / RFC 8252 §7.3).

use super::{RedirectDecision, is_valid_redirect_scheme, match_redirect_uri};

#[test]
fn redirect_uri_exact_string_match_is_accepted() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb", false),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_trailing_slash_mismatch_is_rejected() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb/", false),
    RedirectDecision::Reject
  );

  let registered = ["https://client.example.test/cb/"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb", false),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_loopback_ipv4_port_variance_is_accepted() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb", false),
    RedirectDecision::Loopback
  );

  let registered = ["http://127.0.0.1/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb", false),
    RedirectDecision::Loopback
  );
}

#[test]
fn redirect_uri_loopback_ipv6_port_variance_is_accepted() {
  let registered = ["http://[::1]:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://[::1]:49152/cb", false),
    RedirectDecision::Loopback
  );
}

#[test]
fn redirect_uri_loopback_same_port_is_exact() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:5173/cb", false),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_non_loopback_http_is_rejected() {
  let registered = ["http://evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://evil.example/cb", false),
    RedirectDecision::Reject
  );

  let registered = ["HTTP://evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "HTTP://evil.example/cb", false),
    RedirectDecision::Reject
  );

  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://evil.example/cb", false),
    RedirectDecision::Reject
  );
}

/// With `allow_localhost` off, `localhost` is not loopback: it is rejected as
/// a registration and cannot satisfy a loopback request. This must stay
/// exactly as it was before the flag existed.
#[test]
fn redirect_uri_localhost_is_rejected() {
  let registered = ["http://localhost:8080/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:8080/cb", false),
    RedirectDecision::Reject
  );

  let registered = ["http://127.0.0.1/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb", false),
    RedirectDecision::Reject
  );
}

/// With `allow_localhost` on, `http://localhost` is an RFC 8252 §7.3 loopback
/// host: host+path must match exactly and the port is ignored. `127.0.0.1`
/// and `[::1]` are unaffected by the flag.
#[test]
fn redirect_uri_localhost_port_variance_is_accepted() {
  let registered = ["http://localhost:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb", true),
    RedirectDecision::Loopback
  );

  let registered = ["http://localhost/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb", true),
    RedirectDecision::Loopback
  );

  // Same port is still an exact match.
  let registered = ["http://localhost:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:5173/cb", true),
    RedirectDecision::Exact
  );

  // A path mismatch is never matched, port variance or not.
  let registered = ["http://localhost:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/other", true),
    RedirectDecision::Reject
  );

  // The literal IPs keep their pre-flag behavior when the flag is on.
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb", true),
    RedirectDecision::Loopback
  );
}

/// The flag only widens the loopback exception to the exact host
/// `localhost`; a different host, a suffix confusion, or a request smuggling
/// userinfo/query/fragment is still rejected.
#[test]
fn redirect_uri_localhost_non_loopback_still_rejected() {
  // A non-loopback host is refused even with the flag on.
  let registered = ["http://evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://evil.example/cb", true),
    RedirectDecision::Reject
  );

  // A suffix that merely contains `localhost` is not the exact host.
  let registered = ["http://localhost.evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost.evil.example/cb", true),
    RedirectDecision::Reject
  );

  // A registered localhost URI does not match a different requested host.
  let registered = ["http://localhost:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb", true),
    RedirectDecision::Reject
  );

  // Loopback port variance never excuses a query fragment on the request.
  let registered = ["http://localhost:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb?x=1", true),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb#frag", true),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "http://user@localhost:49152/cb", true),
    RedirectDecision::Reject
  );

  // A registered URI that smuggles userinfo/query/fragment is never eligible.
  let registered = ["http://localhost:5173/cb?x=1"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb", true),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_registered_query_fragment_userinfo_are_rejected() {
  for registered in [
    ["https://client.example.test/cb?x=1"],
    ["https://client.example.test/cb#frag"],
    ["https://user@client.example.test/cb"],
  ] {
    let requested = registered[0];
    assert_eq!(
      match_redirect_uri(&registered, requested, false),
      RedirectDecision::Reject,
      "malformed registration must never match: {requested}"
    );
  }
}

#[test]
fn redirect_uri_loopback_request_with_query_is_rejected() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb?x=1", false),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_prefix_and_substring_are_not_matched() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb/evil", false),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/c", false),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "https://sub.client.example.test/cb", false),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_empty_set_is_rejected() {
  let registered: [&str; 0] = [];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb", false),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_exact_takes_precedence_over_loopback() {
  let registered = ["http://127.0.0.1:5173/cb", "http://127.0.0.1:49152/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb", false),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_private_scheme_without_dot_is_rejected() {
  // draft-ietf-oauth-v2-1-16 §2.3.1 SHOULD: a private-use scheme is
  // reverse-DNS based, so it must contain a `.`.
  let registered = ["myapp:/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "myapp:/cb", false),
    RedirectDecision::Reject
  );

  let registered = ["myapp:/"];
  assert_eq!(
    match_redirect_uri(&registered, "myapp:/", false),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_private_scheme_with_dot_is_accepted() {
  let registered = ["com.example.app:/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "com.example.app:/cb", false),
    RedirectDecision::Exact
  );

  let registered = ["com.example.app:/"];
  assert_eq!(
    match_redirect_uri(&registered, "com.example.app:/", false),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_private_scheme_dot_check_leaves_https_and_loopback_unchanged() {
  assert!(is_valid_redirect_scheme("https://client.example.test/cb"));
  assert!(is_valid_redirect_scheme("http://127.0.0.1:5173/cb"));
  assert!(is_valid_redirect_scheme("http://[::1]:5173/cb"));
  assert!(is_valid_redirect_scheme("com.example.app:/"));
  assert!(is_valid_redirect_scheme("com.example.app:/cb"));
  assert!(!is_valid_redirect_scheme("myapp:/"));
  assert!(!is_valid_redirect_scheme("myapp:/cb"));
}

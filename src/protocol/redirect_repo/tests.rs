//! Tests for `redirect_uri` matching (RFC 3986 §6.2.1 / RFC 8252 §7.3).

use super::{RedirectDecision, match_redirect_uri};

#[test]
fn redirect_uri_exact_string_match_is_accepted() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb"),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_trailing_slash_mismatch_is_rejected() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb/"),
    RedirectDecision::Reject
  );

  let registered = ["https://client.example.test/cb/"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb"),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_loopback_ipv4_port_variance_is_accepted() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb"),
    RedirectDecision::Loopback
  );

  let registered = ["http://127.0.0.1/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb"),
    RedirectDecision::Loopback
  );
}

#[test]
fn redirect_uri_loopback_ipv6_port_variance_is_accepted() {
  let registered = ["http://[::1]:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://[::1]:49152/cb"),
    RedirectDecision::Loopback
  );
}

#[test]
fn redirect_uri_loopback_same_port_is_exact() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:5173/cb"),
    RedirectDecision::Exact
  );
}

#[test]
fn redirect_uri_non_loopback_http_is_rejected() {
  let registered = ["http://evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://evil.example/cb"),
    RedirectDecision::Reject
  );

  let registered = ["HTTP://evil.example/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "HTTP://evil.example/cb"),
    RedirectDecision::Reject
  );

  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://evil.example/cb"),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_localhost_is_rejected() {
  let registered = ["http://localhost:8080/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:8080/cb"),
    RedirectDecision::Reject
  );

  let registered = ["http://127.0.0.1/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://localhost:49152/cb"),
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
      match_redirect_uri(&registered, requested),
      RedirectDecision::Reject,
      "malformed registration must never match: {requested}"
    );
  }
}

#[test]
fn redirect_uri_loopback_request_with_query_is_rejected() {
  let registered = ["http://127.0.0.1:5173/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb?x=1"),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_prefix_and_substring_are_not_matched() {
  let registered = ["https://client.example.test/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb/evil"),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/c"),
    RedirectDecision::Reject
  );
  assert_eq!(
    match_redirect_uri(&registered, "https://sub.client.example.test/cb"),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_empty_set_is_rejected() {
  let registered: [&str; 0] = [];
  assert_eq!(
    match_redirect_uri(&registered, "https://client.example.test/cb"),
    RedirectDecision::Reject
  );
}

#[test]
fn redirect_uri_exact_takes_precedence_over_loopback() {
  let registered = ["http://127.0.0.1:5173/cb", "http://127.0.0.1:49152/cb"];
  assert_eq!(
    match_redirect_uri(&registered, "http://127.0.0.1:49152/cb"),
    RedirectDecision::Exact
  );
}

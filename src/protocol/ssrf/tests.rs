//! `test(ssrf)` suite: URL policy and target blocking (offline).

use std::net::IpAddr;

use super::{check_fetch_host, fetch_guarded_bytes, is_blocked_ip, validate_fetch_url};

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// An assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

fn blocked(addr: &str) -> Result<bool, TestError> {
  let ip: IpAddr = addr
    .parse()
    .map_err(|_| TestError::Unexpected(addr.to_owned()))?;
  Ok(is_blocked_ip(&ip))
}

#[test]
fn ssrf_loopback_and_private_are_blocked() -> TestResult {
  for addr in [
    "127.0.0.1",
    "127.0.0.2",
    "::1",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "169.254.10.20",
    "fe80::1",
    "fc00::1",
    "0.0.0.0",
    "::",
    "255.255.255.255",
    "224.0.0.1",
    "100.64.0.1",
    "192.0.2.1",
    "168.63.129.16",
    "100.100.100.200",
  ] {
    if !blocked(addr)? {
      return Err(TestError::Unexpected(format!("{addr} should be blocked")));
    }
  }
  Ok(())
}

#[test]
fn ssrf_public_addresses_pass() -> TestResult {
  for addr in ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888"] {
    if blocked(addr)? {
      return Err(TestError::Unexpected(format!("{addr} should pass")));
    }
  }
  Ok(())
}

#[test]
fn ssrf_mapped_ipv6_is_blocked() -> TestResult {
  for addr in [
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:10.0.0.1",
    "::ffff:192.168.1.1",
    "::ffff:168.63.129.16",
  ] {
    if !blocked(addr)? {
      return Err(TestError::Unexpected(format!("{addr} should be blocked")));
    }
  }
  if blocked("::ffff:8.8.8.8")? {
    return Err(TestError::Unexpected(
      "::ffff:8.8.8.8 should pass".to_owned(),
    ));
  }
  Ok(())
}

#[test]
fn ssrf_url_policy_rejects_plain_http_and_credentials() -> TestResult {
  if validate_fetch_url("http://example.com/jwks.json").is_ok() {
    return Err(TestError::Unexpected("http must be rejected".to_owned()));
  }
  if validate_fetch_url("https://user:pass@example.com/jwks.json").is_ok() {
    return Err(TestError::Unexpected(
      "credentials in URL must be rejected".to_owned(),
    ));
  }
  if validate_fetch_url("https://").is_ok() {
    return Err(TestError::Unexpected(
      "missing host must be rejected".to_owned(),
    ));
  }
  if validate_fetch_url("not a url").is_ok() {
    return Err(TestError::Unexpected(
      "malformed URL must be rejected".to_owned(),
    ));
  }
  if validate_fetch_url("https://example.com/jwks.json").is_err() {
    return Err(TestError::Unexpected(
      "valid https URL must pass policy".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn ssrf_private_literal_host_is_blocked_pre_fetch() -> TestResult {
  if check_fetch_host("127.0.0.1", 443).await.is_ok() {
    return Err(TestError::Unexpected(
      "loopback literal must be blocked".to_owned(),
    ));
  }
  if check_fetch_host("10.1.2.3", 443).await.is_ok() {
    return Err(TestError::Unexpected(
      "private literal must be blocked".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn ssrf_guarded_fetch_rejects_private_target_without_network() -> TestResult {
  match fetch_guarded_bytes("https://127.0.0.1:8443/jwks.json").await {
    Err(super::SsrfError::BlockedTarget) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => Err(TestError::Unexpected(
      "private target must never be fetched".to_owned(),
    )),
  }
}

#[tokio::test]
async fn ssrf_guarded_fetch_rejects_http_without_network() -> TestResult {
  match fetch_guarded_bytes("http://127.0.0.1:8080/jwks.json").await {
    Err(super::SsrfError::NonHttps) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => Err(TestError::Unexpected(
      "http must never be fetched".to_owned(),
    )),
  }
}

#[tokio::test]
async fn ssrf_check_returns_pinned_addrs_for_public_literal() -> TestResult {
  match check_fetch_host("8.8.8.8", 443).await {
    Ok(addrs) => {
      let expected: IpAddr = "8.8.8.8"
        .parse()
        .map_err(|_| TestError::Unexpected("fixture literal must parse".to_owned()))?;
      if addrs
        .iter()
        .any(|addr| addr.ip() == expected && addr.port() == 443)
      {
        Ok(())
      } else {
        Err(TestError::Unexpected(
          "validated addresses must contain the pinned literal".to_owned(),
        ))
      }
    }
    Err(other) => Err(TestError::Unexpected(format!("wrong error: {other}"))),
  }
}

#[tokio::test]
async fn ssrf_check_denies_blocked_literal_with_blocked_target() -> TestResult {
  match check_fetch_host("127.0.0.1", 443).await {
    Err(super::SsrfError::BlockedTarget) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => Err(TestError::Unexpected(
      "loopback literal must never validate".to_owned(),
    )),
  }
}

#[tokio::test]
async fn ssrf_check_denies_hostname_resolving_to_blocked() -> TestResult {
  // `localhost` resolves via the local hosts file (no external DNS), so
  // this stays offline while proving a hostname whose addresses are all
  // blocked is denied with the validated addresses withheld.
  match check_fetch_host("localhost", 443).await {
    Err(super::SsrfError::BlockedTarget) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => Err(TestError::Unexpected(
      "localhost must never validate".to_owned(),
    )),
  }
}

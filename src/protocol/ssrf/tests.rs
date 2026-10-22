//! `test(ssrf)` suite: URL policy and target blocking (offline).

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
  check_fetch_host, fetch_guarded_bytes, fetch_guarded_bytes_with, fetch_pinned, is_blocked_ip,
  validate_fetch_url,
};

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

async fn serve_once(
  status: u16,
  headers: &[(&str, &str)],
  body: &[u8],
  delay: Duration,
) -> Result<reqwest::Url, TestError> {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .map_err(|err| TestError::Unexpected(err.to_string()))?;
  let addr = listener
    .local_addr()
    .map_err(|err| TestError::Unexpected(err.to_string()))?;
  let body = body.to_vec();
  let headers: Vec<(String, String)> = headers
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect();
  tokio::spawn(async move {
    let Ok((mut socket, _)) = listener.accept().await else {
      return;
    };
    let mut scratch = [0_u8; 1024];
    let _ = socket.read(&mut scratch).await;
    if !delay.is_zero() {
      tokio::time::sleep(delay).await;
    }
    let mut response = format!(
      "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
      body.len()
    );
    for (name, value) in &headers {
      response.push_str(name);
      response.push_str(": ");
      response.push_str(value);
      response.push_str("\r\n");
    }
    response.push_str("\r\n");
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    let _ = socket.shutdown().await;
  });
  reqwest::Url::parse(&format!("http://{addr}/doc.json"))
    .map_err(|err| TestError::Unexpected(err.to_string()))
}

#[tokio::test]
async fn ssrf_per_call_cap_and_timeout() -> TestResult {
  match fetch_guarded_bytes_with(
    "https://127.0.0.1:8443/doc.json",
    5120,
    Duration::from_secs(1),
  )
  .await
  {
    Err(super::SsrfError::BlockedTarget) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "loopback must never be fetched".to_owned(),
      ));
    }
  }
  match fetch_guarded_bytes_with("http://127.0.0.1:9/doc.json", 5120, Duration::from_secs(1)).await
  {
    Err(super::SsrfError::NonHttps) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "http must never be fetched".to_owned(),
      ));
    }
  }
  match fetch_guarded_bytes("https://192.0.2.1/doc.json").await {
    Err(super::SsrfError::BlockedTarget) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "documentation range must not be fetched".to_owned(),
      ));
    }
  }

  // The loopback ban is bypassed for these mechanics only: the https policy
  // is asserted above, and a trusted test CA cannot be stood up offline.
  let over = vec![b'a'; 5121];
  let over_url = serve_once(200, &[], &over, Duration::ZERO).await?;
  match fetch_pinned(&over_url, "127.0.0.1", &[], 5120, Duration::from_secs(5)).await {
    Err(super::SsrfError::TooLarge) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "over-cap body must be rejected".to_owned(),
      ));
    }
  }

  let exact = vec![b'b'; 5120];
  let exact_url = serve_once(200, &[], &exact, Duration::ZERO).await?;
  match fetch_pinned(&exact_url, "127.0.0.1", &[], 5120, Duration::from_secs(5)).await {
    Ok(body) if body.len() == 5120 => {}
    Ok(_) => {
      return Err(TestError::Unexpected(
        "body at the cap must be intact".to_owned(),
      ));
    }
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
  }

  let redirect_url = serve_once(302, &[("Location", "/elsewhere")], b"", Duration::ZERO).await?;
  match fetch_pinned(
    &redirect_url,
    "127.0.0.1",
    &[],
    5120,
    Duration::from_secs(5),
  )
  .await
  {
    Err(super::SsrfError::BadStatus) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "redirect must not be followed".to_owned(),
      ));
    }
  }

  let slow_url = serve_once(200, &[], b"ok", Duration::from_millis(500)).await?;
  match fetch_pinned(&slow_url, "127.0.0.1", &[], 5120, Duration::from_millis(50)).await {
    Err(super::SsrfError::FetchFailed) => {}
    Err(other) => return Err(TestError::Unexpected(format!("wrong error: {other}"))),
    Ok(_) => {
      return Err(TestError::Unexpected(
        "slow response must time out".to_owned(),
      ));
    }
  }

  Ok(())
}

#[test]
fn ssrf_rejects_special_use_ranges() -> TestResult {
  for addr in [
    "0.0.0.0",
    "0.255.255.255",
    "192.0.0.1",
    "192.0.0.170",
    "192.88.99.1",
    "198.18.0.1",
    "198.19.255.255",
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "100.64.0.1",
    "240.0.0.1",
    "192.31.196.1",
    "192.52.193.1",
    "192.175.48.1",
    "64:ff9b::7f00:1",
    "64:ff9b:1::1",
    "2002:7f00:1::",
    "2001::1",
    "2001:1::1",
    "2001:2::1",
    "2001:3::1",
    "2001:4:112::1",
    "2001:10::1",
    "2001:20::1",
    "100::1",
    "2001:db8::1",
    "::127.0.0.1",
    "::169.254.169.254",
    "::ffff:0:127.0.0.1",
    "::ffff:0.0.0.1",
    "::ffff:192.0.0.1",
    "::ffff:198.18.0.1",
  ] {
    if !blocked(addr)? {
      return Err(TestError::Unexpected(format!("{addr} should be blocked")));
    }
  }
  for addr in [
    "192.0.1.1",
    "198.17.0.1",
    "198.20.0.1",
    "192.31.197.1",
    "2001:4860:4860::8888",
    "::8.8.8.8",
  ] {
    if blocked(addr)? {
      return Err(TestError::Unexpected(format!("{addr} should pass")));
    }
  }
  Ok(())
}

/// An expired deadline leaves no budget; a future deadline leaves some. The
/// helper drives the fail-closed total-timeout budget in
/// `fetch_guarded_bytes_with`.
#[test]
fn ssrf_remaining_budget_expired_is_none() -> TestResult {
  let past = tokio::time::Instant::now()
    .checked_sub(Duration::from_secs(1))
    .ok_or_else(|| TestError::Unexpected("clock must allow a past deadline".to_owned()))?;
  if super::remaining_budget(past).is_some() {
    return Err(TestError::Unexpected(
      "an expired deadline must leave no budget".to_owned(),
    ));
  }
  let future = tokio::time::Instant::now() + Duration::from_secs(5);
  match super::remaining_budget(future) {
    Some(left) if !left.is_zero() => Ok(()),
    _ => Err(TestError::Unexpected(
      "a future deadline must leave budget".to_owned(),
    )),
  }
}

/// A zero total budget fails closed before any policy or DNS work: even a
/// blocked target reports `FetchFailed`, never reaching the guard.
#[tokio::test]
async fn ssrf_zero_timeout_fails_closed_before_policy() -> TestResult {
  match fetch_guarded_bytes_with("https://127.0.0.1:8443/doc.json", 5_120, Duration::ZERO).await {
    Err(super::SsrfError::FetchFailed) => Ok(()),
    Err(other) => Err(TestError::Unexpected(format!(
      "zero budget must be FetchFailed, got {other}"
    ))),
    Ok(_) => Err(TestError::Unexpected(
      "zero budget must never fetch".to_owned(),
    )),
  }
}

//! SSRF guard for outbound fetches (`request_uri`, `jwks_uri`).
//!
//! Every server-side fetch of an operator- or client-supplied URL passes
//! through [`fetch_guarded_bytes`]: `https`-only, no redirects, response
//! size/timeout caps, and a pre-flight DNS check that denies
//! private/loopback/link-local targets and cloud-metadata IPs before any
//! socket is opened. A denial is fail-closed and never carries the fetched
//! content.
//!
//! DNS-rebinding hardening: the pre-flight check returns the validated
//! addresses and the fetch pins the HTTP client to exactly those addresses
//! (`resolve_to_addrs`), so a hostname that flips to a blocked address
//! between validation and connect time cannot steer the connection.

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::redirect::Policy;

/// Maximum `jwks_uri`/`request_uri` response body accepted (256 KiB).
pub const SSRF_MAX_BYTES: usize = 256 * 1024;

/// Total budget for DNS check plus the HTTPS fetch.
pub const SSRF_TIMEOUT: Duration = Duration::from_secs(5);

/// Azure Instance Metadata Service (public-looking, link-local-adjacent).
const AZURE_METADATA_V4: [u8; 4] = [168, 63, 129, 16];
/// Alibaba Cloud metadata service.
const ALIBABA_METADATA_V4: [u8; 4] = [100, 100, 100, 200];

/// Fail-closed SSRF/fetch failures. Variants never carry response bytes.
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
  /// The URL did not parse.
  #[error("fetch URL is malformed")]
  MalformedUrl,
  /// The URL scheme was not `https`.
  #[error("fetch URL must use https")]
  NonHttps,
  /// The URL had no host to resolve.
  #[error("fetch URL has no host")]
  MissingHost,
  /// The URL embedded credentials.
  #[error("fetch URL must not carry credentials")]
  CredentialsInUrl,
  /// DNS resolution failed.
  #[error("fetch host did not resolve")]
  DnsFailed,
  /// A resolved address is not a permissible fetch target.
  #[error("fetch target is not a permissible public address")]
  BlockedTarget,
  /// The fetch itself failed (connect, TLS, or timeout).
  #[error("fetch failed")]
  FetchFailed,
  /// The response status was not successful.
  #[error("fetch returned an unsuccessful status")]
  BadStatus,
  /// The response exceeded [`SSRF_MAX_BYTES`].
  #[error("fetch response exceeds the size limit")]
  TooLarge,
}

/// Whether `ip` is forbidden as a server-side fetch target: loopback,
/// unspecified, multicast, broadcast, RFC 1918 private, CGNAT, link-local,
/// unique-local, documentation, reserved, or a cloud-metadata address.
#[must_use]
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
  match ip {
    IpAddr::V4(v4) => is_blocked_v4(v4),
    IpAddr::V6(v6) => {
      // An IPv4-mapped address (`::ffff:a.b.c.d`) reaches the same host as
      // its embedded IPv4 address, so it must be judged by that address —
      // otherwise `::ffff:127.0.0.1` / `::ffff:169.254.169.254` would slip
      // past the guard. `to_ipv4_mapped` returns `None` for every other
      // IPv6 form, including IPv4-compatible (`::a.b.c.d`) and NAT64.
      if let Some(v4) = v6.to_ipv4_mapped() {
        return is_blocked_v4(&v4);
      }
      v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // Unique-local (fc00::/7), link-local (fe80::/10),
        // documentation (2001:db8::/32).
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        || (v6.segments()[0] & 0xffc0) == 0xfe80
        || v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
    }
  }
}

/// Whether an IPv4 address is forbidden as a server-side fetch target.
fn is_blocked_v4(v4: &std::net::Ipv4Addr) -> bool {
  let o = v4.octets();
  v4.is_loopback()
    || v4.is_unspecified()
    || v4.is_multicast()
    || v4.is_broadcast()
    || v4.is_private()
    || v4.is_link_local()
    || v4.is_documentation()
    // CGNAT shared space (RFC 6598): never a public JWKS host.
    || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
    // Reserved benchmarking/reserved ranges.
    || o[0] >= 240
    || o == AZURE_METADATA_V4
    || o == ALIBABA_METADATA_V4
}

/// Parse `raw` as a fetchable URL: absolute `https`, host present, no
/// embedded credentials. Returns the parsed URL for the DNS/fetch steps.
pub fn validate_fetch_url(raw: &str) -> Result<reqwest::Url, SsrfError> {
  let url = reqwest::Url::parse(raw).map_err(|_| SsrfError::MalformedUrl)?;
  if url.scheme() != "https" {
    return Err(SsrfError::NonHttps);
  }
  if url.host_str().is_none_or(str::is_empty) {
    return Err(SsrfError::MissingHost);
  }
  if !url.username().is_empty() || url.password().is_some() {
    return Err(SsrfError::CredentialsInUrl);
  }
  Ok(url)
}

/// Resolve `host` and deny the fetch if any resolved address is blocked.
///
/// Returns the validated addresses so the caller can pin the connection to
/// exactly these addresses. IP literals are checked without touching DNS
/// and pin to themselves.
///
/// A DNS-rebinding hostname that resolves to a mix of public and blocked
/// addresses is denied outright: any blocked address fails the whole host.
pub async fn check_fetch_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, SsrfError> {
  if let Ok(literal) = host.parse::<IpAddr>() {
    if is_blocked_ip(&literal) {
      return Err(SsrfError::BlockedTarget);
    }
    return Ok(vec![SocketAddr::new(literal, port)]);
  }
  let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
    .await
    .map_err(|_| SsrfError::DnsFailed)?
    .collect();
  if addrs.is_empty() {
    return Err(SsrfError::DnsFailed);
  }
  for addr in &addrs {
    if is_blocked_ip(&addr.ip()) {
      return Err(SsrfError::BlockedTarget);
    }
  }
  Ok(addrs)
}

/// Fetch `raw` through the full SSRF guard: URL policy, DNS target check,
/// then an `https` GET with redirects disabled, a total timeout of
/// [`SSRF_TIMEOUT`], and a body cap of [`SSRF_MAX_BYTES`].
///
/// The connection is pinned to the addresses validated by the DNS check
/// (`resolve_to_addrs` for hostnames; IP literals need no DNS and connect
/// directly to the validated literal), closing the DNS-rebinding window
/// between validation and connect time.
///
/// # Errors
///
/// Returns [`SsrfError`] when the URL policy, DNS check, fetch, status, or
/// size cap fails.
pub async fn fetch_guarded_bytes(raw: &str) -> Result<Vec<u8>, SsrfError> {
  let url = validate_fetch_url(raw)?;
  let host = url.host_str().unwrap_or_default().to_owned();
  let port = url.port_or_known_default().unwrap_or(443);
  let addrs = check_fetch_host(&host, port).await?;

  let builder = reqwest::Client::builder()
    .redirect(Policy::none())
    .timeout(SSRF_TIMEOUT)
    .no_proxy();
  let builder = if host.parse::<IpAddr>().is_ok() {
    builder
  } else {
    builder.resolve_to_addrs(&host, &addrs)
  };
  let client = builder.build().map_err(|_| SsrfError::FetchFailed)?;
  let mut response = client
    .get(url)
    .send()
    .await
    .map_err(|_| SsrfError::FetchFailed)?;
  if !response.status().is_success() {
    return Err(SsrfError::BadStatus);
  }
  let mut body = Vec::new();
  while let Some(chunk) = response.chunk().await.map_err(|_| SsrfError::FetchFailed)? {
    body.extend_from_slice(&chunk);
    if body.len() > SSRF_MAX_BYTES {
      return Err(SsrfError::TooLarge);
    }
  }
  Ok(body)
}

/// Fetch `raw` through the guard and parse the body as JSON.
///
/// # Errors
///
/// Returns [`SsrfError`] on any guard/fetch failure or when the body is not
/// valid JSON.
pub async fn fetch_guarded_json(raw: &str) -> Result<serde_json::Value, SsrfError> {
  let bytes = fetch_guarded_bytes(raw).await?;
  serde_json::from_slice(&bytes).map_err(|_| SsrfError::FetchFailed)
}

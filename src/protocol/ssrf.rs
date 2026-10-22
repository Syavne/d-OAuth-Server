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
  /// The response exceeded the configured size cap.
  #[error("fetch response exceeds the size limit")]
  TooLarge,
}

/// Whether `ip` is forbidden as a server-side fetch target.
///
/// The blocked set is the IANA special-purpose ranges that are never a
/// legitimate public fetch target, plus the cloud-metadata IPs:
///
/// - IPv4: `0.0.0.0/8` (this network), `10/8`, `100.64.0.0/10` (CGNAT),
///   `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`
///   (IETF protocol assignments), `192.0.2.0/24`, `192.88.99.0/24` (6to4
///   relay anycast), `192.168.0.0/16`, `198.18.0.0/15` (benchmarking),
///   `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` (multicast),
///   `240.0.0.0/4` (reserved, incl. broadcast), and the Azure/Alibaba
///   metadata addresses.
/// - IPv6: `::1`, `::`, `fc00::/7`, `fe80::/10`, `ff00::/8`, `2001:db8::/32`,
///   `100::/64` (discard-only), `2001:2::/48` (benchmarking), `2001:10::/28`
///   and `2001:20::/28` (ORCHID/ORCHIDv2 identifiers), `2001::/32` (Teredo),
///   `2002::/16` (6to4), and `64:ff9b::/96` / `64:ff9b:1::/48` (NAT64
///   translation — can reach an embedded private IPv4 target).
///
/// IPv4-mapped addresses (`::ffff:a.b.c.d`) are judged by the embedded IPv4
/// address.
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
        || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        // Discard-only (100::/64) and benchmarking (2001:2::/48).
        || (v6.segments()[0] == 0x0100
          && v6.segments()[1] == 0
          && v6.segments()[2] == 0
          && v6.segments()[3] == 0)
        || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0002 && v6.segments()[2] == 0)
        // Non-routable identifier prefixes: ORCHID (2001:10::/28) and
        // ORCHIDv2 (2001:20::/28).
        || (v6.segments()[0] == 0x2001 && (v6.segments()[1] & 0xfff0) == 0x0010)
        || (v6.segments()[0] == 0x2001 && (v6.segments()[1] & 0xfff0) == 0x0020)
        // IPv4 transition/translation: Teredo (2001::/32), 6to4 (2002::/16),
        // NAT64 well-known (64:ff9b::/96) and local-use (64:ff9b:1::/48).
        || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0)
        || v6.segments()[0] == 0x2002
        || (v6.segments()[0] == 0x0064 && v6.segments()[1] == 0xff9b)
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
    // "This network" (0.0.0.0/8): a Linux host can reach loopback through
    // `0.x.y.z`, and only the all-zero address is caught by `is_unspecified`.
    || o[0] == 0
    // CGNAT shared space (RFC 6598): never a public JWKS host.
    || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)
    // IETF protocol assignments (192.0.0.0/24) and 6to4 relay anycast
    // (192.88.99.0/24, deprecated) — no public fetch target lives here.
    || (o[0] == 192 && o[1] == 0 && o[2] == 0)
    || (o[0] == 192 && o[1] == 88 && o[2] == 99)
    // Benchmarking (RFC 2544): 198.18.0.0/15.
    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    // Reserved (240.0.0.0/4, includes 255.255.255.255 broadcast).
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

/// Fetch `raw` through the full SSRF guard with the default `jwks_uri`/
/// `request_uri` caps: a total timeout of [`SSRF_TIMEOUT`] and a body cap of
/// [`SSRF_MAX_BYTES`].
///
/// # Errors
///
/// Returns [`SsrfError`] when the URL policy, DNS check, fetch, status, or
/// size cap fails.
pub async fn fetch_guarded_bytes(raw: &str) -> Result<Vec<u8>, SsrfError> {
  fetch_guarded_bytes_with(raw, SSRF_MAX_BYTES, SSRF_TIMEOUT).await
}

/// Fetch `raw` through the full SSRF guard with per-call limits.
///
/// Same policy as [`fetch_guarded_bytes`] — `https`-only, no redirects, a
/// pre-flight DNS target check pinned to the validated addresses, success
/// statuses only — but the response body cap and total timeout are the
/// caller's, so a tighter caller (for example CIMD's 5120-byte cap and
/// configured timeout) reuses the one fetcher instead of adding a second.
///
/// # Errors
///
/// Returns [`SsrfError`] when the URL policy, DNS check, fetch, status, or
/// `max_bytes` cap fails.
pub async fn fetch_guarded_bytes_with(
  raw: &str,
  max_bytes: usize,
  timeout: Duration,
) -> Result<Vec<u8>, SsrfError> {
  let url = validate_fetch_url(raw)?;
  let host = url.host_str().unwrap_or_default().to_owned();
  let port = url.port_or_known_default().unwrap_or(443);
  let addrs = check_fetch_host(&host, port).await?;
  fetch_pinned(&url, &host, &addrs, max_bytes, timeout).await
}

/// The post-guard network step shared by every guarded fetch: an `https` GET
/// with redirects disabled, `timeout` as the total budget, and a `max_bytes`
/// body cap. The connection is pinned to `addrs` for a hostname
/// (`resolve_to_addrs`); an IP literal needs no DNS and connects to the
/// already-validated literal.
async fn fetch_pinned(
  url: &reqwest::Url,
  host: &str,
  addrs: &[SocketAddr],
  max_bytes: usize,
  timeout: Duration,
) -> Result<Vec<u8>, SsrfError> {
  let builder = reqwest::Client::builder()
    .redirect(Policy::none())
    .timeout(timeout)
    .no_proxy();
  let builder = if host.parse::<IpAddr>().is_ok() {
    builder
  } else {
    builder.resolve_to_addrs(host, addrs)
  };
  let client = builder.build().map_err(|_| SsrfError::FetchFailed)?;
  let mut response = client
    .get(url.clone())
    .send()
    .await
    .map_err(|_| SsrfError::FetchFailed)?;
  if !response.status().is_success() {
    return Err(SsrfError::BadStatus);
  }
  let mut body = Vec::new();
  while let Some(chunk) = response.chunk().await.map_err(|_| SsrfError::FetchFailed)? {
    body.extend_from_slice(&chunk);
    if body.len() > max_bytes {
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

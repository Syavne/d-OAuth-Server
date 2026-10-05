//! SSRF-guarded fetch for pre-registered `request_uri` values.
//!
//! Policy: absolute `https` only, no userinfo, no redirects, every
//! resolved address must be publicly routable (checked before connecting),
//! success statuses only, body capped at [`MAX_REQUEST_OBJECT_BYTES`]
//! within [`FETCH_TIMEOUT`].
//!
//! SEAM(task 18): this duplicates the policy `protocol::ssrf` will own.
//! Delegate to it once its guarded fetch lands; until then this module is
//! the single choke point, so the swap is one call site. Residual risk:
//! resolution happens twice (guard, then the connector), so a hostile DNS
//! flip between the two needs task 18's pinned-connector hardening.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::AppError;

use super::{FETCH_TIMEOUT, MAX_REQUEST_OBJECT_BYTES};

/// Fetch a pre-registered request object behind the SSRF guard.
///
/// # Errors
///
/// Returns `invalid_request_object` for any policy violation or fetch
/// failure; never surfaces transport detail.
pub(crate) async fn fetch_request_object(uri: &str) -> Result<String, AppError> {
  let (host, port) = parse_https_authority(uri)?;
  deny_non_global_host(&host, port).await?;
  let agent = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(FETCH_TIMEOUT)
    .build()
    .map_err(AppError::internal)?;
  let mut response = agent
    .get(uri)
    .send()
    .await
    .map_err(|_| AppError::invalid_request_object("request_uri fetch failed"))?;
  if !response.status().is_success() {
    return Err(AppError::invalid_request_object(
      "request_uri did not return a request object",
    ));
  }
  if response
    .content_length()
    .is_some_and(|len| len > MAX_REQUEST_OBJECT_BYTES as u64)
  {
    return Err(AppError::invalid_request_object(
      "request_uri response is too large",
    ));
  }
  let mut body: Vec<u8> = Vec::new();
  loop {
    let chunk = response
      .chunk()
      .await
      .map_err(|_| AppError::invalid_request_object("request_uri fetch failed"))?;
    let Some(bytes) = chunk else {
      break;
    };
    body.extend_from_slice(&bytes);
    if body.len() > MAX_REQUEST_OBJECT_BYTES {
      return Err(AppError::invalid_request_object(
        "request_uri response is too large",
      ));
    }
  }
  String::from_utf8(body)
    .map_err(|_| AppError::invalid_request_object("request_uri body is not UTF-8"))
}

/// Split an absolute `https` URI into its `(host, port)`, rejecting any
/// other scheme and any userinfo.
fn parse_https_authority(uri: &str) -> Result<(String, u16), AppError> {
  let after_scheme = uri
    .strip_prefix("https://")
    .ok_or_else(|| AppError::invalid_request_object("request_uri must be an absolute https URI"))?;
  let end = after_scheme
    .find(['/', '?', '#'])
    .unwrap_or(after_scheme.len());
  let authority = &after_scheme[..end];
  if authority.is_empty() || authority.contains('@') {
    return Err(AppError::invalid_request_object(
      "request_uri authority is invalid",
    ));
  }
  if let Some(bracketed) = authority.strip_prefix('[') {
    return parse_bracketed_authority(bracketed);
  }
  match authority.rsplit_once(':') {
    Some((host, digits)) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
      if host.is_empty() {
        return Err(AppError::invalid_request_object(
          "request_uri authority is invalid",
        ));
      }
      Ok((host.to_owned(), port_from_str(digits)?))
    }
    _ => Ok((authority.to_owned(), 443)),
  }
}

/// Split a `[v6-literal](:port)?` authority into its `(host, port)`.
fn parse_bracketed_authority(bracketed: &str) -> Result<(String, u16), AppError> {
  let invalid = || AppError::invalid_request_object("request_uri authority is invalid");
  let close = bracketed.find(']').ok_or_else(invalid)?;
  let host = &bracketed[..close];
  let tail = &bracketed[close + 1..];
  if host.is_empty() {
    return Err(invalid());
  }
  if tail.is_empty() {
    return Ok((host.to_owned(), 443));
  }
  let digits = tail.strip_prefix(':').ok_or_else(invalid)?;
  Ok((host.to_owned(), port_from_str(digits)?))
}

/// Parse an explicit port, rejecting out-of-range values.
fn port_from_str(digits: &str) -> Result<u16, AppError> {
  digits
    .parse::<u16>()
    .map_err(|_| AppError::invalid_request_object("request_uri port is invalid"))
}

/// Deny any host that does not resolve exclusively to publicly routable
/// addresses: literal IPs are checked directly, names are resolved and
/// every address is checked (loopback, private, link-local — including the
/// 169.254.169.254 cloud-metadata address — multicast, and other
/// non-global ranges all fail closed).
async fn deny_non_global_host(host: &str, port: u16) -> Result<(), AppError> {
  if let Ok(literal) = host.parse::<IpAddr>() {
    return check_global(&literal);
  }
  let mut seen = false;
  let resolved = tokio::net::lookup_host((host, port))
    .await
    .map_err(|_| AppError::invalid_request_object("request_uri host does not resolve"))?;
  for next in resolved {
    seen = true;
    check_global(&next.ip())?;
  }
  if seen {
    Ok(())
  } else {
    Err(AppError::invalid_request_object(
      "request_uri host does not resolve",
    ))
  }
}

/// Accept only globally routable unicast addresses: loopback, private,
/// link-local (including the 169.254.169.254 cloud-metadata address),
/// multicast, documentation, benchmarking, shared, and reserved ranges all
/// fail closed.
fn check_global(ip: &IpAddr) -> Result<(), AppError> {
  let routable = match ip {
    IpAddr::V4(addr) => ipv4_routable(addr),
    IpAddr::V6(addr) => ipv6_routable(addr),
  };
  if routable {
    Ok(())
  } else {
    Err(AppError::invalid_request_object(
      "request_uri target is not publicly routable",
    ))
  }
}

/// Whether an IPv4 address is publicly routable.
fn ipv4_routable(addr: &Ipv4Addr) -> bool {
  if addr.is_unspecified()
    || addr.is_loopback()
    || addr.is_private()
    || addr.is_link_local()
    || addr.is_broadcast()
    || addr.is_documentation()
    || addr.is_multicast()
  {
    return false;
  }
  let [first, second, ..] = addr.octets();
  if first == 100 && (64..128).contains(&second) {
    return false;
  }
  if first == 198 && (18..20).contains(&second) {
    return false;
  }
  if first >= 240 {
    return false;
  }
  true
}

/// Whether an IPv6 address is publicly routable; IPv4-mapped addresses are
/// judged by the embedded IPv4 address.
fn ipv6_routable(addr: &Ipv6Addr) -> bool {
  if addr.is_unspecified()
    || addr.is_loopback()
    || addr.is_multicast()
    || addr.is_unique_local()
    || addr.is_unicast_link_local()
  {
    return false;
  }
  let segments = addr.segments();
  if segments[0] == 0x2001 && segments[1] == 0x0db8 {
    return false;
  }
  if segments[0] == 0
    && segments[1] == 0
    && segments[2] == 0
    && segments[3] == 0
    && segments[4] == 0
    && segments[5] == 0xffff
  {
    let octets = addr.octets();
    return ipv4_routable(&Ipv4Addr::new(
      octets[12], octets[13], octets[14], octets[15],
    ));
  }
  true
}

//! Request identity for rate limiting: peer IP and `client_id`, both hashed.
//!
//! The raw identity never becomes key material — [`counter_key`] hashes it —
//! and `client_id` is recovered from the query string or, for form posts, a
//! buffered-and-restored body so the downstream handler still sees it.

use std::net::{IpAddr, SocketAddr};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use sha2::{Digest, Sha256};

use crate::config::types::TrustedProxyNet;

/// Largest form body buffered to recover a `client_id`; anything larger is
/// left untouched and simply yields no client identity.
const MAX_FORM_BYTES: usize = 64 * 1024;

/// Largest `X-Forwarded-For` chain honored for rate-limit attribution; only
/// the rightmost entries are considered so header growth cannot grow the
/// parse or let a planted leftmost claim survive the cap.
const MAX_XFF_ENTRIES: usize = 32;

/// The peer address recorded by axum's `ConnectInfo` (present whenever the
/// listener is served with `into_make_service_with_connect_info`).
pub(super) fn peer_ip(request: &Request<Body>) -> Option<IpAddr> {
  request
    .extensions()
    .get::<ConnectInfo<SocketAddr>>()
    .map(|info| info.0.ip())
}

/// The client IP attributed to a request for rate-limit bucket selection
/// (T3-C3; paired T6-X2 decision).
///
/// The verified TCP peer is always the identity unless it belongs to the
/// configured `trusted_proxies` allowlist. Only then is the `X-Forwarded-For`
/// chain consulted, and only its rightmost-untrusted entry is used: addresses appended by downstream trusted proxies are skipped so a
/// spoofed leftmost claim planted before the first trusted hop cannot pick a
/// foreign bucket. A header from an untrusted peer is ignored outright, and
/// an absent header — or one with no parseable bare-IP entry — falls back
/// to the verified peer — the
/// request is still counted, never passed unattributed.
///
/// This trust is narrowly scoped to rate-limit IP attribution: it never
/// authenticates a client and never carries a client certificate (mTLS still
/// requires L4/TCP passthrough). RFC 7239 `Forwarded` is never consulted.
pub(super) fn client_ip(request: &Request<Body>, trusted: &[TrustedProxyNet]) -> Option<IpAddr> {
  let peer = peer_ip(request)?;
  if !trusted.iter().any(|net| net.contains(peer)) {
    return Some(peer);
  }
  let Some(chain) = forwarded_chain(request) else {
    return Some(peer);
  };
  Some(rightmost_untrusted(&chain, trusted))
}

/// Parse the `X-Forwarded-For` header into its address chain, leftmost-first.
/// `None` when the header is absent or holds no bare-IP entry: unparseable
/// entries (ports, brackets, `unknown`, garbage) are skipped — never trusted
/// entry-by-entry — and only the rightmost [`MAX_XFF_ENTRIES`] raw entries
/// are considered. Trusted proxies must emit bare IPs.
fn forwarded_chain(request: &Request<Body>) -> Option<Vec<IpAddr>> {
  let header = request.headers().get("x-forwarded-for")?.to_str().ok()?;
  let raw: Vec<&str> = header.split(',').map(|entry| entry.trim()).collect();
  let tail = if raw.len() > MAX_XFF_ENTRIES {
    &raw[raw.len() - MAX_XFF_ENTRIES..]
  } else {
    raw.as_slice()
  };
  let chain: Vec<IpAddr> = tail
    .iter()
    .filter(|entry| !entry.is_empty())
    .filter_map(|entry| entry.parse::<IpAddr>().ok())
    .collect();
  if chain.is_empty() { None } else { Some(chain) }
}

/// The rightmost chain entry outside the trusted set; when every hop is
/// trusted, the leftmost entry (the originating client as seen through
/// trusted hops only).
fn rightmost_untrusted(chain: &[IpAddr], trusted: &[TrustedProxyNet]) -> IpAddr {
  let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(*ip));
  chain
    .iter()
    .rev()
    .find(|ip| !is_trusted(ip))
    .copied()
    .unwrap_or(chain[0])
}

/// Recover a `client_id` from the query string, or (for form posts) the body.
///
/// A form body is buffered and restored so the handler still sees it; a body
/// that cannot be read yields `None` (the IP bucket still applies).
pub(super) async fn extract_client_id(request: &mut Request<Body>) -> Option<String> {
  if let Some(client_id) = query_param(request.uri().query(), "client_id") {
    return Some(client_id);
  }
  let is_form = request
    .headers()
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
  if !is_form {
    return None;
  }
  let body = std::mem::replace(request.body_mut(), Body::empty());
  let bytes = axum::body::to_bytes(body, MAX_FORM_BYTES).await.ok()?;
  let client_id = std::str::from_utf8(&bytes)
    .ok()
    .and_then(|text| find_param(text, "client_id"));
  *request.body_mut() = Body::from(bytes);
  client_id
}

/// `{prefix}{kind}:{sha256-hex}` — the raw identity never reaches Redis.
///
/// The `raw` value for a client bucket is built with [`client_bucket_raw`]:
/// the composite is hashed as one unit, so the separator never reaches Redis
/// either.
pub(super) fn counter_key(prefix: &str, kind: &str, raw: &str) -> String {
  format!("{prefix}{kind}:{}", sha256_hex(raw.as_bytes()))
}

/// Composite raw identity for the per-client bucket: `(peer_ip, client_id)`.
///
/// `client_id` is recovered before client authentication (T3-C2), so it must
/// never select a global bucket on its own: an attacker could exhaust a
/// victim client's budget or rotate fake ids to evade the limit. Joining the
/// peer IP with a NUL separator keeps each peer's client accounting distinct
/// while the per-IP bucket stays the primary control. The separator is
/// unambiguous even though `%00` form-decodes to NUL inside a `client_id`:
/// the IP rendering never contains NUL, so the first NUL always delimits the
/// IP and distinct pairs always render distinctly.
pub(super) fn client_bucket_raw(ip: &IpAddr, client_id: &str) -> String {
  format!("{ip}\0{client_id}")
}

/// Lowercase hex of the SHA-256 digest.
fn sha256_hex(input: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let digest = Sha256::digest(input);
  let mut out = String::with_capacity(digest.len() * 2);
  for byte in digest {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

/// First value of `name` in a `&`-separated query or form string.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
  query.and_then(|query| find_param(query, name))
}

/// Parse `key=value` pairs (percent- and `+`-decoded) and return the first
/// value whose key matches `name`.
fn find_param(input: &str, name: &str) -> Option<String> {
  input.split('&').find_map(|pair| {
    let (key, value) = pair.split_once('=')?;
    (decode_component(key) == name).then(|| decode_component(value))
  })
}

/// Minimal `application/x-www-form-urlencoded` component decoder.
fn decode_component(raw: &str) -> String {
  let bytes = raw.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    match bytes[index] {
      b'+' => {
        out.push(b' ');
        index += 1;
      }
      b'%' if index + 2 < bytes.len() => {
        match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
          (Some(high), Some(low)) => {
            out.push(high * 16 + low);
            index += 3;
          }
          _ => {
            out.push(b'%');
            index += 1;
          }
        }
      }
      byte => {
        out.push(byte);
        index += 1;
      }
    }
  }
  String::from_utf8_lossy(&out).into_owned()
}

/// Hexadecimal digit value, or `None` for a non-hex byte.
fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

#[cfg(test)]
mod identity_tests {
  use std::error::Error;
  use std::net::{IpAddr, SocketAddr};
  use std::str::FromStr as _;

  use axum::body::Body;
  use axum::extract::ConnectInfo;
  use axum::http::Request;

  use super::client_ip;
  use crate::config::types::TrustedProxyNet;

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult = Result<(), Box<dyn Error>>;

  /// Request carrying `peer` as the recorded TCP peer plus an optional
  /// `X-Forwarded-For` header.
  fn request_with(
    peer: Option<SocketAddr>,
    xff: Option<&str>,
  ) -> Result<Request<Body>, Box<dyn Error>> {
    let mut builder = Request::builder().uri("/token");
    if let Some(value) = xff {
      builder = builder.header("x-forwarded-for", value);
    }
    let mut request = builder.body(Body::empty())?;
    if let Some(addr) = peer {
      request.extensions_mut().insert(ConnectInfo(addr));
    }
    Ok(request)
  }

  /// Parse-to-trusted helper for the test allowlists below.
  fn trusted(entries: &[&str]) -> Result<Vec<TrustedProxyNet>, Box<dyn Error>> {
    entries
      .iter()
      .map(|entry| TrustedProxyNet::from_str(entry).map_err(Box::<dyn Error>::from))
      .collect()
  }

  /// A trusted peer yields the client IP from `X-Forwarded-For`.
  #[test]
  fn ratelimit_trusted_proxy_honors_xff_from_trusted_peer() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.7")?)
    );
    Ok(())
  }

  /// A spoofed header from an untrusted peer is ignored: the peer owns the
  /// bucket, so rotating the header cannot evade the limit.
  #[test]
  fn ratelimit_trusted_proxy_ignores_xff_from_untrusted_peer() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([127, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7"))?;
    assert_eq!(client_ip(&request, &allow), Some(peer.ip()));
    Ok(())
  }

  /// A header with no parseable bare-IP entry from a trusted peer fails
  /// closed onto the verified peer: the request is still counted, never
  /// passed unattributed. Partially valid chains attribute their valid
  /// entries (see the skip tests below).
  #[test]
  fn ratelimit_trusted_proxy_malformed_xff_falls_back_to_peer() -> TestResult {
    let allow = trusted(&["10.0.0.1"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    for xff in ["not-an-ip", "", "unknown", "1.2.3.4:5678", "[2001:db8::1]"] {
      let request = request_with(Some(peer), Some(xff))?;
      assert_eq!(client_ip(&request, &allow), Some(peer.ip()), "xff={xff:?}");
    }
    Ok(())
  }

  /// Rightmost-untrusted selection: trusted hops appended by downstream
  /// proxies are skipped, the first untrusted address wins.
  #[test]
  fn ratelimit_trusted_proxy_selects_rightmost_untrusted() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7, 10.0.0.5, 10.0.0.9"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.7")?)
    );
    Ok(())
  }

  /// An all-trusted chain yields its leftmost entry (the originating client
  /// as seen through trusted hops only).
  #[test]
  fn ratelimit_trusted_proxy_all_trusted_chain_yields_leftmost() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("10.0.0.5, 10.0.0.6"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("10.0.0.5")?)
    );
    Ok(())
  }

  /// Default empty allowlist: every header is ignored, the peer is used.
  #[test]
  fn ratelimit_trusted_proxy_empty_allowlist_ignores_xff() -> TestResult {
    let allow: Vec<TrustedProxyNet> = Vec::new();
    let peer = SocketAddr::from(([203, 0, 113, 9], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7"))?;
    assert_eq!(client_ip(&request, &allow), Some(peer.ip()));
    Ok(())
  }

  /// No recorded peer means no identity: `None` so the caller fails closed.
  #[test]
  fn ratelimit_trusted_proxy_missing_peer_yields_no_identity() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let request = request_with(None, Some("198.51.100.7"))?;
    assert_eq!(client_ip(&request, &allow), None);
    Ok(())
  }

  /// A partially spoofable chain still attributes its valid entries: bad
  /// entries are skipped, rightmost-untrusted wins over what remains.
  #[test]
  fn ratelimit_trusted_proxy_partial_chain_skips_bad_entry() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7, not-an-ip"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.7")?)
    );
    let request = request_with(Some(peer), Some("not-an-ip, 198.51.100.8"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.8")?)
    );
    Ok(())
  }

  /// Entries carrying a port, brackets, or `unknown` are not bare IPs and are
  /// skipped; the remaining valid entry still attributes (previously the
  /// whole chain collapsed to the peer).
  #[test]
  fn ratelimit_trusted_proxy_xff_with_port_still_attributes() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let request = request_with(Some(peer), Some("198.51.100.7:4123, 198.51.100.8"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.8")?)
    );
    let request = request_with(Some(peer), Some("[2001:db8::1], 198.51.100.9"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.9")?)
    );
    let request = request_with(Some(peer), Some("unknown, 198.51.100.10"))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("198.51.100.10")?)
    );
    Ok(())
  }

  /// An oversize chain is capped to the rightmost 32 entries: a leading
  /// entry pushed past the cap cannot select the bucket.
  #[test]
  fn ratelimit_trusted_proxy_oversize_chain_capped() -> TestResult {
    let allow = trusted(&["10.0.0.0/8"])?;
    let peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let mut chain = vec!["198.51.100.7".to_string()];
    for _ in 0..40 {
      chain.push("10.0.0.5".to_string());
    }
    let header = chain.join(", ");
    let request = request_with(Some(peer), Some(header.as_str()))?;
    assert_eq!(
      client_ip(&request, &allow),
      Some(IpAddr::from_str("10.0.0.5")?)
    );
    Ok(())
  }
  #[test]
  fn ratelimit_trusted_proxy_exact_ip_entry_trusts_only_that_peer() -> TestResult {
    let allow = trusted(&["10.0.0.1"])?;
    let trusted_peer = SocketAddr::from(([10, 0, 0, 1], 40_000));
    let other_peer = SocketAddr::from(([10, 0, 0, 2], 40_000));
    let expected = IpAddr::from_str("198.51.100.7")?;
    let via_trusted = request_with(Some(trusted_peer), Some("198.51.100.7"))?;
    assert_eq!(client_ip(&via_trusted, &allow), Some(expected));
    let via_other = request_with(Some(other_peer), Some("198.51.100.7"))?;
    assert_eq!(client_ip(&via_other, &allow), Some(other_peer.ip()));
    Ok(())
  }
}

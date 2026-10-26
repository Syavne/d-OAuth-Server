//! Fuzz the SSRF URL gate and address classifier (`protocol::ssrf`).
//!
//! [`validate_fetch_url`] is pure: an accepted URL is always `https`, has a
//! non-empty host, and carries no credentials. The classifier half maps the
//! first 16 input bytes to an [`IpAddr`] and calls [`is_blocked_ip`]; an
//! IPv4-mapped address must be judged exactly like its embedded IPv4 address.
//! [`fetch_guarded_bytes_with`] is deliberately not called: it is async, opens
//! a socket, and is non-hermetic.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use d_oauth::protocol::ssrf::{is_blocked_ip, validate_fetch_url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  if let Ok(raw) = core::str::from_utf8(data)
    && let Ok(url) = validate_fetch_url(raw)
  {
    assert_eq!(url.scheme(), "https", "accepted URL is not https");
    assert!(
      url.host_str().is_some_and(|host| !host.is_empty()),
      "accepted URL has no host"
    );
    assert!(url.username().is_empty(), "accepted URL kept a username");
    assert!(url.password().is_none(), "accepted URL kept a password");
  }

  if data.len() < 16 {
    return;
  }
  let mut octets = [0u8; 16];
  octets.copy_from_slice(&data[..16]);

  let v6 = IpAddr::V6(Ipv6Addr::from(octets));
  let _ = is_blocked_ip(&v6);

  let v4 = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
  let blocked_v4 = is_blocked_ip(&IpAddr::V4(v4));
  // `::ffff:a.b.c.d` reaches the same host as `a.b.c.d`, so the guard must
  // return the same verdict for both.
  let mapped = IpAddr::V6(v4.to_ipv6_mapped());
  assert_eq!(
    is_blocked_ip(&mapped),
    blocked_v4,
    "IPv4-mapped address was judged differently from its embedded IPv4"
  );
});

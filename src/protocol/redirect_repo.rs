//! `redirect_uri` matching against a client's effective registered set.
//!
//! Implements RFC 3986 §6.2.1 Simple String Comparison (character-for-
//! character, no normalization) plus the RFC 8252 §7.3 loopback exception:
//! a registration whose scheme is `http` and whose host is the loopback
//! literal `127.0.0.1` or `[::1]` matches a request with the same
//! scheme+host+path and any port.
//!
//! Fail-closed: a registered URI carrying userinfo, a query, or a fragment
//! is never eligible, plaintext `http` to a non-loopback host is refused,
//! `localhost` is not treated as loopback, and matching never falls back to
//! prefix/wildcard/substring comparison. A [`RedirectDecision::Reject`] means
//! the authorization request MUST fail without redirecting the user agent.
//!
//! The effective (attached + enabled) set is owned by `db::redirect_repo`;
//! this module is pure and takes that set as a slice of strings.

/// The outcome of matching a requested `redirect_uri` against a client's
/// effective registered set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectDecision {
  /// Exact Simple-String match (RFC 3986 §6.2.1): the requested URI is
  /// character-for-character identical to a registered URI.
  Exact,
  /// RFC 8252 §7.3 loopback match: the registered URI is plaintext `http`
  /// to a loopback literal (`127.0.0.1` or `[::1]`) and the requested URI
  /// has the same scheme, host, and path, with the port ignored.
  Loopback,
  /// No registered URI is an acceptable match. The request MUST be rejected
  /// without redirecting the user agent.
  Reject,
}

/// Match `requested` against the client's effective registered redirect-URI
/// set.
///
/// `registered` holds the client's attached-and-enabled redirect URIs as
/// owned by `db::redirect_repo`. Matching is exact (RFC 3986 §6.2.1); the
/// single exception is the RFC 8252 §7.3 loopback rule. [`RedirectDecision::Exact`]
/// takes precedence over [`RedirectDecision::Loopback`] when several
/// registrations could apply.
///
/// A requested or registered URI whose private-use scheme lacks reverse-DNS
/// dot notation (draft-ietf-oauth-v2-1-16 §2.3.1, SHOULD-level) never
/// matches: the request is rejected without redirecting the user agent.
#[must_use]
pub fn match_redirect_uri<S: AsRef<str>>(registered: &[S], requested: &str) -> RedirectDecision {
  if !is_valid_redirect_scheme(requested) {
    return RedirectDecision::Reject;
  }
  let requested_parts = parse_uri(requested);
  let mut loopback = false;

  for candidate in registered {
    let candidate = candidate.as_ref();
    if !is_valid_redirect_scheme(candidate) {
      continue;
    }
    let Some(reg) = parse_uri(candidate) else {
      continue;
    };

    // A registration that carries userinfo, a query, or a fragment is
    // malformed and can never be matched.
    if reg.userinfo.is_some() || reg.query.is_some() || reg.fragment.is_some() {
      continue;
    }

    // Plaintext http is only ever acceptable to a loopback literal.
    if is_http(reg.scheme) && !is_loopback_host(reg.host) {
      continue;
    }

    // Exact Simple String Comparison (RFC 3986 §6.2.1).
    if candidate == requested {
      return RedirectDecision::Exact;
    }

    // RFC 8252 §7.3 loopback: ignore the port, require scheme+host+path, and
    // refuse a request that smuggles userinfo, a query, or a fragment.
    if is_http(reg.scheme)
      && is_loopback_host(reg.host)
      && let Some(req) = requested_parts.as_ref()
      && is_http(req.scheme)
      && is_loopback_host(req.host)
      && reg.host == req.host
      && reg.path == req.path
      && req.userinfo.is_none()
      && req.query.is_none()
      && req.fragment.is_none()
    {
      loopback = true;
    }
  }

  if loopback {
    RedirectDecision::Loopback
  } else {
    RedirectDecision::Reject
  }
}

/// The URI components needed for redirect matching.
///
/// No percent-decoding, case-folding, or path normalization is performed;
/// this keeps Simple String Comparison exact (RFC 3986 §6.2.1).
struct UriParts<'a> {
  scheme: &'a str,
  userinfo: Option<&'a str>,
  host: &'a str,
  path: &'a str,
  query: Option<&'a str>,
  fragment: Option<&'a str>,
}

/// Parse just enough of an absolute URI to compare its components.
///
/// Returns `None` for anything without a syntactically valid scheme.
fn parse_uri(input: &str) -> Option<UriParts<'_>> {
  let (before_fragment, fragment) = match input.split_once('#') {
    Some((before, fragment)) => (before, Some(fragment)),
    None => (input, None),
  };
  let (before_query, query) = match before_fragment.split_once('?') {
    Some((before, query)) => (before, Some(query)),
    None => (before_fragment, None),
  };
  let (scheme, rest) = before_query.split_once(':')?;
  if !is_valid_scheme(scheme) {
    return None;
  }

  let (userinfo, host, path) = if let Some(after) = rest.strip_prefix("//") {
    let (authority, path) = match after.find('/') {
      Some(index) => (&after[..index], &after[index..]),
      None => (after, ""),
    };
    let (userinfo, hostport) = match authority.find('@') {
      Some(index) => (Some(&authority[..index]), &authority[index + 1..]),
      None => (None, authority),
    };
    (userinfo, parse_host(hostport)?, path)
  } else {
    (None, "", rest)
  };

  Some(UriParts {
    scheme,
    userinfo,
    host,
    path,
    query,
    fragment,
  })
}

/// RFC 3986 §3.1 scheme: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_valid_scheme(scheme: &str) -> bool {
  let mut chars = scheme.chars();
  let Some(first) = chars.next() else {
    return false;
  };
  first.is_ascii_alphabetic()
    && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Extract the host from an authority component, ignoring any port.
///
/// Bracketed IPv6 literals keep their brackets. Returns `None` for a
/// malformed bracketed literal.
fn parse_host(hostport: &str) -> Option<&str> {
  if let Some(rest) = hostport.strip_prefix('[') {
    let close = rest.find(']')?;
    Some(&hostport[..close + 2])
  } else {
    Some(match hostport.split_once(':') {
      Some((host, _port)) => host,
      None => hostport,
    })
  }
}

/// True when the scheme is HTTP (case-insensitively, RFC 3986 §3.1).
fn is_http(scheme: &str) -> bool {
  scheme.eq_ignore_ascii_case("http")
}

/// True when the scheme is HTTPS (case-insensitively, RFC 3986 §3.1).
fn is_https(scheme: &str) -> bool {
  scheme.eq_ignore_ascii_case("https")
}

/// Whether `uri` satisfies the draft-ietf-oauth-v2-1-16 §2.3.1 SHOULD-level
/// reverse-DNS rule for private-use URI schemes: any scheme other than
/// `http`/`https` must contain a `.` (for example `com.example.app:/` is
/// acceptable while `myapp:/` is not). `http`/`https` URIs — including the
/// RFC 8252 §7.3 loopback exception — are unaffected. URIs without a
/// syntactically valid scheme fail closed.
#[must_use]
pub fn is_valid_redirect_scheme(uri: &str) -> bool {
  let before_fragment = match uri.split_once('#') {
    Some((before, _)) => before,
    None => uri,
  };
  let before_query = match before_fragment.split_once('?') {
    Some((before, _)) => before,
    None => before_fragment,
  };
  let (scheme, _) = match before_query.split_once(':') {
    Some(parts) => parts,
    None => return false,
  };
  if !is_valid_scheme(scheme) {
    return false;
  }
  if is_http(scheme) || is_https(scheme) {
    return true;
  }
  scheme.contains('.')
}

/// The only hosts eligible for the RFC 8252 §7.3 loopback exception.
///
/// `localhost` is deliberately absent: hostname resolution is
/// attacker-influenced, so the plan permits loopback literal IPs only.
fn is_loopback_host(host: &str) -> bool {
  host == "127.0.0.1" || host == "[::1]"
}

#[cfg(test)]
mod tests;

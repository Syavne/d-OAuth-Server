//! Security headers and CORS allowlist.
//!
//! [`SecurityHeadersLayer`] decorates every response that reaches the router
//! with `X-Content-Type-Options`, `Referrer-Policy`, and a
//! `Content-Security-Policy` carrying `frame-ancestors 'none'` on every
//! route. Server-rendered pages (`/login`, `/consent`, `/device`) additionally
//! get a strict script policy (`script-src 'none'`: the pages ship no
//! JavaScript), while JSON API endpoints get a locked-down
//! `default-src 'none'` policy. `Strict-Transport-Security` is emitted only
//! when the router serves the TLS public listener (`hsts: true`); the
//! plaintext health listener never claims HSTS.
//!
//! Every response that is not OAuth metadata discovery or the public JWK Set
//! is marked `Cache-Control: no-store` (+ `Pragma: no-cache` for legacy
//! clients), so an authorization page, consent page, token body, or error is
//! never reused by a browser, the back/forward cache, or an intermediary.
//! `/.well-known/…` metadata stays cacheable, and `/jwks.json` gets its own
//! shorter window: a rotated-out key must leave intermediary caches quickly.
//!
//! [`cors_layer`] builds the explicit browser-facing CORS policy from
//! `config.cors_allowed_origins`: an empty allowlist yields `None` (no CORS
//! headers at all — browser clients are unsupported by default), and the
//! wildcard `*` is never honored.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response, header};
use tower::{Layer, Service};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// `Strict-Transport-Security` value (two years + subdomains, preload-ready).
pub const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains";
/// `Referrer-Policy` value: never send a `Referer` header.
pub const REFERRER_POLICY_VALUE: &str = "no-referrer";
/// CSP for JSON API endpoints: nothing may load or frame this resource.
pub const API_CSP_VALUE: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
/// CSP for server-rendered pages: self-only resources, no scripts, no framing.
pub const PAGE_CSP_VALUE: &str = "default-src 'self'; script-src 'none'; style-src 'self'; \
  img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
/// `Access-Control-Max-Age` for preflight responses (ten minutes).
pub const CORS_MAX_AGE_SECS: u64 = 600;
/// `Cache-Control` value forbidding storage of a response.
pub const NO_STORE_VALUE: &str = "no-store";
/// Legacy `Pragma` companion to `no-store` (RFC 6749 §5.1).
pub const NO_CACHE_VALUE: &str = "no-cache";
/// Positive `Cache-Control` for OAuth metadata discovery.
///
/// Metadata is public and changes only when the scope catalog or endpoints do,
/// so caching it is intentional and safe. The explicit directive replaces
/// browser heuristic freshness with a tunable, reviewable policy.
pub const METADATA_CACHE_VALUE: &str = "public, max-age=3600";
/// Positive `Cache-Control` for the public JWK Set (`GET /jwks.json`).
///
/// Shorter than [`METADATA_CACHE_VALUE`] on purpose: a rotated-out key is
/// retained in the JWK Set for resource servers still checking old tokens, so
/// the cache window bounds how long a revoked key can linger in an
/// intermediary cache. Five minutes keeps JWKS fetch traffic low without
/// pinning a dead key for an hour.
pub const JWKS_CACHE_VALUE: &str = "public, max-age=300";

/// Whether `path` serves a server-rendered page (strict script policy).
///
/// Matches the first path segment exactly, so `/device_authorization` (a JSON
/// API endpoint) is never mistaken for the `/device` verification page.
#[must_use]
pub fn is_page_path(path: &str) -> bool {
  let first = path.split('/').nth(1).unwrap_or_default();
  matches!(first, "login" | "consent" | "device")
}

/// The exact `Cache-Control` value for `path`.
///
/// The mapping is per-path, not a boolean: OAuth metadata discovery keeps the
/// one-hour value, the public JWK Set gets a shorter window, and everything
/// else forbids storage entirely. A single "cacheable" flag would force JWKS
/// onto the metadata window and keep a rotated-out key cached for an hour.
#[must_use]
pub fn cache_control_value(path: &str) -> &'static str {
  if path == "/jwks.json" {
    JWKS_CACHE_VALUE
  } else if path.starts_with("/.well-known/") {
    METADATA_CACHE_VALUE
  } else {
    NO_STORE_VALUE
  }
}

/// Tower layer decorating responses with the security-header set.
///
/// Construct with [`SecurityHeadersLayer::new`]; `hsts` must be true only on
/// the TLS public listener.
#[derive(Debug, Clone, Copy)]
pub struct SecurityHeadersLayer {
  /// Whether to emit `Strict-Transport-Security` (TLS listener only).
  hsts: bool,
}

impl SecurityHeadersLayer {
  /// Build the layer; `hsts` enables the HSTS header for TLS listeners.
  #[must_use]
  pub const fn new(hsts: bool) -> Self {
    Self { hsts }
  }
}

impl<S> Layer<S> for SecurityHeadersLayer {
  type Service = SecurityHeadersService<S>;

  fn layer(&self, inner: S) -> Self::Service {
    SecurityHeadersService::new(inner, self.hsts)
  }
}

/// Service produced by [`SecurityHeadersLayer`].
#[derive(Debug, Clone, Copy)]
pub struct SecurityHeadersService<S> {
  inner: S,
  hsts: bool,
}

impl<S> SecurityHeadersService<S> {
  /// Wrap an inner service, capturing the HSTS toggle.
  pub const fn new(inner: S, hsts: bool) -> Self {
    Self { inner, hsts }
  }
}

impl<S, B> Service<Request<B>> for SecurityHeadersService<S>
where
  S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
  S::Future: Send + 'static,
  S::Error: Send + 'static,
  B: Send + 'static,
{
  type Response = Response<Body>;
  type Error = S::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, request: Request<B>) -> Self::Future {
    let page = is_page_path(request.uri().path());
    let cache = cache_control_value(request.uri().path());
    let hsts = self.hsts;
    let mut inner = self.inner.clone();
    Box::pin(async move {
      let mut response = inner.call(request).await?;
      insert_headers(response.headers_mut(), page, hsts, cache);
      Ok(response)
    })
  }
}

/// Insert the header set on an outbound response (`page` selects the CSP;
/// `cache` is the exact `Cache-Control` value for the request path).
fn insert_headers(
  headers: &mut axum::http::HeaderMap,
  page: bool,
  hsts: bool,
  cache: &'static str,
) {
  let csp = if page { PAGE_CSP_VALUE } else { API_CSP_VALUE };
  for (name, value) in [
    (
      header::X_CONTENT_TYPE_OPTIONS,
      HeaderValue::from_static("nosniff"),
    ),
    (
      header::REFERRER_POLICY,
      HeaderValue::from_static(REFERRER_POLICY_VALUE),
    ),
    (
      header::CONTENT_SECURITY_POLICY,
      HeaderValue::from_static(csp),
    ),
  ] {
    headers.insert(name, value);
  }
  headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
  if cache == NO_STORE_VALUE {
    headers.insert(header::PRAGMA, HeaderValue::from_static(NO_CACHE_VALUE));
  }
  if hsts {
    headers.insert(
      header::STRICT_TRANSPORT_SECURITY,
      HeaderValue::from_static(HSTS_VALUE),
    );
  }
}

/// Build the CORS layer from the explicit origin allowlist.
///
/// Returns `None` when the allowlist is empty (the default: no CORS headers
/// are emitted and browser clients are unsupported). The wildcard `*` is
/// filtered out and never honored; origins that do not parse are skipped.
/// A `None` result combined with an allowlist that named only wildcards or
/// unparseable values therefore fails closed to "no CORS".
#[must_use]
pub fn cors_layer(allowed_origins: &[String]) -> Option<CorsLayer> {
  let origins: Vec<HeaderValue> = allowed_origins
    .iter()
    .filter(|origin| origin.as_str() != "*")
    .filter_map(|origin| HeaderValue::from_str(origin).ok())
    .collect();
  if origins.is_empty() {
    return None;
  }
  Some(
    CorsLayer::new()
      .allow_origin(AllowOrigin::list(origins))
      .allow_methods([
        axum::http::Method::GET,
        axum::http::Method::POST,
        axum::http::Method::PUT,
        axum::http::Method::DELETE,
        axum::http::Method::OPTIONS,
      ])
      .allow_headers([
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        HeaderName::from_static("dpop"),
      ])
      .max_age(Duration::from_secs(CORS_MAX_AGE_SECS)),
  )
}

#[cfg(test)]
mod tests {
  use axum::http::header;

  use super::{
    HSTS_VALUE, JWKS_CACHE_VALUE, METADATA_CACHE_VALUE, NO_CACHE_VALUE, NO_STORE_VALUE,
    cache_control_value, insert_headers, is_page_path,
  };

  #[test]
  fn page_paths_match_first_segment_exactly() {
    for path in ["/login", "/login/totp/setup", "/consent", "/device"] {
      assert!(is_page_path(path), "{path} must be a page");
    }
    for path in ["/device_authorization", "/authorize", "/", "/register"] {
      assert!(!is_page_path(path), "{path} must not be a page");
    }
  }

  #[test]
  fn cache_control_is_per_path() {
    assert_eq!(
      cache_control_value("/.well-known/oauth-authorization-server"),
      METADATA_CACHE_VALUE
    );
    assert_eq!(cache_control_value("/jwks.json"), JWKS_CACHE_VALUE);
    assert_ne!(JWKS_CACHE_VALUE, METADATA_CACHE_VALUE);
    assert_ne!(JWKS_CACHE_VALUE, NO_STORE_VALUE);
    for path in ["/login", "/authorize", "/token", "/par", "/health/live"] {
      assert_eq!(
        cache_control_value(path),
        NO_STORE_VALUE,
        "{path} must not be cacheable"
      );
    }
  }

  #[test]
  fn non_cacheable_response_forbids_storage() {
    let mut headers = axum::http::HeaderMap::new();
    insert_headers(&mut headers, true, true, NO_STORE_VALUE);
    let value = |name: header::HeaderName| {
      headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
    };
    assert_eq!(value(header::CACHE_CONTROL), NO_STORE_VALUE);
    assert_eq!(value(header::PRAGMA), NO_CACHE_VALUE);
    assert_eq!(value(header::STRICT_TRANSPORT_SECURITY), HSTS_VALUE);
    assert!(!value(header::CONTENT_SECURITY_POLICY).is_empty());
  }

  #[test]
  fn cacheable_metadata_sets_positive_cache_control() {
    let mut headers = axum::http::HeaderMap::new();
    insert_headers(&mut headers, false, false, METADATA_CACHE_VALUE);
    let cache_control = headers
      .get(header::CACHE_CONTROL)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    assert_eq!(cache_control, METADATA_CACHE_VALUE);
    assert!(!cache_control.contains("no-store"));
    assert!(!headers.contains_key(header::PRAGMA));
    assert!(!headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
    for name in [
      header::X_CONTENT_TYPE_OPTIONS,
      header::REFERRER_POLICY,
      header::CONTENT_SECURITY_POLICY,
    ] {
      assert!(headers.contains_key(name), "security header must survive");
    }
  }
}

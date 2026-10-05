//! Security headers, CORS allowlist, and proxy-header stripping.
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
//! Every response that is not OAuth metadata discovery is marked
//! `Cache-Control: no-store` (+ `Pragma: no-cache` for legacy clients), so an
//! authorization page, consent page, token body, or error is never reused by a
//! browser, the back/forward cache, or an intermediary. `/.well-known/…`
//! metadata stays cacheable.
//!
//! [`cors_layer`] builds the explicit browser-facing CORS policy from
//! `config.cors_allowed_origins`: an empty allowlist yields `None` (no CORS
//! headers at all — browser clients are unsupported by default), and the
//! wildcard `*` is never honored. [`StripProxyHeadersLayer`] removes
//! forwarded client-cert headers on the direct TLS listener so a forged
//! header can never reach [`crate::protocol::mtls`]; it is mounted only when
//! no `trusted_proxy` is configured.

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

/// Whether `path` serves a server-rendered page (strict script policy).
///
/// Matches the first path segment exactly, so `/device_authorization` (a JSON
/// API endpoint) is never mistaken for the `/device` verification page.
#[must_use]
pub fn is_page_path(path: &str) -> bool {
  let first = path.split('/').nth(1).unwrap_or_default();
  matches!(first, "login" | "consent" | "device")
}

/// Whether `path`'s response may be cached: OAuth metadata discovery only.
///
/// Every other response is marked `no-store`, so credentials, tokens, request
/// handles, and server-rendered pages never survive in a browser or an
/// intermediary cache.
#[must_use]
pub fn is_cacheable_path(path: &str) -> bool {
  path.starts_with("/.well-known/")
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
    let cacheable = is_cacheable_path(request.uri().path());
    let hsts = self.hsts;
    let mut inner = self.inner.clone();
    Box::pin(async move {
      let mut response = inner.call(request).await?;
      insert_headers(response.headers_mut(), page, hsts, cacheable);
      Ok(response)
    })
  }
}

/// Insert the header set on an outbound response (`page` selects the CSP;
/// `cacheable` is true only for metadata, so everything else is `no-store`).
fn insert_headers(headers: &mut axum::http::HeaderMap, page: bool, hsts: bool, cacheable: bool) {
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
  if !cacheable {
    headers.insert(
      header::CACHE_CONTROL,
      HeaderValue::from_static(NO_STORE_VALUE),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static(NO_CACHE_VALUE));
  }
  if cacheable {
    headers.insert(
      header::CACHE_CONTROL,
      HeaderValue::from_static(METADATA_CACHE_VALUE),
    );
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

/// Tower layer stripping forwarded client-cert headers on the direct listener.
///
/// Mounted only when no `trusted_proxy` is configured, so a forged
/// `x-forwarded-tls-client-cert` / `x-forwarded-tls-client-verify` header can
/// never be mistaken for proxy evidence downstream. When a trusted proxy IS
/// configured this layer is omitted and
/// [`crate::protocol::mtls::presented_leaf`] applies its own
/// `trusted_proxy`-gated fallback.
#[derive(Debug, Clone, Copy, Default)]
pub struct StripProxyHeadersLayer;

impl<S> Layer<S> for StripProxyHeadersLayer {
  type Service = StripProxyHeadersService<S>;

  fn layer(&self, inner: S) -> Self::Service {
    StripProxyHeadersService::new(inner)
  }
}

/// Service produced by [`StripProxyHeadersLayer`].
#[derive(Debug, Clone, Copy)]
pub struct StripProxyHeadersService<S> {
  inner: S,
}

impl<S> StripProxyHeadersService<S> {
  /// Wrap an inner service.
  pub const fn new(inner: S) -> Self {
    Self { inner }
  }
}

impl<S, B> Service<Request<B>> for StripProxyHeadersService<S>
where
  S: Service<Request<B>> + Clone + Send + 'static,
  S::Future: Send + 'static,
  B: Send + 'static,
{
  type Response = S::Response;
  type Error = S::Error;
  type Future = S::Future;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, mut request: Request<B>) -> Self::Future {
    crate::protocol::mtls::strip_proxy_headers(request.headers_mut());
    self.inner.call(request)
  }
}

#[cfg(test)]
mod tests {
  use axum::http::header;

  use super::{
    HSTS_VALUE, METADATA_CACHE_VALUE, NO_CACHE_VALUE, NO_STORE_VALUE, insert_headers,
    is_cacheable_path, is_page_path,
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
  fn only_metadata_is_cacheable() {
    assert!(is_cacheable_path("/.well-known/oauth-authorization-server"));
    for path in ["/login", "/authorize", "/token", "/par", "/health/live"] {
      assert!(!is_cacheable_path(path), "{path} must not be cacheable");
    }
  }

  #[test]
  fn non_cacheable_response_forbids_storage() {
    let mut headers = axum::http::HeaderMap::new();
    insert_headers(&mut headers, true, true, false);
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
    insert_headers(&mut headers, false, false, true);
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

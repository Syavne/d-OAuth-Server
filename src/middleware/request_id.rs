//! `X-Request-Id` middleware with structured audit events.
//!
//! Propagates or mints a request id, stores it in the request extensions (so
//! handlers and [`super::audit`] can reference it), echoes it on the response,
//! and opens an `http_request` tracing span. The only request material written
//! to logs is the method, the (query-redacted) path, and
//! [`super::redaction`]-projected headers — never the raw body.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request, Response};
use tower::{Layer, Service};
use tracing::Instrument;
use uuid::Uuid;

use super::redaction;

/// Canonical request-id header; also the extension lookup key.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum accepted length of an inbound request id.
const MAX_REQUEST_ID_LEN: usize = 128;

/// A request identifier, either echoed from the client or freshly minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);

impl RequestId {
  /// Mint a new opaque request id.
  #[must_use]
  pub fn new() -> Self {
    Self(Uuid::new_v4().to_string())
  }

  /// Parse a client-supplied id, rejecting anything that could forge log lines
  /// or headers (empty, over-long, or containing non-token bytes).
  #[must_use]
  pub fn parse(raw: &str) -> Option<Self> {
    let candidate = raw.trim();
    let acceptable = (1..=MAX_REQUEST_ID_LEN).contains(&candidate.len())
      && candidate
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    acceptable.then(|| Self(candidate.to_owned()))
  }

  /// Borrow the id as a string slice.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl Default for RequestId {
  fn default() -> Self {
    Self::new()
  }
}

/// Retrieve the request id previously attached by [`RequestIdLayer`].
#[must_use]
pub fn of<B>(request: &Request<B>) -> Option<&RequestId> {
  request.extensions().get::<RequestId>()
}

/// Tower layer that attaches and echoes request ids.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestIdLayer;

impl<S> Layer<S> for RequestIdLayer {
  type Service = RequestIdService<S>;

  fn layer(&self, inner: S) -> Self::Service {
    RequestIdService::new(inner)
  }
}

/// Service produced by [`RequestIdLayer`].
#[derive(Debug, Clone, Copy)]
pub struct RequestIdService<S> {
  inner: S,
}

impl<S> RequestIdService<S> {
  /// Wrap an inner service.
  pub const fn new(inner: S) -> Self {
    Self { inner }
  }
}

impl<S, B> Service<Request<B>> for RequestIdService<S>
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

  fn call(&mut self, mut request: Request<B>) -> Self::Future {
    let request_id = resolve(&request);
    let header_value = HeaderValue::from_str(request_id.as_str()).ok();
    if let Some(value) = header_value.clone() {
      request
        .headers_mut()
        .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    request.extensions_mut().insert(request_id.clone());

    let method = request.method().clone();
    let path = redaction::redact_uri(request.uri());
    let headers = redaction::redact_headers_json(request.headers());

    let span = tracing::info_span!(
      "http_request",
      request_id = %request_id.as_str(),
      method = %method,
      path = %path,
    );

    let mut inner = self.inner.clone();
    Box::pin(
      async move {
        tracing::info!(headers = %headers, "incoming request");
        let mut response = inner.call(request).await?;
        if let Some(value) = header_value {
          response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
        }
        Ok(response)
      }
      .instrument(span),
    )
  }
}

/// Use the inbound id when it is well-formed, otherwise mint one.
fn resolve<B>(request: &Request<B>) -> RequestId {
  request
    .headers()
    .get(REQUEST_ID_HEADER)
    .and_then(|value| value.to_str().ok())
    .and_then(RequestId::parse)
    .unwrap_or_default()
}

#[cfg(test)]
mod redaction_tests {
  use std::io::{self, Write};
  use std::sync::{Arc, Mutex};

  use axum::body::Body;
  use axum::http::Request;
  use tower::{Layer, ServiceExt};
  use tracing_subscriber::EnvFilter;

  use super::*;
  use crate::middleware::{audit, observability};

  const BEARER: &str = "super-secret-bearer-token-value";
  const COOKIE: &str = "session-cookie-secret-value";
  const CODE: &str = "auth-code-secret-value";
  const DPOP: &str = "dpop-proof-secret-value";

  /// In-memory `MakeWriter` sharing one growing buffer with the test.
  #[derive(Clone, Default)]
  struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

  impl SharedBuffer {
    fn contents(&self) -> String {
      let guard = self
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
      String::from_utf8_lossy(&guard).into_owned()
    }
  }

  impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for SharedBuffer {
    type Writer = SharedBufferWriter;

    fn make_writer(&'w self) -> Self::Writer {
      SharedBufferWriter(self.0.clone())
    }
  }

  struct SharedBufferWriter(Arc<Mutex<Vec<u8>>>);

  impl Write for SharedBufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
      self
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .extend_from_slice(buf);
      Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  /// A request whose bearer token, cookie, DPoP proof, and auth `code` all
  /// carry values that must never surface in logs.
  fn request_with_secrets() -> Request<Body> {
    Request::builder()
      .method("POST")
      .uri(format!(
        "/authorize?code={CODE}&client_id=public-client&state=opaque"
      ))
      .header("authorization", format!("Bearer {BEARER}"))
      .header("cookie", format!("session={COOKIE}"))
      .header("dpop", DPOP)
      .body(Body::empty())
      .unwrap_or_else(|_| Request::new(Body::empty()))
  }

  #[tokio::test]
  async fn redaction_scrubs_secrets_and_emits_audit_from_json_logs() {
    let buffer = SharedBuffer::default();
    let subscriber = observability::with_filter(EnvFilter::new("info"), buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let inner = tower::service_fn(|_request: Request<Body>| async {
      Ok::<_, std::io::Error>(Response::new(Body::empty()))
    });
    let service = RequestIdLayer.layer(inner);

    let Ok(response) = service.oneshot(request_with_secrets()).await else {
      return;
    };

    let echoed = response
      .headers()
      .get(REQUEST_ID_HEADER)
      .and_then(|value| value.to_str().ok())
      .map(str::to_owned);
    assert!(echoed.is_some(), "response must echo X-Request-Id");

    audit::AuditEvent::LoginSuccess {
      request_id: echoed.as_deref(),
      subject: "user-1",
    }
    .emit();

    drop(_guard);
    let logs = buffer.contents();

    assert!(
      logs.contains("login.success"),
      "audit event must be emitted: {logs}"
    );
    assert!(
      logs.contains(echoed.as_deref().unwrap_or_default()),
      "request id must appear in logs: {logs}"
    );
    assert!(logs.contains("[REDACTED]"), "redaction marker: {logs}");
    assert!(!logs.contains(BEARER), "bearer token leaked: {logs}");
    assert!(!logs.contains(COOKIE), "cookie leaked: {logs}");
    assert!(!logs.contains(CODE), "authorization code leaked: {logs}");
    assert!(!logs.contains(DPOP), "dpop proof leaked: {logs}");
  }

  #[tokio::test]
  async fn redaction_preserves_a_client_supplied_request_id() {
    let buffer = SharedBuffer::default();
    let subscriber = observability::with_filter(EnvFilter::new("info"), buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let inner = tower::service_fn(|_request: Request<Body>| async {
      Ok::<_, std::io::Error>(Response::new(Body::empty()))
    });
    let service = RequestIdLayer.layer(inner);

    let supplier = "client-supplied-id-123";
    let request = Request::builder()
      .uri("/token")
      .header(REQUEST_ID_HEADER, supplier)
      .body(Body::empty())
      .unwrap_or_else(|_| Request::new(Body::empty()));

    let Ok(response) = service.oneshot(request).await else {
      return;
    };

    assert_eq!(
      response
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok()),
      Some(supplier)
    );
    drop(_guard);
    assert!(buffer.contents().contains(supplier));
  }
}

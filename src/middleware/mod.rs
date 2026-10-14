//! HTTP middleware: observability, rate limiting, request ids, security headers.
//!
//! Ordered in `routes.rs`: request-id → security headers → CORS (when
//! configured) → resilience (load-shed → timeout → concurrency-limit) → rate
//! limit → body limit. Nothing here performs authentication or authorization.
//!
//! `observability` installs the JSON log subscriber; `request_id` attaches the
//! `X-Request-Id` span; `redaction` is the shared secret-scrubbing policy and
//! `audit` emits structured security events. Tasks 13/40 add the rest.

pub mod audit;
pub mod observability;
pub mod ratelimit;
pub mod redaction;
pub mod request_id;
pub mod security_headers;

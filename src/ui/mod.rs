//! Server-rendered user pages: login, consent, device verification.
//!
//! Rendered via `askama` with CSP/`frame-ancestors` and CSRF protection on
//! mutating forms. Login/consent gate `/authorize`; device page drives the
//! user half of RFC 8628.
//!
//! TODO(task 25): wire re-exports for `login`/`consent`/`device`.

pub mod consent;
pub mod device;
pub mod login;

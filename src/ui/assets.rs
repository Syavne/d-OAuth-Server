//! Embedded same-origin assets for the server-rendered pages.
//!
//! The stylesheet is compiled into the binary (`include_str!`) and served from
//! `/assets/app.css`; the page policy `style-src 'self'` allows the `<link>`
//! without weakening CSP and without any inline style.

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// The shared page stylesheet (`src/ui/app.css`), embedded at compile time.
pub const STYLESHEET: &str = include_str!("app.css");

/// `GET /assets/app.css`: serve the embedded stylesheet as `text/css`.
pub async fn stylesheet() -> Response {
  (
    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
    STYLESHEET,
  )
    .into_response()
}

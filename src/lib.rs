//! `d_oauth` — OAuth 2.1-only authorization server library.
//!
//! Module layout (authoritative; see `.omo/plans/rust-oauth21-server.md`):
//! `config`, `keys`, `error`, `state`, `crypto::*`, `jose::*`, `db::*`,
//! `store::*`, `protocol::*`, `ui::*`, `middleware::*`, `resilience`, `routes`,
//! `serve`, `tls`, `cli`.
//! Every later todo places new code in exactly one of these modules.

#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod jose;
pub mod keys;
pub mod middleware;
pub mod protocol;
pub mod resilience;
pub mod routes;
pub mod serve;
pub mod state;
pub mod store;
#[cfg(test)]
pub(crate) mod test_guard;
pub mod tls;
pub mod ui;

/// Build the axum router for the authorization server.
///
/// Minimal skeleton: routes and middleware land here in later todos.
///
/// TODO(task 40): mount health, OAuth, and UI routes with the middleware chain.
pub fn app() -> axum::Router {
  axum::Router::new()
}

#[cfg(test)]
mod tests {
  /// Smoke test proving the crate builds and the router constructs.
  #[test]
  fn crate_builds() {
    let _router: axum::Router = super::app();
  }
}

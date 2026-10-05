//! `d-oauth-server` binary entrypoint.
//!
//! Thin bootstrap only: parse the operator CLI and map its result to a process
//! exit code. All behaviour lives in the `d_oauth` library.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
  std::process::exit(d_oauth::cli::main_entry().await);
}

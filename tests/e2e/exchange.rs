//! Token-exchange rejection rows for `tests/e2e_edge_matrix.rs`.
//!
//! Both rows reach the real `/token` dispatcher: a missing `subject_token` is
//! a grant-level `invalid_grant`, while a repeated known parameter is rejected
//! by the pre-dispatch duplicate gate as `invalid_request`.

use d_oauth::db::TokenEndpointAuthMethod;
use reqwest::StatusCode;
use serde_json::json;

use super::{
  dpop::DpopKey,
  edge::ensure_error,
  harness::{SeedClientOpts, TestError, World, open_rate_limit, seed_client_bound},
};

/// Token-exchange grant URN (RFC 8693).
const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Access-token type URN used for both token-type members.
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// Exchange caller holding the exchange grant (DPoP-bound).
const CALLER_ID: &str = "e2e-edge-exchange-caller";
/// Exchange caller secret.
const CALLER_SECRET: &str = "e2e-edge-exchange-secret-1a2b3c4d5e6f708192a0";

/// A missing `subject_token` is `invalid_grant` at the grant, not
/// `invalid_request`.
pub async fn missing_subject_token() -> Result<(), TestError> {
  let world = World::start_with(open_rate_limit(), json!({"allow_token_exchange": true})).await?;
  seed_client_bound(
    &world.pool,
    &world.state.keys,
    CALLER_ID,
    Some(CALLER_SECRET),
    &SeedClientOpts {
      grants: &[EXCHANGE_GRANT],
      scope: "read",
      method: TokenEndpointAuthMethod::ClientSecretBasic,
      dpop_bound: true,
    },
  )
  .await?;
  let proof =
    DpopKey::generate()?.proof("POST", &format!("{}/token", world.state.config.issuer))?;
  let (status, _, body) = world
    .post_form(
      "/token",
      &[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
      ],
      Some((CALLER_ID, CALLER_SECRET)),
      &[("dpop", proof.as_str())],
    )
    .await?;
  ensure_error(status, &body, StatusCode::BAD_REQUEST, "invalid_grant")
}

/// A repeated `scope` or `grant_type` is rejected before dispatch as
/// `invalid_request`.
pub async fn duplicate_parameter() -> Result<(), TestError> {
  let world = World::start_with(open_rate_limit(), json!({"allow_token_exchange": true})).await?;
  let duplicate_scope = [
    ("grant_type", EXCHANGE_GRANT),
    ("subject_token", "subject"),
    ("subject_token_type", ACCESS_TOKEN_TYPE),
    ("scope", "read"),
    ("scope", "read"),
  ];
  let duplicate_grant_type = [
    ("grant_type", EXCHANGE_GRANT),
    ("grant_type", "refresh_token"),
    ("scope", "read"),
  ];
  for params in [&duplicate_scope[..], &duplicate_grant_type[..]] {
    let (status, _, body) = world.post_form("/token", params, None, &[]).await?;
    ensure_error(status, &body, StatusCode::BAD_REQUEST, "invalid_request")?;
  }
  Ok(())
}

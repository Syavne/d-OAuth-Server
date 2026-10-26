//! `binary(e2e_edge_matrix)` HTTP rejection matrix for DCR, device, and token
//! exchange, plus a `private_key_jwt` mint/replay pair.
//!
//! Every case runs through the REAL production router over a loopback socket
//! against the shared Postgres + Redis. Each row asserts the exact status and
//! OAuth error code and that no token/code/client is issued. DCR rows seed the
//! initial access token through the production keyed-hash path (a plain
//! `sha256_hex` never matches `authorize_caller`).
//!
//! Device rows distinguish `/device` (a consumed user code renders the generic
//! `200` miss) from `/token` (a consumed device code is `400 expired_token`).

#[path = "e2e/harness.rs"]
#[allow(dead_code)]
mod harness;

#[path = "e2e/dpop.rs"]
mod dpop;

#[path = "e2e/browser.rs"]
#[allow(dead_code)]
mod browser;

#[path = "e2e/device.rs"]
#[allow(dead_code)]
mod device;

#[path = "e2e/edge.rs"]
mod edge;

#[path = "e2e/exchange.rs"]
mod exchange;

#[path = "e2e/pkjwt.rs"]
mod pkjwt;

use harness::{TestError, World, ensure, fail, json_body, open_rate_limit};
use pkjwt::{AssertionKey, CLIENT_ID, seed_assertion_client};
use reqwest::StatusCode;
use serde_json::json;

/// `private_key_jwt` assertion-type URN (RFC 7523).
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// One rejection row of the matrix.
#[derive(Clone, Copy)]
enum EdgeCase {
  /// DCR wildcard redirect under the default `catalog` policy.
  DcrWildcardRedirect,
  /// DCR `http://` non-loopback redirect under the `catalog` policy.
  DcrPlainHttpNonLoopback,
  /// DCR metadata carrying both `jwks` and `jwks_uri`.
  DcrJwksAndJwksUri,
  /// Device authorization asking beyond the client registration.
  DeviceOverRegisteredScope,
  /// Consumed user code at `/device` renders the generic 200 miss.
  DeviceUserCodeConsumed,
  /// Consumed device code at `/token` is `400 expired_token`.
  DeviceCodeConsumedAtToken,
  /// Token exchange without a `subject_token`.
  ExchangeMissingSubjectToken,
  /// Token exchange with a repeated `scope` or `grant_type`.
  ExchangeDuplicateParameter,
}

impl EdgeCase {
  /// Row label used in failure context.
  const fn name(self) -> &'static str {
    match self {
      Self::DcrWildcardRedirect => "dcr wildcard redirect",
      Self::DcrPlainHttpNonLoopback => "dcr http non-loopback",
      Self::DcrJwksAndJwksUri => "dcr jwks+jwks_uri",
      Self::DeviceOverRegisteredScope => "device over-registered scope",
      Self::DeviceUserCodeConsumed => "device consumed user_code at /device",
      Self::DeviceCodeConsumedAtToken => "device consumed device_code at /token",
      Self::ExchangeMissingSubjectToken => "exchange missing subject_token",
      Self::ExchangeDuplicateParameter => "exchange duplicate scope/grant_type",
    }
  }
}

/// The full matrix, one row per case.
const CASES: [EdgeCase; 8] = [
  EdgeCase::DcrWildcardRedirect,
  EdgeCase::DcrPlainHttpNonLoopback,
  EdgeCase::DcrJwksAndJwksUri,
  EdgeCase::DeviceOverRegisteredScope,
  EdgeCase::DeviceUserCodeConsumed,
  EdgeCase::DeviceCodeConsumedAtToken,
  EdgeCase::ExchangeMissingSubjectToken,
  EdgeCase::ExchangeDuplicateParameter,
];

/// Every listed edge case rejects at the HTTP layer with its exact code.
#[tokio::test]
async fn e2e_edge_matrix_http_rejections() -> Result<(), TestError> {
  for case in CASES {
    run(case)
      .await
      .map_err(|error| fail(format!("row {}: {error}", case.name())))?;
  }
  Ok(())
}

/// Dispatch one row.
async fn run(case: EdgeCase) -> Result<(), TestError> {
  match case {
    EdgeCase::DcrWildcardRedirect => {
      edge::dcr_rejects(
        json!({
          "redirect_uris": ["https://*.example.test/cb"],
          "token_endpoint_auth_method": "client_secret_basic",
          "dpop_bound_access_tokens": true,
        }),
        "invalid_redirect_uri",
      )
      .await
    }
    EdgeCase::DcrPlainHttpNonLoopback => {
      edge::dcr_rejects(
        json!({
          "redirect_uris": ["http://app.example.test/cb"],
          "token_endpoint_auth_method": "client_secret_basic",
          "dpop_bound_access_tokens": true,
        }),
        "invalid_redirect_uri",
      )
      .await
    }
    EdgeCase::DcrJwksAndJwksUri => {
      edge::dcr_rejects(
        json!({
          "redirect_uris": ["https://app.example.test/cb"],
          "token_endpoint_auth_method": "client_secret_basic",
          "dpop_bound_access_tokens": true,
          "jwks": {"keys": []},
          "jwks_uri": "https://app.example.test/jwks.json",
        }),
        "invalid_client_metadata",
      )
      .await
    }
    EdgeCase::DeviceOverRegisteredScope => edge::device_over_registered_scope().await,
    EdgeCase::DeviceUserCodeConsumed => edge::device_user_code_consumed().await,
    EdgeCase::DeviceCodeConsumedAtToken => edge::device_code_consumed_at_token().await,
    EdgeCase::ExchangeMissingSubjectToken => exchange::missing_subject_token().await,
    EdgeCase::ExchangeDuplicateParameter => exchange::duplicate_parameter().await,
  }
}

/// A valid assertion authenticates and mints; replaying its `jti` is
/// `invalid_client`.
#[tokio::test]
async fn e2e_private_key_jwt_mint_and_replay() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  let key = AssertionKey::generate("k1")?;
  seed_assertion_client(&world, key.jwks()).await?;
  let audience = format!("{}/token", world.state.config.issuer);
  let assertion = key.mint(CLIENT_ID, &audience, "edge-pkjwt-replay-jti")?;
  let params = [
    ("grant_type", "client_credentials"),
    ("client_id", CLIENT_ID),
    ("client_assertion_type", CLIENT_ASSERTION_TYPE),
    ("client_assertion", assertion.as_str()),
  ];

  let (status, _, body) = world.post_form("/token", &params, None, &[]).await?;
  ensure(
    status == StatusCode::OK,
    format!("a valid private_key_jwt must authenticate and mint: {status} {body}"),
  )?;
  ensure(
    json_body(&body)?["access_token"]
      .as_str()
      .is_some_and(|token| !token.is_empty()),
    "the positive leg must issue an access token",
  )?;

  let (status, _, body) = world.post_form("/token", &params, None, &[]).await?;
  edge::ensure_error(status, &body, StatusCode::BAD_REQUEST, "invalid_client")
}

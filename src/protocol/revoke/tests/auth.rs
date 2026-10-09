//! Revocation request validation: unauthenticated `401`, missing token `400`.

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  response::IntoResponse,
  routing::post,
};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

use super::{
  TestError, TestResult, handler_state, lazy_pool, lazy_redis, no_credentials, service, store,
  test_keys,
};
use crate::{
  error::OAuthErrorCode,
  protocol::revoke::{RevokeContext, RevokeRequest, RevokeStores, revoke_handler, revoke_tokens},
};

/// An unauthenticated request fails closed with `401 invalid_client`.
#[tokio::test]
async fn revoke_unauthenticated_request_is_401() -> TestResult {
  let mut conn = lazy_redis()?;
  let pool = lazy_pool()?;
  let store = store();
  let service = service()?;
  let auth = no_credentials();
  let ring = test_keys()?;
  let mut stores = RevokeStores {
    pool: &pool,
    keys: &ring,
    conn: &mut conn,
    store: &store,
    service: &service,
  };
  let ctx = RevokeContext {
    token_endpoint: "https://auth.example.test/token",
    now: time::OffsetDateTime::now_utc(),
    request_id: Some("req-revoke-test"),
  };
  let request = RevokeRequest {
    token: "some-token",
    token_type_hint: None,
    auth: &auth,
  };

  match revoke_tokens(&mut stores, &ctx, &request).await {
    Err(error) => {
      if error.code() != OAuthErrorCode::InvalidClient {
        return Err(TestError::Unexpected(
          "unauthenticated request must be invalid_client".to_owned(),
        ));
      }
      if error.status() != StatusCode::UNAUTHORIZED {
        return Err(TestError::Unexpected(
          "unauthenticated request must be 401".to_owned(),
        ));
      }
      let response = error.into_response();
      if response.status() != StatusCode::UNAUTHORIZED
        || response.headers().get(header::WWW_AUTHENTICATE).is_none()
      {
        return Err(TestError::Unexpected(
          "401 must carry a WWW-Authenticate challenge".to_owned(),
        ));
      }
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "unauthenticated request must not succeed".to_owned(),
      ));
    }
  }
  Ok(())
}

/// A missing `token` is `invalid_request`, not a silent success.
#[tokio::test]
async fn revoke_missing_token_is_invalid_request() -> TestResult {
  let mut conn = lazy_redis()?;
  let pool = lazy_pool()?;
  let store = store();
  let service = service()?;
  let auth = no_credentials();
  let ring = test_keys()?;
  let mut stores = RevokeStores {
    pool: &pool,
    keys: &ring,
    conn: &mut conn,
    store: &store,
    service: &service,
  };
  let ctx = RevokeContext {
    token_endpoint: "https://auth.example.test/token",
    now: time::OffsetDateTime::now_utc(),
    request_id: None,
  };
  let request = RevokeRequest {
    token: "",
    token_type_hint: None,
    auth: &auth,
  };
  match revoke_tokens(&mut stores, &ctx, &request).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidRequest => Ok(()),
    Err(_) | Ok(_) => Err(TestError::Unexpected(
      "missing token must be invalid_request".to_owned(),
    )),
  }
}

/// A request missing the `token` form field is `400 invalid_request`
/// (RFC 7009 §2.1: `token` is REQUIRED; §2.2.1 defines the error response).
#[tokio::test]
async fn revoke_missing_token_form_is_400_invalid_request() -> TestResult {
  let app = Router::new()
    .route("/revoke", post(revoke_handler))
    .with_state(handler_state()?);
  let request = Request::post("/revoke")
    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
    .header(header::AUTHORIZATION, "Basic cmV2b2tlLXRlc3Q6c2VjcmV0")
    .body(Body::from("token_type_hint=access_token"))
    .map_err(|error| TestError::Unexpected(format!("request build failed: {error}")))?;
  let response = match app.oneshot(request).await {
    Ok(response) => response,
    Err(never) => match never {},
  };

  if response.status() != StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(format!(
      "a missing token parameter must be 400, got {}",
      response.status()
    )));
  }
  let bytes = response.into_body().collect().await?.to_bytes();
  let body: Value = serde_json::from_slice(&bytes)?;
  if body.get("error").and_then(Value::as_str) != Some("invalid_request") {
    return Err(TestError::Unexpected(
      "a missing token parameter must render invalid_request".to_owned(),
    ));
  }
  Ok(())
}

//! Revocation request validation: unauthenticated `401`, missing token `400`.

use axum::{
  http::{StatusCode, header},
  response::IntoResponse,
};

use super::{TestError, TestResult, lazy_pool, lazy_redis, no_credentials, service, store};
use crate::{
  error::OAuthErrorCode,
  protocol::revoke::{RevokeContext, RevokeRequest, RevokeStores, revoke_tokens},
};

/// An unauthenticated request fails closed with `401 invalid_client`.
#[tokio::test]
async fn revoke_unauthenticated_request_is_401() -> TestResult {
  let mut conn = lazy_redis()?;
  let pool = lazy_pool()?;
  let store = store();
  let service = service()?;
  let auth = no_credentials();
  let mut stores = RevokeStores {
    pool: &pool,
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
  let mut stores = RevokeStores {
    pool: &pool,
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

//! `test(dcr_manage)` read suite: GET metadata, auth denials, wire shape.

use super::read_client;
use super::support::{
  TestResult, expect_forbidden, expect_unauthorized, harness, manage_parts, register,
};

#[tokio::test]
async fn dcr_manage_read_returns_metadata() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", Some("read")).await?;

  let response = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| super::support::TestError::Unexpected(format!("read failed: {error:?}")))?
  };

  if response.client_id != registered.client_id {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong client_id: {}",
      response.client_id
    )));
  }
  if response.redirect_uris != vec!["https://app.example.test/cb".to_owned()] {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong redirects: {:?}",
      response.redirect_uris
    )));
  }
  if response.client_name != "dcr manage client" {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong name: {}",
      response.client_name
    )));
  }
  if response.token_endpoint_auth_method != "client_secret_basic" {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong method: {}",
      response.token_endpoint_auth_method
    )));
  }
  if response.scope != "read" {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong scope: {}",
      response.scope
    )));
  }
  if response.registration_client_uri
    != format!(
      "https://auth.example.test/register/{}",
      registered.client_id
    )
  {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong management uri: {}",
      response.registration_client_uri
    )));
  }
  if response.client_secret.is_some() || response.registration_access_token.is_some() {
    return Err(super::support::TestError::Unexpected(
      "GET must not return credentials".to_owned(),
    ));
  }
  if response.client_id_issued_at <= 0 {
    return Err(super::support::TestError::Unexpected(
      "missing client_id_issued_at".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_get() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", Some("read")).await?;

  let response = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| super::support::TestError::Unexpected(format!("get failed: {error:?}")))?
  };

  if response.client_id != registered.client_id {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong client_id: {}",
      response.client_id
    )));
  }
  if response.client_name != "dcr manage client" {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong name: {}",
      response.client_name
    )));
  }
  if response.redirect_uris != vec!["https://app.example.test/cb".to_owned()] {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong redirects: {:?}",
      response.redirect_uris
    )));
  }
  if response.scope != "read" {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong scope: {}",
      response.scope
    )));
  }
  if response.client_secret.is_some() || response.registration_access_token.is_some() {
    return Err(super::support::TestError::Unexpected(
      "GET must not return credentials".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_read_missing_token_401() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let (mut stores, ctx) = manage_parts(&mut harness);
  match read_client(&mut stores, &ctx, &registered.client_id, None).await {
    Ok(_) => Err(super::support::TestError::Unexpected(
      "tokenless read succeeded".to_owned(),
    )),
    Err(error) => expect_unauthorized(error),
  }
}

#[tokio::test]
async fn dcr_manage_read_unknown_client_401() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let (mut stores, ctx) = manage_parts(&mut harness);
  match read_client(
    &mut stores,
    &ctx,
    "no-such-client",
    Some(&registered.reg_token),
  )
  .await
  {
    Ok(_) => Err(super::support::TestError::Unexpected(
      "unknown-client read succeeded".to_owned(),
    )),
    Err(error) => expect_unauthorized(error),
  }
}

#[tokio::test]
async fn dcr_manage_read_wrong_token_403() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let (mut stores, ctx) = manage_parts(&mut harness);
  match read_client(
    &mut stores,
    &ctx,
    &registered.client_id,
    Some("garbage-token-value"),
  )
  .await
  {
    Ok(_) => Err(super::support::TestError::Unexpected(
      "wrong-token read succeeded".to_owned(),
    )),
    Err(error) => expect_forbidden(error),
  }
}

#[tokio::test]
async fn dcr_manage_forbidden_renders_403() -> TestResult {
  use axum::response::IntoResponse as _;
  use http_body_util::BodyExt as _;

  let response = super::ManageError::Forbidden.into_response();
  if response.status() != axum::http::StatusCode::FORBIDDEN {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong status: {}",
      response.status()
    )));
  }
  let body = match response.into_body().collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(_) => axum::body::Bytes::new(),
  };
  let value: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
    super::support::TestError::Unexpected(format!("non-JSON 403 body: {error}"))
  })?;
  if value.get("error").and_then(|error| error.as_str()) != Some("access_denied") {
    return Err(super::support::TestError::Unexpected(format!(
      "wrong 403 body: {value}"
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_bad_redirect_rejected() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let request = crate::protocol::dcr::RegisterRequest {
    redirect_uris: Some(vec!["https://evil.example.test/cb".to_owned()]),
    client_name: None,
    token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    dpop_bound_access_tokens: Some(true),
    contacts: None,
    request_uris: None,
    software_id: None,
  };
  let (mut stores, ctx) = manage_parts(&mut harness);
  match super::update::update_client(
    &mut stores,
    &ctx,
    &registered.client_id,
    Some(&registered.reg_token),
    &request,
  )
  .await
  {
    Ok(_) => Err(super::support::TestError::Unexpected(
      "non-catalog redirect accepted on PUT".to_owned(),
    )),
    Err(super::ManageError::Protocol(error)) => {
      if error.code() != crate::error::OAuthErrorCode::InvalidRedirectUri {
        return Err(super::support::TestError::Unexpected(format!(
          "wrong code: {}",
          error.code()
        )));
      }
      Ok(())
    }
    Err(super::ManageError::Forbidden) => Err(super::support::TestError::Unexpected(
      "valid token read as forbidden".to_owned(),
    )),
  }
}

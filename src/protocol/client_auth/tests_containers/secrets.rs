//! Secret-method dispatch tests: Basic, POST, `none`, expiry, and misuse.

use secrecy::SecretString;

use super::{
  TestError, TestResult, bare_request, basic_header, basic_request, ctx_of, expect_invalid_client,
  harness, insert_client, post_request, stores_of,
};
use crate::db::TokenEndpointAuthMethod;
use crate::protocol::client_auth::authenticate_client;

#[tokio::test]
async fn client_auth_basic_valid() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-basic-valid";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("correct-secret"),
    None,
    None,
    None,
  )
  .await?;
  let header = basic_header(client_id, "correct-secret");
  let authed = authenticate_client(
    &mut stores_of(&mut h),
    &ctx_of(&endpoint),
    &basic_request(&header),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("valid basic rejected: {error}")))?;
  if authed.method != TokenEndpointAuthMethod::ClientSecretBasic {
    return Err(TestError::Unexpected("wrong method".to_owned()));
  }
  if authed.client.client_id != client_id {
    return Err(TestError::Unexpected("wrong client".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn client_auth_basic_wrong_secret_is_401() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-basic-wrong";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("correct-secret"),
    None,
    None,
    None,
  )
  .await?;
  let header = basic_header(client_id, "wrong-secret");
  match authenticate_client(
    &mut stores_of(&mut h),
    &ctx_of(&endpoint),
    &basic_request(&header),
  )
  .await
  {
    Err(error) => expect_invalid_client(error, 401),
    Ok(_) => Err(TestError::Unexpected("wrong secret accepted".to_owned())),
  }
}

#[tokio::test]
async fn client_auth_post_valid() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-post-valid";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("post-secret"),
    None,
    None,
    None,
  )
  .await?;
  let req = post_request(client_id, SecretString::from("post-secret"));
  let authed = authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req)
    .await
    .map_err(|error| TestError::Unexpected(format!("valid post rejected: {error}")))?;
  if authed.method != TokenEndpointAuthMethod::ClientSecretPost {
    return Err(TestError::Unexpected("wrong method".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn client_auth_none_on_confidential_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-none-on-conf";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("secret"),
    None,
    None,
    None,
  )
  .await?;
  match authenticate_client(
    &mut stores_of(&mut h),
    &ctx_of(&endpoint),
    &bare_request(client_id),
  )
  .await
  {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected(
      "bare client_id on confidential accepted".to_owned(),
    )),
  }
}

#[tokio::test]
async fn client_auth_none_on_public_accepted() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-none-public";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::None,
    None,
    None,
    None,
    None,
  )
  .await?;
  let authed = authenticate_client(
    &mut stores_of(&mut h),
    &ctx_of(&endpoint),
    &bare_request(client_id),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("public none rejected: {error}")))?;
  if authed.method != TokenEndpointAuthMethod::None {
    return Err(TestError::Unexpected("wrong method".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn client_auth_expired_secret_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-expired-secret";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretPost,
    Some("right-secret"),
    Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(60)),
    None,
    None,
  )
  .await?;
  let req = post_request(client_id, SecretString::from("right-secret"));
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("expired secret accepted".to_owned())),
  }
}

#[tokio::test]
async fn client_auth_unknown_client_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let req = post_request("client-auth-no-such-client", SecretString::from("whatever"));
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("unknown client accepted".to_owned())),
  }
}

#[tokio::test]
async fn client_auth_multiple_methods_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-multi-method";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("secret"),
    None,
    None,
    None,
  )
  .await?;
  let header = basic_header(client_id, "secret");
  let req = crate::protocol::client_auth::ClientAuthRequest {
    basic_header: Some(header.as_str()),
    client_id: Some(client_id),
    body_secret: Some(SecretString::from("secret")),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 401),
    Ok(_) => Err(TestError::Unexpected("two methods accepted".to_owned())),
  }
}

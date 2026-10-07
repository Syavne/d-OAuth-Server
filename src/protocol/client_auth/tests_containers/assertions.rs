//! Assertion dispatch tests: wrong `aud`, `jti` replay, `jwks_uri` SSRF guard.

use super::{
  ContainerKey, TestError, TestResult, assertion_request, ctx_of, expect_invalid_client, harness,
  insert_client, stores_of,
};
use crate::db::TokenEndpointAuthMethod;
use crate::error::{AppError, OAuthErrorCode};
use crate::protocol::client_auth::assertion::validate_assertion;
use crate::protocol::client_auth::authenticate_client;

#[tokio::test]
async fn client_auth_assertion_wrong_aud_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-ct-wrong-aud";
  let key = ContainerKey::generate("k1")?;
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::PrivateKeyJwt,
    None,
    None,
    Some(key.jwks.clone()),
    None,
  )
  .await?;
  let assertion = key.mint(client_id, "https://evil.example.com/token", "jti-aud-1")?;
  let req = assertion_request(client_id, &assertion);
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("wrong aud accepted".to_owned())),
  }
}

#[tokio::test]
async fn client_auth_assertion_replayed_jti_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-ct-replay";
  let key = ContainerKey::generate("k1")?;
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::PrivateKeyJwt,
    None,
    None,
    Some(key.jwks.clone()),
    None,
  )
  .await?;
  let assertion = key.mint(client_id, &h.endpoint, "jti-replay-1")?;
  let req = assertion_request(client_id, &assertion);
  authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req)
    .await
    .map_err(|error| TestError::Unexpected(format!("first use rejected: {error}")))?;
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("replayed jti accepted".to_owned())),
  }
}

#[test]
fn client_auth_assertion_aud_array_membership() -> TestResult {
  let key = ContainerKey::generate("k1")?;
  let client_id = "client-auth-aud-array";
  let endpoint = crate::protocol::client_auth::token_endpoint("https://auth.example.com");
  let now = time::OffsetDateTime::now_utc();
  let stamp = now.unix_timestamp();
  let mint_with_aud = |aud: serde_json::Value| {
    let claims = serde_json::json!({
      "iss": client_id,
      "sub": client_id,
      "aud": aud,
      "jti": "jti-array-1",
      "exp": stamp + 300,
      "iat": stamp,
    });
    jsonwebtoken::encode(
      &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
      &claims,
      &key.encoding,
    )
    .map_err(|error| TestError::Crypto(format!("mint failed: {error}")))
  };
  let member = mint_with_aud(serde_json::json!([endpoint, "https://other.example.com"]))?;
  validate_assertion(&member, &key.jwks, client_id, &endpoint, now)
    .map_err(|error| TestError::Unexpected(format!("array aud rejected: {error}")))?;
  let outsider = mint_with_aud(serde_json::json!(["https://evil.example.com/token"]))?;
  if validate_assertion(&outsider, &key.jwks, client_id, &endpoint, now).is_ok() {
    return Err(TestError::Unexpected(
      "array aud without endpoint accepted".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn client_auth_jwks_uri_private_ip_rejected() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-ct-ssrf";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::PrivateKeyJwt,
    None,
    None,
    None,
    Some("https://127.0.0.1:9/jwks.json"),
  )
  .await?;
  let req = assertion_request(client_id, "aaa.bbb.ccc");
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("SSRF jwks_uri accepted".to_owned())),
  }
}

/// An encrypted `jwks_uri` decrypts before the SSRF-guarded fetch (a
/// private-IP URI fails as `invalid_client`, proving the fetch ran on the
/// plaintext); a corrupt `jwks_uri_enc` fails as 503 `PiiDecrypt`.
#[tokio::test]
async fn private_key_jwt_jwks_uri_fetch() -> TestResult {
  let (_container, mut h) = harness().await?;
  let endpoint = h.endpoint.clone();
  let client_id = "client-auth-ct-jwks-fetch";
  insert_client(
    &h.pool,
    client_id,
    TokenEndpointAuthMethod::PrivateKeyJwt,
    None,
    None,
    None,
    Some("https://127.0.0.1:9/jwks.json"),
  )
  .await?;
  let sealed: bool = sqlx::query_scalar(
    "SELECT jwks_uri_enc IS NOT NULL AND jwks_uri IS NULL FROM oauth_clients WHERE client_id = $1",
  )
  .bind(client_id)
  .fetch_one(&h.pool)
  .await
  .map_err(TestError::Database)?;
  if !sealed {
    return Err(TestError::Unexpected(
      "jwks_uri not encrypt-only at rest".to_owned(),
    ));
  }
  let req = assertion_request(client_id, "aaa.bbb.ccc");
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Err(error) => expect_invalid_client(error, 400),
    Ok(_) => Err(TestError::Unexpected("SSRF jwks_uri accepted".to_owned())),
  }?;

  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE oauth_clients SET jwks_uri_enc = $1 WHERE client_id = $2")
    .bind(corrupt)
    .bind(client_id)
    .execute(&h.pool)
    .await?;
  let req = assertion_request(client_id, "aaa.bbb.ccc");
  match authenticate_client(&mut stores_of(&mut h), &ctx_of(&endpoint), &req).await {
    Ok(_) => Err(TestError::Unexpected(
      "corrupt jwks_uri_enc accepted".to_owned(),
    )),
    Err(error) => {
      if !matches!(error, AppError::PiiDecrypt) {
        return Err(TestError::Unexpected(format!(
          "corrupt jwks_uri_enc must be PiiDecrypt, got {}",
          error.code()
        )));
      }
      if error.code() != OAuthErrorCode::TemporarilyUnavailable || error.status().as_u16() != 503 {
        return Err(TestError::Unexpected("PiiDecrypt must be 503".to_owned()));
      }
      Ok(())
    }
  }
}

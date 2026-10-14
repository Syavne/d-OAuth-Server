//! PAR enforcement tests: client authentication is mandatory and pushed
//! request rules reject malformed or foreign bodies.

use secrecy::SecretString;

use super::{
  super::push_authorization_request, attach_redirect, bare_auth, ctx_of, expect_code, harness,
  insert_client, push_params, stores_of,
};
use crate::{
  db::TokenEndpointAuthMethod,
  error::{AppError, OAuthErrorCode},
  protocol::client_auth::ClientAuthRequest,
};

use super::TestError;

#[tokio::test]
async fn par_rejects_unauthenticated_client() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_id = "par-conf-client";
  let redirect_uri = "https://client.example.test/cb";
  insert_client(
    &h.pool,
    &h.keys,
    client_id,
    TokenEndpointAuthMethod::ClientSecretBasic,
    Some("correct-secret"),
  )
  .await?;
  attach_redirect(&h.pool, &h.keys, client_id, redirect_uri).await?;

  // Unknown client: no authentication possible.
  let params = push_params("par-ghost", redirect_uri);
  let auth = bare_auth("par-ghost");
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => return Err(TestError::Unexpected("ghost push accepted".to_owned())),
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidClient)?,
  }

  // Confidential client presenting no credentials at all.
  let params = push_params(client_id, redirect_uri);
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "credential-free push accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidClient)?,
  }

  // Confidential client presenting the wrong secret.
  let params = push_params(client_id, redirect_uri);
  let auth = ClientAuthRequest {
    basic_header: None,
    client_id: Some(client_id),
    body_secret: Some(SecretString::from("wrong-secret")),
    assertion_type: None,
    assertion: None,
    peer_certs: None,
  };
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "wrong-secret push accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidClient)?,
  }
  Ok(())
}

#[tokio::test]
async fn par_rejects_invalid_request_rules() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_id = "par-rules-client";
  let redirect_uri = "https://client.example.test/cb";
  insert_client(
    &h.pool,
    &h.keys,
    client_id,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  attach_redirect(&h.pool, &h.keys, client_id, redirect_uri).await?;

  // Missing response_type.
  let mut params = push_params(client_id, redirect_uri);
  params.remove("response_type");
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "missing response_type accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }

  // A foreign request_uri smuggled into the pushed body.
  let mut params = push_params(client_id, redirect_uri);
  params.insert(
    "request_uri".to_owned(),
    "https://evil.example.test/req.jwt".to_owned(),
  );
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "foreign request_uri accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }

  // Redirect URI that was never registered for this client.
  let mut params = push_params(client_id, "https://evil.example.test/cb");
  params.insert("client_id".to_owned(), client_id.to_owned());
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "unregistered redirect accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }
  Ok(())
}

/// A pushed redirect that was never registered is rejected, and a corrupt
/// `uri_enc` fails as 503 `PiiDecrypt` (never a flattened client error).
#[tokio::test]
async fn par_redirect_mismatch_rejected() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_id = "par-mismatch-client";
  let redirect_uri = "https://client.example.test/cb";
  insert_client(
    &h.pool,
    &h.keys,
    client_id,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  attach_redirect(&h.pool, &h.keys, client_id, redirect_uri).await?;

  let params = push_params(client_id, "https://evil.example.test/cb");
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected("evil redirect accepted".to_owned()));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }

  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE redirect_uris SET uri_enc = $1")
    .bind(corrupt)
    .execute(&h.pool)
    .await?;
  let params = push_params(client_id, redirect_uri);
  let auth = bare_auth(client_id);
  let endpoint = h.endpoint.clone();
  let ctx = ctx_of(&endpoint);
  let mut stores = stores_of(&mut h);
  match push_authorization_request(&mut stores, &ctx, &auth, &params).await {
    Ok(_) => {
      return Err(TestError::Unexpected("corrupt uri_enc accepted".to_owned()));
    }
    Err(error) => {
      if !matches!(error, AppError::PiiDecrypt) {
        return Err(TestError::Unexpected(format!(
          "corrupt uri_enc must be PiiDecrypt, got {}",
          error.code()
        )));
      }
      expect_code(&error, OAuthErrorCode::TemporarilyUnavailable)?;
      if error.status().as_u16() != 503 {
        return Err(TestError::Unexpected(format!(
          "PiiDecrypt must be 503, got {}",
          error.status()
        )));
      }
    }
  }
  Ok(())
}

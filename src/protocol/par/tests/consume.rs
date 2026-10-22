//! Push-to-consume PAR tests: one-time records, authorize-side client
//! binding, replay rejection, and TTL expiry.

use std::{collections::HashMap, time::Duration};

use super::TestError;
use super::{
  super::push_authorization_request, attach_redirect, bare_auth, ctx_of, expect_code, harness,
  insert_client, push_params, stores_of,
};
use crate::{
  db::{TokenEndpointAuthMethod, client_repo},
  error::OAuthErrorCode,
  jose::jar::{JarRequest, PAR_REQUEST_URI_PREFIX, resolve},
  store::par,
};

/// Push via a public client and return the issued `request_uri`.
async fn push_public(
  h: &mut super::Harness,
  endpoint: &str,
  client_id: &str,
  redirect_uri: &str,
) -> Result<String, TestError> {
  let params = push_params(client_id, redirect_uri);
  let auth = bare_auth(client_id);
  let ctx = ctx_of(endpoint);
  let mut stores = stores_of(h);
  let response = push_authorization_request(&mut stores, &ctx, &auth, &params, &[])
    .await
    .map_err(|error| TestError::Unexpected(format!("push failed: {}", error.code())))?;
  if response.expires_in != 90 {
    return Err(TestError::Unexpected(format!(
      "wrong expires_in: {}",
      response.expires_in
    )));
  }
  if !response.request_uri.starts_with(PAR_REQUEST_URI_PREFIX) {
    return Err(TestError::Unexpected(format!(
      "bad request_uri: {}",
      response.request_uri
    )));
  }
  Ok(response.request_uri)
}

#[tokio::test]
async fn par_push_stores_one_time_record() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_id = "par-public-client";
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

  let endpoint = h.endpoint.clone();
  let request_uri = push_public(&mut h, &endpoint, client_id, redirect_uri).await?;
  let Some(id) = request_uri.strip_prefix(PAR_REQUEST_URI_PREFIX) else {
    return Err(TestError::Unexpected("missing PAR prefix".to_owned()));
  };

  let record = par::consume(&mut h.conn, &h.store, id)
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  let Some(record) = record else {
    return Err(TestError::Unexpected("PAR record missing".to_owned()));
  };
  if record.client_id != client_id {
    return Err(TestError::Unexpected("PAR record wrong client".to_owned()));
  }
  let stored: serde_json::Value = serde_json::from_str(&record.request)
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  if stored.get("redirect_uri").and_then(|value| value.as_str()) != Some(redirect_uri) {
    return Err(TestError::Unexpected("stored redirect_uri lost".to_owned()));
  }
  if stored.get("client_secret").is_some() {
    return Err(TestError::Unexpected(
      "credential leaked into store".to_owned(),
    ));
  }

  let replayed = par::consume(&mut h.conn, &h.store, id)
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  if replayed.is_some() {
    return Err(TestError::Unexpected("PAR record reusable".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn par_authorize_binds_client_and_rejects_replay() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_a = "par-client-a";
  let client_b = "par-client-b";
  let redirect_uri = "https://client.example.test/cb";
  insert_client(
    &h.pool,
    &h.keys,
    client_a,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  insert_client(
    &h.pool,
    &h.keys,
    client_b,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  attach_redirect(&h.pool, &h.keys, client_a, redirect_uri).await?;
  attach_redirect(&h.pool, &h.keys, client_b, redirect_uri).await?;

  let endpoint = h.endpoint.clone();
  let request_uri = push_public(&mut h, &endpoint, client_a, redirect_uri).await?;

  let issuer = "https://auth.example.test";
  let client_row_b = client_repo::find_active_by_client_id(&h.pool, &h.keys, client_b)
    .await?
    .ok_or_else(|| TestError::Unexpected("client B missing".to_owned()))?;
  let query_b = HashMap::from([
    ("client_id".to_owned(), client_b.to_owned()),
    ("request_uri".to_owned(), request_uri.clone()),
  ]);
  let foreign = JarRequest {
    client: &client_row_b,
    issuer,
    query: &query_b,
    request: None,
    request_uri: Some(request_uri.as_str()),
  };
  match resolve(&mut h.conn, &h.store, &foreign).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "cross-client request_uri accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }

  // The foreign attempt must not burn the victim record: the legitimate
  // first use resolves the same `request_uri`.
  let client_row_a = client_repo::find_active_by_client_id(&h.pool, &h.keys, client_a)
    .await?
    .ok_or_else(|| TestError::Unexpected("client A missing".to_owned()))?;
  let query_a = HashMap::from([
    ("client_id".to_owned(), client_a.to_owned()),
    ("request_uri".to_owned(), request_uri.clone()),
  ]);
  let first = JarRequest {
    client: &client_row_a,
    issuer,
    query: &query_a,
    request: None,
    request_uri: Some(request_uri.as_str()),
  };
  let merged = resolve(&mut h.conn, &h.store, &first)
    .await
    .map_err(|error| TestError::Unexpected(format!("first use failed: {}", error.code())))?;
  if merged.params.get("redirect_uri").map(String::as_str) != Some(redirect_uri) {
    return Err(TestError::Unexpected("merged params lost".to_owned()));
  }

  let replay = JarRequest {
    client: &client_row_a,
    issuer,
    query: &query_a,
    request: None,
    request_uri: Some(request_uri.as_str()),
  };
  match resolve(&mut h.conn, &h.store, &replay).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "replayed request_uri accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }
  Ok(())
}

#[tokio::test]
async fn par_foreign_presentation_does_not_consume_victim_record() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_a = "par-victim-client";
  let client_b = "par-foreign-client";
  let redirect_uri = "https://client.example.test/cb";
  insert_client(
    &h.pool,
    &h.keys,
    client_a,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  insert_client(
    &h.pool,
    &h.keys,
    client_b,
    TokenEndpointAuthMethod::None,
    None,
  )
  .await?;
  attach_redirect(&h.pool, &h.keys, client_a, redirect_uri).await?;
  attach_redirect(&h.pool, &h.keys, client_b, redirect_uri).await?;

  let endpoint = h.endpoint.clone();
  let request_uri = push_public(&mut h, &endpoint, client_a, redirect_uri).await?;
  let issuer = "https://auth.example.test";

  let client_row_b = client_repo::find_active_by_client_id(&h.pool, &h.keys, client_b)
    .await?
    .ok_or_else(|| TestError::Unexpected("client B missing".to_owned()))?;
  let query_b = HashMap::from([
    ("client_id".to_owned(), client_b.to_owned()),
    ("request_uri".to_owned(), request_uri.clone()),
  ]);
  let foreign = JarRequest {
    client: &client_row_b,
    issuer,
    query: &query_b,
    request: None,
    request_uri: Some(request_uri.as_str()),
  };
  match resolve(&mut h.conn, &h.store, &foreign).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "cross-client request_uri accepted".to_owned(),
      ));
    }
    Err(error) => expect_code(&error, OAuthErrorCode::InvalidRequest)?,
  }

  let client_row_a = client_repo::find_active_by_client_id(&h.pool, &h.keys, client_a)
    .await?
    .ok_or_else(|| TestError::Unexpected("client A missing".to_owned()))?;
  let query_a = HashMap::from([
    ("client_id".to_owned(), client_a.to_owned()),
    ("request_uri".to_owned(), request_uri.clone()),
  ]);
  let legitimate = JarRequest {
    client: &client_row_a,
    issuer,
    query: &query_a,
    request: None,
    request_uri: Some(request_uri.as_str()),
  };
  resolve(&mut h.conn, &h.store, &legitimate)
    .await
    .map_err(|error| {
      TestError::Unexpected(format!(
        "victim record burned by foreign use: {}",
        error.code()
      ))
    })?;
  Ok(())
}

#[tokio::test]
async fn par_consume_bound_transport_error_recovery() -> Result<(), TestError> {
  let mut h = harness().await?;
  let client_id = "par-recovery-client";
  let record = par::ParRecord {
    client_id: client_id.to_owned(),
    request: "{\"response_type\":\"code\"}".to_owned(),
    aud: Vec::new(),
  };
  par::put(
    &mut h.conn,
    &h.store,
    "par-recovery-id",
    &record,
    Duration::from_secs(300),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  // Poison the key type through the public key layout: the guarded `HGETALL`
  // script fails indeterminately on a string key, the recovery re-read sees
  // the surviving key, and the consume fails closed without deleting it.
  let key = h.store.par_key("par-recovery-id");
  let _: () = redis::cmd("DEL")
    .arg(&key)
    .query_async(&mut h.conn)
    .await
    .map_err(TestError::Redis)?;
  let _: () = redis::cmd("SET")
    .arg(&key)
    .arg("poison")
    .query_async(&mut h.conn)
    .await
    .map_err(TestError::Redis)?;
  match par::consume_bound(&mut h.conn, &h.store, "par-recovery-id", client_id).await {
    Err(_) => {}
    Ok(_) => {
      return Err(TestError::Unexpected(
        "indeterminate consume with a surviving key must fail closed".to_owned(),
      ));
    }
  }
  let present: i64 = redis::cmd("EXISTS")
    .arg(&key)
    .query_async(&mut h.conn)
    .await
    .map_err(TestError::Redis)?;
  if present != 1 {
    return Err(TestError::Unexpected(
      "failed consume must leave the surviving key intact".to_owned(),
    ));
  }
  // An absent key reports `Absent` through the same public API: no record,
  // no error, never a replay.
  match par::consume_bound(&mut h.conn, &h.store, "par-recovery-absent", client_id).await {
    Ok(par::ConsumeOutcome::Absent) => Ok(()),
    Ok(_) => Err(TestError::Unexpected(
      "absent PAR record must report Absent".to_owned(),
    )),
    Err(error) => Err(TestError::Unexpected(format!(
      "absent consume error: {error}"
    ))),
  }
}

#[tokio::test]
async fn par_expired_request_uri_is_rejected() -> Result<(), TestError> {
  let mut h = harness().await?;
  let record = par::ParRecord {
    client_id: "par-expiry-client".to_owned(),
    request: "{\"response_type\":\"code\"}".to_owned(),
    aud: Vec::new(),
  };
  par::put(
    &mut h.conn,
    &h.store,
    "par-expiry-id",
    &record,
    Duration::from_millis(50),
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  tokio::time::sleep(Duration::from_millis(300)).await;
  let expired = par::consume(&mut h.conn, &h.store, "par-expiry-id")
    .await
    .map_err(|error| TestError::Unexpected(format!("{error}")))?;
  if expired.is_some() {
    return Err(TestError::Unexpected(
      "expired PAR record survived".to_owned(),
    ));
  }
  Ok(())
}

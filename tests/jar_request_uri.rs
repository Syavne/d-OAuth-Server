//! `test(jar)` suite, part 2: `request_uri` references.
//!
//! Unknown URIs are never fetched; registered URIs behind the SSRF guard
//! reject private-IP and plaintext targets; PAR URNs consume one-time and
//! bind to the issuing client. No test performs an arbitrary fetch.

#[path = "jar_support.rs"]
mod support;

use std::{
  collections::HashMap,
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use d_oauth::{
  error::OAuthErrorCode,
  jose::jar::{JarRequest, PAR_REQUEST_URI_PREFIX, resolve},
  store::par::{self, ParRecord},
};
use serde_json::json;

use support::{CLIENT_ID, ISSUER, TestError, TestResult, code_of, store_conn, test_client};

static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

/// Unique PAR id per test so the shared container stays isolated.
fn unique_par_id() -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("jar-test-{n}")
}

#[tokio::test]
async fn jar_non_registered_request_uri_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let mut query = HashMap::new();
  query.insert("client_id".to_owned(), CLIENT_ID.to_owned());
  let uri = "https://127.0.0.1:9/unregistered.jwt";
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: Some(uri),
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected(
      "non-registered request_uri accepted".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn jar_registered_request_uri_private_ip_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let uri = "https://127.0.0.1:9/req.jwt";
  let client = test_client("client_secret_basic", Some(json!([uri])));
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: Some(uri),
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected(
      "private-IP request_uri accepted".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn jar_registered_request_uri_http_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let uri = "http://127.0.0.1:9/req.jwt";
  let client = test_client("client_secret_basic", Some(json!([uri])));
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: Some(uri),
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected(
      "http request_uri accepted".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn jar_par_request_uri_consumed_once() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let id = unique_par_id();
  let record = ParRecord {
    client_id: CLIENT_ID.to_owned(),
    request: serde_json::to_string(&json!({
      "response_type": "code", "client_id": CLIENT_ID,
      "redirect_uri": "https://client.example.test/cb", "scope": "read",
    }))?,
  };
  par::put(&mut conn, &store, &id, &record, Duration::from_secs(90)).await?;
  let uri = format!("{PAR_REQUEST_URI_PREFIX}{id}");
  let mut query = HashMap::new();
  query.insert("client_id".to_owned(), CLIENT_ID.to_owned());
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: Some(&uri),
  };
  let merged = resolve(&mut conn, &store, &input)
    .await
    .map_err(|error| TestError::Unexpected(error.to_string()))?;
  if merged.get("scope").map(String::as_str) != Some("read") {
    return Err(TestError::Unexpected("PAR params not merged".to_owned()));
  }
  let replay = resolve(&mut conn, &store, &input).await;
  if code_of(&replay) != Some(OAuthErrorCode::InvalidRequest) {
    return Err(TestError::Unexpected("PAR request_uri replayed".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_par_cross_client_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let mut foreign = test_client("client_secret_basic", None);
  foreign.client_id = "jar-foreign-client".to_owned();
  let id = unique_par_id();
  let record = ParRecord {
    client_id: CLIENT_ID.to_owned(),
    request: serde_json::to_string(&json!({"response_type": "code"}))?,
  };
  par::put(&mut conn, &store, &id, &record, Duration::from_secs(90)).await?;
  let uri = format!("{PAR_REQUEST_URI_PREFIX}{id}");
  let query = HashMap::new();
  let input = JarRequest {
    client: &foreign,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: Some(&uri),
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequest) {
    return Err(TestError::Unexpected(
      "cross-client PAR accepted".to_owned(),
    ));
  }
  Ok(())
}

//! `test(cimd_)` suite: strict CIMD fetch/validation rules (offline except
//! the cache round-trip, which uses the shared compose Redis).

use std::{collections::HashSet, time::Duration};

use serde_json::{Value, json};

use super::{
  CimdAuthMethod, CimdDocument, CimdError, CimdLimits, CimdValidation, ValidatedCimd, cache_key,
  fetch_document, get_cached, put_cached, resolve, validate_document,
};
use crate::state::RedisConn;

/// This suite's error type (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

/// Test scaffolding failures.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// An assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// The enabled scope catalog used by the validation tests.
fn scopes() -> HashSet<String> {
  ["profile", "email"]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Build a document value; callers override one member per test.
fn document_value(client_id: &str, redirect_uris: &[&str]) -> Value {
  json!({
    "client_id": client_id,
    "redirect_uris": redirect_uris,
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "scope": "profile",
  })
}

/// Parse a test document.
fn parse(value: Value) -> Result<CimdDocument, TestError> {
  serde_json::from_value(value)
    .map_err(|error| TestError::Unexpected(format!("document parse: {error}")))
}

/// Parse and validate one document, requiring acceptance.
fn expect_ok(
  client_id: &str,
  value: Value,
  enabled_scopes: &HashSet<String>,
  allow_localhost: bool,
) -> Result<ValidatedCimd, TestError> {
  let document = parse(value)?;
  validate_document(
    client_id,
    &document,
    &CimdValidation {
      enabled_scopes,
      allow_localhost,
    },
  )
  .map_err(|error| TestError::Unexpected(format!("{client_id}: rejected ({error})")))
}

/// Parse and validate one document, requiring rejection; returns the error.
fn expect_err(
  client_id: &str,
  value: Value,
  enabled_scopes: &HashSet<String>,
  allow_localhost: bool,
) -> Result<CimdError, TestError> {
  let document = parse(value)?;
  match validate_document(
    client_id,
    &document,
    &CimdValidation {
      enabled_scopes,
      allow_localhost,
    },
  ) {
    Ok(_) => Err(TestError::Unexpected(format!("{client_id}: accepted"))),
    Err(error) => Ok(error),
  }
}

/// The guarded fetcher rejects special-use and private IP literals before any
/// connection is attempted (no DNS, no network I/O).
#[tokio::test]
async fn cimd_rejects_special_use_ip() -> TestResult {
  let limits = CimdLimits {
    max_bytes: 5_120,
    timeout: Duration::from_secs(1),
  };
  for url in [
    "https://127.0.0.1/cimd.json",
    "https://10.0.0.1/cimd.json",
    "https://169.254.169.254/latest/meta-data",
    "https://192.168.1.10/cimd.json",
    "https://[::1]/cimd.json",
  ] {
    match fetch_document(url, limits).await {
      Err(CimdError::Fetch) => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!("{url}: wrong error {other}")));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(format!(
          "{url}: fetched a blocked target"
        )));
      }
    }
  }
  Ok(())
}

/// Empty, wildcarded, non-http(s), and query-bearing redirect URIs are all
/// rejected; the strict redirect matcher is the single authority.
#[test]
fn cimd_rejects_redirect() -> TestResult {
  let enabled = scopes();
  let client_id = "https://client.example/cimd.json";
  for redirects in [
    Vec::<&str>::new(),
    vec!["https://client.example/*"],
    vec!["https://*.client.example/cb"],
    vec!["com.example.app:/cb"],
    vec!["https://client.example/cb?next=1"],
  ] {
    match expect_err(
      client_id,
      document_value(client_id, &redirects),
      &enabled,
      false,
    )? {
      CimdError::InvalidRedirectUri => {}
      other => {
        return Err(TestError::Unexpected(format!(
          "{redirects:?}: wrong error {other}"
        )));
      }
    }
  }
  Ok(())
}

/// CIMD §4.1: every shared-secret and mTLS method is rejected; only `none`
/// and `private_key_jwt` are registration-free-safe.
#[test]
fn cimd_rejects_shared_secret_method() -> TestResult {
  let enabled = scopes();
  let client_id = "https://client.example/cimd.json";
  for method in [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
  ] {
    let mut value = document_value(client_id, &["https://client.example/cb"]);
    value["token_endpoint_auth_method"] = json!(method);
    match expect_err(client_id, value, &enabled, false)? {
      CimdError::UnsupportedAuthMethod => {}
      other => {
        return Err(TestError::Unexpected(format!(
          "{method}: wrong error {other}"
        )));
      }
    }
  }
  Ok(())
}

/// `private_key_jwt` requires an INLINE `jwks`; a `jwks_uri`-only document is
/// rejected so no second fetch ever happens on the auth path.
#[test]
fn cimd_rejects_jwks_uri_only() -> TestResult {
  let enabled = scopes();
  let client_id = "https://client.example/cimd.json";

  let mut remote = document_value(client_id, &["https://client.example/cb"]);
  remote["token_endpoint_auth_method"] = json!("private_key_jwt");
  remote["jwks_uri"] = json!("https://client.example/jwks.json");
  match expect_err(client_id, remote, &enabled, false)? {
    CimdError::JwksUriNotAllowed => {}
    other => {
      return Err(TestError::Unexpected(format!(
        "jwks_uri-only: wrong error {other}"
      )));
    }
  }

  let mut missing = document_value(client_id, &["https://client.example/cb"]);
  missing["token_endpoint_auth_method"] = json!("private_key_jwt");
  match expect_err(client_id, missing, &enabled, false)? {
    CimdError::JwksRequired => {}
    other => {
      return Err(TestError::Unexpected(format!(
        "no jwks: wrong error {other}"
      )));
    }
  }

  let mut inline = document_value(client_id, &["https://client.example/cb"]);
  inline["token_endpoint_auth_method"] = json!("private_key_jwt");
  inline["jwks"] = json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "x", "y": "y" }] });
  let validated = expect_ok(client_id, inline, &enabled, false)?;
  if validated.token_endpoint_auth_method != CimdAuthMethod::PrivateKeyJwt {
    return Err(TestError::Unexpected(
      "inline jwks: wrong auth method".to_owned(),
    ));
  }
  Ok(())
}

/// Plaintext `http` is accepted only for a loopback host; a non-loopback host
/// (and `localhost` with the flag off) is rejected while `https` passes.
#[test]
fn cimd_rejects_non_loopback_http() -> TestResult {
  let enabled = scopes();
  let client_id = "https://client.example/cimd.json";
  for uri in ["http://example.com/cb", "http://localhost/cb"] {
    match expect_err(
      client_id,
      document_value(client_id, &[uri]),
      &enabled,
      false,
    )? {
      CimdError::InvalidRedirectUri => {}
      other => {
        return Err(TestError::Unexpected(format!("{uri}: wrong error {other}")));
      }
    }
  }
  // https is always acceptable, and a loopback literal is acceptable even
  // with the `localhost` flag off.
  for uri in [
    "https://client.example/cb",
    "http://127.0.0.1/cb",
    "http://[::1]/cb",
  ] {
    expect_ok(
      client_id,
      document_value(client_id, &[uri]),
      &enabled,
      false,
    )?;
  }
  Ok(())
}

/// RFC 8252 §7.3 loopback: plaintext `http` to `127.0.0.1`/`[::1]` is always
/// accepted; the exact host `localhost` only while `allow_localhost` is on.
#[test]
fn cimd_accepts_loopback_redirect() -> TestResult {
  let enabled = scopes();
  let client_id = "https://client.example/cimd.json";
  for uri in [
    "http://127.0.0.1/cb",
    "http://127.0.0.1:8080/cb",
    "http://[::1]/cb",
    "http://[::1]:9000/cb",
    "http://localhost/cb",
    "http://localhost:3000/cb",
  ] {
    expect_ok(client_id, document_value(client_id, &[uri]), &enabled, true)?;
  }
  for uri in ["http://localhost/cb", "http://localhost:3000/cb"] {
    match expect_err(
      client_id,
      document_value(client_id, &[uri]),
      &enabled,
      false,
    )? {
      CimdError::InvalidRedirectUri => {}
      other => {
        return Err(TestError::Unexpected(format!("{uri}: wrong error {other}")));
      }
    }
  }
  Ok(())
}

/// The document must echo the fetched URL exactly.
#[test]
fn cimd_rejects_client_id_mismatch() -> TestResult {
  let enabled = scopes();
  let fetched = "https://client.example/cimd.json";
  let document = document_value(
    "https://other.example/cimd.json",
    &["https://other.example/cb"],
  );
  match expect_err(fetched, document, &enabled, false)? {
    CimdError::ClientIdMismatch => Ok(()),
    other => Err(TestError::Unexpected(format!("wrong error {other}"))),
  }
}

/// A validated document is cached under `{state}` `cimd:<sha256>` for 15
/// minutes; `resolve` serves the cached copy without fetching.
#[tokio::test]
async fn cimd_cache_round_trip() -> TestResult {
  let manager = crate::test_support::redis_manager()
    .await
    .map_err(|error| TestError::Unexpected(format!("shared redis: {error}")))?;
  let mut conn = RedisConn::Single(manager);
  let (prefix, _ratelimit) = crate::test_support::unique_prefixes();
  // `.invalid` never resolves, so a cache miss would fail the fetch.
  let url = "https://client.invalid/cimd.json";
  let document = parse(document_value(url, &["https://client.invalid/cb"]))?;

  let key = cache_key(&prefix, url);
  if !key.starts_with(&prefix) || !key.contains("{state}") || !key.contains("cimd:") {
    return Err(TestError::Unexpected(format!("bad cache key {key}")));
  }
  put_cached(&mut conn, &key, &document)
    .await
    .map_err(|error| TestError::Unexpected(format!("cache write: {error}")))?;
  match get_cached(&mut conn, &key)
    .await
    .map_err(|error| TestError::Unexpected(format!("cache read: {error}")))?
  {
    Some(cached) if cached.client_id == url => {}
    Some(_) => return Err(TestError::Unexpected("cached wrong document".to_owned())),
    None => return Err(TestError::Unexpected("cache miss".to_owned())),
  }

  let enabled = scopes();
  let resolved = resolve(
    &mut conn,
    &prefix,
    url,
    &CimdValidation {
      enabled_scopes: &enabled,
      allow_localhost: false,
    },
    CimdLimits {
      max_bytes: 5_120,
      timeout: Duration::from_secs(1),
    },
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("resolve: {error}")))?;
  if resolved.client_id != url {
    return Err(TestError::Unexpected("resolved wrong client".to_owned()));
  }
  Ok(())
}

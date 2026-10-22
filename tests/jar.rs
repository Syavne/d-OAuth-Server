//! `test(jar)` suite, part 1: inline signed request objects (RFC 9101).
//!
//! Valid objects merge over the query; bad signature, wrong `aud`,
//! expiry, `alg:none`, conflicting duplicates, and the JAR/PAR-mandatory
//! rule are covered here. `request_uri` paths live in `jar_request_uri.rs`.

#[path = "jar_support.rs"]
mod support;

use std::collections::HashMap;

use d_oauth::{
  error::OAuthErrorCode,
  jose::jar::{JarRequest, resolve},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use support::{CLIENT_ID, ISSUER, KEY_ID, TestError, TestResult, code_of, store_conn, test_client};
use time::OffsetDateTime;

/// PKCS#8 DER (base64) of the client's RSA signing key (test-only fixture).
const CLIENT_KEY_B64: &str = concat!(
  "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCzwV9fZoba06PGlNq2GXjZ4dZaQDALF6zUCp6kDARqV++kJ43c7u6uULPOweopNeiGk17R8xKk1CMyMbvkbMyLwOmN0ZvxKq+dH1Q/bX6l5OirR26jx8G+vFsGsuRz/zOV",
  "B5PgQ3REhxP6QnxS7rwBcD2QLGO3bBZXLufpXTpiF+IIKwiSdzjdO6ccTZVABCi8LQrENBt/GxmGtA8u5z44SirZohoYOu3LYbROp21TtpfOZgMcyCYOUb+g9A0DNWMc2Xn7645RPdRYQXWAXUG+y+nYWqxevOB5v9SaUYFmnxp23oYzUxrX",
  "gShJhMTAxhgIthmaT0vnrKRPRGvKQcRhAgMBAAECggEAWUTOmt+dWB4jpvJ0nVuQB1Be9coLse6Lf3BYsWpgZPmPwqt8CbzE3t+oNCVcJyQk+nREcipvV1kcs4g8YefgOwVOV4ZBleaXeQW+fpNfgn5oR+s9GGwTHSiIYg7EYpDZ6ohtWUHW",
  "g1O7yZxsBnmV93bos+k/ii9M9vYN6PhKDr0qlX+NKtSZkUxWDvnsfTizkocEBKMGBHLNm6g4KS7N8bClzbgwxCAMLzNtT+/rKEvb6/dQhuSIiVeRlDSDvCaTBdSEqajcoWsrTpzkplb/KbAT8Rkin1KnlQ0s8NHZaC3R/cddvvfJZYgOBDhq",
  "WPW7qNGdzeqb6pevZyS4+LjrcwKBgQD9ZLEo0AlJj9wm243JH0Ob2ubi/wnifa28vg4pEvEXbYhQbLJBJluxn3fQ4LuWObiNwo0SpagOmLScjpqV6mr9/U7/f9BldrKrtPsYDM/JzwzBSox+HgBUvvIgT6Gm3PwCbGfqyLnivFj5PfEoQQ+D",
  "tq+oQjFnnU3gUGo4BGl7QwKBgQC1msGDZdYr4mmaBLXwIsWqJHQ7adogF16xSPRGGUONena5bhrhcPGAKRG+XxCrpV0vQZZ2cY5VXv/K80+RFm+z1fEI+FENiLTxfkj0aE+5FRxViEl6LDJy8oGUk9DSIglcrAd6DzUA9RZnLiqapsP/TQxH",
  "Mh1NmzZ1QO9OD3HdiwKBgQCAb0Mkjp3GfXZ2853gLUqVetTAhci61jzzh9mhlApDd686JH4Na6XaWBvg8afjMwqKP+xFYVXXYCtblyRfjFwCtRwPgPdeFlXllmwW+pdvkNTEPEcNvaMpUUdkfThQXX4WtF/Pr0IY3KK0YmMTpjZ46mYKgNKN",
  "1Due0OOl1QaqBQKBgQCqftge3ITuPmqWRsXo5TxeOEtHXGGEr2wfVTbAeQeK0+aSwGRMMxUIFYarC+VCwMVzkEgKeyH91Gqhxzx0InRMihb5LOgrpKT79GvZyfTO9prbUlBpewUCFdrB+uSZ44qWjouWdKB2faLCy/0DpH1uOo/EZ7BLI+VE",
  "v+nrh2SHcQKBgQD0LMmasHOwG1SFsIObaquSVb6ETbloZ4J1OmpeUrMJEN9TcpY6KbzSrqXl0npSziiUTCE8nQgqDyqCTduhswD413irGN2vIkyfrR2pqBlLOF+INfH0HUQQZLiH6P4L+sFNbeizpHT9qLa5KtBBs9UD40kfZjUPqYMmgA6J",
  "DNOf1Q==",
);

/// PKCS#8 DER (base64) of a foreign RSA key: signatures under it must fail.
const OTHER_KEY_B64: &str = concat!(
  "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDNSLFGmYGgzFFpJ+Pj2p6aTttNl2vG2YRTvfKd45WYGX044GJx8zHwIQuOCSGFtLW92HOdXxsU81na/BXPwIXI4cw97D+y5ufIEo9toJmUcyaPF6JFWLKcqgoJqrci520/",
  "1ovafGYBqL+JyjSKsvZHRH38nHtlzLiPU7fS1NMW1RAnd9smyRRKUK0tawFx+dXyrACuppNFWHGHJZDKsRN8t0z2SOx4RjhLHOGZzw1b9/gJA0ag+1GK4NnzemCd62TM5wSrgXw5IEEJ2NqKfRk54uZCM26DD9moZV3xrqI8OBL8dLbsFie6",
  "/zaxC9UTV0A54h66mxXYhGLdC6tdyNV1AgMBAAECggEAGASaBzBVKA7XtJWv9lwBA/1Xb8HYYIzZDGI0NXBn84KB8epg4kOps1Zub2kWlLnyrJpbVo2G0eHyAKrPU34LORhgCNuwDTqyYih3wwQQC/wYBhRmDjaFOUq0v3JLmIgasmYj+UVm",
  "Oun3NQQlNxges/Jpyik1z9COxGgvYPm5E9nWo+eWSj/iz+slp14KVb/YKtbt0kBtqNKlH8SR8g0JRbt2M7Vs/7bMFX2NqzeiSsj3re73+3abSx1p76bj6YNqCW4nYy/7dVawP8V4f8uXM4TkwexMWqP82PDP01zsEuiKVxFVcF/ogOZ9ZtjX",
  "rRdeTBaOeTDCJVSgqwL3IlXN0QKBgQDwpKR2BADW/2JntB17Bu67g48jRz7xJ54C8fV2ZV7hW6ytFVTUH6LdjK5OR/1oiqZG0lyQcgdDTuUoqdVcphjbnJHt8RNMAG9JkehuUoQq6xPAmYZHs72450kFuQgAKoaDCqOnbHdsHlmpN/hMZmvK",
  "ulOF4bJoZK/7oYlQ8A0JhQKBgQDaYmQ2ExfML3rgZ2BIFYSEMDFIordSWOENvVIIkDTuFiqWBiRSzS5IZY1gq+ToVh0rALGMZN6lb0y+v6WdRAqbY8IPcmlb8FZvnq1MXge0Xr+DUHvdHo1uZ9RlXqlfdc7M9pwzdQ7smK6oNnQctrvjBkBy",
  "Aq0WhF85h6jX1dfnMQKBgQCQENFQwfbKwBvmn+MiWzUjV5Ci+y1IbIJhmv9sASY7XonTGTkuwT3cyzMzNFAWfSMstRWreEi22A3DOWG91MZ++4412CTIVF5LuilfmtD7bL7niEHmvUmw3+5MmcibaNocq4rsWbhpJwZgk1x4SLzxonkMZuFL",
  "NDRTPhMaPIxhjQKBgQDFQ8Ffsyl48J6fG+I12vID8gBiq1DLGqvYHF6Ai7q0IeO/9rZS8TJQhSMK4tr4H+ljEdJPjkIrz/jUCQuRnoeyS49dIq0XNmbtlrjV1c5B2KBH/qiUWWfKBhIuqy51o1X1gQIh3ShpAZYrLlz+HvZjIR+PnOk7AMF/",
  "lxImPO000QKBgQDEwUbOROo7xR5rIB2CFTeg9HK/UyC3EYPZvqq6HBMSRQv6H3eOpu1Oro/5G/AzA9TbFJDUtlvDT+RPxk7uWTjtqoUZpeokpLRpgWhJZNlZUuFmEXZlObrHN4TtLiusU1B4FhCJznUOEpPXkQ02ZpJCV6/vW8MNcMKBUzLp",
  "2J8sJQ==",
);

/// Sign `claims` with the given fixture key under RS256.
fn sign(key_b64: &str, kid: Option<&str>, claims: &Value) -> Result<String, TestError> {
  use base64::{Engine as _, engine::general_purpose::STANDARD};
  let der = STANDARD
    .decode(key_b64)
    .map_err(|_| TestError::Unexpected("fixture key is not decodable".to_owned()))?;
  let pem = format!(
    "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
    STANDARD.encode(&der)
  );
  let mut header = Header::new(Algorithm::RS256);
  header.kid = kid.map(str::to_owned);
  Ok(encode(
    &header,
    claims,
    &EncodingKey::from_rsa_pem(pem.as_bytes())?,
  )?)
}

/// Base request-object claims bound to this suite's client and issuer.
fn base_claims(extra: Value) -> Value {
  let now = OffsetDateTime::now_utc().unix_timestamp();
  let mut claims = json!({
    "iss": CLIENT_ID, "aud": ISSUER, "exp": now + 300,
    "response_type": "code", "client_id": CLIENT_ID,
    "redirect_uri": "https://client.example.test/cb",
    "scope": "read", "state": "xyz",
  });
  if let (Some(into), Some(from)) = (claims.as_object_mut(), extra.as_object()) {
    for (key, value) in from {
      into.insert(key.clone(), value.clone());
    }
  }
  claims
}

#[tokio::test]
async fn jar_valid_signed_request_merged() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let jwt = sign(CLIENT_KEY_B64, Some(KEY_ID), &base_claims(json!({})))?;
  let mut query = HashMap::new();
  query.insert("client_id".to_owned(), CLIENT_ID.to_owned());
  query.insert("state".to_owned(), "xyz".to_owned());
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let merged = resolve(&mut conn, &store, &input)
    .await
    .map_err(|error| TestError::Unexpected(error.to_string()))?;
  if merged.params.get("scope").map(String::as_str) != Some("read")
    || merged.params.get("redirect_uri").map(String::as_str)
      != Some("https://client.example.test/cb")
    || merged.params.get("state").map(String::as_str) != Some("xyz")
  {
    return Err(TestError::Unexpected("merged params mismatch".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_bad_signature_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let jwt = sign(OTHER_KEY_B64, Some(KEY_ID), &base_claims(json!({})))?;
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected("bad signature accepted".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_wrong_aud_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let jwt = sign(
    CLIENT_KEY_B64,
    Some(KEY_ID),
    &base_claims(json!({"aud": "https://other.example.test"})),
  )?;
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected("wrong aud accepted".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_expired_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let now = OffsetDateTime::now_utc().unix_timestamp();
  let jwt = sign(
    CLIENT_KEY_B64,
    Some(KEY_ID),
    &base_claims(json!({"exp": now - 3600})),
  )?;
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected("expired object accepted".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_alg_none_rejected() -> TestResult {
  use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
  let body = URL_SAFE_NO_PAD.encode(r#"{"iss":"jar-test-client"}"#);
  let jwt = format!("{header}.{body}.");
  let query = HashMap::new();
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected("alg:none accepted".to_owned()));
  }
  Ok(())
}

#[tokio::test]
async fn jar_conflicting_duplicates_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let jwt = sign(CLIENT_KEY_B64, Some(KEY_ID), &base_claims(json!({})))?;
  let mut query = HashMap::new();
  query.insert("scope".to_owned(), "write".to_owned());
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: Some(&jwt),
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequestObject) {
    return Err(TestError::Unexpected(
      "conflicting duplicate accepted".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn jar_confidential_client_without_par_or_request_rejected() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("client_secret_basic", None);
  let mut query = HashMap::new();
  query.insert("client_id".to_owned(), CLIENT_ID.to_owned());
  query.insert("response_type".to_owned(), "code".to_owned());
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: None,
  };
  let outcome = resolve(&mut conn, &store, &input).await;
  if code_of(&outcome) != Some(OAuthErrorCode::InvalidRequest) {
    return Err(TestError::Unexpected(
      "plain query accepted for confidential client".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn jar_public_client_without_request_object_uses_query() -> TestResult {
  let (_redis, mut conn, store) = store_conn().await?;
  let client = test_client("none", None);
  let mut query = HashMap::new();
  query.insert("client_id".to_owned(), CLIENT_ID.to_owned());
  query.insert("response_type".to_owned(), "code".to_owned());
  let input = JarRequest {
    client: &client,
    issuer: ISSUER,
    query: &query,
    request: None,
    request_uri: None,
  };
  let merged = resolve(&mut conn, &store, &input)
    .await
    .map_err(|error| TestError::Unexpected(error.to_string()))?;
  if merged.params != query {
    return Err(TestError::Unexpected(
      "public query passthrough altered".to_owned(),
    ));
  }
  if !merged.resource.is_empty() {
    return Err(TestError::Unexpected(
      "plain query must pin no resource".to_owned(),
    ));
  }
  Ok(())
}

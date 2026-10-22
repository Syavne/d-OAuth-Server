//! `test(params)` suite: strict urlencoded parsing, repeated-value capture,
//! transport-contract preservation, and fail-closed resource validation.

use super::{
  MAX_FORM_PAIRS, MAX_RESOURCE_VALUES, RESOURCE_PARAM, form_pairs, has_duplicate_field,
  parse_pairs, query_pairs, require_form_content_type, single_valued_map, validate_resources,
  values_of,
};
use crate::{db::resource_repo, error::OAuthErrorCode};

/// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Repeated `resource` values are captured in order.
#[test]
fn params_repeated_resource_is_captured_in_order() -> TestResult {
  let raw = "client_id=web&resource=https%3A%2F%2Fapi.example.test%2Fa&scope=read&resource=https%3A%2F%2Fapi.example.test%2Fb";
  let pairs = parse_pairs(raw)?;
  let values = values_of(&pairs, RESOURCE_PARAM);
  if values
    != vec![
      "https://api.example.test/a".to_owned(),
      "https://api.example.test/b".to_owned(),
    ]
  {
    return Err(format!("repeated resource order lost: {values:?}").into());
  }
  Ok(())
}

/// A body with more than `MAX_FORM_PAIRS` pairs is rejected, bounding the
/// ~170 MB amplification of a 2 MiB repeated-pair body.
#[test]
fn params_form_pair_cap_rejects_oversized_body() -> TestResult {
  let mut raw = String::new();
  for index in 0..=MAX_FORM_PAIRS {
    if index > 0 {
      raw.push('&');
    }
    raw.push_str("a=1");
  }
  match parse_pairs(&raw) {
    Err(_) => Ok(()),
    Ok(_) => Err("oversized pair body was silently accepted".into()),
  }
}

/// More than `MAX_RESOURCE_VALUES` raw values are `invalid_target`.
#[tokio::test]
async fn params_resource_value_cap_rejects_oversized_set() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  let values: Vec<String> = (0..=MAX_RESOURCE_VALUES)
    .map(|index| format!("https://api.example.test/{index}"))
    .collect();
  match validate_resources(&pool, true, &values).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => Ok(()),
    Err(error) => Err(format!("wrong code for oversized resource set: {}", error.code()).into()),
    Ok(_) => Err("oversized resource set was accepted".into()),
  }
}

/// Duplicate resource values collapse to one sorted output with a single
/// catalog lookup per distinct value.
#[tokio::test]
async fn params_duplicate_resources_deduped_before_catalog() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  resource_repo::upsert(&pool, "https://b.example.test/", "b").await?;
  resource_repo::upsert(&pool, "https://a.example.test/", "a").await?;
  let aud = validate_resources(
    &pool,
    true,
    &[
      "https://b.example.test/".to_owned(),
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
      "https://a.example.test/".to_owned(),
    ],
  )
  .await?;
  if aud
    != vec![
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
    ]
  {
    return Err(format!("duplicates must collapse to one sorted output: {aud:?}").into());
  }
  Ok(())
}

/// A `%00`/NUL resource is `invalid_target`, never a database error or 500.
#[tokio::test]
async fn params_nul_resource_is_invalid_target() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  for value in [
    "https://api.example.test/\0",
    "https://api.example.test/\x01x",
  ] {
    match validate_resources(&pool, true, &[value.to_owned()]).await {
      Err(error) if error.code() == OAuthErrorCode::InvalidTarget => {}
      Err(error) => {
        return Err(format!("wrong code for control-char resource: {}", error.code()).into());
      }
      Ok(_) => return Err(format!("control-char resource accepted: {value:?}").into()),
    }
  }
  Ok(())
}

/// Repeated-resource capture from pre-parsed pairs matches the old behavior:
/// wire order, `+` as space, invalid `%` literal, bare name empty, empty
/// segments skipped, `;` not a separator.
#[test]
fn params_values_of_matches_wire_order() -> TestResult {
  let pairs = parse_pairs(
    "resource=a+b&resource=%ZZ&empty&resource=x%3By&;resource=semi&other=1&resource=last",
  )?;
  let values = values_of(&pairs, RESOURCE_PARAM);
  if values
    != vec![
      "a b".to_owned(),
      "%ZZ".to_owned(),
      "x;y".to_owned(),
      "last".to_owned(),
    ]
  {
    return Err(format!("values_of wire order broken: {values:?}").into());
  }
  if !values_of(&pairs, "missing").is_empty() {
    return Err("unknown name must yield empty".into());
  }
  Ok(())
}

/// The single-valued map is last-wins: duplicates are silently absorbed.
#[test]
fn params_single_valued_map_absorbs_duplicates_last_wins() -> TestResult {
  let pairs = parse_pairs("resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example")?;
  let map = single_valued_map(&pairs);
  if map.get("resource").map(String::as_str) != Some("https://b.example") {
    return Err(format!("last-wins absorption broken: {map:?}").into());
  }
  Ok(())
}

/// Misencoded input decodes lossily, mirroring `serde_urlencoded`: a `%`
/// not followed by two hex digits stays a literal `%` (`%ZZ`, trailing `%`,
/// short `%2`), and non-UTF-8 bytes decode with replacement (`%FF`).
/// Nothing here fails the parse; odd encodings reach typed validation
/// downstream (`unsupported_grant_type`, `invalid_scope`, ...).
#[test]
fn params_malformed_input_fails_strict_parse() -> TestResult {
  let map = single_valued_map(&parse_pairs("a=%ZZ&b=%&c=%2&d=%FF")?);
  if map.get("a").map(String::as_str) != Some("%ZZ") {
    return Err(format!("bare % must stay literal: {map:?}").into());
  }
  if map.get("b").map(String::as_str) != Some("%") {
    return Err(format!("trailing % must stay literal: {map:?}").into());
  }
  if map.get("c").map(String::as_str) != Some("%2") {
    return Err(format!("short % must stay literal: {map:?}").into());
  }
  if map.get("d").map(String::as_str) != Some("�") {
    return Err(format!("non-UTF-8 must decode lossily: {map:?}").into());
  }
  if parse_pairs("a=ok&b=%41").is_err() {
    return Err("well-formed input rejected".into());
  }
  Ok(())
}

/// `+` decodes to a space and a bare key carries an empty value.
#[test]
fn params_plus_and_bare_key_decode() -> TestResult {
  let pairs = parse_pairs("scope=orders+read&flag")?;
  let map = single_valued_map(&pairs);
  if map.get("scope").map(String::as_str) != Some("orders read") {
    return Err(format!("plus decoding broken: {map:?}").into());
  }
  if map.get("flag").map(String::as_str) != Some("") {
    return Err(format!("bare key must carry an empty value: {map:?}").into());
  }
  Ok(())
}

/// Only repeated KNOWN fields count as duplicates; repeated `resource`
/// (unknown to every struct form) is silently absorbed, never rejected.
#[test]
fn params_duplicate_detection_ignores_unknown_resource() -> TestResult {
  let known = ["grant_type", "code"];
  let pairs = parse_pairs(
    "grant_type=code&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example",
  )?;
  if has_duplicate_field(&pairs, &known) {
    return Err("repeated unknown resource must not count as a duplicate".into());
  }
  let pairs = parse_pairs("grant_type=code&grant_type=refresh")?;
  if !has_duplicate_field(&pairs, &known) {
    return Err("repeated known field must count as a duplicate".into());
  }
  Ok(())
}

/// The content-type gate preserves axum's 415 contract for `Bytes` bodies.
#[test]
fn params_content_type_gate_preserves_415() -> TestResult {
  use axum::http::{HeaderMap, header};

  let mut headers = HeaderMap::new();
  if require_form_content_type(&headers).is_ok() {
    return Err("missing content-type must be 415".into());
  }
  headers.insert(header::CONTENT_TYPE, "application/json".parse()?);
  if require_form_content_type(&headers).is_ok() {
    return Err("json content-type must be 415".into());
  }
  headers.insert(
    header::CONTENT_TYPE,
    "application/x-www-form-urlencoded; charset=UTF-8".parse()?,
  );
  require_form_content_type(&headers).map_err(|_| "suffixed urlencoded must pass")?;
  Ok(())
}

/// Only structurally unreadable bodies map to 400 (the `Form` extractor's
/// class): raw non-UTF-8 bytes. Percent-misencodings (`%ZZ`, `%FF`)
/// decode lossily and reach typed validation downstream, never the parse.
#[test]
fn params_malformed_body_is_400_not_silent() -> TestResult {
  use axum::http::StatusCode;

  let (status, _) = match form_pairs(b"a=\xFF") {
    Ok(_) => return Err("non-UTF-8 body was silently accepted".into()),
    Err(reject) => reject,
  };
  if status != StatusCode::BAD_REQUEST {
    return Err(format!("non-UTF-8 body must be 400, got {status}").into());
  }
  if form_pairs(b"grant_type=%ZZ").is_err()
    || form_pairs(b"grant_type=%E0%A4%A").is_err()
    || query_pairs(Some("grant_type=%ZZ")).is_err()
  {
    return Err("misencoded input must decode lossily, not fail the parse".into());
  }
  if form_pairs(b"grant_type=code").is_err() || query_pairs(None).is_err() {
    return Err("well-formed input must parse".into());
  }
  Ok(())
}

/// Flag off + `resource` present is `invalid_target` (fail-closed, no drop).
#[tokio::test]
async fn params_flag_off_with_resource_is_invalid_target() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  match validate_resources(&pool, false, &["https://api.example.test".to_owned()]).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => Ok(()),
    Err(error) => Err(format!("wrong code for flag-off resource: {}", error.code()).into()),
    Ok(_) => Err("flag-off resource was silently accepted".into()),
  }
}

/// Empty input pins an empty set without touching the catalog.
#[tokio::test]
async fn params_empty_input_pins_empty_without_catalog() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  let aud = validate_resources(&pool, true, &[]).await?;
  if !aud.is_empty() {
    return Err(format!("empty input must pin empty, got {aud:?}").into());
  }
  Ok(())
}

/// `http:` and relative values are `invalid_target` (no loopback exception).
#[tokio::test]
async fn params_http_and_relative_resources_are_invalid_target() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  for value in [
    "http://api.example.test/",
    "http://localhost:8080/",
    "https://127.0.0.1/",
    "//api.example.test/",
    "/relative/path",
    "not-a-uri",
  ] {
    match validate_resources(&pool, true, &[value.to_owned()]).await {
      Err(error) if error.code() == OAuthErrorCode::InvalidTarget => {}
      Err(error) => {
        return Err(format!("wrong code for {value}: {}", error.code()).into());
      }
      Ok(_) => return Err(format!("non-https resource accepted: {value}").into()),
    }
  }
  Ok(())
}

/// Unknown and disabled catalog entries are `invalid_target`.
#[tokio::test]
async fn params_unknown_and_disabled_resources_are_invalid_target() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  match validate_resources(&pool, true, &["https://ghost.example.test/".to_owned()]).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => {}
    Err(error) => {
      return Err(format!("wrong code for unknown resource: {}", error.code()).into());
    }
    Ok(_) => return Err("unknown resource was accepted".into()),
  }

  resource_repo::upsert(&pool, "https://api.example.test/", "test api").await?;
  resource_repo::disable(&pool, "https://api.example.test/").await?;
  match validate_resources(&pool, true, &["https://api.example.test/".to_owned()]).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => Ok(()),
    Err(error) => Err(format!("wrong code for disabled resource: {}", error.code()).into()),
    Ok(_) => Err("disabled resource was accepted".into()),
  }
}

/// Two catalog resources validate and pin as a sorted deduped set.
#[tokio::test]
async fn params_two_catalog_resources_pin_sorted_deduped() -> TestResult {
  let (_db, pool) = crate::db::test_support::migrated_pool().await?;
  resource_repo::upsert(&pool, "https://b.example.test/", "b").await?;
  resource_repo::upsert(&pool, "https://a.example.test/", "a").await?;
  let aud = validate_resources(
    &pool,
    true,
    &[
      "https://b.example.test/".to_owned(),
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
    ],
  )
  .await?;
  if aud
    != vec![
      "https://a.example.test/".to_owned(),
      "https://b.example.test/".to_owned(),
    ]
  {
    return Err(format!("sorted deduped set broken: {aud:?}").into());
  }
  Ok(())
}

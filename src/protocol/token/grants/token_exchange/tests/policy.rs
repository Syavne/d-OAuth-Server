//! Policy rejections: unlisted pairs, unsupported types, scope widening.

use super::super::exchange;
use super::{
  Ctx, TestError, TestResult, dpop_proof, input, is_invalid_grant, is_invalid_request,
  is_invalid_scope, mint_subject, service, test_redis, unique,
};
use crate::config::TokenExchangeRule;
use crate::error::AppError;
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::SenderProof;

#[tokio::test]
async fn grant_token_exchange_unlisted_pair_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let subject_client = unique("subject-client");
  let subject_raw = mint_subject(
    &service,
    &mut conn,
    &store,
    &subject_client,
    "user-1",
    "api:read",
    SenderProof::none(),
  )
  .await?;
  let caller_registered = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let allowlist: Vec<TokenExchangeRule> = vec![];
  let proof = dpop_proof("caller-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &proof,
  };
  let error = match exchange(
    &mut conn,
    &store,
    &service,
    &input(
      &unique("unlisted-caller"),
      &subject_raw,
      Some("api:read"),
      &ctx,
    ),
  )
  .await
  {
    Ok(_) => AppError::server_error(),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "unlisted caller to subject pair must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_token_exchange_unsupported_types_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let caller = unique("caller");
  let subject_client = unique("subject-client");
  let subject_raw = mint_subject(
    &service,
    &mut conn,
    &store,
    &subject_client,
    "user-1",
    "api:read",
    SenderProof::none(),
  )
  .await?;
  let caller_registered = ScopeSet::parse("api:read")?;
  let entitled = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let allowlist = vec![TokenExchangeRule {
    caller: caller.clone(),
    subject: subject_client.clone(),
    scopes: vec!["api:read".to_owned()],
  }];
  let proof = dpop_proof("caller-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &proof,
  };
  let mut bad_subject = input(&caller, &subject_raw, Some("api:read"), &ctx);
  bad_subject.subject_token_type = "urn:ietf:params:oauth:token-type:jwt";
  let first = exchange(&mut conn, &store, &service, &bad_subject).await;
  if !first.is_err_and(|error| is_invalid_request(&error)) {
    return Err(TestError::Unexpected(
      "unsupported subject_token_type must be invalid_request".to_owned(),
    ));
  }
  let mut bad_requested = input(&caller, &subject_raw, Some("api:read"), &ctx);
  bad_requested.requested_token_type = Some("urn:ietf:params:oauth:token-type:refresh_token");
  let second = exchange(&mut conn, &store, &service, &bad_requested).await;
  if !second.is_err_and(|error| is_invalid_request(&error)) {
    return Err(TestError::Unexpected(
      "unsupported requested_token_type must be invalid_request".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_token_exchange_scope_widening_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let caller = unique("caller");
  let subject_client = unique("subject-client");
  let subject_raw = mint_subject(
    &service,
    &mut conn,
    &store,
    &subject_client,
    "user-1",
    "api:read",
    SenderProof::none(),
  )
  .await?;
  let caller_registered = ScopeSet::parse("api:read api:admin")?;
  let entitled = ScopeSet::parse("api:read api:admin")?;
  let enabled = ScopeSet::parse("api:read api:admin")?;
  let allowlist = vec![TokenExchangeRule {
    caller: caller.clone(),
    subject: subject_client.clone(),
    scopes: vec!["api:read".to_owned(), "api:admin".to_owned()],
  }];
  let proof = dpop_proof("caller-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &proof,
  };
  let error = match exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &subject_raw, Some("api:admin"), &ctx),
  )
  .await
  {
    Ok(_) => AppError::server_error(),
    Err(error) => error,
  };
  if !is_invalid_scope(&error) {
    return Err(TestError::Unexpected(
      "scope the subject token does not hold must be invalid_scope".to_owned(),
    ));
  }
  Ok(())
}

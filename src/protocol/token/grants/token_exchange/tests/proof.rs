//! Proof rejections: missing proof, subject-`cnf` mismatch, chaining.

use super::super::exchange;
use super::{
  Ctx, TestError, TestResult, dpop_proof, input, is_invalid_grant, mint_subject, service,
  test_redis, unique,
};
use crate::config::TokenExchangeRule;
use crate::error::AppError;
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::SenderProof;

#[tokio::test]
async fn grant_token_exchange_missing_proof_rejected() -> TestResult {
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
    dpop_proof("subject-jkt"),
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
  let no_proof = SenderProof::none();
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &no_proof,
  };
  let error = match exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &subject_raw, Some("api:read"), &ctx),
  )
  .await
  {
    Ok(_) => AppError::server_error(),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "exchange without a fresh proof must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_token_exchange_subject_binding_mismatch_rejected() -> TestResult {
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
    dpop_proof("subject-jkt"),
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
  let wrong_key = dpop_proof("some-other-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &wrong_key,
  };
  let error = match exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &subject_raw, Some("api:read"), &ctx),
  )
  .await
  {
    Ok(_) => AppError::server_error(),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "proof mismatching the subject cnf must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_token_exchange_chained_rejected() -> TestResult {
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
  let allowlist = vec![
    TokenExchangeRule {
      caller: caller.clone(),
      subject: subject_client.clone(),
      scopes: vec!["api:read".to_owned()],
    },
    TokenExchangeRule {
      caller: caller.clone(),
      subject: caller.clone(),
      scopes: vec!["api:read".to_owned()],
    },
  ];
  let proof = dpop_proof("caller-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &proof,
  };
  let first = exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &subject_raw, Some("api:read"), &ctx),
  )
  .await?;
  let chained = exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &first.access_token, Some("api:read"), &ctx),
  )
  .await;
  if !chained.is_err_and(|error| is_invalid_grant(&error)) {
    return Err(TestError::Unexpected(
      "exchanging an exchanged token must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

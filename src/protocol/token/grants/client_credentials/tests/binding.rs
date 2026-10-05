//! Sender-constraint matrix: bound clients need a matching fresh proof.

use super::super::issue_client_credentials;
use super::{
  Ctx, TestError, TestResult, dpop_proof, input, is_invalid_grant, mtls_proof, no_proof, service,
  test_redis, unique,
};
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::ClientKind;

#[tokio::test]
async fn grant_client_credentials_unbound_bearer_ok() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = no_proof();
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let issued =
    issue_client_credentials(&mut conn, &store, &service, &input(&client, None, &ctx)).await?;
  if issued.token_type != "Bearer" || issued.cnf.is_bound() {
    return Err(TestError::Unexpected(
      "an unconstrained confidential client mints an unbound Bearer token".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_dpop_bound_no_proof_rejected() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = no_proof();
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: Some("bound-jkt"),
    mtls_bound: None,
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, None, &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a DPoP-bound client without a proof must not mint".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "missing DPoP proof on a bound client must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_dpop_bound_stale_proof_rejected() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = dpop_proof("some-other-jkt");
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: Some("bound-jkt"),
    mtls_bound: None,
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, None, &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a DPoP-bound client with a stale proof must not mint".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "stale DPoP proof on a bound client must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_dpop_bound_fresh_proof_ok() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = dpop_proof("bound-jkt");
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: Some("bound-jkt"),
    mtls_bound: None,
    proof: &proof,
  };
  let issued =
    issue_client_credentials(&mut conn, &store, &service, &input(&client, None, &ctx)).await?;
  if issued.token_type != "DPoP" {
    return Err(TestError::Unexpected(
      "a DPoP-proven issuance must be a DPoP token".to_owned(),
    ));
  }
  if issued.cnf.jkt.as_deref() != Some("bound-jkt") {
    return Err(TestError::Unexpected(
      "the fresh DPoP proof must propagate into cnf".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_mtls_bound_no_proof_rejected() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = no_proof();
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: Some("bound-x5t"),
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, None, &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "an mTLS-bound client without a proof must not mint".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "missing mTLS proof on a bound client must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_mtls_bound_stale_proof_rejected() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = mtls_proof("some-other-x5t");
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: Some("bound-x5t"),
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, None, &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "an mTLS-bound client with a stale proof must not mint".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(
      "stale mTLS proof on a bound client must be invalid_grant".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_mtls_bound_fresh_proof_ok() -> TestResult {
  let (_lease, mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = mtls_proof("bound-x5t");
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: Some("bound-x5t"),
    proof: &proof,
  };
  let issued =
    issue_client_credentials(&mut conn, &store, &service, &input(&client, None, &ctx)).await?;
  if issued.cnf.x5t_s256.as_deref() != Some("bound-x5t") {
    return Err(TestError::Unexpected(
      "the fresh mTLS proof must propagate into cnf".to_owned(),
    ));
  }
  if issued.token_type != "Bearer" {
    return Err(TestError::Unexpected(
      "an mTLS-only issuance stays a Bearer token".to_owned(),
    ));
  }
  Ok(())
}

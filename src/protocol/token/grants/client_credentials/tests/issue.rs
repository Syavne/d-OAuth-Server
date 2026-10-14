//! Happy path, client-kind, scope, and no-refresh coverage.

use super::super::issue_client_credentials;
use super::{
  ClientCredentialsTokens, Ctx, TestError, TestResult, dpop_proof, input, is_invalid_client,
  is_invalid_scope, no_proof, service, test_redis, unique,
};
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::ClientKind;

#[tokio::test]
async fn grant_client_credentials_valid_issue() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read api:write")?;
  let enabled = ScopeSet::parse("api:read api:write")?;
  let proof = no_proof();
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let issued = issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, Some("api:read"), &ctx),
  )
  .await?;
  if issued.access_token.is_empty() || issued.access_hash.is_empty() {
    return Err(TestError::Unexpected(
      "issued access token must be non-empty".to_owned(),
    ));
  }
  if issued.token_type != "Bearer" {
    return Err(TestError::Unexpected(
      "unbound confidential issuance must be Bearer".to_owned(),
    ));
  }
  if issued.scope != "api:read" {
    return Err(TestError::Unexpected(
      "issued scope must echo the narrowed request".to_owned(),
    ));
  }
  if issued.cnf.is_bound() {
    return Err(TestError::Unexpected(
      "unbound issuance must carry an empty cnf".to_owned(),
    ));
  }
  let found = service
    .find_access(&mut conn, &store, &issued.access_token)
    .await?;
  let record = found.ok_or_else(|| {
    TestError::Unexpected("issued access token must resolve in the store".to_owned())
  })?;
  if !record.record.subject.is_empty() {
    return Err(TestError::Unexpected(
      "client-credentials tokens must carry no user subject".to_owned(),
    ));
  }
  if record.record.scope != "api:read" {
    return Err(TestError::Unexpected(
      "stored scope must match the issued scope".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_default_scope_narrows_to_registry() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read api:write")?;
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
  if issued.scope != "api:read" {
    return Err(TestError::Unexpected(
      "omitted scope must default to registered narrowed by the catalog".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_public_client_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("public");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read")?;
  let proof = dpop_proof("public-jkt");
  let ctx = Ctx {
    kind: ClientKind::Public,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, Some("api:read"), &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "public clients must not use client_credentials".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_client(&error) {
    return Err(TestError::Unexpected(
      "public client_credentials must be invalid_client".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_over_scope_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let client = unique("m2m");
  let registered = ScopeSet::parse("api:read")?;
  let enabled = ScopeSet::parse("api:read api:admin")?;
  let proof = no_proof();
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let error = match issue_client_credentials(
    &mut conn,
    &store,
    &service,
    &input(&client, Some("api:admin"), &ctx),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "scope beyond the registry must not issue".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_scope(&error) {
    return Err(TestError::Unexpected(
      "over-scope client_credentials must be invalid_scope".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_client_credentials_no_refresh_token() -> TestResult {
  let (mut conn, store) = test_redis().await?;
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
  let issued: ClientCredentialsTokens =
    issue_client_credentials(&mut conn, &store, &service, &input(&client, None, &ctx)).await?;
  let members: Vec<String> = redis::cmd("SMEMBERS")
    .arg(store.grant_tokens_key(&issued.grant_id))
    .query_async(&mut conn)
    .await?;
  if members != vec![issued.access_hash.clone()] {
    return Err(TestError::Unexpected(
      "grant set must hold only the access hash: no refresh was issued".to_owned(),
    ));
  }
  Ok(())
}

//! Fresh proof-of-possession: absent or mismatched proofs are rejected.

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_grant, mint_grant, mtls_proof, service,
  test_redis,
};
use crate::protocol::{
  scope::ScopeSet,
  token::{ClientKind, SenderProof, grants::refresh_token::refresh},
};

/// A public client presenting no `DPoP` proof is rejected.
#[tokio::test]
async fn grant_refresh_public_proof_required() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("nopublic-client");
  let proof = dpop_proof(&super::unique("nopublic-jkt"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;
  let bare = SenderProof::none();

  let rejected = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &bare,
      &enabled,
    ),
  )
  .await;
  let error = match rejected {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "proof-less refresh rotated".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "no-proof code: {}",
      error.code()
    )));
  }
  Ok(())
}

/// A public client presenting a mismatched `DPoP` key is rejected.
#[tokio::test]
async fn grant_refresh_public_proof_mismatch_rejected() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("badpublic-client");
  let proof = dpop_proof(&super::unique("badpublic-jkt"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof,
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;
  let wrong = dpop_proof(&super::unique("badpublic-other-jkt"));

  let rejected = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &wrong,
      &enabled,
    ),
  )
  .await;
  let error = match rejected {
    Ok(_) => return Err(TestError::Unexpected("mismatched proof rotated".to_owned())),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "mismatch code: {}",
      error.code()
    )));
  }
  Ok(())
}

/// An `mTLS`-bound grant presented with the wrong certificate is rejected.
#[tokio::test]
async fn grant_refresh_mtls_mismatch_rejected() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("mtls-client");
  let bound = mtls_proof(&super::unique("mtls-thumbprint"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Confidential,
    "read",
    bound,
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;
  let wrong = mtls_proof(&super::unique("mtls-other-thumbprint"));

  let rejected = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Confidential,
      &minted.refresh_token,
      None,
      &wrong,
      &enabled,
    ),
  )
  .await;
  let error = match rejected {
    Ok(_) => return Err(TestError::Unexpected("mismatched mTLS rotated".to_owned())),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "mtls code: {}",
      error.code()
    )));
  }
  Ok(())
}

/// An `mTLS`-bound grant presented with the matching certificate rotates.
#[tokio::test]
async fn grant_refresh_mtls_match_rotates() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = super::unique("mtls-ok-client");
  let bound = mtls_proof(&super::unique("mtls-ok-thumbprint"));
  let minted = mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Confidential,
    "read",
    bound.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  let rotated = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Confidential,
      &minted.refresh_token,
      None,
      &bound,
      &enabled,
    ),
  )
  .await?;
  if rotated.token_type != "Bearer" {
    return Err(TestError::Unexpected(format!(
      "token_type: {}",
      rotated.token_type
    )));
  }
  Ok(())
}

//! `test(jwt_mint_revoke_race_no_bypass)`: a freshly minted JWT passes the
//! strict allowlist check (marker present plus grant membership), while a
//! late marker written after the grant cascade reports inactive — the
//! forbidden marker-after-`SADD` ordering can never smuggle a token past
//! the membership-bound liveness check (RFC 9068 §2.2/§4).

use secrecy::SecretString;

use super::{TestError, TestResult, mint_request, ring, test_redis, unique};
use crate::{
  config::{JwtSigningAlg, JwtSigningKey, TtlConfig},
  error::{AppError, OAuthErrorCode},
  jose::jwt_access::{JwtAccessSigner, jti_hash, marker_live, marker_live_strict},
  keys::KeyId,
  protocol::token::{ClientKind, SenderProof, TokenFormat, TokenService, TokenServiceError},
};

/// A fixed 32-byte ASCII signing key (the e2e JWT fixture material).
const JWT_TEST_KEY: &str = "bcdefghijklmnopqrstuvwxyzabcdefg";

/// Issuer the test signer asserts.
const TEST_ISSUER: &str = "https://jwt-test.example.test";

/// A test signer over the fixed key material.
fn test_signer() -> Result<JwtAccessSigner, TestError> {
  let raw = SecretString::from(JWT_TEST_KEY);
  let key = JwtSigningKey::from_raw(
    KeyId::new("test-kid"),
    JwtSigningAlg::Es256,
    &raw,
    "jwt_signing_key",
  )
  .map_err(|error| TestError::Unexpected(format!("signing key rejected: {error}")))?;
  Ok(JwtAccessSigner::new(
    TEST_ISSUER.to_owned(),
    key,
    Vec::new(),
  ))
}

/// A service wired with the JWT signer.
fn jwt_service(signer: JwtAccessSigner) -> Result<TokenService, TestError> {
  TokenService::new(&TtlConfig::default(), &ring(&[("v1", "jwt-race-pepper")])?)
    .map_err(TestError::from)
    .map(|service| service.with_jwt_signer(signer))
}

/// Fresh mint: marker plus grant membership both live, so the token is
/// strictly live; after the cascade plus a manually re-written late marker,
/// the membership is gone and the token is strictly inactive even though the
/// marker hash itself exists again.
#[tokio::test]
async fn jwt_mint_revoke_race_no_bypass() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let client = unique("jwt-race-client");
  let grant = unique("jwt-race-grant");
  let mut request = mint_request(
    &client,
    ClientKind::Confidential,
    &grant,
    SenderProof::none(),
  );
  request.format = TokenFormat::Jwt;
  request.aud = vec!["https://api.example.test/".to_owned()];
  request.refresh_aud = request.aud.clone();
  let minted = service
    .mint(&mut conn, &store, &request, super::now_unix())
    .await?;
  if minted.access_token.split('.').count() != 3 {
    return Err(TestError::Unexpected(
      "a jwt mint must return three JOSE segments".to_owned(),
    ));
  }
  let verified = signer
    .verify(&minted.access_token, Some(&request.aud))
    .map_err(|error| TestError::Unexpected(format!("fresh jwt rejected: {error:?}")))?;
  if verified.claims.aud != request.aud {
    return Err(TestError::Unexpected(format!(
      "aud must be {:?}, got {:?}",
      request.aud, verified.claims.aud
    )));
  }
  let hash = jti_hash(&verified.claims.jti);
  let member = format!("jwt:{hash}");
  if !marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the fresh mint must leave a live marker".to_owned(),
    ));
  }
  if !marker_live_strict(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the fresh mint must be strictly live (marker plus membership)".to_owned(),
    ));
  }

  // Revoke the grant chain (the cascade wipes records and members), then
  // simulate the forbidden late marker write: correct fields, fresh TTL, but
  // no grant-set membership behind it.
  let _ = service.revoke_grant(&mut conn, &store, &grant).await?;
  let marker_key = store.jwt_marker_key(&hash);
  let _: () = redis::cmd("HSET")
    .arg(&marker_key)
    .arg("grant_id")
    .arg(&grant)
    .arg("client_id")
    .arg(&client)
    .arg("subject")
    .arg("user-1")
    .query_async(&mut conn)
    .await?;
  let _: () = redis::cmd("PEXPIRE")
    .arg(&marker_key)
    .arg(300_000_i64)
    .query_async(&mut conn)
    .await?;
  // The orphan marker hash exists, so the marker-only check still fires: the
  // hazard this test pins is real.
  if !marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the late marker write must land for the race to be meaningful".to_owned(),
    ));
  }
  // But the membership-bound check reports inactive: no `SADD` backs the
  // late marker, so the token cannot bypass revocation.
  if marker_live_strict(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "a late marker without grant membership must report inactive".to_owned(),
    ));
  }
  let member_present: bool = redis::cmd("SISMEMBER")
    .arg(store.grant_tokens_key(&grant))
    .arg(&member)
    .query_async(&mut conn)
    .await?;
  if member_present {
    return Err(TestError::Unexpected(
      "the cascade must have removed the grant-set member".to_owned(),
    ));
  }
  Ok(())
}

/// `test(jwt_cascade_revoke_deletes_marker)`: the grant cascade deletes the
/// LITERAL `jwt:<jti-hash>` marker hash, not merely the grant-set member.
///
/// The access record for a JWT lives at `access:jwt:<jti-hash>`, so the
/// existing `access:`-prefix concatenation already deletes it; the marker is
/// a separate `{state}jwt:<jti-hash>` hash that only the third Lua ARGV
/// reaches. The test pins the literal key (read from the marker helper, the
/// same `token_key` path the mint uses): after `revoke_grant` the key must be
/// GONE (`EXISTS == 0`), and both the marker-only and the membership-bound
/// liveness checks must report inactive.
#[tokio::test]
async fn jwt_cascade_revoke_deletes_marker() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer.clone())?;
  let client = unique("jwt-cascade-marker-client");
  let grant = unique("jwt-cascade-marker-grant");
  let mut request = mint_request(
    &client,
    ClientKind::Confidential,
    &grant,
    SenderProof::none(),
  );
  request.format = TokenFormat::Jwt;
  request.aud = vec!["https://api.example.test/".to_owned()];
  request.refresh_aud = request.aud.clone();
  // Empty subject keeps the liveness verdict on the marker alone (no account
  // lookup), so the assertion pins exactly the allowlist behavior.
  request.subject = String::new();
  let minted = service
    .mint(&mut conn, &store, &request, super::now_unix())
    .await?;
  let verified = signer
    .verify(&minted.access_token, Some(&request.aud))
    .map_err(|error| TestError::Unexpected(format!("fresh jwt rejected: {error:?}")))?;
  let hash = jti_hash(&verified.claims.jti);
  let marker_key = store.jwt_marker_key(&hash);
  let marker_live_before: bool = marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?;
  if !marker_live_before {
    return Err(TestError::Unexpected(
      "the fresh mint must leave a live marker".to_owned(),
    ));
  }

  let _ = service.revoke_grant(&mut conn, &store, &grant).await?;

  // The LITERAL marker key must be gone: member-set absence alone would still
  // leave a live hash behind.
  let marker_exists: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut conn)
    .await?;
  if marker_exists {
    return Err(TestError::Unexpected(format!(
      "the cascade must delete the literal marker key {marker_key}"
    )));
  }
  let member_present: bool = redis::cmd("SISMEMBER")
    .arg(store.grant_tokens_key(&grant))
    .arg(format!("jwt:{hash}"))
    .query_async(&mut conn)
    .await?;
  if member_present {
    return Err(TestError::Unexpected(
      "the cascade must have removed the jwt grant-set member".to_owned(),
    ));
  }
  let live_after: bool = marker_live(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("marker check failed: {error:?}")))?;
  if live_after {
    return Err(TestError::Unexpected(
      "the marker must read dead after the cascade".to_owned(),
    ));
  }
  let strict_after: bool = marker_live_strict(&mut conn, &store, &hash)
    .await
    .map_err(|error| TestError::Unexpected(format!("strict check failed: {error:?}")))?;
  if strict_after {
    return Err(TestError::Unexpected(
      "the membership-bound check must read dead after the cascade".to_owned(),
    ));
  }
  // The cascade revokes liveness, not the signature: the token must still
  // parse and verify while both liveness checks report dead.
  signer
    .verify(&minted.access_token, Some(&request.aud))
    .map_err(|error| TestError::Unexpected(format!("signature check failed: {error:?}")))?;
  Ok(())
}

/// `test(jwt_mint_rejects_empty_audience)`: `mint_jwt` with an empty `aud`
/// fails with `EmptyAudience` before signing or writing anything, and the
/// error maps to `invalid_target` (HTTP 400), never `server_error`.
#[tokio::test]
async fn jwt_mint_rejects_empty_audience() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let signer = test_signer()?;
  let service = jwt_service(signer)?;
  let client = unique("jwt-empty-aud-client");
  let grant = unique("jwt-empty-aud-grant");
  let mut request = mint_request(
    &client,
    ClientKind::Confidential,
    &grant,
    SenderProof::none(),
  );
  request.format = TokenFormat::Jwt;
  request.aud = Vec::new();
  request.refresh_aud = Vec::new();
  match service
    .mint(&mut conn, &store, &request, super::now_unix())
    .await
  {
    Err(TokenServiceError::EmptyAudience) => {}
    Err(other) => {
      return Err(TestError::Unexpected(format!(
        "empty-audience jwt mint must be EmptyAudience, got {other}"
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "an empty-audience jwt mint must never succeed".to_owned(),
      ));
    }
  }
  let mapped = AppError::from(TokenServiceError::EmptyAudience);
  if mapped.code() != OAuthErrorCode::InvalidTarget {
    return Err(TestError::Unexpected(format!(
      "EmptyAudience must map to invalid_target, got {}",
      mapped.code()
    )));
  }
  if mapped.status() != axum::http::StatusCode::BAD_REQUEST {
    return Err(TestError::Unexpected(format!(
      "EmptyAudience must render 400, got {}",
      mapped.status()
    )));
  }
  if mapped.description() != "jwt access tokens require a resource audience" {
    return Err(TestError::Unexpected(format!(
      "EmptyAudience description mismatch: {}",
      mapped.description()
    )));
  }
  Ok(())
}

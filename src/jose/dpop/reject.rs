//! `test(dpop)` rejection suite: binding, freshness, and shape.
//!
//! Every invalid proof maps to `invalid_dpop_proof` and never reaches the
//! replay store.

use super::{
  DpopRequest,
  support::{
    TEST_HTM, TEST_HTU, TestResult, assert_invalid, fresh_es256_key, mint_proof, now_unix,
    test_redis, unique_jti, valid_params,
  },
  verify_dpop,
};

/// A proof bound to one method does not verify for another.
#[tokio::test]
async fn dpop_tampered_htm_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let proof = mint_proof(&valid_params(
    &key.encoding,
    key.jwk.clone(),
    &unique_jti(),
    now,
  ))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: "GET",
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// A proof bound to one URI does not verify for another.
#[tokio::test]
async fn dpop_htu_mismatch_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let proof = mint_proof(&valid_params(
    &key.encoding,
    key.jwk.clone(),
    &unique_jti(),
    now,
  ))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: "https://as.example.test/other",
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// A proof `htu` carrying a query string is malformed (RFC 9449 §4.2).
#[tokio::test]
async fn dpop_htu_with_query_in_proof_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let jti = unique_jti();
  let base = valid_params(&key.encoding, key.jwk.clone(), &jti, now);
  let proof = mint_proof(&super::support::ProofParams {
    htu: "https://as.example.test/token?code=abc",
    ..base
  })?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// A long-dead proof is rejected by the freshness window.
#[tokio::test]
async fn dpop_stale_iat_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let proof = mint_proof(&valid_params(
    &key.encoding,
    key.jwk.clone(),
    &unique_jti(),
    now - 3_600,
  ))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// A proof from the far future is rejected despite clock-skew tolerance.
#[tokio::test]
async fn dpop_future_iat_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let proof = mint_proof(&valid_params(
    &key.encoding,
    key.jwk.clone(),
    &unique_jti(),
    now + 3_600,
  ))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// A missing proof (no `DPoP` header) is `invalid_dpop_proof`, not silent.
#[tokio::test]
async fn dpop_missing_proof_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let request = DpopRequest {
    proof: None,
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now_unix(),
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// Only the exact `dpop+jwt` type is accepted.
#[tokio::test]
async fn dpop_wrong_or_missing_typ_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  for typ in [Some("jwt"), Some("dpop"), None] {
    let jti = unique_jti();
    let base = valid_params(&key.encoding, key.jwk.clone(), &jti, now);
    let proof = mint_proof(&super::support::ProofParams { typ, ..base })?;
    let request = DpopRequest {
      proof: Some(&proof),
      htm: TEST_HTM,
      htu: TEST_HTU,
      access_token: None,
      now_unix: now,
    };
    assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  }
  Ok(())
}

/// A proof without an embedded JWK leaves nothing to verify against.
#[tokio::test]
async fn dpop_missing_jwk_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let jti = unique_jti();
  let base = valid_params(&key.encoding, key.jwk.clone(), &jti, now);
  let proof = mint_proof(&super::support::ProofParams { jwk: None, ..base })?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// Oversized and misshapen inputs are rejected before any crypto runs.
#[tokio::test]
async fn dpop_malformed_shape_rejected() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let now = now_unix();
  let big = "p".repeat(super::MAX_PROOF_LEN + 1);
  for proof in ["not-a-jwt", "a.b", "a.b.c.d", "", big.as_str()] {
    let request = DpopRequest {
      proof: Some(proof),
      htm: TEST_HTM,
      htu: TEST_HTU,
      access_token: None,
      now_unix: now,
    };
    assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  }
  Ok(())
}

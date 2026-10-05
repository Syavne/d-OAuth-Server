//! `test(dpop)` accept-path suite: valid proofs, freshness window, replay,
//! the RFC 7638 vector, and resource-bound `ath`.

use serde_json::Value;

use super::{
  DPOP_FUTURE_SKEW_SECS, DPOP_IAT_WINDOW_SECS, DpopRequest,
  support::{
    TEST_HTM, TEST_HTU, TestResult, assert_invalid, ath_of, fresh_es256_key, mint_proof, now_unix,
    test_redis, unique_jti, valid_params,
  },
  verify_dpop,
};
use crate::jose::jwk::thumbprint;

/// A valid proof verifies and returns the proof-key thumbprint as `jkt`.
#[tokio::test]
async fn dpop_valid_proof_accepted_returns_bound_jkt() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let jti = unique_jti();
  let proof = mint_proof(&valid_params(&key.encoding, key.jwk.clone(), &jti, now))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  let verified = verify_dpop(&mut conn, &store, &request).await?;
  assert_eq!(verified.jkt, thumbprint(&key.jwk)?);
  assert_eq!(verified.jti, jti);
  assert_eq!(verified.iat, now);
  Ok(())
}

/// The RFC 7638 §3.1 RSA vector pins the canonical form, member order, and
/// base64url digest assumed by every `jkt` comparison.
#[test]
fn dpop_rfc7638_thumbprint_vector() -> TestResult {
  let jwk: Value = serde_json::from_str(
    r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#,
  )?;
  assert_eq!(
    thumbprint(&jwk)?,
    "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  );
  Ok(())
}

/// The freshness window edges are exact: the oldest and newest tolerable
/// `iat` values verify, one second beyond either side is rejected.
#[tokio::test]
async fn dpop_iat_window_boundaries_enforced() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  for offset in [-DPOP_IAT_WINDOW_SECS, DPOP_FUTURE_SKEW_SECS] {
    let jti = unique_jti();
    let proof = mint_proof(&valid_params(
      &key.encoding,
      key.jwk.clone(),
      &jti,
      now + offset,
    ))?;
    let request = DpopRequest {
      proof: Some(&proof),
      htm: TEST_HTM,
      htu: TEST_HTU,
      access_token: None,
      now_unix: now,
    };
    verify_dpop(&mut conn, &store, &request).await?;
  }
  for offset in [-DPOP_IAT_WINDOW_SECS - 1, DPOP_FUTURE_SKEW_SECS + 1] {
    let jti = unique_jti();
    let proof = mint_proof(&valid_params(
      &key.encoding,
      key.jwk.clone(),
      &jti,
      now + offset,
    ))?;
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

/// The second presentation of a proof loses the `jti` race and is rejected.
#[tokio::test]
async fn dpop_replayed_jti_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let jti = unique_jti();
  let proof = mint_proof(&valid_params(&key.encoding, key.jwk.clone(), &jti, now))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: None,
    now_unix: now,
  };
  verify_dpop(&mut conn, &store, &request).await?;
  assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  Ok(())
}

/// Resource-bound use: a proof carrying the access-token hash verifies when
/// the token matches.
#[tokio::test]
async fn dpop_ath_bound_access_accepted() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let token = "dpop-test-access-token";
  let jti = unique_jti();
  let params = valid_params(&key.encoding, key.jwk.clone(), &jti, now);
  let proof = mint_proof(&super::support::ProofParams {
    ath: Some(&ath_of(token)),
    ..params
  })?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: TEST_HTU,
    access_token: Some(token),
    now_unix: now,
  };
  let verified = verify_dpop(&mut conn, &store, &request).await?;
  assert_eq!(verified.jkt, thumbprint(&key.jwk)?);
  Ok(())
}

/// The server strips query and fragment from its own request URI, so a
/// token-endpoint call with parameters still matches a canonical proof.
#[tokio::test]
async fn dpop_htu_query_stripped_server_side_accepted() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let jti = unique_jti();
  let proof = mint_proof(&valid_params(&key.encoding, key.jwk.clone(), &jti, now))?;
  let request = DpopRequest {
    proof: Some(&proof),
    htm: TEST_HTM,
    htu: "https://as.example.test/token?extra=1#frag",
    access_token: None,
    now_unix: now,
  };
  verify_dpop(&mut conn, &store, &request).await?;
  Ok(())
}

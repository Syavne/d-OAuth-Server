//! `test(dpop)` key/algorithm rejection suite: `none`, HMAC, key
//! confusion, private material, symmetric JWKs, and `ath` binding.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::Value;

use super::{
  DPOP_TYP, DpopRequest,
  support::{
    TEST_HTM, TEST_HTU, TestError, TestResult, assert_invalid, ath_of, fresh_es256_key, mint_proof,
    now_unix, test_redis, unique_jti, valid_params,
  },
  verify_dpop,
};

/// `alg:none` never verifies, even with well-formed claims.
#[tokio::test]
async fn dpop_alg_none_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let header =
    URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": "none", "typ": DPOP_TYP}).to_string());
  let payload = URL_SAFE_NO_PAD.encode(
    serde_json::json!({
      "htm": TEST_HTM,
      "htu": TEST_HTU,
      "iat": now,
      "jti": unique_jti(),
      "jwk": key.jwk,
    })
    .to_string(),
  );
  let proof = format!("{header}.{payload}.");
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

/// HMAC proofs are rejected at the allowlist, before any key is built.
#[tokio::test]
async fn dpop_hmac_alg_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let mut header = Header::new(Algorithm::HS256);
  header.typ = Some(DPOP_TYP.to_owned());
  let claims = serde_json::json!({
    "htm": TEST_HTM,
    "htu": TEST_HTU,
    "iat": now,
    "jti": unique_jti(),
    "jwk": key.jwk,
  });
  let proof = encode(&header, &claims, &EncodingKey::from_secret(b"hmac-only"))?;
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

/// A proof is verified against its embedded JWK: signing with one key while
/// embedding another fails the signature check.
#[tokio::test]
async fn dpop_jwk_signature_mismatch_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let signer = fresh_es256_key()?;
  let embedded = fresh_es256_key()?;
  let now = now_unix();
  let proof = mint_proof(&valid_params(
    &signer.encoding,
    embedded.jwk,
    &unique_jti(),
    now,
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

/// A JWK smuggling private material is refused before signature work.
#[tokio::test]
async fn dpop_private_jwk_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let mut evil = key.jwk.clone();
  match evil.as_object_mut() {
    Some(map) => {
      map.insert(
        "d".to_owned(),
        Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
      );
    }
    None => {
      return Err(TestError::Unexpected(
        "test jwk is not an object".to_owned(),
      ));
    }
  }
  let proof = mint_proof(&valid_params(&key.encoding, evil, &unique_jti(), now))?;
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

/// Symmetric JWKs have no place in `DPoP` and are refused outright.
#[tokio::test]
async fn dpop_oct_jwk_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let oct = serde_json::json!({"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"});
  let proof = mint_proof(&valid_params(&key.encoding, oct, &unique_jti(), now))?;
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

/// Resource-bound use requires the exact access-token hash: a wrong or
/// absent `ath` is rejected when a token is presented.
#[tokio::test]
async fn dpop_ath_mismatch_rejected() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let key = fresh_es256_key()?;
  let now = now_unix();
  let token = "dpop-test-access-token";
  let wrong = ath_of("another-token");
  for ath in [Some(wrong.as_str()), None] {
    let jti = unique_jti();
    let base = valid_params(&key.encoding, key.jwk.clone(), &jti, now);
    let proof = mint_proof(&super::support::ProofParams { ath, ..base })?;
    let request = DpopRequest {
      proof: Some(&proof),
      htm: TEST_HTM,
      htu: TEST_HTU,
      access_token: Some(token),
      now_unix: now,
    };
    assert_invalid(verify_dpop(&mut conn, &store, &request).await)?;
  }
  Ok(())
}

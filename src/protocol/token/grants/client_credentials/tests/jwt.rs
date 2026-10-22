//! `test(jwt_mint_carries_aud_and_cnf)`: the client-credentials grant with
//! `TokenFormat::Jwt` mints a real RFC 9068 access token bound to the
//! request audience and the fresh DPoP proof (RFC 9068 §2.1/§2.2/§4,
//! RFC 8707 §2).

use jsonwebtoken::{Algorithm, decode_header};
use secrecy::SecretString;

use super::super::issue_client_credentials;
use super::{Ctx, TestError, TestResult, dpop_proof, ring, test_redis, unique};
use crate::{
  config::{JwtSigningAlg, JwtSigningKey, TtlConfig},
  error::OAuthErrorCode,
  jose::jwt_access::{JwtAccessSigner, jti_hash, marker_live},
  keys::KeyId,
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, TokenFormat, TokenService},
  },
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

/// The grant mints a signed JWT (not an opaque token) carrying the request
/// audience and the proven `cnf.jkt`: header `typ`/`kid`/`alg`, `client_id`,
/// `scope`, `aud == [A, B]`, `jti` non-empty, and `exp - iat == access_ttl`.
#[tokio::test]
async fn jwt_mint_carries_aud_and_cnf() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let signer = test_signer()?;
  let service = TokenService::new(&TtlConfig::default(), &ring()?)
    .map_err(TestError::from)?
    .with_jwt_signer(signer.clone());
  let client = unique("jwt-cc");
  let registered = ScopeSet::parse("read")?;
  let enabled = ScopeSet::parse("read")?;
  let proof = dpop_proof("jwt-mint-test-jkt");
  let aud = vec![
    "https://rs-a.example.test/api".to_owned(),
    "https://rs-b.example.test/api".to_owned(),
  ];
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let mut inputs = super::input(&client, None, &ctx);
  inputs.aud = &aud;
  inputs.token_format = TokenFormat::Jwt;
  let issued = issue_client_credentials(&mut conn, &store, &service, &inputs).await?;

  if issued.access_token.split('.').count() != 3 {
    return Err(TestError::Unexpected(
      "a jwt mint must return three JOSE segments".to_owned(),
    ));
  }
  if issued.token_type != "DPoP" {
    return Err(TestError::Unexpected(format!(
      "a jkt-bound jwt mint must be DPoP, got {}",
      issued.token_type
    )));
  }
  let header = decode_header(&issued.access_token)
    .map_err(|error| TestError::Unexpected(format!("header undecodable: {error}")))?;
  if header.typ.as_deref() != Some("at+jwt") {
    return Err(TestError::Unexpected("header typ is not at+jwt".to_owned()));
  }
  if header.kid.as_deref() != Some("test-kid") {
    return Err(TestError::Unexpected(
      "header kid is not the test key".to_owned(),
    ));
  }
  if header.alg != Algorithm::ES256 {
    return Err(TestError::Unexpected("header alg is not ES256".to_owned()));
  }
  let verified = signer
    .verify(&issued.access_token, Some(&aud))
    .map_err(|error| TestError::Unexpected(format!("jwt rejected: {error:?}")))?;
  if verified.claims.aud != aud {
    return Err(TestError::Unexpected(format!(
      "aud must be [A, B], got {:?}",
      verified.claims.aud
    )));
  }
  if verified
    .claims
    .cnf
    .as_ref()
    .and_then(|cnf| cnf.jkt.as_deref())
    != Some("jwt-mint-test-jkt")
  {
    return Err(TestError::Unexpected(
      "cnf.jkt must carry the proven thumbprint".to_owned(),
    ));
  }
  if verified.claims.client_id != client {
    return Err(TestError::Unexpected(
      "client_id did not survive the round-trip".to_owned(),
    ));
  }
  if verified.claims.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "scope must be read, got {}",
      verified.claims.scope
    )));
  }
  if verified.claims.jti.is_empty() {
    return Err(TestError::Unexpected("jti must be non-empty".to_owned()));
  }
  if verified.claims.exp - verified.claims.iat != service.access_ttl().as_secs() as i64 {
    return Err(TestError::Unexpected(
      "exp - iat must equal the access TTL".to_owned(),
    ));
  }
  if verified.claims.iss != TEST_ISSUER {
    return Err(TestError::Unexpected(
      "iss must be the test issuer".to_owned(),
    ));
  }
  if !marker_live(&mut conn, &store, &jti_hash(&verified.claims.jti))
    .await
    .map_err(|error| TestError::Unexpected(format!("marker liveness failed: {error:?}")))?
  {
    return Err(TestError::Unexpected(
      "the fresh mint must leave a live allowlist marker".to_owned(),
    ));
  }
  Ok(())
}

/// `test(jwt_client_credentials_without_resource_is_invalid_target)`: a JWT
/// client-credentials request with no `resource` fails `invalid_target`
/// before minting, so no JWT is issued.
#[tokio::test]
async fn jwt_client_credentials_without_resource_is_invalid_target() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let signer = test_signer()?;
  let service = TokenService::new(&TtlConfig::default(), &ring()?)
    .map_err(TestError::from)?
    .with_jwt_signer(signer);
  let client = unique("jwt-cc-no-resource");
  let registered = ScopeSet::parse("read")?;
  let enabled = ScopeSet::parse("read")?;
  let proof = dpop_proof("jwt-no-resource-jkt");
  let ctx = Ctx {
    kind: ClientKind::Confidential,
    registered: &registered,
    enabled: &enabled,
    dpop_bound: None,
    mtls_bound: None,
    proof: &proof,
  };
  let mut inputs = super::input(&client, None, &ctx);
  inputs.aud = &[];
  inputs.token_format = TokenFormat::Jwt;
  match issue_client_credentials(&mut conn, &store, &service, &inputs).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => {}
    Err(error) => {
      return Err(TestError::Unexpected(format!(
        "a resourceless jwt mint must be invalid_target, got {}",
        error.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a resourceless jwt mint must never issue a token".to_owned(),
      ));
    }
  }
  Ok(())
}

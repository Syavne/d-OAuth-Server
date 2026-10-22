//! `test(jwt_)` suite: mint/verify round-trips, header discipline, rotation,
//! allowlist markers, and disabled-subject rejection for AS-minted JWT
//! access tokens (RFC 9068 profile subset).

use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header, decode_header, encode};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::{
  ActClaim, JwtAccessSigner, JwtClaims, JwtError, VerifiedJwt, jti_hash, marker_live,
  subject_active,
};
use crate::{
  config::{DurabilityMode, JwtSigningAlg, JwtSigningKey},
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    test_support::migrated_pool,
    user_repo::{NewUser, create_user, disable_user},
  },
  keys::{KeyId, KeyRing},
  protocol::token::Cnf,
  state::RedisConn,
  store::Store,
};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

/// Issuer every test signer asserts.
const TEST_ISSUER: &str = "https://as.example.test";
/// Access-token TTL stand-in: the round-trip pins `exp == iat + TTL`.
const TEST_TTL: i64 = 3_600;

static JTI_NONCE: AtomicU64 = AtomicU64::new(1);

/// A `jti` no other test uses, so allowlist markers never collide.
fn unique_jti() -> String {
  let n = JTI_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("jwt-test-jti-{n}")
}

/// Current time as seconds since the Unix epoch.
fn now_unix() -> i64 {
  OffsetDateTime::now_utc().unix_timestamp()
}

/// A validated signing key from a fixed 32-byte printable scalar.
fn signing_key(kid: &str, seed: &str, alg: JwtSigningAlg) -> Result<JwtSigningKey, TestError> {
  let raw = SecretString::from(seed.repeat(32));
  Ok(JwtSigningKey::from_raw(
    KeyId::new(kid),
    alg,
    &raw,
    "jwt_signing_key",
  )?)
}

/// An ES256 signer with no previous keys.
fn test_signer() -> Result<(JwtAccessSigner, JwtSigningKey), TestError> {
  let current = signing_key("v2", "C", JwtSigningAlg::Es256)?;
  let signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), current.clone(), Vec::new());
  Ok((signer, current))
}

/// A well-formed claim set; tests override fields via struct-update syntax.
fn valid_claims(now: i64) -> JwtClaims {
  JwtClaims {
    iss: TEST_ISSUER.to_owned(),
    sub: "subject@example.test".to_owned(),
    aud: vec!["https://rs.example.test".to_owned()],
    scope: "orders:read orders:write".to_owned(),
    exp: now + TEST_TTL,
    iat: now,
    jti: unique_jti(),
    client_id: "test-client".to_owned(),
    cnf: None,
    act: None,
  }
}

/// Fresh connection plus store handle against the shared compose Redis.
async fn test_redis() -> Result<(RedisConn, Store), TestError> {
  let manager = crate::test_support::redis_manager().await?;
  let (state_prefix, ratelimit_prefix) = crate::test_support::unique_prefixes();
  let store = Store::from_parts(state_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  Ok((RedisConn::Single(manager), store))
}

/// Test PII key ring for the disabled-subject re-check.
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(KeyId::new("v1"), SecretString::from("jwt-test-pepper"))],
    vec![(KeyId::new("v1"), SecretString::from("jwt-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("jwt-test-pii"))],
  )?)
}

/// Write the `jwt:<jti-hash>` allowlist marker hash for `jti`.
async fn write_marker(
  conn: &mut RedisConn,
  store: &Store,
  jti: &str,
  subject: &str,
) -> Result<(), TestError> {
  let key = store.jwt_marker_key(&jti_hash(jti));
  let hash = jti_hash(jti);
  redis::cmd("HSET")
    .arg(&key)
    .arg("grant_id")
    .arg("grant-1")
    .arg("client_id")
    .arg("test-client")
    .arg("subject")
    .arg(subject)
    .query_async::<()>(conn)
    .await?;
  redis::cmd("SADD")
    .arg(store.grant_tokens_key("grant-1"))
    .arg(format!("jwt:{hash}"))
    .query_async::<()>(conn)
    .await?;
  Ok(())
}

/// Assert a verification outcome is exactly the expected `JwtError`.
fn assert_jwt_error(result: Result<VerifiedJwt, JwtError>, want: JwtError) -> TestResult {
  match result {
    Ok(_) => Err(format!("expected {want:?}, token was accepted").into()),
    Err(got) => {
      if got == want {
        Ok(())
      } else {
        Err(format!("expected {want:?}, got {got:?}").into())
      }
    }
  }
}

/// Sign with the configured key but a forged `typ: "JWT"` header: the
/// signature is valid, yet verification must reject the type.
#[test]
fn jwt_verify_rejects_wrong_typ() -> TestResult {
  let (signer, key) = test_signer()?;
  let claims = valid_claims(now_unix());
  let mut header = Header::new(Algorithm::ES256);
  header.kid = Some(key.kid().as_str().to_owned());
  header.typ = Some("JWT".to_owned());
  let forged = encode(&header, &claims, key.encoding_key())?;
  assert_jwt_error(signer.verify(&forged, None), JwtError::WrongTyp)
}

/// A token whose `aud` lacks a required value is rejected, even when the
/// signature and every other claim verify.
#[test]
fn jwt_verify_rejects_wrong_aud() -> TestResult {
  let (signer, _) = test_signer()?;
  let claims = valid_claims(now_unix());
  let token = signer.sign(&claims)?;
  assert_jwt_error(
    signer.verify(&token, Some(&["https://other.example.test".to_owned()])),
    JwtError::WrongAudience,
  )
}

/// Signature and claims valid, but no marker hash in Redis: the token is
/// unusable (revoked, expired, or purged).
#[tokio::test]
async fn jwt_verify_rejects_unknown_marker() -> TestResult {
  let (signer, _) = test_signer()?;
  let (mut conn, store) = test_redis().await?;
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let claims = JwtClaims {
    sub: String::new(),
    ..valid_claims(now_unix())
  };
  let token = signer.sign(&claims)?;
  if marker_live(&mut conn, &store, &jti_hash(&claims.jti)).await? {
    return Err("marker exists for a fresh jti".into());
  }
  match signer
    .verify_live(&mut conn, &store, &pool, &keys, &token, None)
    .await
  {
    Err(JwtError::MarkerAbsent) => Ok(()),
    Err(got) => Err(format!("expected MarkerAbsent, got {got:?}").into()),
    Ok(_) => Err("markerless token was accepted".into()),
  }
}

/// A token with no `cnf` (unbound bearer, e.g. client-credentials) verifies,
/// and `cnf` round-trips to `None` on the wire.
#[test]
fn jwt_verify_accepts_absent_cnf() -> TestResult {
  let (signer, _) = test_signer()?;
  let claims = valid_claims(now_unix());
  let token = signer.sign(&claims)?;
  let verified = signer.verify(&token, None)?;
  if verified.claims.cnf.is_some() {
    return Err("absent cnf did not round-trip to None".into());
  }
  let segments: Vec<&str> = token.split('.').collect();
  if segments.len() != 3 {
    return Err("minted token is not three segments".into());
  }
  let payload: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1])?)?;
  if payload.get("cnf").is_some() {
    return Err("absent cnf was serialized onto the wire".into());
  }
  let bound = JwtClaims {
    cnf: Some(Cnf {
      jkt: Some("test-thumbprint".to_owned()),
      x5t_s256: None,
    }),
    ..valid_claims(now_unix())
  };
  let bound_verified = signer.verify(&signer.sign(&bound)?, None)?;
  if bound_verified.claims.cnf != bound.cnf {
    return Err("present cnf did not survive the round-trip".into());
  }
  Ok(())
}

/// Mint-to-verify round-trip: header `typ`/`kid`/`alg`, `client_id`, `scope`,
/// `aud`, `jti`, `act`, and `iat`/`exp` pinned to now plus the access TTL.
#[test]
fn jwt_sign_verify_round_trip() -> TestResult {
  let (signer, key) = test_signer()?;
  let now = now_unix();
  let claims = JwtClaims {
    act: Some(ActClaim {
      sub: "subject-client".to_owned(),
    }),
    ..valid_claims(now)
  };
  let token = signer.sign(&claims)?;
  let header = decode_header(&token)?;
  if header.typ.as_deref() != Some("at+jwt") {
    return Err("header typ is not at+jwt".into());
  }
  if header.kid.as_deref() != Some(key.kid().as_str()) {
    return Err("header kid is not the current key".into());
  }
  if header.alg != Algorithm::ES256 {
    return Err("header alg is not the configured algorithm".into());
  }
  let verified = signer.verify(
    &token,
    Some(&[
      "https://rs.example.test".to_owned(),
      "https://rs.example.test".to_owned(),
    ]),
  )?;
  if verified.claims != claims {
    return Err("claims did not survive the round-trip".into());
  }
  if verified.claims.iat != now || verified.claims.exp != now + TEST_TTL {
    return Err("iat/exp are not now plus the access TTL".into());
  }
  if verified.claims.client_id != "test-client" {
    return Err("client_id did not survive the round-trip".into());
  }
  Ok(())
}

/// Rotation: a token minted under the previous kid verifies once that kid is
/// retained verify-only; the current kid still signs.
#[test]
fn jwt_verify_rotation_previous_kid_accepted() -> TestResult {
  let old = signing_key("v1", "P", JwtSigningAlg::Es256)?;
  let current = signing_key("v2", "C", JwtSigningAlg::Es256)?;
  let old_signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), old.clone(), Vec::new());
  let rotated = JwtAccessSigner::new(TEST_ISSUER.to_owned(), current.clone(), vec![old.clone()]);
  let token = old_signer.sign(&valid_claims(now_unix()))?;
  let verified = rotated.verify(&token, None)?;
  if decode_header(&token)?.kid.as_deref() != Some("v1") {
    return Err("rotated token does not carry the previous kid".into());
  }
  if verified.claims.jti.is_empty() {
    return Err("rotated token claims are empty".into());
  }
  assert_jwt_error(
    JwtAccessSigner::new(TEST_ISSUER.to_owned(), current, Vec::new()).verify(&token, None),
    JwtError::UnknownKid,
  )
}

/// A single flipped signature character rejects with `Signature`.
#[test]
fn jwt_verify_rejects_tampered_signature() -> TestResult {
  let (signer, _) = test_signer()?;
  let token = signer.sign(&valid_claims(now_unix()))?;
  assert_jwt_error(
    signer.verify(&tamper_signature(&token)?, None),
    JwtError::Signature,
  )
}

/// An expired token is rejected with zero leeway.
#[test]
fn jwt_verify_rejects_expired() -> TestResult {
  let (signer, _) = test_signer()?;
  let now = now_unix();
  let claims = JwtClaims {
    iat: now - TEST_TTL - 20,
    exp: now - 10,
    ..valid_claims(now)
  };
  assert_jwt_error(
    signer.verify(&signer.sign(&claims)?, None),
    JwtError::Expired,
  )
}

/// Flip the first signature character: every base64url symbol there carries
/// full data bits, so the token still parses and only the signature breaks.
fn tamper_signature(token: &str) -> Result<String, TestError> {
  let segments: Vec<&str> = token.split('.').collect();
  if segments.len() != 3 {
    return Err("minted token is not three segments".into());
  }
  let mut sig = segments[2].to_owned();
  let first = sig.remove(0);
  sig.insert(0, if first == 'a' { 'b' } else { 'a' });
  Ok(format!("{}.{}.{}", segments[0], segments[1], sig))
}

/// A token minted for another issuer is rejected.
#[test]
fn jwt_verify_rejects_wrong_issuer() -> TestResult {
  let (signer, _) = test_signer()?;
  let claims = JwtClaims {
    iss: "https://other.example.test".to_owned(),
    ..valid_claims(now_unix())
  };
  assert_jwt_error(
    signer.verify(&signer.sign(&claims)?, None),
    JwtError::WrongIssuer,
  )
}

/// A header `kid` naming no current or previous key fails with no fallback.
#[test]
fn jwt_verify_rejects_unknown_kid() -> TestResult {
  let (signer, _) = test_signer()?;
  let stranger = signing_key("v9", "S", JwtSigningAlg::Es256)?;
  let stranger_signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), stranger, Vec::new());
  let token = stranger_signer.sign(&valid_claims(now_unix()))?;
  assert_jwt_error(signer.verify(&token, None), JwtError::UnknownKid)
}

/// A token signed under another algorithm is rejected even with a valid
/// signature for that algorithm: the header never picks the algorithm.
#[test]
fn jwt_verify_rejects_wrong_alg() -> TestResult {
  let (signer, _) = test_signer()?;
  let ed_key = signing_key("ek1", "E", JwtSigningAlg::EdDsa)?;
  let ed_signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), ed_key, Vec::new());
  let token = ed_signer.sign(&valid_claims(now_unix()))?;
  assert_jwt_error(signer.verify(&token, None), JwtError::WrongAlg)
}

/// EdDSA keys mint and verify under the same header discipline.
#[test]
fn jwt_eddsa_sign_verify_round_trip() -> TestResult {
  let key = signing_key("ek1", "E", JwtSigningAlg::EdDsa)?;
  let signer = JwtAccessSigner::new(TEST_ISSUER.to_owned(), key.clone(), Vec::new());
  let token = signer.sign(&valid_claims(now_unix()))?;
  let header = decode_header(&token)?;
  if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some("at+jwt") {
    return Err("eddsa header does not carry alg EdDSA and typ at+jwt".into());
  }
  signer.verify(&token, None)?;
  Ok(())
}

/// Marker present, subject enabled: live. After `disable_user`: the same
/// token reports `SubjectDisabled`. Empty and unmapped subjects stay live.
#[tokio::test]
async fn jwt_verify_live_rejects_disabled_subject() -> TestResult {
  let (signer, _) = test_signer()?;
  let (mut conn, store) = test_redis().await?;
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let params = Argon2Params::new(8, 1, 1, 32)?;
  let email = format!("jwt-subject-{}@example.test", now_unix());
  let record = create_user(
    &pool,
    &keys,
    false,
    &NewUser {
      email: email.clone(),
      password_hash: hash_secret("correct-horse-01", &params)?,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  let claims = JwtClaims {
    sub: email.clone(),
    ..valid_claims(now_unix())
  };
  let token = signer.sign(&claims)?;
  write_marker(&mut conn, &store, &claims.jti, &email).await?;
  signer
    .verify_live(&mut conn, &store, &pool, &keys, &token, None)
    .await?;
  if !subject_active(&pool, &keys, "").await? {
    return Err("empty subject must stay live".into());
  }
  if !subject_active(&pool, &keys, "synthetic-subject").await? {
    return Err("unmapped subject must stay live".into());
  }
  if !disable_user(&pool, record.id).await? {
    return Err("disable_user reported no change".into());
  }
  match signer
    .verify_live(&mut conn, &store, &pool, &keys, &token, None)
    .await
  {
    Err(JwtError::SubjectDisabled) => Ok(()),
    Err(got) => Err(format!("expected SubjectDisabled, got {got:?}").into()),
    Ok(_) => Err("disabled subject token was accepted".into()),
  }
}

/// Strict liveness: a marker hash without grant membership is dead
/// (`MarkerAbsent`), even though the marker-only check reads live.
#[tokio::test]
async fn jwt_verify_live_rejects_orphan_marker() -> TestResult {
  let (signer, _) = test_signer()?;
  let (mut conn, store) = test_redis().await?;
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let claims = JwtClaims {
    sub: String::new(),
    ..valid_claims(now_unix())
  };
  let token = signer.sign(&claims)?;
  let hash = jti_hash(&claims.jti);
  let key = store.jwt_marker_key(&hash);
  redis::cmd("HSET")
    .arg(&key)
    .arg("grant_id")
    .arg("orphan-grant")
    .arg("client_id")
    .arg("test-client")
    .arg("subject")
    .arg("")
    .query_async::<()>(&mut conn)
    .await?;
  if !marker_live(&mut conn, &store, &hash).await? {
    return Err("orphan marker must read live on the marker-only check".into());
  }
  match signer
    .verify_live(&mut conn, &store, &pool, &keys, &token, None)
    .await
  {
    Err(JwtError::MarkerAbsent) => Ok(()),
    Err(got) => Err(format!("expected MarkerAbsent, got {got:?}").into()),
    Ok(_) => Err("orphan marker token was accepted".into()),
  }
}

/// `Debug` on the signer and on every key shape carries no key material: the
/// raw 32-byte scalars appear nowhere; only `kid`/`alg`/public coordinates.
#[test]
fn jwt_debug_redacts_key_material() -> TestResult {
  let current = signing_key("v2", "C", JwtSigningAlg::Es256)?;
  let previous = signing_key("v1", "P", JwtSigningAlg::Es256)?;
  let ed = signing_key("ek1", "E", JwtSigningAlg::EdDsa)?;
  let signer = JwtAccessSigner::new(
    TEST_ISSUER.to_owned(),
    current.clone(),
    vec![previous.clone()],
  );
  for raw in ["C".repeat(32), "P".repeat(32), "E".repeat(32)] {
    for rendered in [
      format!("{signer:?}"),
      format!("{current:?}"),
      format!("{previous:?}"),
      format!("{ed:?}"),
    ] {
      if rendered.contains(&raw) {
        return Err("key material leaked into Debug".into());
      }
    }
  }
  let rendered = format!("{signer:?}");
  for marker in ["v2", "v1", "Es256"] {
    if !rendered.contains(marker) {
      return Err(format!("signer Debug lost {marker}").into());
    }
  }
  if !rendered.contains(current.public_jwk().x.as_str()) {
    return Err("signer Debug lost the public coordinates".into());
  }
  Ok(())
}

/// `JwtClaims` Debug never prints the PII `sub` or the raw `jti` (the
/// allowlist marker key material); public claim members stay visible.
#[test]
fn jwt_claims_debug_redacts_sub_and_jti() {
  let claims = JwtClaims {
    iss: "https://auth.example.test".to_owned(),
    sub: "user@example.test".to_owned(),
    aud: vec!["https://api.example.test".to_owned()],
    scope: "read".to_owned(),
    exp: 1_700_000_000,
    iat: 1_699_999_700,
    jti: "raw-jti-marker".to_owned(),
    client_id: "client-abc".to_owned(),
    cnf: None,
    act: None,
  };
  let rendered = format!("{claims:?}");
  assert!(!rendered.contains("user@example.test"));
  assert!(!rendered.contains("raw-jti-marker"));
  assert!(rendered.contains("[REDACTED]"));
  assert!(rendered.contains("client-abc"));
}

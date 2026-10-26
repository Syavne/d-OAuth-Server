//! Fuzz RFC 9068 `at+jwt` access-token verification.
//!
//! [`JwtAccessSigner::verify`] checks the JOSE envelope (`typ`, `alg`, `kid`),
//! the signature, `iss`/`exp`, and `aud` containment without touching Redis or
//! Postgres. A first selector byte of `0` replays one fixed, valid token so the
//! accepted branch is exercised deterministically; any other selector treats
//! the remaining bytes as a hostile compact JWT. Random bytes alone are not
//! claimed to reach the accepted branch (that needs a valid signature).
//!
//! Any accepted token must carry the audience the signer was minted for.

#![no_main]

use std::sync::OnceLock;

use d_oauth::{
  config::{JwtSigningAlg, JwtSigningKey},
  jose::jwt_access::{JwtAccessSigner, JwtClaims},
  keys::KeyId,
};
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

/// Fixed issuer the signer asserts (never the wall clock or config).
const ISSUER: &str = "https://issuer.fuzz.test";
/// The one audience the fixed token carries.
const AUD: &str = "https://rs.fuzz.test";

/// The fixed signer and its one valid token, built once per process.
struct Fixture {
  signer: JwtAccessSigner,
  token: String,
  aud: Vec<String>,
}

/// Build the fixed ES256 signer and token. `None` when key material or signing
/// fails, which makes the target a no-op instead of panicking on setup.
fn build_fixture() -> Option<Fixture> {
  let secret = SecretString::from("C".repeat(32));
  let key = JwtSigningKey::from_raw(
    KeyId::new("v2"),
    JwtSigningAlg::Es256,
    &secret,
    "fuzz_jwt_signing_key",
  )
  .ok()?;
  let signer = JwtAccessSigner::new(ISSUER.to_owned(), key, Vec::new());
  let now = time::OffsetDateTime::now_utc().unix_timestamp();
  let aud = vec![AUD.to_owned()];
  let claims = JwtClaims {
    iss: ISSUER.to_owned(),
    sub: "subject@example.test".to_owned(),
    aud: aud.clone(),
    scope: "read".to_owned(),
    exp: now + 86_400,
    iat: now,
    jti: "fuzz-jti".to_owned(),
    client_id: "fuzz-client".to_owned(),
    cnf: None,
    act: None,
  };
  let token = signer.sign(&claims).ok()?;
  Some(Fixture { signer, token, aud })
}

/// The process-wide fixture, built on first use and reused thereafter.
fn fixture() -> Option<&'static Fixture> {
  static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
  FIXTURE.get_or_init(build_fixture).as_ref()
}

fuzz_target!(|data: &[u8]| {
  let Some(fixture) = fixture() else {
    return;
  };
  let Some((selector, rest)) = data.split_first() else {
    return;
  };
  let token: &str = if *selector == 0 {
    fixture.token.as_str()
  } else {
    match core::str::from_utf8(rest) {
      Ok(text) => text,
      Err(_) => return,
    }
  };
  // No expected audience: any accepted token must still carry the minted one.
  if let Ok(verified) = fixture.signer.verify(token, None) {
    assert!(
      verified.claims.aud.iter().any(|aud| aud == AUD),
      "accepted token lost its expected audience"
    );
  }
  // With an expected audience, acceptance implies containment.
  if let Ok(verified) = fixture.signer.verify(token, Some(fixture.aud.as_slice())) {
    assert!(
      verified.claims.aud.iter().any(|aud| aud == AUD),
      "accepted token lost its expected audience"
    );
  }
});

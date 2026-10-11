//! Fuzz the DPoP proof's embedded-JWK gate (`jose::jwk`).
//!
//! The proof JWK is self-asserted hostile input: [`decoding_key`] must refuse
//! private/symmetric material, enforce the `alg`-to-key-type correspondence,
//! and floor RSA moduli, while [`thumbprint`] canonicalizes (RFC 7638) only
//! the public members. Both must never panic on any input; a JWK accepted by
//! [`decoding_key`] always carries the members [`thumbprint`] needs.
//! Signature verification and the `jti` replay claim need keys and Redis, so
//! they stay under unit/proptest cover.

#![no_main]

use d_oauth::jose::jwk::{decoding_key, thumbprint};
use jsonwebtoken::Algorithm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  let Some((&selector, rest)) = data.split_first() else {
    return;
  };
  let alg = match selector % 3 {
    0 => Algorithm::ES256,
    1 => Algorithm::EdDSA,
    _ => Algorithm::RS256,
  };
  let Ok(text) = core::str::from_utf8(rest) else {
    return;
  };
  let Ok(jwk) = serde_json::from_str::<serde_json::Value>(text) else {
    return;
  };
  let key = decoding_key(alg, &jwk);
  let print = thumbprint(&jwk);
  // An accepted verification key always thumbprints: every path that builds
  // a `DecodingKey` already required the exact public members the canonical
  // form consumes.
  if key.is_ok() {
    debug_assert!(print.is_ok());
  }
});

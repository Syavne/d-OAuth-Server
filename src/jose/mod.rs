//! JOSE verification: `DPoP`, JAR, `private_key_jwt`, JWK thumbprints, and
//! AS-minted JWT access tokens.
//!
//! Single verifier (`jsonwebtoken`) for every spec-signed artifact. The AS
//! signs nothing except JWT access tokens: when the
//! `jwt_access_tokens_enabled` kill-switch is on, [`jwt_access`] mints and
//! verifies `at+jwt` tokens under the configured `JwtSigningKey` ring, and
//! task 28 advertises the ring's public halves as `jwks_uri`.
//!
//! TODO(task 20): wire re-exports for `dpop`/`jar`/`jwk`.

pub mod dpop;
pub mod jar;
pub mod jwk;
pub mod jwt_access;

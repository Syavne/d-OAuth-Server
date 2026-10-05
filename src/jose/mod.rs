//! JOSE verification: `DPoP`, JAR, `private_key_jwt`, JWK thumbprints.
//!
//! Single verifier (`jsonwebtoken`) for every spec-signed artifact. The AS
//! signs nothing itself, so there is no AS signing key and no `jwks_uri`.
//!
//! TODO(task 20): wire re-exports for `dpop`/`jar`/`client_assertion`/`jwk`.

pub mod client_assertion;
pub mod dpop;
pub mod jar;
pub mod jwk;

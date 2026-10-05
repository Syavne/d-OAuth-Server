//! Crypto core: token minting, keyed hash-at-rest, constant-time helpers.
//!
//! Re-exports `tokens`, `pkce`, `secret`, `totp`, and `ct`. All secret
//! comparison goes through `ct`; intermediates are `zeroize`d.

pub mod ct;
pub mod pkce;
pub mod secret;
pub mod tokens;
pub mod totp;

pub use ct::ct_eq;
pub use tokens::{
  KeyId, MAX_RETAINED_KEYS, TOKEN_BYTES, TOKEN_STR_LEN, TokenError, TokenHash, mint_token,
  redact_token, token_hash, verify_token_hash,
};

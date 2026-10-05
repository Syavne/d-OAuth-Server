//! Token endpoint: dispatch, mint, and sender-constraint enforcement.
//!
//! Every sender-constrained grant requires a freshly verified proof at the
//! token endpoint on every use; `private_key_jwt` alone never satisfies it.
//!
//! The token service ([`service::TokenService`]) mints opaque pairs, stores
//! only versioned keyed hashes, enforces the sender-constraint matrix, and
//! exposes find/revoke/rotate/tombstone primitives over
//! [`crate::store::tokens`]. Grants (tasks 31-35) build on this module.

mod dispatch;
mod service;
#[cfg(test)]
mod tests;
mod types;

pub mod grants;

pub use dispatch::{TokenForm, handler};
pub use service::TokenService;
pub use types::{
  ClientKind, Cnf, FoundAccess, FoundRefresh, MintRequest, MintedTokens, SenderProof,
  TokenServiceError,
};

//! OAuth 2.1 protocol handlers and guards.
//!
//! Pure protocol layer on audited primitives: metadata, authorize, token
//! grants, client auth, DCR, introspection, revocation, PAR, mTLS, SSRF
//! guard. No persistence details leak in here beyond the store traits.
//!
//! TODO(task 19): wire re-exports as each endpoint lands.

pub mod authorize;
pub mod client_auth;
pub mod code;
pub mod dcr;
pub mod device;
pub mod introspect;
pub mod metadata;
pub mod mtls;
pub mod par;
pub mod purge;
pub mod redirect_repo;
pub mod revoke;
pub mod scope;
pub mod ssrf;
pub mod token;

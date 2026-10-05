//! Token-exchange grant subtree (RFC 8693; tasks 31-35 own one file each).
//!
//! This module declares the per-grant handlers that build on
//! [`super::TokenService`].

pub mod authorization_code;
pub mod client_credentials;
pub mod device_code;
pub mod refresh_token;
pub mod token_exchange;

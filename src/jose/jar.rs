//! JAR request-object verification (RFC 9101).
//!
//! Validates signed `request` objects and `request_uri` references for
//! `/authorize` (and PAR): the signature is checked against the client's
//! registered JWKS, `iss` must equal the `client_id`, `aud` must equal the
//! server issuer, and `exp` must be present and unexpired. Claims merge over
//! the query parameters with conflicting duplicates rejected (RFC 9101
//! §5.2); unsigned (`alg:none`) and symmetrically signed objects are
//! rejected. A `request_uri` is either a PAR-issued URN (consumed one-time
//! and client-bound from the PAR store) or an exact pre-registered client
//! URI fetched behind the SSRF guard — never an arbitrary fetch.
//!
//! `fetch` delegates to the shared `protocol::ssrf` guarded fetch
//! (`https`-only, no redirects, DNS-validated and connection-pinned
//! targets, 5 s / 256 KiB caps) and then enforces the 64 KiB
//! request-object cap with a UTF-8 requirement here.
//!
//! INTEGRATION(task 23): `protocol::authorize` must call [`resolve`]. The
//! JAR/PAR-mandatory rule for confidential clients is enforced here by
//! [`require_par_or_jar`]: no `request`, no `request_uri`, no authorization.

mod fetch;
mod merge;
mod request_uri;
mod verify;

use std::{collections::HashMap, time::Duration};

use crate::{db::client_repo::Client, error::AppError, state::RedisConn, store::Store};

use merge::merge_claims;
use request_uri::resolve_uri;
use verify::verify_request_object;

/// PAR `request_uri` URN prefix (RFC 9126 §3); the suffix is the PAR id.
pub const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
/// Maximum fetched request-object body (SSRF size cap).
pub const MAX_REQUEST_OBJECT_BYTES: usize = 64 * 1024;
/// Outbound `request_uri` fetch timeout, matching the shared SSRF guard's
/// budget; the effective timeout is enforced by `protocol::ssrf`.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Authorize-time JAR input: at most one of `request` / `request_uri`.
pub struct JarRequest<'a> {
  /// The resolved, active client the request is bound to.
  pub client: &'a Client,
  /// The server issuer; the request object's `aud`.
  pub issuer: &'a str,
  /// Query parameters as received on the authorize endpoint.
  pub query: &'a HashMap<String, String>,
  /// Inline signed request object (RFC 9101 §4.1), if supplied.
  pub request: Option<&'a str>,
  /// Request-object reference: PAR URN or pre-registered URI, if supplied.
  pub request_uri: Option<&'a str>,
}

/// Resolve the effective authorize parameters.
///
/// `request` is verified and merged over `query`; `request_uri` is resolved
/// through the PAR store or the SSRF-guarded fetch and then merged; with
/// neither, a public client falls back to the raw query while a
/// confidential client is rejected (see [`require_par_or_jar`]).
///
/// # Errors
///
/// Returns `invalid_request_object` for malformed, mis-bound, or
/// conflicting request objects, `invalid_request` for PAR misuse and for a
/// confidential client without PAR/JAR, and a masked `server_error` when a
/// stored PAR record does not parse.
pub async fn resolve(
  conn: &mut RedisConn,
  store: &Store,
  input: &JarRequest<'_>,
) -> Result<HashMap<String, String>, AppError> {
  match (input.request, input.request_uri) {
    (Some(_), Some(_)) => Err(AppError::invalid_request_object(
      "request and request_uri must not both be present",
    )),
    (Some(jwt), None) => {
      let claims = verify_request_object(input.client, input.issuer, jwt)?;
      merge_claims(input.query, &claims, &input.client.client_id)
    }
    (None, Some(uri)) => {
      resolve_uri(conn, store, input.client, input.issuer, input.query, uri).await
    }
    (None, None) => {
      require_par_or_jar(input.client)?;
      Ok(input.query.clone())
    }
  }
}

/// Enforce the JAR/PAR-mandatory rule: a confidential client (any
/// `token_endpoint_auth_method` other than `none`) must present either a
/// PAR-issued `request_uri` or a valid signed `request` object; a plain
/// query-parameter authorization request is rejected with
/// `invalid_request`. Public (`none`) clients may use plain query + PKCE.
///
/// # Errors
///
/// Returns `invalid_request` for a confidential client.
pub fn require_par_or_jar(client: &Client) -> Result<(), AppError> {
  if client.token_endpoint_auth_method == "none" {
    Ok(())
  } else {
    Err(AppError::invalid_request(
      "confidential clients must use a PAR request_uri or a signed request object",
    ))
  }
}

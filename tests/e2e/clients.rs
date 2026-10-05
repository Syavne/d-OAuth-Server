//! `oauth2`-crate client builder for the E2E suites (baseline flows only:
//! authorization-code + PKCE, client-credentials, device).
//!
//! The v5 typestate requires each endpoint to be set before the matching flow
//! method exists, so the setters chain in one expression and the return type
//! names the set state (`EndpointSet` for auth + token). Extension flows
//! (DPoP, mTLS, PAR, JAR, token exchange, DCR) stay hand-rolled `reqwest`.
//!
//! Included by the grant and conformance suites, which both use it.

use super::harness::{TestError, fail};

/// Build an `oauth2`-crate client pointed at this world's base URL.
pub fn oauth2_client(
  base: &str,
  client_id: &str,
  secret: Option<&str>,
) -> Result<
  oauth2::basic::BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
  >,
  TestError,
> {
  use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
  let auth_uri = AuthUrl::new(format!("{base}/authorize"))
    .map_err(|error| fail(format!("auth url: {error}")))?;
  let token_uri =
    TokenUrl::new(format!("{base}/token")).map_err(|error| fail(format!("token url: {error}")))?;
  let redirect_uri = RedirectUrl::new("http://127.0.0.1:9/cb".to_owned())
    .map_err(|error| fail(format!("redirect url: {error}")))?;
  let client = BasicClient::new(ClientId::new(client_id.to_owned()));
  let client = match secret {
    Some(secret) => client.set_client_secret(ClientSecret::new(secret.to_owned())),
    None => client,
  };
  Ok(
    client
      .set_auth_uri(auth_uri)
      .set_redirect_uri(redirect_uri)
      .set_token_uri(token_uri),
  )
}

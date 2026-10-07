//! Certificate-to-client matching: thumbprint pinning and subject DNs.
//!
//! `self_signed_tls_client_auth` pins the leaf thumbprint (the default);
//! `tls_client_auth` matches the subject DN and rejects an ambiguous DN
//! (more than one client sharing it) even though the partial unique index
//! should prevent one from being written.

use rustls::pki_types::CertificateDer;
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::{
  MtlsCnf, MtlsError,
  cert::{subject_dn, thumbprint_b64url},
};
use crate::db::client_repo::{self, Client, TokenEndpointAuthMethod};
use crate::keys::KeyRing;

/// Select the unique client enrolled with this certificate thumbprint.
pub fn select_by_thumbprint<'a>(
  clients: &'a [Client],
  thumbprint: &str,
) -> Result<&'a Client, MtlsError> {
  clients
    .iter()
    .find(|client| {
      client
        .tls_client_auth_cert_thumbprint
        .as_deref()
        .is_some_and(|registered| bool::from(registered.as_bytes().ct_eq(thumbprint.as_bytes())))
    })
    .ok_or(MtlsError::UnknownCertificate)
}

/// Select the unique client enrolled with this subject DN, rejecting an
/// ambiguous DN even though the partial unique index should prevent one.
pub fn select_by_subject_dn<'a>(clients: &'a [Client], dn: &str) -> Result<&'a Client, MtlsError> {
  let mut matches = clients
    .iter()
    .filter(|client| client.tls_client_auth_subject_dn.as_deref() == Some(dn));
  let first = matches.next().ok_or(MtlsError::UnknownCertificate)?;
  if matches.next().is_some() {
    return Err(MtlsError::AmbiguousSubjectDn);
  }
  Ok(first)
}

/// Authenticate `client` with the presented leaf, enforcing the method the
/// client registered: thumbprint pinning for `self_signed_tls_client_auth`,
/// subject-DN matching for `tls_client_auth`. Returns the `cnf` to bind.
pub async fn authenticate(
  pool: &PgPool,
  keys: &KeyRing,
  client: &Client,
  leaf: Option<&CertificateDer<'_>>,
) -> Result<MtlsCnf, MtlsError> {
  let method = TokenEndpointAuthMethod::try_from(client.token_endpoint_auth_method.as_str())
    .map_err(|_| MtlsError::UnexpectedMethod)?;
  match method {
    TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
      let der = leaf.ok_or(MtlsError::MissingCertificate)?;
      let thumbprint = thumbprint_b64url(der.as_ref());
      let registered = client
        .tls_client_auth_cert_thumbprint
        .as_deref()
        .ok_or(MtlsError::UnknownCertificate)?;
      if !bool::from(registered.as_bytes().ct_eq(thumbprint.as_bytes())) {
        return Err(MtlsError::UnknownCertificate);
      }
      Ok(MtlsCnf {
        x5t_s256: thumbprint,
      })
    }
    TokenEndpointAuthMethod::TlsClientAuth => {
      let der = leaf.ok_or(MtlsError::MissingCertificate)?;
      let dn = subject_dn(der.as_ref())?;
      let registered = client
        .tls_client_auth_subject_dn
        .as_deref()
        .ok_or(MtlsError::UnknownCertificate)?;
      if registered != dn {
        return Err(MtlsError::UnknownCertificate);
      }
      let clients = client_repo::list(pool, keys, false).await?;
      select_by_subject_dn(&clients, &dn)?;
      Ok(MtlsCnf {
        x5t_s256: thumbprint_b64url(der.as_ref()),
      })
    }
    TokenEndpointAuthMethod::ClientSecretBasic
    | TokenEndpointAuthMethod::ClientSecretPost
    | TokenEndpointAuthMethod::None
    | TokenEndpointAuthMethod::PrivateKeyJwt => Err(MtlsError::UnexpectedMethod),
  }
}

/// Load the client by `client_id`, then [`authenticate`] it with the leaf.
pub async fn authenticate_by_id(
  pool: &PgPool,
  keys: &KeyRing,
  client_id: &str,
  leaf: Option<&CertificateDer<'_>>,
) -> Result<MtlsCnf, MtlsError> {
  let client = client_repo::find_active_by_client_id(pool, keys, client_id)
    .await?
    .ok_or(MtlsError::UnknownClient)?;
  authenticate(pool, keys, &client, leaf).await
}

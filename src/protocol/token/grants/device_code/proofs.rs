//! Fresh sender proofs for one device-code poll.
//!
//! Verification itself belongs to tasks 20/21; this module only collects
//! what was proven on this request. Public clients must carry a DPoP proof;
//! confidential clients authenticate as registered.

use time::OffsetDateTime;

use super::super::super::SenderProof;
use super::{DevicePollError, DevicePollInputs, PollState};
use crate::{
  db::TokenEndpointAuthMethod,
  error::AppError,
  jose::dpop::{DpopRequest, verify_dpop},
  protocol::{
    client_auth::{self, AuthContext, AuthStores, ClientAuthRequest},
    mtls,
  },
};

/// Authenticate the polling client and verify its fresh sender proofs.
///
/// Public clients present no secret and must carry a DPoP proof on this
/// request; confidential clients authenticate as registered, with mTLS
/// clients additionally proving the leaf and DPoP clients proving the key.
pub(super) async fn fresh_proofs(
  state: &mut PollState<'_>,
  client: &crate::db::Client,
  inputs: &DevicePollInputs<'_>,
) -> Result<SenderProof, DevicePollError> {
  let used_basic = inputs.basic_header.is_some();
  let unknown_client = || {
    if used_basic {
      AppError::invalid_client_basic()
    } else {
      AppError::invalid_client_non_basic()
    }
  };
  let method = client.auth_method().map_err(|_| unknown_client())?;
  let htu = client_auth::token_endpoint(state.issuer);
  let dpop_jkt = match inputs.dpop_proof {
    Some(proof) => Some(
      verify_dpop(
        state.conn,
        state.store,
        &DpopRequest {
          proof: Some(proof),
          htm: "POST",
          htu: &htu,
          access_token: None,
          now_unix: state.now_unix,
        },
      )
      .await?
      .jkt,
    ),
    None => None,
  };
  let mtls_x5t_s256 = match method {
    TokenEndpointAuthMethod::None => {
      if inputs.basic_header.is_some() || inputs.body_secret.is_some() || inputs.assertion.is_some()
      {
        return Err(unknown_client().into());
      }
      None
    }
    TokenEndpointAuthMethod::ClientSecretBasic
    | TokenEndpointAuthMethod::ClientSecretPost
    | TokenEndpointAuthMethod::PrivateKeyJwt => {
      authenticate_confidential(state, client, inputs).await?;
      None
    }
    TokenEndpointAuthMethod::TlsClientAuth | TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
      let leaf = inputs.peer_certs.and_then(|chain| chain.chain().first());
      Some(
        mtls::authenticate(state.pool, state.keys, client, leaf)
          .await
          .map_err(mtls::MtlsError::into_app_error)?
          .x5t_s256,
      )
    }
  };
  let dpop_jkt = match method {
    TokenEndpointAuthMethod::None if client.dpop_bound_access_tokens => Some(
      dpop_jkt
        .filter(|jkt| !jkt.is_empty())
        .ok_or_else(|| AppError::invalid_dpop_proof("DPoP proof is required"))?,
    ),
    _ => dpop_jkt.filter(|jkt| !jkt.is_empty()),
  };
  Ok(SenderProof {
    dpop_jkt,
    mtls_x5t_s256,
  })
}

/// Authenticate a secret/assertion client through the shared dispatch.
///
/// The returned row is discarded: the pre-lookup above already owns the
/// client record, and this call exists only for its proof.
async fn authenticate_confidential(
  state: &mut PollState<'_>,
  client: &crate::db::Client,
  inputs: &DevicePollInputs<'_>,
) -> Result<(), DevicePollError> {
  let endpoint = client_auth::token_endpoint(state.issuer);
  let request = ClientAuthRequest {
    basic_header: inputs.basic_header,
    client_id: Some(client.client_id.as_str()),
    body_secret: inputs.body_secret.clone(),
    assertion_type: inputs.assertion_type,
    assertion: inputs.assertion,
    peer_certs: inputs.peer_certs,
  };
  let mut auth = AuthStores {
    pool: state.pool,
    keys: state.keys,
    conn: &mut *state.conn,
    store: state.store,
  };
  let auth_ctx = AuthContext {
    token_endpoint: endpoint.as_str(),
    now: OffsetDateTime::from_unix_timestamp(state.now_unix).unwrap_or(OffsetDateTime::UNIX_EPOCH),
    cimd: state.cimd.clone(),
  };
  client_auth::authenticate_client(&mut auth, &auth_ctx, &request).await?;
  Ok(())
}

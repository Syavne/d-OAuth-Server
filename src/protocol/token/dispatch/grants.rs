//! Per-grant `POST /token` branches: form inputs to grant handler, response
//! shaping, and the `grant_type` dispatch table.

use std::time::Duration;

use secrecy::SecretString;

use super::{
  Dispatch, TokenError, TokenFormat, TokenResponseBody, basic_header, client_kind, dpop_proof,
  enabled_scopes, jwt_signer, require_dpop_binding, require_grant, token_service,
};
use crate::{
  db::{user_repo, user_scope_repo},
  error::AppError,
  protocol::{
    client_auth,
    device::{DEVICE_GRANT, DEVICE_INTERVAL_SECS},
    scope::ScopeSet,
    token::{
      TokenService,
      grants::{
        authorization_code::{self, CodeGrantInputs, CodeGrantState},
        client_credentials::{self, ClientCredentialsInput},
        device_code::{self, DevicePollInputs, PollState},
        refresh_token::{self, RefreshInput},
        token_exchange::{self, ExchangeInput},
      },
    },
  },
};

/// Dispatch on the parsed `grant_type`.
///
/// A missing or empty member is the RFC 6749 §5.2 `invalid_request` (the
/// request is missing a required parameter); an unknown value fails closed
/// with `unsupported_grant_type`.
pub(super) async fn dispatch_grant(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let Some(grant_type) = d
    .form
    .grant_type
    .as_deref()
    .filter(|value| !value.is_empty())
  else {
    return Err(AppError::invalid_request("grant_type is required").into());
  };
  match grant_type {
    authorization_code::GRANT_TYPE_AUTHORIZATION_CODE => authorization_code(d).await,
    refresh_token::GRANT_TYPE_REFRESH_TOKEN => refresh(d).await,
    client_credentials::GRANT_TYPE_CLIENT_CREDENTIALS => client_credentials(d).await,
    DEVICE_GRANT => device(d).await,
    token_exchange::GRANT_TYPE_TOKEN_EXCHANGE => exchange(d).await,
    _ => Err(AppError::unsupported_grant_type("the grant type is not supported").into()),
  }
}

/// The candidate presenter id for `authorization_code`, mirroring the grant's
/// own resolution so the format gate and the grant agree: Basic wins, and a
/// disagreeing body id is left to the grant's `invalid_client` path.
fn authorization_code_candidate_id(form_id: Option<&str>, basic: Option<&str>) -> Option<String> {
  match basic {
    Some(header) => {
      let creds = client_auth::parse_basic_header(header)?;
      match form_id {
        Some(body_id) if body_id != creds.client_id => None,
        _ => Some(creds.client_id),
      }
    }
    None => form_id.map(str::to_owned),
  }
}

/// `grant_type=authorization_code`: the grant authenticates the client itself.
async fn authorization_code(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let basic = basic_header(d.headers);
  let proof = dpop_proof(d.headers);
  let format = d
    .gate_candidate_client_format(authorization_code_candidate_id(
      d.form.client_id.as_deref(),
      basic,
    ))
    .await?
    .unwrap_or(TokenFormat::Opaque);
  let jwt = if format == TokenFormat::Jwt {
    Some(jwt_signer(d.state)?)
  } else {
    None
  };
  let body_secret = d.form.client_secret.clone().map(SecretString::from);
  let mut grant = CodeGrantState {
    pool: &d.state.pool,
    conn: &mut *d.conn,
    store: d.store,
    keys: &d.state.keys,
    issuer: &d.state.config.issuer,
    ttl: &d.state.config.ttl,
    token_format: format,
    jwt_signer: jwt,
    cimd: d.cimd,
    now_unix: d.now_unix,
  };
  let inputs = CodeGrantInputs {
    code: d.form.code.as_deref().unwrap_or(""),
    redirect_uri: d.form.redirect_uri.as_deref().unwrap_or(""),
    code_verifier: d.form.code_verifier.as_deref(),
    client_id: d.form.client_id.as_deref(),
    basic_header: basic,
    body_secret,
    assertion_type: d.form.client_assertion_type.as_deref(),
    assertion: d.form.client_assertion.as_deref(),
    dpop_proof: proof,
    peer_certs: d.peer_certs,
    aud: d.resources,
  };
  let tokens = authorization_code::redeem_code(&mut grant, &inputs).await?;
  Ok(TokenResponseBody {
    access_token: tokens.access_token,
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    refresh_token: tokens.refresh_token,
    scope: tokens.scope,
    issued_token_type: None,
  })
}

/// `grant_type=refresh_token`: authenticate, then rotate with fresh proofs.
async fn refresh(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let authenticated = d.authenticate().await?;
  let client = authenticated.client;
  require_grant(&client, refresh_token::GRANT_TYPE_REFRESH_TOKEN)?;
  let format = d.require_token_format(&client)?;
  let kind = client_kind(&client)?;
  let proof = d.sender_proof(&client).await?;
  require_dpop_binding(&client, &proof)?;
  let enabled = enabled_scopes(&d.state.pool).await?;
  let mut service = token_service(d.state)?;
  if format == TokenFormat::Jwt {
    service = service.with_jwt_signer(jwt_signer(d.state)?);
  }
  let users = refresh_token::RefreshUserStores {
    pool: &d.state.pool,
    keys: &d.state.keys,
  };
  let registered = ScopeSet::parse(&client.scope).map_err(|_| AppError::server_error())?;
  // The user term is resolved fresh inside `refresh_with_subject_check` from
  // the presented token's subject; this placeholder only flows through on the
  // unknown-token path, where scope is never minted.
  let no_user_term = ScopeSet::empty();
  let refreshed = refresh_token::refresh_with_subject_check(
    &mut *d.conn,
    d.store,
    &service,
    &users,
    &RefreshInput {
      client_id: &client.client_id,
      client_kind: kind,
      dpop_required: client.dpop_bound_access_tokens,
      refresh_token: d.form.refresh_token.as_deref().unwrap_or(""),
      requested_scope: d.form.scope.as_deref(),
      requested_resources: d.resources,
      proof: &proof,
      enabled: &enabled,
      client_registered: &registered,
      user_entitled: &no_user_term,
      token_format: format,
      now_unix: d.now_unix,
    },
  )
  .await?;
  Ok(TokenResponseBody {
    access_token: refreshed.access_token,
    token_type: refreshed.token_type,
    expires_in: refreshed.expires_in,
    refresh_token: Some(refreshed.refresh_token),
    scope: refreshed.scope,
    issued_token_type: None,
  })
}

/// `grant_type=client_credentials`: confidential clients only, access-only.
async fn client_credentials(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let authenticated = d.authenticate().await?;
  let client = authenticated.client;
  require_grant(&client, client_credentials::GRANT_TYPE_CLIENT_CREDENTIALS)?;
  let format = d.require_token_format(&client)?;
  let kind = client_kind(&client)?;
  let proof = d.sender_proof(&client).await?;
  require_dpop_binding(&client, &proof)?;
  let registered = ScopeSet::parse(&client.scope).map_err(|_| AppError::server_error())?;
  let enabled = enabled_scopes(&d.state.pool).await?;
  let mut service = token_service(d.state)?;
  if format == TokenFormat::Jwt {
    service = service.with_jwt_signer(jwt_signer(d.state)?);
  }
  let issued = client_credentials::issue_client_credentials(
    &mut *d.conn,
    d.store,
    &service,
    &ClientCredentialsInput {
      client_id: &client.client_id,
      client_kind: kind,
      client_registered: &registered,
      enabled: &enabled,
      requested_scope: d.form.scope.as_deref(),
      dpop_bound_jkt: None,
      mtls_bound_x5t_s256: client.tls_client_auth_cert_thumbprint.as_deref(),
      proof: &proof,
      aud: d.resources,
      token_format: format,
      now_unix: d.now_unix,
    },
  )
  .await?;
  Ok(TokenResponseBody {
    access_token: issued.access_token,
    token_type: issued.token_type,
    expires_in: issued.expires_in,
    refresh_token: None,
    scope: issued.scope,
    issued_token_type: None,
  })
}

/// `grant_type=urn:ietf:params:oauth:grant-type:device_code`: poll.
async fn device(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let basic = basic_header(d.headers);
  let proof = dpop_proof(d.headers);
  let body_secret = d.form.client_secret.clone().map(SecretString::from);
  let client_id = d
    .form
    .client_id
    .clone()
    .or_else(|| {
      basic.and_then(|header| client_auth::parse_basic_header(header).map(|creds| creds.client_id))
    })
    .unwrap_or_default();
  let candidate = (!client_id.is_empty()).then_some(client_id.clone());
  let format = d
    .gate_candidate_client_format(candidate)
    .await?
    .unwrap_or(TokenFormat::Opaque);
  let jwt = if format == TokenFormat::Jwt {
    Some(jwt_signer(d.state)?)
  } else {
    None
  };
  let mut poll = PollState {
    pool: &d.state.pool,
    conn: &mut *d.conn,
    store: d.store,
    keys: &d.state.keys,
    issuer: &d.state.config.issuer,
    device_ttl: d.state.config.ttl.device,
    interval: Duration::from_secs(DEVICE_INTERVAL_SECS),
    ttl: &d.state.config.ttl,
    token_format: format,
    jwt_signer: jwt,
    cimd: d.cimd,
    now_unix: d.now_unix,
  };
  let inputs = DevicePollInputs {
    client_id: &client_id,
    device_code: d.form.device_code.as_deref().unwrap_or(""),
    basic_header: basic,
    body_secret,
    assertion_type: d.form.client_assertion_type.as_deref(),
    assertion: d.form.client_assertion.as_deref(),
    dpop_proof: proof,
    peer_certs: d.peer_certs,
    aud: d.resources,
  };
  let tokens = device_code::poll_device(&mut poll, &inputs).await?;
  Ok(TokenResponseBody {
    access_token: tokens.access_token,
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    refresh_token: Some(tokens.refresh_token),
    scope: tokens.scope,
    issued_token_type: None,
  })
}

/// `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`: policy gate.
///
/// Token exchange mints an access token, so it is subject to the same
/// per-client `access_token_format` gate as every other minting path: a `jwt`
/// caller while the global switch is off fails closed with
/// `temporarily_unavailable` (503) rather than exchanging. A `jwt` caller
/// with the switch on is rejected the same way (Todo 26): exchange never
/// mints an `act` JWT, so the format gate is a rejection, not a mint branch.
async fn exchange(d: &mut Dispatch<'_>) -> Result<TokenResponseBody, TokenError> {
  let authenticated = d.authenticate().await?;
  let client = authenticated.client;
  require_grant(&client, token_exchange::GRANT_TYPE_TOKEN_EXCHANGE)?;
  match d.require_token_format(&client)? {
    TokenFormat::Opaque => {}
    TokenFormat::Jwt => return Err(AppError::temporarily_unavailable().into()),
  }
  let kind = client_kind(&client)?;
  let proof = d.sender_proof(&client).await?;
  require_dpop_binding(&client, &proof)?;
  let registered = ScopeSet::parse(&client.scope).map_err(|_| AppError::server_error())?;
  let enabled = enabled_scopes(&d.state.pool).await?;
  let service = token_service(d.state)?;
  let subject_token = d.form.subject_token.as_deref().unwrap_or("");
  let entitled = subject_entitlements(d, &service, subject_token).await?;
  let exchanged = token_exchange::exchange(
    &mut *d.conn,
    d.store,
    &service,
    &ExchangeInput {
      caller_client_id: &client.client_id,
      caller_kind: kind,
      caller_dpop_required: client.dpop_bound_access_tokens,
      caller_registered: &registered,
      subject_token,
      subject_token_type: d.form.subject_token_type.as_deref().unwrap_or(""),
      actor_token: d.form.actor_token.as_deref(),
      actor_token_type: d.form.actor_token_type.as_deref(),
      requested_token_type: d.form.requested_token_type.as_deref(),
      requested_scope: d.form.scope.as_deref(),
      subject_user_entitled: &entitled,
      enabled: &enabled,
      allow_exchange: d.state.config.allow_token_exchange,
      allowlist: &d.state.config.token_exchange_allowlist,
      proof: &proof,
      now_unix: d.now_unix,
    },
  )
  .await?;
  Ok(TokenResponseBody {
    access_token: exchanged.access_token,
    token_type: exchanged.token_type,
    expires_in: token_exchange::exchange_ttl(&service).as_secs(),
    refresh_token: None,
    scope: exchanged.scope,
    issued_token_type: Some(token_exchange::TOKEN_TYPE_ACCESS_TOKEN.to_owned()),
  })
}

/// The subject token's user entitlements; empty (fail closed) when the token
/// is unknown, the user is gone, or the subject is a client-credentials
/// principal (bounded by the subject token's own scope).
async fn subject_entitlements(
  d: &mut Dispatch<'_>,
  service: &TokenService,
  subject_token: &str,
) -> Result<ScopeSet, AppError> {
  let Some(found) = service
    .find_access(&mut *d.conn, d.store, subject_token)
    .await
    .map_err(AppError::from)?
  else {
    return Ok(ScopeSet::empty());
  };
  let subject_scope = ScopeSet::parse(&found.record.scope).unwrap_or_else(|_| ScopeSet::empty());
  if found.record.subject.trim().is_empty() {
    return Ok(subject_scope);
  }
  let Some(user) =
    user_repo::find_by_email(&d.state.pool, &d.state.keys, &found.record.subject).await?
  else {
    return Ok(ScopeSet::empty());
  };
  if user.disabled {
    return Ok(ScopeSet::empty());
  }
  let names = user_scope_repo::list_for_user(&d.state.pool, user.id).await?;
  ScopeSet::from_names(&names)
}

//! Authorization-code redemption grant (RFC 9700 §4.5.3, RFC 7636, RFC 9449 §6).
//!
//! `POST /token` with `grant_type=authorization_code` redeems a code issued by
//! [`crate::protocol::code::CodeIssuer`]. The handler authenticates the
//! client, atomically consumes the code (exactly one redemption; a wrong,
//! expired, or already-used code fails with `invalid_grant` and is never
//! re-consumed), then verifies — against the consumed record — the client id,
//! the redirect URI, the PKCE verifier, and the sender binding: a stored
//! DPoP `jkt` must be matched by a freshly verified DPoP proof on this
//! request, and an mTLS-registered client must freshly authenticate its leaf
//! (task-27 records carry no mTLS binding, so mTLS is proven, not matched).
//! Only then is an access token minted — plus a refresh token when the client
//! is registered for the `refresh_token` grant (the minted refresh half is
//! revoked before returning otherwise) — under the code's `grant_id`.

use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use sqlx::PgPool;
use time::OffsetDateTime;

use super::super::dispatch::require_dpop_binding;
use super::super::{ClientKind, MintRequest, SenderProof, TokenService};
use crate::{
  config::TtlConfig,
  crypto::{pkce, tokens as crypto_tokens},
  db::{TokenEndpointAuthMethod, client_repo},
  error::AppError,
  jose::dpop::{DpopRequest, verify_dpop},
  keys::KeyRing,
  protocol::{
    client_auth::{self, AuthContext, AuthStores, ClientAuthRequest},
    mtls,
  },
  state::RedisConn,
  store::{Store, codes},
  tls::PeerCertificates,
};

/// Grant-type value for authorization-code redemption (RFC 6749 §4.1.3).
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";
/// Grant-type value gating refresh-token issuance for this flow.
pub const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";

/// Everything one authorization-code redemption needs.
pub struct CodeGrantState<'a> {
  /// Postgres pool for client lookup and authentication.
  pub pool: &'a PgPool,
  /// Redis connection for code records, DPoP replay markers, and tokens.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
  /// Token-pepper ring for keyed code hashes (newest-first retry).
  pub keys: &'a KeyRing,
  /// Public issuer URL (no trailing slash); scopes the DPoP `htu`.
  pub issuer: &'a str,
  /// Token lifetimes used for the minted pair.
  pub ttl: &'a TtlConfig,
  /// Current time as seconds since the Unix epoch.
  pub now_unix: i64,
}

/// One authorization-code redemption request at the token endpoint.
pub struct CodeGrantInputs<'a> {
  /// The `code` to redeem (raw; never logged).
  pub code: &'a str,
  /// The `redirect_uri` the code was bound to at issuance.
  pub redirect_uri: &'a str,
  /// The `code_verifier` for the stored S256 challenge, when supplied.
  pub code_verifier: Option<&'a str>,
  /// `client_id` from the form body, when present.
  pub client_id: Option<&'a str>,
  /// Raw `Authorization` header, when present.
  pub basic_header: Option<&'a str>,
  /// `client_secret` form field (body only), when present.
  pub body_secret: Option<SecretString>,
  /// `client_assertion_type` form field, when present.
  pub assertion_type: Option<&'a str>,
  /// `client_assertion` form field, when present.
  pub assertion: Option<&'a str>,
  /// Raw `DPoP` header (proof JWT), when present.
  pub dpop_proof: Option<&'a str>,
  /// Verified peer chain injected by the TLS accept loop, when present.
  pub peer_certs: Option<&'a PeerCertificates>,
}

/// Successful authorization-code redemption (RFC 6749 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeTokenResponse {
  /// Opaque access token (raw; stored only as a keyed hash).
  pub access_token: String,
  /// `DPoP` for sender-bound tokens, `Bearer` otherwise.
  pub token_type: String,
  /// Access-token lifetime, seconds.
  pub expires_in: u64,
  /// Opaque refresh token, absent when the client may not use the
  /// `refresh_token` grant (the minted half is revoked, never leaked).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub refresh_token: Option<String>,
  /// Space-joined scope granted with the code.
  pub scope: String,
}

/// Redeem an authorization code at the token endpoint (RFC 9700 §4.5.3).
///
/// The client is authenticated, then the code is consumed atomically bound to
/// the expected client id, redirect URI, and PKCE challenge: a foreign or
/// mismatched presentation observes `Mismatched` and the victim record
/// survives for its legitimate presenter, so a wrong, expired, or
/// already-redeemed code fails with `invalid_grant` without ever burning a
/// live value. The consumed record then feeds the sender-binding checks
/// before anything is minted. Tokens join the code's `grant_id` chain.
///
/// # Errors
///
/// Returns `invalid_client` for authentication failures, `invalid_grant` for
/// unknown/consumed codes and every binding mismatch, `invalid_dpop_proof`
/// for a missing or bad DPoP proof, `unauthorized_client` when the client
/// may not use this grant, and `server_error` for store corruption.
pub async fn redeem_code(
  state: &mut CodeGrantState<'_>,
  inputs: &CodeGrantInputs<'_>,
) -> Result<CodeTokenResponse, AppError> {
  if inputs.code.trim().is_empty() {
    return Err(AppError::invalid_request("code is required"));
  }
  // draft-ietf-oauth-v2-1-16 §4.1.3 and §10.2: `redirect_uri` is
  // accept-but-ignore at the token endpoint. An absent or empty value skips
  // the binding check; a supplied value must still match exactly.
  let redirect_binding = if inputs.redirect_uri.trim().is_empty() {
    None
  } else {
    Some(inputs.redirect_uri)
  };
  let used_basic = inputs.basic_header.is_some();
  let unknown_client = || {
    if used_basic {
      AppError::invalid_client_basic()
    } else {
      AppError::invalid_client_non_basic()
    }
  };

  let candidate_id = candidate_client_id(inputs).ok_or_else(unknown_client)?;
  let client = client_repo::find_active_by_client_id(state.pool, state.keys, candidate_id.as_str())
    .await?
    .ok_or_else(unknown_client)?;
  if !client
    .grant_types
    .iter()
    .any(|grant| grant == GRANT_TYPE_AUTHORIZATION_CODE)
  {
    return Err(AppError::unauthorized_client(
      "client may not use the authorization_code grant",
    ));
  }

  let verifier = inputs
    .code_verifier
    .filter(|value| !value.is_empty())
    .ok_or_else(|| AppError::invalid_grant("code_verifier does not match code_challenge"))?;
  let expected_challenge = pkce::challenge_from_verifier(verifier)
    .map_err(|_| AppError::invalid_grant("code_verifier does not match code_challenge"))?;
  let record = consume_code(
    state,
    inputs.code.trim(),
    client.client_id.as_str(),
    redirect_binding,
    expected_challenge.as_str(),
  )
  .await?;

  let proofs = fresh_proofs(state, &client, inputs, used_basic).await?;
  require_dpop_binding(&client, &proofs)?;
  if let Some(want) = non_empty(&record.cnf) {
    if proofs.dpop_jkt.as_deref().unwrap_or("") != want {
      return Err(AppError::invalid_grant(
        "DPoP binding does not match this grant",
      ));
    }
  } else if client_kind_of(&client)? == ClientKind::Public {
    return Err(AppError::invalid_grant(
      "public client grant is missing its DPoP binding",
    ));
  }

  let kind = client_kind_of(&client)?;
  let service = TokenService::new(state.ttl, state.keys).map_err(AppError::internal)?;
  let minted = service
    .mint(
      state.conn,
      state.store,
      &MintRequest {
        client_id: client.client_id.clone(),
        client_kind: kind,
        subject: record.subject.clone(),
        scope: record.scope.clone(),
        grant_id: record.grant_id.clone(),
        proof: proofs,
      },
      state.now_unix,
    )
    .await
    .map_err(AppError::from)?;

  let refresh_token = if client
    .grant_types
    .iter()
    .any(|grant| grant == GRANT_TYPE_REFRESH_TOKEN)
  {
    Some(minted.refresh_token)
  } else {
    service
      .revoke_token(state.conn, state.store, &minted.refresh_token)
      .await
      .map_err(AppError::from)?;
    None
  };

  Ok(CodeTokenResponse {
    token_type: if minted.cnf.jkt.is_some() {
      "DPoP".to_owned()
    } else {
      "Bearer".to_owned()
    },
    expires_in: state.ttl.access.as_secs(),
    access_token: minted.access_token,
    refresh_token,
    scope: record.scope,
  })
}

/// Resolve the authenticating client id: the Basic header wins when present
/// (a conflicting body id fails closed); otherwise the body id is required.
fn candidate_client_id(inputs: &CodeGrantInputs<'_>) -> Option<String> {
  if let Some(header) = inputs.basic_header {
    let creds = client_auth::parse_basic_header(header)?;
    if let Some(body_id) = inputs.client_id
      && body_id != creds.client_id
    {
      return None;
    }
    Some(creds.client_id)
  } else {
    inputs.client_id.map(str::to_owned)
  }
}

/// Atomically consume a code bound to its expected presenter values.
///
/// The expected client id, redirect URI, and PKCE challenge travel inside the
/// consume script: only the hash under the issuing generation names an
/// existing key, and a generation holding the record but observing a binding
/// mismatch reports `Mismatched` without deleting anything, so exactly one
/// matching caller across all generations observes the record while a foreign
/// presentation leaves the victim value live.
async fn consume_code(
  state: &mut CodeGrantState<'_>,
  code: &str,
  expected_client_id: &str,
  expected_redirect_uri: Option<&str>,
  expected_challenge: &str,
) -> Result<codes::CodeRecord, AppError> {
  for (id, secret) in state
    .keys
    .peppers_newest_first()
    .take(crypto_tokens::MAX_RETAINED_KEYS)
  {
    let hash = crypto_tokens::token_hash(
      &crypto_tokens::KeyId::new(id.as_str()),
      secret.expose_secret().as_bytes(),
      code,
    )
    .to_storage_string();
    let mut expected = vec![
      ("client_id", expected_client_id),
      ("code_challenge", expected_challenge),
    ];
    if let Some(redirect_uri) = expected_redirect_uri {
      expected.push(("redirect_uri", redirect_uri));
    }
    match codes::consume_bound(state.conn, state.store, &hash, &expected)
      .await
      .map_err(AppError::from)?
    {
      codes::ConsumeOutcome::Consumed(record) => return Ok(record),
      codes::ConsumeOutcome::Mismatched => {
        return Err(AppError::invalid_grant(
          "authorization code is invalid or expired",
        ));
      }
      codes::ConsumeOutcome::Absent => {}
    }
  }
  Err(AppError::invalid_grant(
    "authorization code is invalid or expired",
  ))
}

/// Public clients carry no secret; every other registered method is
/// confidential for the sender-constraint matrix.
fn client_kind_of(client: &client_repo::Client) -> Result<ClientKind, AppError> {
  match client.auth_method() {
    Ok(TokenEndpointAuthMethod::None) => Ok(ClientKind::Public),
    Ok(_) => Ok(ClientKind::Confidential),
    Err(_) => Err(AppError::invalid_client_non_basic()),
  }
}

/// Treat `None` and `""` alike: an absent parameter.
fn non_empty(value: &str) -> Option<&str> {
  if value.is_empty() { None } else { Some(value) }
}

/// Authenticate the client and verify its fresh sender proofs.
///
/// Secret/assertion clients prove themselves through the shared dispatch;
/// mTLS clients authenticate their leaf; public clients must present no
/// secret and must carry a DPoP proof. A presented DPoP proof is always
/// verified (its `jkt` later binds the minted token).
async fn fresh_proofs(
  state: &mut CodeGrantState<'_>,
  client: &client_repo::Client,
  inputs: &CodeGrantInputs<'_>,
  used_basic: bool,
) -> Result<SenderProof, AppError> {
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
        return Err(unknown_client());
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
    TokenEndpointAuthMethod::None => Some(
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

/// Prove a secret/assertion client through the shared dispatch.
///
/// The returned row is discarded: the caller already owns the client record,
/// and this call exists only for its proof.
async fn authenticate_confidential(
  state: &mut CodeGrantState<'_>,
  client: &client_repo::Client,
  inputs: &CodeGrantInputs<'_>,
) -> Result<(), AppError> {
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
  };
  client_auth::authenticate_client(&mut auth, &auth_ctx, &request).await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  //! `test(grant_code)` suite: happy paths, single-use, and binding checks.
  //!
  //! Live Postgres (client registry) plus the shared compose Redis, isolated
  //! per test by a unique `{state}`/`{rl}` prefix pair.
  //! Codes are issued through [`crate::protocol::code::CodeIssuer`] so the
  //! keyed-hash path is exercised end to end; every negative test issues a
  //! fresh code because redemption consumes exactly once.

  use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
  };

  use secrecy::SecretString;

  use super::{CodeGrantInputs, CodeGrantState, CodeTokenResponse, GRANT_TYPE_REFRESH_TOKEN};
  use crate::{
    config::{DurabilityMode, TtlConfig},
    crypto::{
      secret::{Argon2Params, hash_secret},
      tokens as crypto_tokens,
    },
    db::{NewClient, TokenEndpointAuthMethod, client_repo},
    error::{AppError, OAuthErrorCode},
    keys::{KeyId, KeyRing, KeyRingError},
    protocol::{
      code::{CodeClientKind, CodeIssueRequest, CodeIssuer, IssuedCode},
      scope::ScopeSet,
      token::TokenService,
    },
    state::RedisConn,
    store::Store,
  };

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult = Result<(), TestError>;

  /// Errors raised by the authorization-code test scaffolding itself.
  #[derive(Debug, thiserror::Error)]
  enum TestError {
    /// A Redis command failed.
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    /// A database operation failed.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// A store operation failed.
    #[error("store error: {0}")]
    Store(#[from] crate::store::StoreError),
    /// The token service failed.
    #[error("service error: {0}")]
    Service(#[from] crate::protocol::token::TokenServiceError),
    /// The key ring was rejected.
    #[error("keys error: {0}")]
    Keys(#[from] KeyRingError),
    /// A code issuance failed.
    #[error("issuance error: {0}")]
    Issue(#[from] crate::protocol::code::CodeIssueError),
    /// A scope value did not parse.
    #[error("scope error: {0}")]
    Scope(#[from] AppError),
    /// A JWT operation failed.
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// A JWK helper failed.
    #[error("jwk error: {0}")]
    Jwk(#[from] crate::jose::jwk::JwkError),
    /// Test key generation was rejected.
    #[error("test key generation failed: {0}")]
    KeyGen(String),
    /// A test assertion observed an unexpected value.
    #[error("unexpected test value: {0}")]
    Unexpected(String),
  }

  /// RFC 7636 Appendix B vector: the verifier every happy path redeems with.
  const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  /// S256 challenge bound into every test code.
  const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  /// Redirect URI every test code is bound to.
  const REDIRECT: &str = "https://app.example.test/cb";
  /// Public issuer scoping DPoP `htu` values.
  const ISSUER: &str = "https://auth.example.test";

  static NONCE: AtomicU64 = AtomicU64::new(31_000);

  fn unique(label: &str) -> String {
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    format!("grant-code-test-{n}-{label}")
  }

  fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
  }

  /// Live handles for one test.
  struct Harness {
    _db: crate::test_guard::Lease<crate::db::test_support::Db>,
    pool: sqlx::PgPool,
    conn: RedisConn,
    store: Store,
    ring: KeyRing,
    ttl: TtlConfig,
  }

  async fn harness() -> Result<Harness, TestError> {
    let (db, pool) = crate::db::test_support::migrated_pool()
      .await
      .map_err(|error| TestError::Unexpected(format!("pg: {error}")))?;
    let manager = crate::test_support::redis_manager()
      .await
      .map_err(|error| TestError::Unexpected(format!("redis: {error}")))?;
    let (state_prefix, rl_prefix) = crate::test_support::unique_prefixes();
    let ring = KeyRing::from_parts(
      vec![(
        KeyId::new("v1"),
        SecretString::from("grant-code-test-pepper"),
      )],
      vec![(KeyId::new("v1"), SecretString::from("grant-code-test-totp"))],
      vec![(KeyId::new("v1"), SecretString::from("grant-code-test-pii"))],
    )?;
    Ok(Harness {
      _db: db,
      pool,
      conn: RedisConn::Single(manager),
      store: Store::from_parts(state_prefix, rl_prefix, DurabilityMode::WaitAof),
      ring,
      ttl: TtlConfig::default(),
    })
  }

  /// Register a client with the given method, secret, grants, and scope.
  async fn insert_client(
    h: &Harness,
    client_id: &str,
    method: TokenEndpointAuthMethod,
    secret: Option<&str>,
    grants: &[&str],
  ) -> TestResult {
    let params =
      Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
    let secret_hash = secret
      .map(|value| hash_secret(value, &params))
      .transpose()
      .map_err(|error| TestError::KeyGen(format!("{error:?}")))?;
    let new = NewClient {
      id: uuid::Uuid::new_v4(),
      client_id: client_id.to_owned(),
      client_secret_hash: secret_hash,
      client_secret_expires_at: None,
      client_name: format!("{client_id} name"),
      grant_types: grants.iter().map(|grant| (*grant).to_owned()).collect(),
      response_types: Vec::new(),
      scope: "orders:read".to_owned(),
      token_endpoint_auth_method: method.as_str().to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      registration_access_token_hash: None,
    };
    client_repo::insert(&h.pool, &h.ring, false, &new).await?;
    Ok(())
  }

  /// Issue a code through the real issuer over the harness ring.
  async fn issue_code(
    h: &mut Harness,
    client_id: &str,
    kind: CodeClientKind,
    jkt: Option<&str>,
  ) -> Result<IssuedCode, TestError> {
    let issuer = CodeIssuer::new(&h.ttl, &h.ring)?;
    let approved = ScopeSet::parse("orders:read")?;
    let entitled = ScopeSet::parse("orders:read orders:admin")?;
    let request = CodeIssueRequest {
      client_id,
      client_kind: kind,
      user_id: "user-1",
      redirect_uri: REDIRECT,
      approved_scope: &approved,
      user_entitled: &entitled,
      code_challenge: CHALLENGE,
      dpop_jkt: jkt,
      state: None,
      issuer: ISSUER,
    };
    Ok(issuer.issue(&mut h.conn, &h.store, &request).await?)
  }

  /// Redeem through the grant at a pinned time.
  async fn redeem_once(
    h: &mut Harness,
    inputs: &CodeGrantInputs<'_>,
    now: i64,
  ) -> Result<CodeTokenResponse, AppError> {
    let mut state = CodeGrantState {
      pool: &h.pool,
      conn: &mut h.conn,
      store: &h.store,
      keys: &h.ring,
      issuer: ISSUER,
      ttl: &h.ttl,
      now_unix: now,
    };
    super::redeem_code(&mut state, inputs).await
  }

  fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
  }

  /// A fresh ES256 signing key plus its public JWK for DPoP proofs.
  struct TestKey {
    encoding: jsonwebtoken::EncodingKey,
    jwk: serde_json::Value,
  }

  fn fresh_key() -> Result<TestKey, TestError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::{
      rand::SystemRandom,
      signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
    };

    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
      .map_err(|error| TestError::KeyGen(format!("generate: {error:?}")))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
      .map_err(|error| TestError::KeyGen(format!("parse: {error:?}")))?;
    let raw = pair.public_key().as_ref();
    let x = raw
      .get(1..33)
      .ok_or_else(|| TestError::Unexpected("bad ec key".to_owned()))?;
    let y = raw
      .get(33..65)
      .ok_or_else(|| TestError::Unexpected("bad ec key".to_owned()))?;
    Ok(TestKey {
      encoding: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()),
      jwk: serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
      }),
    })
  }

  fn mint_proof(key: &TestKey, jti: &str, iat: i64) -> Result<String, TestError> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_owned());
    let htu = crate::protocol::client_auth::token_endpoint(ISSUER);
    let claims = serde_json::json!({
      "htm": "POST",
      "htu": htu,
      "iat": iat,
      "jti": jti,
      "jwk": key.jwk,
    });
    Ok(jsonwebtoken::encode(&header, &claims, &key.encoding)?)
  }

  fn is_invalid_grant(error: &AppError) -> bool {
    error.code() == OAuthErrorCode::InvalidGrant
  }

  #[tokio::test]
  async fn test_grant_code_confidential_happy_issues_pair() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("conf");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    let issued = issue_code(&mut h, &client_id, CodeClientKind::Confidential, None).await?;
    let now = now_unix();

    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: Some(secret("code-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    let tokens = redeem_once(&mut h, &inputs, now)
      .await
      .map_err(|error| TestError::Unexpected(format!("happy redemption rejected: {error}")))?;
    if tokens.token_type != "Bearer"
      || tokens.scope != "orders:read"
      || tokens.expires_in != h.ttl.access.as_secs()
      || tokens.access_token.is_empty()
      || tokens.access_token == tokens.refresh_token.clone().unwrap_or_default()
    {
      return Err(TestError::Unexpected(
        "happy redemption must return a Bearer pair with the granted scope".to_owned(),
      ));
    }
    let refresh = tokens
      .refresh_token
      .ok_or_else(|| TestError::Unexpected("refresh must issue when allowed".to_owned()))?;

    let service = TokenService::new(&h.ttl, &h.ring)?;
    let found = service
      .find_access(&mut h.conn, &h.store, &tokens.access_token)
      .await?
      .ok_or_else(|| TestError::Unexpected("access token must resolve".to_owned()))?;
    if found.record.subject != "user-1"
      || found.record.grant_id != issued.grant_id
      || found.record.scope != "orders:read"
      || found.record.client_id != client_id
    {
      return Err(TestError::Unexpected(
        "access record must bind subject, grant, scope, and client".to_owned(),
      ));
    }
    if service
      .find_refresh(&mut h.conn, &h.store, &refresh)
      .await?
      .is_none()
    {
      return Err(TestError::Unexpected(
        "refresh token must resolve".to_owned(),
      ));
    }
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_public_dpop_happy_then_replay_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("public");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::None,
      None,
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    let key = fresh_key()?;
    let jkt = crate::jose::jwk::thumbprint(&key.jwk)?;
    let issued = issue_code(&mut h, &client_id, CodeClientKind::Public, Some(&jkt)).await?;
    let now = now_unix();

    let proof = mint_proof(&key, &unique("jti"), now)?;
    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: None,
      assertion_type: None,
      assertion: None,
      dpop_proof: Some(proof.as_str()),
      peer_certs: None,
    };
    let tokens = redeem_once(&mut h, &inputs, now)
      .await
      .map_err(|error| TestError::Unexpected(format!("public redemption rejected: {error}")))?;
    if tokens.token_type != "DPoP" || tokens.refresh_token.is_none() {
      return Err(TestError::Unexpected(
        "public redemption must return a DPoP pair".to_owned(),
      ));
    }

    let replay_proof = mint_proof(&key, &unique("jti"), now + 5)?;
    let replay = CodeGrantInputs {
      dpop_proof: Some(replay_proof.as_str()),
      ..inputs_clone(&inputs)
    };
    match redeem_once(&mut h, &replay, now + 5).await {
      Err(error) if is_invalid_grant(&error) => Ok(()),
      Err(other) => Err(TestError::Unexpected(format!(
        "consumed code must be invalid_grant, got {other}"
      ))),
      Ok(_) => Err(TestError::Unexpected(
        "a code must redeem exactly once".to_owned(),
      )),
    }
  }

  /// Rebuild inputs sharing the same borrowed values (lifetimes are explicit
  /// so a fresh proof can replace the consumed one).
  fn inputs_clone<'a>(inputs: &CodeGrantInputs<'a>) -> CodeGrantInputs<'a> {
    CodeGrantInputs {
      code: inputs.code,
      redirect_uri: inputs.redirect_uri,
      code_verifier: inputs.code_verifier,
      client_id: inputs.client_id,
      basic_header: inputs.basic_header,
      body_secret: inputs.body_secret.clone(),
      assertion_type: inputs.assertion_type,
      assertion: inputs.assertion,
      dpop_proof: inputs.dpop_proof,
      peer_certs: inputs.peer_certs,
    }
  }

  #[tokio::test]
  async fn test_grant_code_wrong_redirect_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("conf");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    let issued = issue_code(&mut h, &client_id, CodeClientKind::Confidential, None).await?;
    let now = now_unix();

    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: "https://app.example.test/other",
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: Some(secret("code-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    match redeem_once(&mut h, &inputs, now).await {
      Err(error) if is_invalid_grant(&error) => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!(
          "wrong redirect must be invalid_grant, got {other}"
        )));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(
          "a redirect mismatch must never mint".to_owned(),
        ));
      }
    }
    // The mismatched attempt must not burn the victim value: the legitimate
    // presenter redeems the same code on retry.
    let retry = CodeGrantInputs {
      redirect_uri: REDIRECT,
      ..inputs_clone(&inputs)
    };
    redeem_once(&mut h, &retry, now + 1)
      .await
      .map_err(|error| {
        TestError::Unexpected(format!("mismatched redirect burned the code: {error}"))
      })?;
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_missing_redirect_accepted() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("no-redirect");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    for redirect_uri in ["", "   "] {
      let issued = issue_code(&mut h, &client_id, CodeClientKind::Confidential, None).await?;
      let inputs = CodeGrantInputs {
        code: issued.code.as_str(),
        redirect_uri,
        code_verifier: Some(VERIFIER),
        client_id: Some(client_id.as_str()),
        basic_header: None,
        body_secret: Some(secret("code-secret")),
        assertion_type: None,
        assertion: None,
        dpop_proof: None,
        peer_certs: None,
      };
      redeem_once(&mut h, &inputs, now_unix())
        .await
        .map_err(|error| {
          TestError::Unexpected(format!("missing redirect_uri must redeem, got {error}"))
        })?;
    }
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_wrong_client_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_a = unique("a");
    let client_b = unique("b");
    for client_id in [&client_a, &client_b] {
      insert_client(
        &h,
        client_id,
        TokenEndpointAuthMethod::ClientSecretPost,
        Some("shared-secret"),
        &[
          super::GRANT_TYPE_AUTHORIZATION_CODE,
          GRANT_TYPE_REFRESH_TOKEN,
        ],
      )
      .await?;
    }
    let issued = issue_code(&mut h, &client_a, CodeClientKind::Confidential, None).await?;

    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_b.as_str()),
      basic_header: None,
      body_secret: Some(secret("shared-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    match redeem_once(&mut h, &inputs, now_unix()).await {
      Err(error) if is_invalid_grant(&error) => Ok(()),
      Err(other) => Err(TestError::Unexpected(format!(
        "foreign client must be invalid_grant, got {other}"
      ))),
      Ok(_) => Err(TestError::Unexpected(
        "a code must never redeem for another client".to_owned(),
      )),
    }
  }

  #[tokio::test]
  async fn test_grant_code_foreign_client_does_not_consume_victim_code() -> TestResult {
    let mut h = harness().await?;
    let client_a = unique("victim");
    let client_b = unique("foreign");
    for client_id in [&client_a, &client_b] {
      insert_client(
        &h,
        client_id,
        TokenEndpointAuthMethod::ClientSecretPost,
        Some("shared-secret"),
        &[
          super::GRANT_TYPE_AUTHORIZATION_CODE,
          GRANT_TYPE_REFRESH_TOKEN,
        ],
      )
      .await?;
    }
    let issued = issue_code(&mut h, &client_a, CodeClientKind::Confidential, None).await?;
    let now = now_unix();

    let foreign = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_b.as_str()),
      basic_header: None,
      body_secret: Some(secret("shared-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    match redeem_once(&mut h, &foreign, now).await {
      Err(error) if is_invalid_grant(&error) => {}
      Err(other) => {
        return Err(TestError::Unexpected(format!(
          "foreign client must be invalid_grant, got {other}"
        )));
      }
      Ok(_) => {
        return Err(TestError::Unexpected(
          "a code must never redeem for another client".to_owned(),
        ));
      }
    }

    let legitimate = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_a.as_str()),
      basic_header: None,
      body_secret: Some(secret("shared-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    redeem_once(&mut h, &legitimate, now + 1)
      .await
      .map_err(|error| {
        TestError::Unexpected(format!("victim code burned by foreign use: {error}"))
      })?;
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_wrong_verifier_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("conf");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    let now = now_unix();

    for verifier in [Some("aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), None] {
      let issued = issue_code(&mut h, &client_id, CodeClientKind::Confidential, None).await?;
      let inputs = CodeGrantInputs {
        code: issued.code.as_str(),
        redirect_uri: REDIRECT,
        code_verifier: verifier,
        client_id: Some(client_id.as_str()),
        basic_header: None,
        body_secret: Some(secret("code-secret")),
        assertion_type: None,
        assertion: None,
        dpop_proof: None,
        peer_certs: None,
      };
      match redeem_once(&mut h, &inputs, now).await {
        Err(error) if is_invalid_grant(&error) => {}
        Err(other) => {
          return Err(TestError::Unexpected(format!(
            "bad verifier must be invalid_grant, got {other}"
          )));
        }
        Ok(_) => {
          return Err(TestError::Unexpected(
            "a PKCE mismatch must never mint".to_owned(),
          ));
        }
      }
    }
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_dpop_mismatch_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("public");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::None,
      None,
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;
    let bound = fresh_key()?;
    let other = fresh_key()?;
    let jkt = crate::jose::jwk::thumbprint(&bound.jwk)?;
    let issued = issue_code(&mut h, &client_id, CodeClientKind::Public, Some(&jkt)).await?;
    let now = now_unix();

    let proof = mint_proof(&other, &unique("jti"), now)?;
    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: None,
      assertion_type: None,
      assertion: None,
      dpop_proof: Some(proof.as_str()),
      peer_certs: None,
    };
    match redeem_once(&mut h, &inputs, now).await {
      Err(error) if is_invalid_grant(&error) => Ok(()),
      Err(other) => Err(TestError::Unexpected(format!(
        "DPoP mismatch must be invalid_grant, got {other}"
      ))),
      Ok(_) => Err(TestError::Unexpected(
        "a DPoP mismatch must never mint".to_owned(),
      )),
    }
  }

  #[tokio::test]
  async fn test_grant_code_unknown_code_rejected() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("conf");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[
        super::GRANT_TYPE_AUTHORIZATION_CODE,
        GRANT_TYPE_REFRESH_TOKEN,
      ],
    )
    .await?;

    let inputs = CodeGrantInputs {
      code: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: Some(secret("code-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    match redeem_once(&mut h, &inputs, now_unix()).await {
      Err(error) if is_invalid_grant(&error) => Ok(()),
      Err(other) => Err(TestError::Unexpected(format!(
        "unknown code must be invalid_grant, got {other}"
      ))),
      Ok(_) => Err(TestError::Unexpected(
        "an unknown code must never mint".to_owned(),
      )),
    }
  }

  #[tokio::test]
  async fn test_grant_code_no_refresh_when_grant_disallowed() -> TestResult {
    let mut h = harness().await?;
    let client_id = unique("norefresh");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::ClientSecretPost,
      Some("code-secret"),
      &[super::GRANT_TYPE_AUTHORIZATION_CODE],
    )
    .await?;
    let issued = issue_code(&mut h, &client_id, CodeClientKind::Confidential, None).await?;

    let inputs = CodeGrantInputs {
      code: issued.code.as_str(),
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: Some(secret("code-secret")),
      assertion_type: None,
      assertion: None,
      dpop_proof: None,
      peer_certs: None,
    };
    let tokens = redeem_once(&mut h, &inputs, now_unix())
      .await
      .map_err(|error| TestError::Unexpected(format!("redemption rejected: {error}")))?;
    if tokens.refresh_token.is_some() {
      return Err(TestError::Unexpected(
        "no refresh_token grant must mean no refresh token".to_owned(),
      ));
    }
    let service = TokenService::new(&h.ttl, &h.ring)?;
    if service
      .find_access(&mut h.conn, &h.store, &tokens.access_token)
      .await?
      .is_none()
    {
      return Err(TestError::Unexpected(
        "access token must still resolve".to_owned(),
      ));
    }
    Ok(())
  }

  #[tokio::test]
  async fn test_grant_code_public_empty_cnf_is_invalid_grant() -> TestResult {
    use secrecy::ExposeSecret as _;

    let mut h = harness().await?;
    let client_id = unique("public-empty-cnf");
    insert_client(
      &h,
      &client_id,
      TokenEndpointAuthMethod::None,
      None,
      &[super::GRANT_TYPE_AUTHORIZATION_CODE],
    )
    .await?;
    let key = fresh_key()?;
    let raw = "empty-cnf-code";
    let (key_id, secret) = h
      .ring
      .peppers_newest_first()
      .next()
      .ok_or_else(|| TestError::Unexpected("no pepper configured".to_owned()))?;
    let hash = crypto_tokens::token_hash(
      &crypto_tokens::KeyId::new(key_id.as_str()),
      secret.expose_secret().as_bytes(),
      raw,
    )
    .to_storage_string();
    let record = crate::store::codes::CodeRecord {
      client_id: client_id.clone(),
      redirect_uri: REDIRECT.to_owned(),
      scope: "orders:read".to_owned(),
      code_challenge: CHALLENGE.to_owned(),
      subject: "user-1".to_owned(),
      grant_id: "grant-empty-cnf".to_owned(),
      cnf: String::new(),
    };
    crate::store::codes::issue(
      &mut h.conn,
      &h.store,
      &hash,
      &record,
      Duration::from_secs(60),
    )
    .await?;

    let now = now_unix();
    let proof = mint_proof(&key, &unique("jti"), now)?;
    let inputs = CodeGrantInputs {
      code: raw,
      redirect_uri: REDIRECT,
      code_verifier: Some(VERIFIER),
      client_id: Some(client_id.as_str()),
      basic_header: None,
      body_secret: None,
      assertion_type: None,
      assertion: None,
      dpop_proof: Some(proof.as_str()),
      peer_certs: None,
    };
    match redeem_once(&mut h, &inputs, now).await {
      Err(error) if is_invalid_grant(&error) => Ok(()),
      Err(other) => Err(TestError::Unexpected(format!(
        "empty cnf on a public client must be invalid_grant, got {other}"
      ))),
      Ok(_) => Err(TestError::Unexpected(
        "an empty public binding must never mint".to_owned(),
      )),
    }
  }
}

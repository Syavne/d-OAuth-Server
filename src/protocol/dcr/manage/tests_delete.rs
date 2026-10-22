//! `test(dcr_manage)` delete suite: cross-client denial, DELETE, revocation,
//! and Redis-loss survival.

use secrecy::SecretString;
use testcontainers::{
  GenericImage, ImageExt as _,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use uuid::Uuid;

use super::delete::delete_client;
use super::read_client;
use super::support::{
  Harness, TestError, TestResult, expect_app_error, expect_forbidden, expect_unauthorized, harness,
  harness_with_redis, manage_parts, mtls_request, register, register_mtls, try_register,
};
use crate::config::{JwtSigningAlg, JwtSigningKey};
use crate::db::client_repo::{self, NewClient};
use crate::error::OAuthErrorCode;
use crate::jose::jwt_access::JwtAccessSigner;
use crate::keys::KeyId;
use crate::protocol::scope::ScopeSet;
use crate::protocol::token::grants::client_credentials::{
  ClientCredentialsInput, issue_client_credentials,
};
use crate::protocol::token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService};

#[tokio::test]
async fn dcr_manage_cross_client_forbidden() -> TestResult {
  let mut harness = harness("catalog").await?;
  let first = register(&mut harness, "https://app.example.test/a", None).await?;
  let second = register(&mut harness, "https://app.example.test/b", None).await?;

  let request = crate::protocol::dcr::RegisterRequest {
    redirect_uris: Some(vec!["https://app.example.test/b".to_owned()]),
    client_name: Some("attacker rename".to_owned()),
    token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    dpop_bound_access_tokens: Some(true),
    contacts: None,
    request_uris: None,
    software_id: None,
  };

  let (mut stores, ctx) = manage_parts(&mut harness);
  match read_client(&mut stores, &ctx, &second.client_id, Some(&first.reg_token)).await {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "cross-client read succeeded".to_owned(),
      ));
    }
    Err(error) => expect_forbidden(error)?,
  }

  let (mut stores, ctx) = manage_parts(&mut harness);
  match super::update::update_client(
    &mut stores,
    &ctx,
    &second.client_id,
    Some(&first.reg_token),
    &request,
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "cross-client update succeeded".to_owned(),
      ));
    }
    Err(error) => expect_forbidden(error)?,
  }

  let (mut stores, ctx) = manage_parts(&mut harness);
  match delete_client(&mut stores, &ctx, &second.client_id, Some(&first.reg_token)).await {
    Ok(()) => {
      return Err(TestError::Unexpected(
        "cross-client delete succeeded".to_owned(),
      ));
    }
    Err(error) => expect_forbidden(error)?,
  }

  let row =
    client_repo::find_active_by_client_id(&harness.pool, &harness.config.keys, &second.client_id)
      .await?;
  if row.is_none() {
    return Err(TestError::Unexpected(
      "victim client changed by cross-client calls".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_delete_deactivates() -> TestResult {
  let mut harness = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }

  if client_repo::find_active_by_client_id(
    &harness.pool,
    &harness.config.keys,
    &registered.client_id,
  )
  .await?
  .is_some()
  {
    return Err(TestError::Unexpected(
      "deleted client still active".to_owned(),
    ));
  }
  let listed = client_repo::list(&harness.pool, &harness.config.keys, true).await?;
  let kept = listed
    .iter()
    .find(|row| row.client_id == registered.client_id)
    .ok_or_else(|| TestError::Unexpected("deleted row missing from list".to_owned()))?;
  if kept.active {
    return Err(TestError::Unexpected(
      "deleted row still flagged active".to_owned(),
    ));
  }

  let (mut stores, ctx) = manage_parts(&mut harness);
  match read_client(
    &mut stores,
    &ctx,
    &registered.client_id,
    Some(&registered.reg_token),
  )
  .await
  {
    Ok(_) => Err(TestError::Unexpected(
      "read after delete succeeded".to_owned(),
    )),
    Err(error) => expect_unauthorized(error),
  }
}

#[tokio::test]
async fn dcr_manage_delete_revokes_tokens() -> TestResult {
  let mut harness = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;
  let other = register(&mut harness, "https://app.example.test/other", None).await?;

  let service = TokenService::new(&harness.config.ttl, &harness.config.keys)
    .map_err(|error| TestError::Unexpected(format!("token service: {error}")))?;
  let now = time::OffsetDateTime::now_utc().unix_timestamp();
  let mut victim_hashes: Vec<String> = Vec::new();
  for _ in 0..2 {
    let minted = service
      .mint(
        &mut harness.conn,
        &harness.store,
        &MintRequest {
          client_id: registered.client_id.clone(),
          client_kind: ClientKind::Confidential,
          dpop_required: false,
          subject: String::new(),
          scope: String::new(),
          access_scope: String::new(),
          grant_id: Uuid::new_v4().to_string(),
          proof: SenderProof::none(),
          aud: Vec::new(),
          refresh_aud: Vec::new(),
          format: TokenFormat::Opaque,
        },
        now,
      )
      .await
      .map_err(|error| TestError::Unexpected(format!("mint failed: {error}")))?;
    victim_hashes.push(minted.access_hash);
    victim_hashes.push(minted.refresh_hash);
  }
  let survivor = service
    .mint(
      &mut harness.conn,
      &harness.store,
      &MintRequest {
        client_id: other.client_id.clone(),
        client_kind: ClientKind::Confidential,
        dpop_required: false,
        subject: String::new(),
        scope: String::new(),
        access_scope: String::new(),
        grant_id: Uuid::new_v4().to_string(),
        proof: SenderProof::none(),
        aud: Vec::new(),
        refresh_aud: Vec::new(),
        format: TokenFormat::Opaque,
      },
      now,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("mint failed: {error}")))?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }

  for hash in &victim_hashes {
    let access = crate::store::tokens::get_access(&mut harness.conn, &harness.store, hash)
      .await
      .map_err(|error| TestError::Unexpected(format!("lookup failed: {error}")))?;
    let refresh = crate::store::tokens::get_refresh(&mut harness.conn, &harness.store, hash)
      .await
      .map_err(|error| TestError::Unexpected(format!("lookup failed: {error}")))?;
    if access.is_some() || refresh.is_some() {
      return Err(TestError::Unexpected(
        "deleted client's token survived".to_owned(),
      ));
    }
  }
  let live =
    crate::store::tokens::get_access(&mut harness.conn, &harness.store, &survivor.access_hash)
      .await
      .map_err(|error| TestError::Unexpected(format!("lookup failed: {error}")))?;
  if live.is_none() {
    return Err(TestError::Unexpected(
      "unrelated client's token was revoked".to_owned(),
    ));
  }
  Ok(())
}

/// RFC 7592 DELETE must also remove the JWT allowlist marker. A
/// client-credentials token has no refresh half (the grant revokes it before
/// returning), so the access scan is the only path that can delete its
/// `jwt:<jti-hash>` marker.
#[tokio::test]
async fn dcr_manage_delete_removes_jwt_marker() -> TestResult {
  let mut harness = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;
  let raw_key = SecretString::from("bcdefghijklmnopqrstuvwxyzabcdefg");
  let key = JwtSigningKey::from_raw(
    KeyId::new("test-kid"),
    JwtSigningAlg::Es256,
    &raw_key,
    "jwt_signing_key",
  )
  .map_err(|error| TestError::Unexpected(format!("signing key rejected: {error}")))?;
  let signer = JwtAccessSigner::new(harness.config.issuer.clone(), key, Vec::new());
  let service = TokenService::new(&harness.config.ttl, &harness.config.keys)
    .map_err(|error| TestError::Unexpected(format!("token service: {error}")))?
    .with_jwt_signer(signer);
  let empty = ScopeSet::empty();
  let proof = SenderProof::none();
  let aud = vec!["https://api.example.test/".to_owned()];
  let issued = issue_client_credentials(
    &mut harness.conn,
    &harness.store,
    &service,
    &ClientCredentialsInput {
      client_id: &registered.client_id,
      client_kind: ClientKind::Confidential,
      client_registered: &empty,
      enabled: &empty,
      requested_scope: None,
      dpop_bound_jkt: None,
      mtls_bound_x5t_s256: None,
      proof: &proof,
      aud: &aud,
      token_format: TokenFormat::Jwt,
      now_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
    },
  )
  .await
  .map_err(|error| TestError::Unexpected(format!("client-credentials mint failed: {error}")))?;
  let jti_hash = issued
    .access_hash
    .strip_prefix("jwt:")
    .ok_or_else(|| TestError::Unexpected("jwt mint did not use a jwt: member".to_owned()))?
    .to_owned();
  let marker_key = harness.store.jwt_marker_key(&jti_hash);
  let marker_before: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut harness.conn)
    .await?;
  if !marker_before {
    return Err(TestError::Unexpected(
      "jwt marker missing before delete".to_owned(),
    ));
  }

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }

  let marker_after: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut harness.conn)
    .await?;
  if marker_after {
    return Err(TestError::Unexpected(
      "deleted client's jwt marker survived".to_owned(),
    ));
  }
  let access =
    crate::store::tokens::get_access(&mut harness.conn, &harness.store, &issued.access_hash)
      .await
      .map_err(|error| TestError::Unexpected(format!("lookup failed: {error}")))?;
  if access.is_some() {
    return Err(TestError::Unexpected(
      "deleted client's jwt access record survived".to_owned(),
    ));
  }
  let member: bool = redis::cmd("SISMEMBER")
    .arg(harness.store.grant_tokens_key(&issued.grant_id))
    .arg(&issued.access_hash)
    .query_async(&mut harness.conn)
    .await?;
  if member {
    return Err(TestError::Unexpected(
      "deleted client's jwt grant membership survived".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_delete_token_denials_match_read() -> TestResult {
  // RFC 7592 §2.3: DELETE is authenticated by the registration access token.
  // The same denial contract as GET applies: absent or unknown/deactivated
  // client answers 401, a mismatched credential on an existing client answers
  // 403. A successful DELETE invalidates the token, so replaying it answers
  // 401 (the deactivated row no longer authorizes management).
  let mut harness = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match delete_client(&mut stores, &ctx, &registered.client_id, None).await {
      Ok(()) => {
        return Err(TestError::Unexpected(
          "tokenless DELETE succeeded".to_owned(),
        ));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match delete_client(
      &mut stores,
      &ctx,
      "no-such-client",
      Some(&registered.reg_token),
    )
    .await
    {
      Ok(()) => {
        return Err(TestError::Unexpected(
          "unknown-client DELETE succeeded".to_owned(),
        ));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some("garbage-token-value"),
    )
    .await
    {
      Ok(()) => {
        return Err(TestError::Unexpected(
          "wrong-token DELETE succeeded".to_owned(),
        ));
      }
      Err(error) => expect_forbidden(error)?,
    }
  }

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match delete_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    {
      Ok(()) => {
        return Err(TestError::Unexpected(
          "revoked token accepted on repeated DELETE".to_owned(),
        ));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  Ok(())
}

/// Load a client row regardless of its `active` flag.
async fn find_any_row(
  harness: &Harness,
  client_id: &str,
) -> Result<client_repo::Client, TestError> {
  client_repo::list(&harness.pool, &harness.config.keys, true)
    .await?
    .into_iter()
    .find(|row| row.client_id == client_id)
    .ok_or_else(|| TestError::Unexpected(format!("client row {client_id} missing")))
}

/// Insert a `self_signed_tls_client_auth` client directly.
///
/// DCR's `RegisterRequest` has no certificate-thumbprint field, so the
/// repository is the only seam that can express this mTLS identity; the row
/// then goes through the real management DELETE path with the supplied
/// registration token.
async fn insert_thumbprint_client(
  harness: &Harness,
  thumbprint: &str,
  registration_token_hash: &str,
) -> Result<client_repo::Client, TestError> {
  let client_id = crate::crypto::tokens::mint_token()
    .map_err(|error| TestError::Unexpected(format!("mint failed: {error}")))?;
  let new = NewClient {
    id: Uuid::new_v4(),
    client_id,
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: "dcr manage thumbprint client".to_owned(),
    grant_types: vec!["authorization_code".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: String::new(),
    token_endpoint_auth_method: "self_signed_tls_client_auth".to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: Some(thumbprint.to_owned()),
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: Some(registration_token_hash.to_owned()),
  };
  client_repo::insert(
    &harness.pool,
    &harness.config.keys,
    harness.config.pii_dual_write,
    &new,
  )
  .await
  .map_err(TestError::from)
}

#[tokio::test]
async fn dcr_manage_delete_subject_dn_stays_reserved() -> TestResult {
  // RFC 7592 §2.3 DELETE deactivates the client; it does not erase the row.
  // mTLS identities stay unique per the partial indexes over every non-NULL
  // identity, independent of `active` (docs/SECURITY.md "Sender constraints";
  // docs/DATABASE.md "oauth_clients" and its edge cases). Re-registering the
  // same subject DN must therefore stay a typed 400 invalid_client_metadata
  // duplicate, while a different DN is unaffected.
  let mut harness = harness("catalog").await?;
  let redirect = "https://app.example.test/cb";
  let subject_dn = "CN=reserved-dn, O=Example";
  let first = register_mtls(&mut harness, redirect, subject_dn).await?;
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(&mut stores, &ctx, &first.client_id, Some(&first.reg_token))
      .await
      .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }

  let inactive = find_any_row(&harness, &first.client_id).await?;
  if inactive.active {
    return Err(TestError::Unexpected(
      "deleted client row still flagged active".to_owned(),
    ));
  }
  if inactive.tls_client_auth_subject_dn.as_deref() != Some(subject_dn) {
    return Err(TestError::Unexpected(format!(
      "deactivated row lost its subject DN: {:?}",
      inactive.tls_client_auth_subject_dn
    )));
  }

  match try_register(&mut harness, &mtls_request(redirect, subject_dn)).await? {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "deactivated client's subject DN was freed".to_owned(),
      ));
    }
    Err(error) => expect_app_error(error, OAuthErrorCode::InvalidClientMetadata, 400)?,
  }

  match try_register(
    &mut harness,
    &mtls_request(redirect, "CN=fresh-dn, O=Example"),
  )
  .await?
  {
    Ok(response) => {
      if response.client_id == first.client_id {
        return Err(TestError::Unexpected(
          "fresh registration reused the deleted client_id".to_owned(),
        ));
      }
    }
    Err(error) => {
      return Err(TestError::Unexpected(format!(
        "unaffected subject DN rejected: {error}"
      )));
    }
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_delete_thumbprint_stays_reserved() -> TestResult {
  // Same identity contract for `self_signed_tls_client_auth`: the certificate
  // thumbprint is a partial unique index over every non-NULL value with no
  // `active` predicate (docs/DATABASE.md "oauth_clients"), so deactivation
  // must not free it. The row is driven through the real management DELETE.
  let mut harness = harness("catalog").await?;
  let thumbprint = "x5t-s256-manage-thumbprint-fixture";

  let raw = crate::crypto::tokens::mint_token()
    .map_err(|error| TestError::Unexpected(format!("mint failed: {error}")))?;
  let hash = super::super::keyed_hash(&harness.config, &raw)
    .map_err(|error| TestError::Unexpected(format!("hash failed: {error}")))?;
  let first = insert_thumbprint_client(&harness, thumbprint, &hash).await?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    delete_client(&mut stores, &ctx, &first.client_id, Some(&raw))
      .await
      .map_err(|error| TestError::Unexpected(format!("delete failed: {error:?}")))?;
  }

  let inactive = find_any_row(&harness, &first.client_id).await?;
  if inactive.active {
    return Err(TestError::Unexpected(
      "deleted client row still flagged active".to_owned(),
    ));
  }
  if inactive.tls_client_auth_cert_thumbprint.as_deref() != Some(thumbprint) {
    return Err(TestError::Unexpected(
      "deactivated row lost its certificate thumbprint".to_owned(),
    ));
  }

  let second_raw = crate::crypto::tokens::mint_token()
    .map_err(|error| TestError::Unexpected(format!("mint failed: {error}")))?;
  let second_hash = super::super::keyed_hash(&harness.config, &second_raw)
    .map_err(|error| TestError::Unexpected(format!("hash failed: {error}")))?;
  match insert_thumbprint_client(&harness, thumbprint, &second_hash).await {
    Ok(_) => Err(TestError::Unexpected(
      "deactivated client's certificate thumbprint was freed".to_owned(),
    )),
    Err(TestError::App(crate::error::AppError::DuplicateClientIdentity)) => Ok(()),
    Err(error) => Err(TestError::Unexpected(format!(
      "unexpected duplicate-identity failure: {error}"
    ))),
  }
}

#[tokio::test]
async fn dcr_manage_token_survives_redis_flush() -> TestResult {
  // Private-container test: its purpose is a full Redis wipe (`FLUSHALL`),
  // which must never touch the shared compose Redis, and DCR state is
  // Postgres-backed, so a prefix-scoped `SCAN`+`DEL` would be a vacuous
  // no-op. The harness is built via the container-free `harness_with_redis`
  // over this container's URL (`_private` keeps it alive for the test).
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await
    .map_err(|error| TestError::Unexpected(format!("private redis: {error}")))?;
  let guarded = crate::test_guard::ContainerGuard::new(container);
  let port = guarded
    .get_host_port_ipv4(6379)
    .await
    .map_err(|error| TestError::Unexpected(format!("private redis port: {error}")))?;
  let _private = guarded;
  let mut harness = harness_with_redis(&format!("redis://127.0.0.1:{port}"), "catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("pre-flush read failed: {error:?}")))?;
  }

  let _: () = redis::cmd("FLUSHALL")
    .query_async(&mut harness.conn)
    .await?;

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let reread = read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("post-flush read failed: {error:?}")))?;
    if reread.client_id != registered.client_id {
      return Err(TestError::Unexpected(format!(
        "wrong client after flush: {}",
        reread.client_id
      )));
    }
  }
  Ok(())
}

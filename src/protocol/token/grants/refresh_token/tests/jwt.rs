//! `test(jwt_failed_rotation_leaves_no_marker)`: a REUSE/REPLAY rotation for
//! a JWT-format client leaves no live `jwt:` marker for the discarded
//! pre-mint, and the discarded pair resolves to nothing.

use super::{TestError, TestResult, dpop_proof, input, is_invalid_grant, test_redis, unique};
use crate::{
  config::{JwtSigningAlg, JwtSigningKey, TtlConfig},
  error::OAuthErrorCode,
  jose::jwt_access::{JwtAccessSigner, jti_hash},
  keys::KeyId,
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService},
  },
  store::tokens as low,
};

/// Resource audience every JWT mint in this module binds (RFC 8707 §2:
/// a JWT access token without a requested resource is rejected).
fn jwt_aud() -> Vec<String> {
  vec!["https://api.example.test/".to_owned()]
}

/// A fixed 32-byte ASCII signing key (the e2e JWT fixture material).
const JWT_TEST_KEY: &str = "bcdefghijklmnopqrstuvwxyzabcdefg";

/// Issuer the test signer asserts.
const TEST_ISSUER: &str = "https://jwt-test.example.test";

/// A test signer over the fixed key material.
fn test_signer() -> Result<JwtAccessSigner, TestError> {
  let raw = secrecy::SecretString::from(JWT_TEST_KEY);
  let key = JwtSigningKey::from_raw(
    KeyId::new("test-kid"),
    JwtSigningAlg::Es256,
    &raw,
    "jwt_signing_key",
  )
  .map_err(|error| TestError::Unexpected(format!("signing key rejected: {error}")))?;
  Ok(JwtAccessSigner::new(
    TEST_ISSUER.to_owned(),
    key,
    Vec::new(),
  ))
}

/// A service wired with the JWT signer.
fn jwt_service(signer: JwtAccessSigner) -> Result<TokenService, TestError> {
  TokenService::new(&TtlConfig::default(), &super::ring()?)
    .map_err(TestError::from)
    .map(|service| service.with_jwt_signer(signer))
}

/// Mint an initial JWT grant the tests can rotate; returns the minted pair.
async fn mint_jwt_grant(
  service: &TokenService,
  conn: &mut crate::state::RedisConn,
  store: &crate::store::Store,
  client: &str,
  proof: SenderProof,
) -> Result<crate::protocol::token::MintedTokens, TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: client.to_owned(),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: unique("subject"),
        scope: "read".to_owned(),
        access_scope: "read".to_owned(),
        grant_id: unique("grant"),
        proof,
        aud: jwt_aud(),
        refresh_aud: jwt_aud(),
        format: TokenFormat::Jwt,
      },
      super::now_unix(),
    )
    .await?;
  if minted.access_token.split('.').count() != 3 {
    return Err(TestError::Unexpected(
      "a jwt mint must return three JOSE segments".to_owned(),
    ));
  }
  Ok(minted)
}

/// A narrowed JWT refresh binds the ACCESS token to the narrowed scope: the
/// response, the JWT `scope` claim (which is what introspection reports),
/// and the stored access record all carry `read`, while the rotated refresh
/// record retains the full `read write` grant scope.
#[tokio::test]
async fn jwt_narrowed_refresh_binds_access_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = jwt_service(test_signer()?)?;
  let verifier = test_signer()?;
  let client = unique("jwt-narrow-client");
  let proof = dpop_proof(&unique("jwt-narrow-jkt"));
  let minted = service
    .mint(
      &mut conn,
      &store,
      &MintRequest {
        client_id: client.clone(),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: unique("subject"),
        scope: "read write".to_owned(),
        access_scope: "read write".to_owned(),
        grant_id: unique("grant"),
        proof: proof.clone(),
        aud: jwt_aud(),
        refresh_aud: jwt_aud(),
        format: TokenFormat::Jwt,
      },
      super::now_unix(),
    )
    .await?;
  let enabled = ScopeSet::parse("read write")?;

  let mut narrowed_input = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    Some("read"),
    &proof,
    &enabled,
  );
  narrowed_input.token_format = TokenFormat::Jwt;
  let narrowed = super::super::refresh(&mut conn, &store, &service, &narrowed_input).await?;
  if narrowed.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "response scope not narrowed: {}",
      narrowed.scope
    )));
  }
  let verified = verifier
    .verify(&narrowed.access_token, None)
    .map_err(|error| TestError::Unexpected(format!("rotated jwt rejected: {error}")))?;
  if verified.claims.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "jwt scope claim not narrowed: {}",
      verified.claims.scope
    )));
  }
  let member = format!("jwt:{}", jti_hash(&verified.claims.jti));
  let access_scope = match low::get_access(&mut conn, &store, &member).await? {
    Some(record) => record.scope,
    None => {
      return Err(TestError::Unexpected(
        "rotated jwt access record not found".to_owned(),
      ));
    }
  };
  if access_scope != "read" {
    return Err(TestError::Unexpected(format!(
      "access record scope not narrowed: {access_scope}"
    )));
  }
  let refresh_scope = match service
    .find_refresh(&mut conn, &store, &narrowed.refresh_token)
    .await?
  {
    Some(found) => found.record.scope,
    None => {
      return Err(TestError::Unexpected(
        "rotated refresh token not found".to_owned(),
      ));
    }
  };
  if refresh_scope != "read write" {
    return Err(TestError::Unexpected(format!(
      "refresh scope not retained: {refresh_scope}"
    )));
  }
  Ok(())
}

/// `discard_orphan` deletes the JWT marker by key: a leaked marker written
/// for the discarded pre-mint `jti` is gone afterwards, with no live record
/// or grant-set member left behind.
#[tokio::test]
async fn jwt_discard_orphan_deletes_marker_by_key() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = jwt_service(test_signer()?)?;
  let client = unique("jwt-discard-client");
  let proof = dpop_proof(&unique("jwt-discard-jkt"));
  let minted = service
    .mint_for_rotation(
      &mut conn,
      &store,
      &MintRequest {
        client_id: client.clone(),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: unique("subject"),
        scope: "read".to_owned(),
        access_scope: "read".to_owned(),
        grant_id: unique("grant"),
        proof,
        aud: jwt_aud(),
        refresh_aud: jwt_aud(),
        format: TokenFormat::Jwt,
      },
      super::now_unix(),
    )
    .await?;
  let jti_hash = minted
    .jwt_jti_hash()
    .ok_or_else(|| TestError::Unexpected("jwt mint must carry a jti hash".to_owned()))?
    .to_owned();
  // Simulate a leaked marker for the discarded pre-mint (the forbidden
  // marker-after-SADD ordering): the orphan must not survive the discard.
  let marker_key = store.jwt_marker_key(&jti_hash);
  let _: () = redis::cmd("HSET")
    .arg(&marker_key)
    .arg("grant_id")
    .arg(unique("grant"))
    .arg("client_id")
    .arg(&client)
    .arg("subject")
    .arg("user-1")
    .query_async(&mut conn)
    .await?;
  let _: () = redis::cmd("PEXPIRE")
    .arg(&marker_key)
    .arg(300_000_i64)
    .query_async(&mut conn)
    .await?;
  super::super::discard_orphan(&mut conn, &store, &service, &minted).await?;
  let marker_left: bool = redis::cmd("EXISTS")
    .arg(&marker_key)
    .query_async(&mut conn)
    .await?;
  if marker_left {
    return Err(TestError::Unexpected(
      "discard_orphan left a live jwt marker for the discarded jti".to_owned(),
    ));
  }
  if low::get_access(&mut conn, &store, &minted.access_hash)
    .await?
    .is_some()
  {
    return Err(TestError::Unexpected(
      "discard_orphan left the discarded access record".to_owned(),
    ));
  }
  let member: bool = redis::cmd("SISMEMBER")
    .arg(
      store.grant_tokens_key(
        &low::get_refresh(&mut conn, &store, &minted.refresh_hash)
          .await?
          .map(|record| record.grant_id)
          .unwrap_or_default(),
      ),
    )
    .arg(&minted.access_hash)
    .query_async(&mut conn)
    .await?;
  if member {
    return Err(TestError::Unexpected(
      "discard_orphan left the discarded grant-set member".to_owned(),
    ));
  }
  Ok(())
}

/// A REUSE rotation for a JWT client leaves no live `jwt:` marker for the
/// discarded pre-mint: the `jwt:` key set after the failed rotation holds no
/// key beyond the committed pair's own marker, and the attempt is
/// `invalid_grant` with no tokens.
#[tokio::test]
async fn jwt_failed_rotation_leaves_no_marker() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = jwt_service(test_signer()?)?;
  let client = unique("jwt-reuse-client");
  let proof = dpop_proof(&unique("jwt-reuse-jkt"));
  let minted = mint_jwt_grant(&service, &mut conn, &store, &client, proof.clone()).await?;
  let enabled = ScopeSet::parse("read")?;

  let mut first_input = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    None,
    &proof,
    &enabled,
  );
  first_input.token_format = TokenFormat::Jwt;
  let current = super::super::refresh(&mut conn, &store, &service, &first_input).await?;

  // The committed pair's marker key: the only `jwt:` key allowed to exist.
  // Read the idempotency mapping BEFORE deleting it: it names the committed
  // access member (`jwt:<jti-hash>`), which derives the marker key.
  let old = service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .ok_or_else(|| TestError::Unexpected("tombstoned old token unreadable".to_owned()))?;
  let request_id = service.request_id_for(&old.hash)?;
  let map_key = store.rotation_map_key(&request_id);
  let mapping: Option<String> = redis::cmd("GET")
    .arg(&map_key)
    .query_async(&mut conn)
    .await?;
  let committed_member = mapping
    .as_deref()
    .and_then(|payload| {
      serde_json::from_str::<std::collections::HashMap<String, String>>(payload).ok()
    })
    .and_then(|members| members.get("access").cloned())
    .ok_or_else(|| TestError::Unexpected("rotation mapping must name the pair".to_owned()))?;
  let committed_marker = committed_member
    .strip_prefix("jwt:")
    .map(|hash| store.jwt_marker_key(hash))
    .ok_or_else(|| TestError::Unexpected("committed access must be a jwt member".to_owned()))?;
  if current.access_token.split('.').count() != 3 {
    return Err(TestError::Unexpected(
      "a rotated jwt access token must stay a JWT".to_owned(),
    ));
  }
  // Snapshot the `jwt:` key set: the initial mint's marker and the
  // committed pair's marker both legitimately exist (the cascade does not
  // purge markers until Todo 27), so the invariant is that the failed
  // rotation ADDS nothing.
  let mut before: Vec<String> = redis::cmd("KEYS")
    .arg("oauth:{state}:jwt:*")
    .query_async(&mut conn)
    .await?;
  before.sort();
  if !before.contains(&committed_marker) {
    return Err(TestError::Unexpected(format!(
      "committed marker must exist before reuse, saw {before:?}"
    )));
  }
  // Expire the idempotency mapping so the second presentation is REUSE
  // (tombstone, no mapping) rather than REPLAY.
  let _: () = redis::cmd("DEL")
    .arg(&map_key)
    .query_async(&mut conn)
    .await?;

  let mut reuse_input = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    None,
    &proof,
    &enabled,
  );
  reuse_input.token_format = TokenFormat::Jwt;
  let reuse = super::super::refresh(&mut conn, &store, &service, &reuse_input).await;
  let error = match reuse {
    Ok(_) => return Err(TestError::Unexpected("reused token rotated".to_owned())),
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "reuse code: {}",
      error.code()
    )));
  }
  let mut after: Vec<String> = redis::cmd("KEYS")
    .arg("oauth:{state}:jwt:*")
    .query_async(&mut conn)
    .await?;
  after.sort();
  let added: Vec<&String> = after.iter().filter(|key| !before.contains(key)).collect();
  if !added.is_empty() {
    return Err(TestError::Unexpected(format!(
      "failed rotation leaves live jwt markers: {added:?}"
    )));
  }
  Ok(())
}

/// Refreshing an unbound grant (no `resource` was ever requested) after the
/// client switches to `Jwt` fails `invalid_target` before minting or
/// rotating, so the refresh record stays live for a retry.
#[tokio::test]
async fn jwt_refresh_of_unbound_grant_is_invalid_target_and_preserves_refresh() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = jwt_service(test_signer()?)?;
  let client = unique("jwt-unbound-refresh-client");
  let proof = dpop_proof(&unique("jwt-unbound-refresh-jkt"));
  let minted = super::mint_grant(
    &service,
    &mut conn,
    &store,
    &client,
    ClientKind::Public,
    "read",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;
  let mut refresh_input = input(
    &client,
    ClientKind::Public,
    &minted.refresh_token,
    None,
    &proof,
    &enabled,
  );
  refresh_input.token_format = TokenFormat::Jwt;
  match super::super::refresh(&mut conn, &store, &service, &refresh_input).await {
    Err(error) if error.code() == OAuthErrorCode::InvalidTarget => {}
    Err(error) => {
      return Err(TestError::Unexpected(format!(
        "a resourceless jwt refresh must be invalid_target, got {}",
        error.code()
      )));
    }
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a resourceless jwt refresh must never rotate".to_owned(),
      ));
    }
  }
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the refresh token must stay live after an invalid_target rejection".to_owned(),
    ));
  }
  Ok(())
}

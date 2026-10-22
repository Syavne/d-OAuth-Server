//! `test(jwt_failed_rotation_leaves_no_marker)`: a REUSE/REPLAY rotation for
//! a JWT-format client leaves no live `jwt:` marker for the discarded
//! pre-mint, and the discarded pair resolves to nothing.

use super::{TestError, TestResult, dpop_proof, input, is_invalid_grant, test_redis, unique};
use crate::{
  config::{JwtSigningAlg, JwtSigningKey, TtlConfig},
  jose::jwt_access::JwtAccessSigner,
  keys::KeyId,
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, SenderProof, TokenFormat, TokenService},
  },
  store::tokens as low,
};

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
        grant_id: unique("grant"),
        proof,
        aud: Vec::new(),
        refresh_aud: Vec::new(),
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
        grant_id: unique("grant"),
        proof,
        aud: Vec::new(),
        refresh_aud: Vec::new(),
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
      "failed rotation left live jwt markers: {added:?}"
    )));
  }
  Ok(())
}

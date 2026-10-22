//! Disabled-user use-time re-check: `invalid_grant` without rotation.
//!
//! A refresh record whose non-empty subject resolves to a disabled user
//! (by email or by UUID string) is rejected before minting or rotating, so
//! the presented token stays live for a later retry after re-enable.
//! Client-credentials (empty) and synthetic (unmapped) subjects still rotate.

use sqlx::PgPool;
use uuid::Uuid;

use super::{
  TestError, TestResult, dpop_proof, input, is_invalid_grant, now_unix, ring, service, test_redis,
  unique,
};
use crate::{
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    scope_repo,
    test_support::migrated_pool,
    user_repo::{self, NewUser},
    user_scope_repo,
  },
  keys::KeyRing,
  protocol::{
    scope::ScopeSet,
    token::{
      ClientKind, MintRequest, MintedTokens, SenderProof, TokenFormat, TokenService,
      grants::refresh_token::{RefreshUserStores, refresh_with_subject_check},
    },
  },
  state::RedisConn,
  store::Store,
  test_guard::Lease,
};

/// Postgres pool from the shared test server; errors as a test failure.
async fn pg_pool() -> Result<(Lease<crate::db::test_support::Db>, PgPool), TestError> {
  migrated_pool()
    .await
    .map_err(|error| TestError::Unexpected(format!("pg harness: {error}")))
}

/// Provision one enabled user; returns its id.
async fn provision(pool: &PgPool, keys: &KeyRing, email: &str) -> Result<Uuid, TestError> {
  let params =
    Argon2Params::new(8, 1, 1, 32).map_err(|error| TestError::Unexpected(format!("{error:?}")))?;
  let record = user_repo::create_user(
    pool,
    keys,
    false,
    &NewUser {
      email: email.to_owned(),
      password_hash: hash_secret("correct-horse-01", &params)
        .map_err(|error| TestError::Unexpected(format!("{error:?}")))?,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  Ok(record.id)
}

/// Mint a refreshable grant with an explicit subject.
async fn mint_subject(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  subject: &str,
  proof: SenderProof,
) -> Result<MintedTokens, TestError> {
  Ok(
    service
      .mint(
        conn,
        store,
        &MintRequest {
          client_id: client.to_owned(),
          client_kind: ClientKind::Public,
          dpop_required: true,
          subject: subject.to_owned(),
          scope: "read".to_owned(),
          access_scope: "read".to_owned(),
          grant_id: unique("grant"),
          proof,
          aud: Vec::new(),
          refresh_aud: Vec::new(),
          format: TokenFormat::Opaque,
        },
        now_unix(),
      )
      .await?,
  )
}

fn pg_error(error: sqlx::Error) -> TestError {
  TestError::Unexpected(format!("pg op: {error}"))
}

#[tokio::test]
async fn grant_refresh_disabled_email_subject_is_invalid_grant_without_rotation() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("disabled-client");
  let proof = dpop_proof(&unique("disabled-jkt"));
  let email = format!("{}@example.test", unique("disabled-user"));
  let user_id = provision(&pool, &keys, &email).await?;
  let minted = mint_subject(&service, &mut conn, &store, &client, &email, proof.clone()).await?;
  if !user_repo::disable_user(&pool, user_id).await? {
    return Err(TestError::Unexpected(
      "disable_user updated no rows".to_owned(),
    ));
  }
  let enabled = ScopeSet::parse("read")?;
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let error = match refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a disabled subject rotated".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "expected invalid_grant, got {}",
      error.code().as_str()
    )));
  }
  // No rotation and no mint: the presented token is still live.
  let live = service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?;
  if live.is_none() {
    return Err(TestError::Unexpected(
      "the presented token was rotated or revoked".to_owned(),
    ));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_disabled_uuid_subject_is_invalid_grant() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("disabled-uuid-client");
  let proof = dpop_proof(&unique("disabled-uuid-jkt"));
  let email = format!("{}@example.test", unique("disabled-uuid-user"));
  let user_id = provision(&pool, &keys, &email).await?;
  // Device-code tokens carry the user UUID string as subject.
  let minted = mint_subject(
    &service,
    &mut conn,
    &store,
    &client,
    &user_id.to_string(),
    proof.clone(),
  )
  .await?;
  if !user_repo::disable_user(&pool, user_id).await? {
    return Err(TestError::Unexpected(
      "disable_user updated no rows".to_owned(),
    ));
  }
  let enabled = ScopeSet::parse("read")?;
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let error = match refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a disabled UUID subject rotated".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "expected invalid_grant, got {}",
      error.code().as_str()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_reenabled_subject_rotates_again() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("reenabled-client");
  let proof = dpop_proof(&unique("reenabled-jkt"));
  let email = format!("{}@example.test", unique("reenabled-user"));
  let user_id = provision(&pool, &keys, &email).await?;
  // The re-enabled rotation must keep `read`, so the user holds a current
  // entitlement for it (refresh now enforces live entitlements).
  scope_repo::upsert(&pool, "read", "reenable test scope").await?;
  user_scope_repo::entitle(&pool, user_id, "read", None).await?;
  let minted = mint_subject(&service, &mut conn, &store, &client, &email, proof.clone()).await?;
  if !user_repo::disable_user(&pool, user_id).await? {
    return Err(TestError::Unexpected(
      "disable_user updated no rows".to_owned(),
    ));
  }
  let enabled = ScopeSet::parse("read")?;
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };
  let refused = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await;
  if refused.is_ok() {
    return Err(TestError::Unexpected(
      "a disabled subject rotated".to_owned(),
    ));
  }

  sqlx::query("UPDATE users SET disabled = false, updated_at = now() WHERE id = $1")
    .bind(user_id)
    .execute(&pool)
    .await
    .map_err(pg_error)?;
  let rotated = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await
  .map_err(TestError::from)?;
  if rotated.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "scope changed: {}",
      rotated.scope
    )));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_empty_and_unknown_subjects_still_rotate() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("non-user-client");
  let proof = dpop_proof(&unique("non-user-jkt"));
  let enabled = ScopeSet::parse("read")?;
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };
  // Client-credentials-style empty subjects and synthetic subjects resolve to
  // no user and must keep rotating.
  for subject in ["", "synthetic-subject-7"] {
    let minted = mint_subject(&service, &mut conn, &store, &client, subject, proof.clone()).await?;
    let rotated = refresh_with_subject_check(
      &mut conn,
      &store,
      &service,
      &users,
      &input(
        &client,
        ClientKind::Public,
        &minted.refresh_token,
        None,
        &proof,
        &enabled,
      ),
    )
    .await
    .map_err(TestError::from)?;
    if rotated.refresh_token == minted.refresh_token {
      return Err(TestError::Unexpected("rotation did not rotate".to_owned()));
    }
  }
  Ok(())
}

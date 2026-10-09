//! Current-entitlement enforcement on refresh: a revoked user entitlement or
//! a scope removed from the client registration drops out on the next
//! rotation, and explicitly requesting a no-longer-held scope is
//! `invalid_scope`.

use sqlx::PgPool;
use uuid::Uuid;

use super::{
  TestError, TestResult, dpop_proof, is_invalid_scope, now_unix, ring, service, test_redis, unique,
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
      ClientKind, MintRequest, MintedTokens, SenderProof, TokenService,
      grants::refresh_token::{RefreshInput, RefreshUserStores, refresh_with_subject_check},
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

/// Provision one enabled user entitled to every scope in `scopes` (creating
/// the catalog rows first, since entitlements reference them); returns its id.
async fn provision_entitled(
  pool: &PgPool,
  keys: &KeyRing,
  email: &str,
  scopes: &[&str],
) -> Result<Uuid, TestError> {
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
  for scope in scopes {
    scope_repo::upsert(pool, scope, "entitlement test scope").await?;
    user_scope_repo::entitle(pool, record.id, scope, None).await?;
  }
  Ok(record.id)
}

/// Mint a refreshable grant with an explicit subject and scope.
async fn mint_subject(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  subject: &str,
  scope: &str,
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
          subject: subject.to_owned(),
          scope: scope.to_owned(),
          grant_id: unique("grant"),
          proof,
        },
        now_unix(),
      )
      .await?,
  )
}

/// Refresh inputs carrying the CURRENT client registration alongside the
/// enabled catalog; the user term is always re-read fresh from Postgres, so
/// the caller-supplied entitlement here is only a placeholder.
fn entitled_input<'a>(
  client: &'a str,
  token: &'a str,
  scope: Option<&'a str>,
  proof: &'a SenderProof,
  enabled: &'a ScopeSet,
  registered: &'a ScopeSet,
  entitled: &'a ScopeSet,
) -> RefreshInput<'a> {
  RefreshInput {
    client_id: client,
    client_kind: ClientKind::Public,
    refresh_token: token,
    requested_scope: scope,
    proof,
    enabled,
    client_registered: registered,
    user_entitled: entitled,
    now_unix: now_unix(),
  }
}

#[tokio::test]
async fn grant_refresh_revoked_entitlement_drops_on_omitted_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("revoked-client");
  let proof = dpop_proof(&unique("revoked-jkt"));
  let email = format!("{}@example.test", unique("revoked-user"));
  let user_id = provision_entitled(&pool, &keys, &email, &["read", "write"]).await?;
  let minted = mint_subject(
    &service,
    &mut conn,
    &store,
    &client,
    &email,
    "read write",
    proof.clone(),
  )
  .await?;
  if !user_scope_repo::revoke(&pool, user_id, "write").await? {
    return Err(TestError::Unexpected("revoke removed no rows".to_owned()));
  }
  let enabled = ScopeSet::parse("read write")?;
  let registered = ScopeSet::parse("read write")?;
  let placeholder = ScopeSet::empty();
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let rotated = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  .map_err(TestError::from)?;
  if rotated.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "revoked scope survived refresh: {}",
      rotated.scope
    )));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_revoked_entitlement_explicit_request_is_invalid_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("revoked-explicit-client");
  let proof = dpop_proof(&unique("revoked-explicit-jkt"));
  let email = format!("{}@example.test", unique("revoked-explicit-user"));
  let user_id = provision_entitled(&pool, &keys, &email, &["read", "write"]).await?;
  let minted = mint_subject(
    &service,
    &mut conn,
    &store,
    &client,
    &email,
    "read write",
    proof.clone(),
  )
  .await?;
  if !user_scope_repo::revoke(&pool, user_id, "write").await? {
    return Err(TestError::Unexpected("revoke removed no rows".to_owned()));
  }
  let enabled = ScopeSet::parse("read write")?;
  let registered = ScopeSet::parse("read write")?;
  let placeholder = ScopeSet::empty();
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let error = match refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &minted.refresh_token,
      Some("read write"),
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a de-entitled scope rotated".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_scope(&error) {
    return Err(TestError::Unexpected(format!(
      "expected invalid_scope, got {}",
      error.code().as_str()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_removed_client_scope_drops_on_omitted_scope() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("deregistered-client");
  let proof = dpop_proof(&unique("deregistered-jkt"));
  let email = format!("{}@example.test", unique("deregistered-user"));
  provision_entitled(&pool, &keys, &email, &["read", "write"]).await?;
  let minted = mint_subject(
    &service,
    &mut conn,
    &store,
    &client,
    &email,
    "read write",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read write")?;
  // The client's current registration no longer carries `write`.
  let registered = ScopeSet::parse("read")?;
  let placeholder = ScopeSet::empty();
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let rotated = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  .map_err(TestError::from)?;
  if rotated.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "de-registered scope survived refresh: {}",
      rotated.scope
    )));
  }
  let error = match refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &rotated.refresh_token,
      Some("read write"),
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "a de-registered scope rotated".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_scope(&error) {
    return Err(TestError::Unexpected(format!(
      "expected invalid_scope, got {}",
      error.code().as_str()
    )));
  }
  Ok(())
}

#[tokio::test]
async fn grant_refresh_still_entitled_scope_is_kept() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let (_db, pool) = pg_pool().await?;
  let keys = ring()?;
  let service = service()?;
  let client = unique("kept-client");
  let proof = dpop_proof(&unique("kept-jkt"));
  let email = format!("{}@example.test", unique("kept-user"));
  provision_entitled(&pool, &keys, &email, &["read", "write"]).await?;
  let minted = mint_subject(
    &service,
    &mut conn,
    &store,
    &client,
    &email,
    "read write",
    proof.clone(),
  )
  .await?;
  let enabled = ScopeSet::parse("read write")?;
  let registered = ScopeSet::parse("read write")?;
  let placeholder = ScopeSet::empty();
  let users = RefreshUserStores {
    pool: &pool,
    keys: &keys,
  };

  let rotated = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  .map_err(TestError::from)?;
  if rotated.scope != "read write" {
    return Err(TestError::Unexpected(format!(
      "entitled scope changed: {}",
      rotated.scope
    )));
  }
  let narrowed = refresh_with_subject_check(
    &mut conn,
    &store,
    &service,
    &users,
    &entitled_input(
      &client,
      &rotated.refresh_token,
      Some("read"),
      &proof,
      &enabled,
      &registered,
      &placeholder,
    ),
  )
  .await
  .map_err(TestError::from)?;
  if narrowed.scope != "read" {
    return Err(TestError::Unexpected(format!(
      "explicit narrow failed: {}",
      narrowed.scope
    )));
  }
  Ok(())
}

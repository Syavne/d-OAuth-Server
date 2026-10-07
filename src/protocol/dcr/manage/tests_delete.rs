//! `test(dcr_manage)` delete suite: cross-client denial, DELETE, revocation,
//! and Redis-loss survival.

use uuid::Uuid;

use super::delete::delete_client;
use super::read_client;
use super::support::{
  TestError, TestResult, expect_forbidden, expect_unauthorized, harness, manage_parts, register,
};
use crate::db::client_repo;
use crate::protocol::token::{ClientKind, MintRequest, SenderProof, TokenService};

#[tokio::test]
async fn dcr_manage_cross_client_forbidden() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
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
  let (_guard, mut harness) = harness("catalog").await?;
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
  let (_guard, mut harness) = harness("catalog").await?;
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
          subject: String::new(),
          scope: String::new(),
          grant_id: Uuid::new_v4().to_string(),
          proof: SenderProof::none(),
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
        subject: String::new(),
        scope: String::new(),
        grant_id: Uuid::new_v4().to_string(),
        proof: SenderProof::none(),
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

#[tokio::test]
async fn dcr_manage_token_survives_redis_flush() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
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

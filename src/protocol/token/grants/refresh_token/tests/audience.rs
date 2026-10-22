//! Refresh audience propagation (RFC 8707 §2 and §2.2).
//!
//! The consumed refresh record's `aud` is the FULL ORIGINAL grant set: an
//! omitted `resource` keeps that set on both rotated records, a present
//! `resource` narrows only the access token while the rotated refresh token
//! stays bound to the full set, and any member outside the original set is
//! `invalid_target` with nothing rotated.

use super::{TestError, TestResult, dpop_proof, mint_grant, now_unix, service, test_redis, unique};
use crate::{
  error::OAuthErrorCode,
  protocol::{
    scope::ScopeSet,
    token::{
      ClientKind, MintRequest, MintedTokens, SenderProof, TokenFormat, TokenService,
      grants::refresh_token::{RefreshInput, refresh},
    },
  },
  state::RedisConn,
  store::Store,
};

/// First catalog-registered resource indicator (RFC 8707).
const RES_A: &str = "https://rs-a.example.test/api";
/// Second catalog-registered resource indicator (RFC 8707).
const RES_B: &str = "https://rs-b.example.test/api";
/// Third indicator, outside the `{A, B}` grant set (widening probe).
const RES_C: &str = "https://rs-c.example.test/api";
/// Differing indicator, outside the `{A, B}` grant set (mismatch probe).
const RES_X: &str = "https://rs-x.example.test/api";

/// Whether the rejection is `invalid_target`.
fn is_invalid_target(error: &crate::error::AppError) -> bool {
  error.code() == OAuthErrorCode::InvalidTarget
}

/// Mint an initial pair whose records carry `aud` on both halves.
async fn mint_aud_grant(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  client: &str,
  scope: &str,
  proof: SenderProof,
  aud: &[String],
) -> Result<MintedTokens, TestError> {
  let minted = service
    .mint(
      conn,
      store,
      &MintRequest {
        client_id: client.to_owned(),
        client_kind: ClientKind::Public,
        dpop_required: true,
        subject: unique("audience-subject"),
        scope: scope.to_owned(),
        grant_id: unique("audience-grant"),
        proof,
        aud: aud.to_vec(),
        refresh_aud: aud.to_vec(),
        format: TokenFormat::Opaque,
      },
      now_unix(),
    )
    .await?;
  Ok(minted)
}

/// Refresh inputs with an explicit RFC 8707 `resource` set.
fn aud_input<'a>(
  client: &'a str,
  token: &'a str,
  resources: &'a [String],
  proof: &'a SenderProof,
  enabled: &'a ScopeSet,
) -> RefreshInput<'a> {
  RefreshInput {
    client_id: client,
    client_kind: ClientKind::Public,
    dpop_required: true,
    refresh_token: token,
    requested_scope: None,
    requested_resources: resources,
    proof,
    enabled,
    client_registered: enabled,
    user_entitled: enabled,
    token_format: TokenFormat::Opaque,
    now_unix: now_unix(),
  }
}

/// Read back the stored audience of an access token.
async fn access_aud(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  raw: &str,
) -> Result<Vec<String>, TestError> {
  match service.find_access(conn, store, raw).await? {
    Some(found) => Ok(found.record.aud),
    None => Err(TestError::Unexpected(
      "rotated access token not found".to_owned(),
    )),
  }
}

/// Read back the stored audience of a refresh token.
async fn refresh_aud(
  service: &TokenService,
  conn: &mut RedisConn,
  store: &Store,
  raw: &str,
) -> Result<Vec<String>, TestError> {
  match service.find_refresh(conn, store, raw).await? {
    Some(found) => Ok(found.record.aud),
    None => Err(TestError::Unexpected(
      "rotated refresh token not found".to_owned(),
    )),
  }
}

/// Refresh without `resource` keeps the original audience on both records.
#[tokio::test]
async fn refresh_preserves_audience() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = unique("preserve-client");
  let proof = dpop_proof(&unique("preserve-jkt"));
  let original = vec![RES_A.to_owned(), RES_B.to_owned()];
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    "read",
    proof.clone(),
    &original,
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  let rotated = refresh(
    &mut conn,
    &store,
    &service,
    &aud_input(&client, &minted.refresh_token, &[], &proof, &enabled),
  )
  .await?;
  if access_aud(&service, &mut conn, &store, &rotated.access_token).await? != original {
    return Err(TestError::Unexpected(
      "rotated access token lost its audience".to_owned(),
    ));
  }
  if refresh_aud(&service, &mut conn, &store, &rotated.refresh_token).await? != original {
    return Err(TestError::Unexpected(
      "rotated refresh token lost its audience".to_owned(),
    ));
  }
  Ok(())
}

/// A `resource` outside the original grant set is `invalid_target`, and the
/// presented refresh token stays live for a retry.
#[tokio::test]
async fn refresh_rejects_audience_widening() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = unique("widen-client");
  let proof = dpop_proof(&unique("widen-jkt"));
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    "read",
    proof.clone(),
    &[RES_A.to_owned(), RES_B.to_owned()],
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  for widened in [
    vec![RES_A.to_owned(), RES_B.to_owned(), RES_C.to_owned()],
    vec![RES_A.to_owned(), RES_X.to_owned()],
  ] {
    let error = match refresh(
      &mut conn,
      &store,
      &service,
      &aud_input(&client, &minted.refresh_token, &widened, &proof, &enabled),
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(format!(
          "widened audience rotated: {widened:?}"
        )));
      }
      Err(error) => error,
    };
    if !is_invalid_target(&error) {
      return Err(TestError::Unexpected(format!(
        "widen code: {}",
        error.code()
      )));
    }
  }
  // Nothing was consumed or rotated: the presented token still works.
  if service
    .find_refresh(&mut conn, &store, &minted.refresh_token)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "the rejected refresh token was consumed".to_owned(),
    ));
  }
  refresh(
    &mut conn,
    &store,
    &service,
    &aud_input(&client, &minted.refresh_token, &[], &proof, &enabled),
  )
  .await?;
  Ok(())
}

/// A narrowed `resource` narrows only the access token: the rotated refresh
/// token keeps the full original set, so the next resourceless refresh
/// restores the full audience on the access token.
#[tokio::test]
async fn refresh_narrow_access_keeps_full_refresh_binding() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = unique("narrow-client");
  let proof = dpop_proof(&unique("narrow-jkt"));
  let full = vec![RES_A.to_owned(), RES_B.to_owned()];
  let minted = mint_aud_grant(
    &service,
    &mut conn,
    &store,
    &client,
    "read",
    proof.clone(),
    &full,
  )
  .await?;
  let enabled = ScopeSet::parse("read")?;

  let narrowed = refresh(
    &mut conn,
    &store,
    &service,
    &aud_input(
      &client,
      &minted.refresh_token,
      &[RES_A.to_owned()],
      &proof,
      &enabled,
    ),
  )
  .await?;
  if access_aud(&service, &mut conn, &store, &narrowed.access_token).await?
    != vec![RES_A.to_owned()]
  {
    return Err(TestError::Unexpected(
      "rotated access token did not narrow".to_owned(),
    ));
  }
  if refresh_aud(&service, &mut conn, &store, &narrowed.refresh_token).await? != full {
    return Err(TestError::Unexpected(
      "rotated refresh token lost the full binding".to_owned(),
    ));
  }
  // The preserved binding still authorizes the full set: a resourceless
  // refresh restores the full audience on the access token.
  let restored = refresh(
    &mut conn,
    &store,
    &service,
    &aud_input(&client, &narrowed.refresh_token, &[], &proof, &enabled),
  )
  .await?;
  if access_aud(&service, &mut conn, &store, &restored.access_token).await? != full {
    return Err(TestError::Unexpected(
      "the full binding did not survive narrowing".to_owned(),
    ));
  }
  Ok(())
}

/// An unbound grant cannot gain an audience: a non-empty `resource` against
/// an empty original set is `invalid_target`.
#[tokio::test]
async fn refresh_unbound_cannot_gain_audience() -> TestResult {
  let (_container, mut conn, store, _url) = test_redis().await?;
  let service = service()?;
  let client = unique("unbound-client");
  let proof = dpop_proof(&unique("unbound-jkt"));
  let minted = mint_grant(
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

  let error = match refresh(
    &mut conn,
    &store,
    &service,
    &aud_input(
      &client,
      &minted.refresh_token,
      &[RES_A.to_owned()],
      &proof,
      &enabled,
    ),
  )
  .await
  {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "an unbound grant gained an audience".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_target(&error) {
    return Err(TestError::Unexpected(format!(
      "unbound gain code: {}",
      error.code()
    )));
  }
  Ok(())
}

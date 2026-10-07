//! `test(dcr_manage)` update suite: full-replace PUT, rotation, redirects.

use super::read_client;
use super::support::{
  TestError, TestResult, harness, manage_parts, register, register_mtls, seed_redirect, seed_scope,
};
use super::update::update_client;
use crate::db::{client_repo, redirect_repo};

/// Build a PUT body: full replacement metadata for `redirect_uris`.
fn put_request(
  redirect_uris: Vec<String>,
  name: Option<&str>,
  scope: Option<&str>,
) -> crate::protocol::dcr::RegisterRequest {
  crate::protocol::dcr::RegisterRequest {
    redirect_uris: Some(redirect_uris),
    client_name: name.map(str::to_owned),
    token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: scope.map(str::to_owned),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    dpop_bound_access_tokens: Some(true),
    contacts: None,
    request_uris: None,
    software_id: None,
  }
}

#[tokio::test]
async fn dcr_manage_update_full_replace_rotates() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", Some("read")).await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/other",
  )
  .await?;
  seed_scope(&harness.pool, "write").await?;
  let issued_before = client_repo::find_active_by_client_id(
    &harness.pool,
    &harness.config.keys,
    &registered.client_id,
  )
  .await?
  .ok_or_else(|| TestError::Unexpected("client row missing".to_owned()))?
  .client_id_issued_at
  .unix_timestamp();

  let request = put_request(
    vec!["https://app.example.test/other".to_owned()],
    Some("renamed client"),
    Some("write"),
  );
  let response = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("update failed: {error:?}")))?
  };

  if response.client_name != "renamed client" {
    return Err(TestError::Unexpected(format!(
      "name not replaced: {}",
      response.client_name
    )));
  }
  if response.scope != "write" {
    return Err(TestError::Unexpected(format!(
      "scope not replaced: {}",
      response.scope
    )));
  }
  if response.redirect_uris != vec!["https://app.example.test/other".to_owned()] {
    return Err(TestError::Unexpected(format!(
      "redirects not replaced: {:?}",
      response.redirect_uris
    )));
  }
  let new_token = response
    .registration_access_token
    .clone()
    .ok_or_else(|| TestError::Unexpected("PUT must rotate the registration token".to_owned()))?;
  if new_token == registered.reg_token {
    return Err(TestError::Unexpected(
      "registration token was not rotated".to_owned(),
    ));
  }
  let new_secret = response
    .client_secret
    .clone()
    .ok_or_else(|| TestError::Unexpected("PUT must rotate the secret".to_owned()))?;
  if Some(&new_secret) == registered.secret.as_ref() {
    return Err(TestError::Unexpected(
      "client secret was not rotated".to_owned(),
    ));
  }
  let verified = client_repo::verify_secret(&harness.pool, &registered.client_id, &new_secret)
    .await
    .map_err(|error| TestError::Unexpected(format!("secret verify failed: {error}")))?;
  if verified != Some(true) {
    return Err(TestError::Unexpected(
      "rotated secret hash does not verify".to_owned(),
    ));
  }
  if response.client_id_issued_at != issued_before {
    return Err(TestError::Unexpected(
      "PUT must not touch client_id_issued_at".to_owned(),
    ));
  }

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "superseded registration token still works".to_owned(),
        ));
      }
      Err(error) => super::support::expect_forbidden(error)?,
    }
  }

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let reread = read_client(&mut stores, &ctx, &registered.client_id, Some(&new_token))
      .await
      .map_err(|error| TestError::Unexpected(format!("reread failed: {error:?}")))?;
    if reread.client_name != "renamed client" || reread.redirect_uris != response.redirect_uris {
      return Err(TestError::Unexpected(format!(
        "reread mismatch: {} {:?}",
        reread.client_name, reread.redirect_uris
      )));
    }
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_replaces_redirect_attachments() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/a", None).await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/b",
  )
  .await?;
  seed_redirect(
    &harness.pool,
    &harness.config.keys,
    "https://app.example.test/c",
  )
  .await?;

  let request = put_request(
    vec![
      "https://app.example.test/b".to_owned(),
      "https://app.example.test/c".to_owned(),
    ],
    Some("renamed"),
    None,
  );
  let token = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let response = update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("update failed: {error:?}")))?;
    response
      .registration_access_token
      .ok_or_else(|| TestError::Unexpected("missing rotated token".to_owned()))?
  };

  let effective =
    redirect_repo::effective_for_client(&harness.pool, &harness.config.keys, &registered.client_id)
      .await?;
  let uris: Vec<String> = effective.into_iter().map(|row| row.uri).collect();
  if uris
    != vec![
      "https://app.example.test/b".to_owned(),
      "https://app.example.test/c".to_owned(),
    ]
  {
    return Err(TestError::Unexpected(format!(
      "attachments not replaced: {uris:?}"
    )));
  }
  if client_repo::redirect_uri_allowed(
    &harness.pool,
    &harness.config.keys,
    &registered.client_id,
    "https://app.example.test/a",
  )
  .await?
  {
    return Err(TestError::Unexpected(
      "detached URI still matches".to_owned(),
    ));
  }
  let _ = token;
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_omitted_fields_clear() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", Some("read")).await?;

  let request = put_request(vec!["https://app.example.test/cb".to_owned()], None, None);
  let token = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let response = update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("update failed: {error:?}")))?;
    response
      .registration_access_token
      .ok_or_else(|| TestError::Unexpected("missing rotated token".to_owned()))?
  };

  let (mut stores, ctx) = manage_parts(&mut harness);
  let reread = read_client(&mut stores, &ctx, &registered.client_id, Some(&token))
    .await
    .map_err(|error| TestError::Unexpected(format!("reread failed: {error:?}")))?;
  if !reread.client_name.is_empty() {
    return Err(TestError::Unexpected(format!(
      "omitted name not cleared: {}",
      reread.client_name
    )));
  }
  if !reread.scope.is_empty() {
    return Err(TestError::Unexpected(format!(
      "omitted scope not cleared: {}",
      reread.scope
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_rename() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let request = put_request(
    vec!["https://app.example.test/cb".to_owned()],
    Some("renamed via manage"),
    None,
  );
  let token = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let response = update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("update failed: {error:?}")))?;
    if response.client_name != "renamed via manage" {
      return Err(TestError::Unexpected(format!(
        "PUT did not rename: {}",
        response.client_name
      )));
    }
    response
      .registration_access_token
      .ok_or_else(|| TestError::Unexpected("missing rotated token".to_owned()))?
  };

  let (mut stores, ctx) = manage_parts(&mut harness);
  let reread = read_client(&mut stores, &ctx, &registered.client_id, Some(&token))
    .await
    .map_err(|error| TestError::Unexpected(format!("reread failed: {error:?}")))?;
  if reread.client_name != "renamed via manage" {
    return Err(TestError::Unexpected(format!(
      "GET did not return the renamed value: {}",
      reread.client_name
    )));
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_same_mtls_identity_ok() -> TestResult {
  let (_guard, mut harness) = harness("catalog").await?;
  let subject_dn = "CN=manage-mtls, O=Example";
  let registered = register_mtls(&mut harness, "https://app.example.test/cb", subject_dn).await?;

  let request = crate::protocol::dcr::RegisterRequest {
    redirect_uris: Some(vec!["https://app.example.test/cb".to_owned()]),
    client_name: Some("dcr manage mtls client".to_owned()),
    token_endpoint_auth_method: Some("tls_client_auth".to_owned()),
    grant_types: Some(vec!["authorization_code".to_owned()]),
    response_types: Some(vec!["code".to_owned()]),
    scope: None,
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: Some(subject_dn.to_owned()),
    dpop_bound_access_tokens: None,
    contacts: None,
    request_uris: None,
    software_id: None,
  };
  let token = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let response = update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("unchanged identity rejected: {error:?}")))?;
    if response.tls_client_auth_subject_dn.as_deref() != Some(subject_dn) {
      return Err(TestError::Unexpected(format!(
        "subject DN changed: {:?}",
        response.tls_client_auth_subject_dn
      )));
    }
    response
      .registration_access_token
      .ok_or_else(|| TestError::Unexpected("missing rotated token".to_owned()))?
  };

  let (mut stores, ctx) = manage_parts(&mut harness);
  let reread = read_client(&mut stores, &ctx, &registered.client_id, Some(&token))
    .await
    .map_err(|error| TestError::Unexpected(format!("reread failed: {error:?}")))?;
  if reread.tls_client_auth_subject_dn.as_deref() != Some(subject_dn) {
    return Err(TestError::Unexpected(format!(
      "GET returned a different DN: {:?}",
      reread.tls_client_auth_subject_dn
    )));
  }
  Ok(())
}

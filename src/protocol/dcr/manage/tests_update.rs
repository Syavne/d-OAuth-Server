//! `test(dcr_manage)` update suite: full-replace PUT, rotation, redirects.

use super::delete::delete_client;
use super::read_client;
use super::support::{
  TestError, TestResult, expect_forbidden, expect_ssrf_denied, expect_unauthorized, harness,
  manage_parts, register, register_mtls, seed_redirect, seed_scope,
};
use super::update::update_client;
use crate::db::{client_repo, redirect_repo};
use crate::error::OAuthErrorCode;

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

/// Build a PUT body carrying `request_uris` (RFC 7591 §2 metadata).
fn put_request_with_request_uris(
  redirect_uris: Vec<String>,
  request_uris: serde_json::Value,
) -> crate::protocol::dcr::RegisterRequest {
  let mut request = put_request(redirect_uris, Some("dcr manage client"), None);
  request.request_uris = Some(request_uris);
  request
}

#[tokio::test]
async fn dcr_manage_update_rotated_token_forbidden_on_put_and_delete() -> TestResult {
  // RFC 7592 §2.2 and Appendix A.1: a successful PUT issues a new registration
  // access token and invalidates the previous one. The old token must fail for
  // every management verb, not only the read the existing suite covers.
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;

  let first_put = put_request(
    vec!["https://app.example.test/cb".to_owned()],
    Some("rotated"),
    None,
  );
  let rotated = {
    let (mut stores, ctx) = manage_parts(&mut harness);
    update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &first_put,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("first PUT failed: {error:?}")))?
  };
  let fresh = rotated
    .registration_access_token
    .clone()
    .ok_or_else(|| TestError::Unexpected("PUT must rotate the registration token".to_owned()))?;
  if fresh == registered.reg_token {
    return Err(TestError::Unexpected(
      "registration token was not rotated".to_owned(),
    ));
  }

  let second_put = put_request(
    vec!["https://app.example.test/cb".to_owned()],
    Some("should not apply"),
    None,
  );
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &second_put,
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "superseded token accepted on PUT".to_owned(),
        ));
      }
      Err(error) => expect_forbidden(error)?,
    }
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
          "superseded token accepted on DELETE".to_owned(),
        ));
      }
      Err(error) => expect_forbidden(error)?,
    }
  }

  let active = client_repo::find_active_by_client_id(
    &harness.pool,
    &harness.config.keys,
    &registered.client_id,
  )
  .await?;
  if active.is_none() {
    return Err(TestError::Unexpected(
      "rejected DELETE deactivated the client".to_owned(),
    ));
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let reread = read_client(&mut stores, &ctx, &registered.client_id, Some(&fresh))
      .await
      .map_err(|error| TestError::Unexpected(format!("fresh-token read failed: {error:?}")))?;
    if reread.client_name != "rotated" {
      return Err(TestError::Unexpected(format!(
        "fresh token read wrong state: {}",
        reread.client_name
      )));
    }
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_token_denials_match_read() -> TestResult {
  // Manage denial contract (docs/OAUTH.md error table; manage.rs module doc):
  // absent credentials or an unknown/deactivated client answer 401, a
  // mismatched credential on an existing client answers 403. PUT obeys the
  // same contract as GET. Registration tokens carry no expiry field in the
  // schema, so revocation (a successful DELETE that deactivates the client)
  // is the only invalidation path besides rotation.
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;
  let request = put_request(
    vec!["https://app.example.test/cb".to_owned()],
    Some("denied"),
    None,
  );

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match update_client(&mut stores, &ctx, &registered.client_id, None, &request).await {
      Ok(_) => {
        return Err(TestError::Unexpected("tokenless PUT succeeded".to_owned()));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match update_client(
      &mut stores,
      &ctx,
      "no-such-client",
      Some(&registered.reg_token),
      &request,
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "unknown-client PUT succeeded".to_owned(),
        ));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some("garbage-token-value"),
      &request,
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "wrong-token PUT succeeded".to_owned(),
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
    match update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "revoked token accepted on PUT".to_owned(),
        ));
      }
      Err(error) => expect_unauthorized(error)?,
    }
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_rejects_jwks_and_jwks_uri_together() -> TestResult {
  // RFC 7591 §2: "The jwks_uri and jwks parameters MUST NOT both be present in
  // the same request or response." The PUT validation must reject the pair
  // before any write, so the client and its registration token stay intact.
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;
  let mut request = put_request(
    vec!["https://app.example.test/cb".to_owned()],
    Some("should not apply"),
    None,
  );
  request.jwks = Some(serde_json::json!({
    "keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]
  }));
  request.jwks_uri = Some("https://app.example.test/jwks.json".to_owned());

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    match update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    {
      Ok(_) => {
        return Err(TestError::Unexpected(
          "PUT accepted jwks and jwks_uri together".to_owned(),
        ));
      }
      Err(super::ManageError::Protocol(error)) => {
        super::support::expect_app_error(error, OAuthErrorCode::InvalidClientMetadata, 400)?;
      }
      Err(super::ManageError::Forbidden) => {
        return Err(TestError::Unexpected(
          "valid token read as forbidden".to_owned(),
        ));
      }
    }
  }

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let reread = read_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("post-reject read failed: {error:?}")))?;
    if reread.client_name != "dcr manage client" {
      return Err(TestError::Unexpected(format!(
        "rejected PUT mutated the client: {}",
        reread.client_name
      )));
    }
    if reread.jwks.is_some() || reread.jwks_uri.is_some() {
      return Err(TestError::Unexpected(
        "rejected PUT persisted JWKS metadata".to_owned(),
      ));
    }
  }
  Ok(())
}

#[tokio::test]
async fn dcr_manage_update_request_uris_stored_verbatim() -> TestResult {
  // Same RFC 7591 §2 metadata-passthrough contract as registration: PUT stores
  // request_uris verbatim and never fetches them; the SSRF guard is the
  // fetch-time enforcement point (docs/OAUTH.md "JAR and PAR",
  // docs/SECURITY.md "PAR and JAR"). Full-replace semantics must persist the
  // array exactly, including plaintext, loopback, and non-https values.
  let (_guard, mut harness) = harness("catalog").await?;
  let registered = register(&mut harness, "https://app.example.test/cb", None).await?;
  let request_uris = serde_json::json!([
    "http://app.example.test/req.jwt",
    "https://127.0.0.1/req.jwt",
    "ftp://app.example.test/req.jwt"
  ]);
  let request = put_request_with_request_uris(
    vec!["https://app.example.test/cb".to_owned()],
    request_uris.clone(),
  );

  {
    let (mut stores, ctx) = manage_parts(&mut harness);
    let response = update_client(
      &mut stores,
      &ctx,
      &registered.client_id,
      Some(&registered.reg_token),
      &request,
    )
    .await
    .map_err(|error| TestError::Unexpected(format!("PUT with request_uris failed: {error:?}")))?;
    if response.registration_access_token.is_none() {
      return Err(TestError::Unexpected(
        "successful PUT did not rotate the registration token".to_owned(),
      ));
    }
  }

  let row = client_repo::find_active_by_client_id(
    &harness.pool,
    &harness.config.keys,
    &registered.client_id,
  )
  .await?
  .ok_or_else(|| TestError::Unexpected("client row missing after PUT".to_owned()))?;
  if row.request_uris.as_ref() != Some(&request_uris) {
    return Err(TestError::Unexpected(format!(
      "request_uris not stored verbatim on PUT: {:?}",
      row.request_uris
    )));
  }

  for uri in [
    "http://app.example.test/req.jwt",
    "https://127.0.0.1/req.jwt",
    "ftp://app.example.test/req.jwt",
  ] {
    expect_ssrf_denied(uri).await?;
  }
  Ok(())
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

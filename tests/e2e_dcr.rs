//! `binary(e2e_dcr)` dynamic-client-registration lifecycle over the live
//! router (RFC 7591 registration, RFC 7592 management).
//!
//! Every request goes through the production router over a loopback socket
//! against the real shared Postgres + Redis. Initial access tokens are seeded
//! through the same keyed-hash path the CLI uses, so the registration
//! authorization the tests observe is the production one (not `sha256_hex`).
//!
//! DCR forbids `client_credentials` (`SUPPORTED_GRANTS`), so no case attempts
//! it. Confidential `client_secret_basic` registration requires a sender
//! constraint, hence every positive body sets `dpop_bound_access_tokens`.

#[path = "e2e/harness.rs"]
#[allow(dead_code)]
mod harness;

use std::time::Duration;

use d_oauth::{
  crypto::tokens::{KeyId as TokenKeyId, mint_token, token_hash},
  db::TokenEndpointAuthMethod,
  protocol::token::ClientKind,
  store::dcr::{self, InitialAccessRecord},
};
use harness::{TestError, World, ensure, fail, json_body, open_rate_limit, seed_client};
use reqwest::StatusCode;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

/// Persisted portion of one RFC 7591 registration response used by a test.
struct Registered {
  client_id: String,
  client_secret: String,
  registration_token: String,
}

/// RFC 7591 body for a confidential, DPoP-bound client in its one grant.
fn registration_body(name: &str, redirect: &str) -> Value {
  json!({
    "redirect_uris": [redirect],
    "client_name": name,
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "dpop_bound_access_tokens": true,
  })
}

/// Read a required string member of a JSON response.
fn string_field<'a>(body: &'a Value, key: &str) -> Result<&'a str, TestError> {
  body
    .get(key)
    .and_then(Value::as_str)
    .ok_or_else(|| fail(format!("response is missing string field {key}")))
}

/// Seed an IAT exactly as `protocol::dcr::tests::issue_iat` does: the storage
/// key is the active pepper's keyed hash, not a plain `sha256_hex`.
async fn seed_iat(world: &World, uses: u64) -> Result<String, TestError> {
  let raw = mint_token().map_err(|error| fail(format!("mint IAT failed: {error}")))?;
  let (key_id, pepper) = world
    .state
    .config
    .keys
    .active_pepper()
    .ok_or_else(|| fail("config has no active token pepper"))?;
  let hash = token_hash(
    &TokenKeyId::new(key_id.as_str()),
    pepper.expose_secret().as_bytes(),
    &raw,
  )
  .to_storage_string();
  let mut conn = world.state.redis.clone();
  dcr::issue(
    &mut conn,
    &world.store,
    &hash,
    &InitialAccessRecord {
      uses_remaining: uses,
      label: "e2e".to_owned(),
    },
    Duration::from_secs(600),
  )
  .await
  .map_err(|error| fail(format!("seed IAT failed: {error}")))?;
  Ok(raw)
}

/// `POST {path}` as JSON with a bearer credential.
async fn post_json(
  world: &World,
  path: &str,
  bearer: &str,
  body: &Value,
) -> Result<(StatusCode, String), TestError> {
  let response = world
    .client
    .post(format!("{}{path}", world.base))
    .bearer_auth(bearer)
    .json(body)
    .send()
    .await?;
  Ok((response.status(), response.text().await?))
}

/// `PUT {path}` as JSON with a bearer credential.
async fn put_json(
  world: &World,
  path: &str,
  bearer: &str,
  body: &Value,
) -> Result<(StatusCode, String), TestError> {
  let response = world
    .client
    .put(format!("{}{path}", world.base))
    .bearer_auth(bearer)
    .json(body)
    .send()
    .await?;
  Ok((response.status(), response.text().await?))
}

/// `DELETE {path}` with a bearer credential.
async fn delete(
  world: &World,
  path: &str,
  bearer: &str,
) -> Result<(StatusCode, String), TestError> {
  let response = world
    .client
    .delete(format!("{}{path}", world.base))
    .bearer_auth(bearer)
    .send()
    .await?;
  Ok((response.status(), response.text().await?))
}

/// Register one client and return the credentials the response exposes once.
async fn register(
  world: &World,
  iat: &str,
  name: &str,
  redirect: &str,
) -> Result<Registered, TestError> {
  let (status, body) =
    post_json(world, "/register", iat, &registration_body(name, redirect)).await?;
  ensure(
    status == StatusCode::CREATED,
    format!("POST /register must be 201, got {status}: {body}"),
  )?;
  let parsed = json_body(&body)?;
  Ok(Registered {
    client_id: string_field(&parsed, "client_id")?.to_owned(),
    client_secret: string_field(&parsed, "client_secret")?.to_owned(),
    registration_token: string_field(&parsed, "registration_access_token")?.to_owned(),
  })
}

/// Assert an exact `403 access_denied` management denial.
fn ensure_forbidden(status: StatusCode, body: &str) -> Result<(), TestError> {
  ensure(
    status == StatusCode::FORBIDDEN,
    format!("cross-client management must be 403, got {status}: {body}"),
  )?;
  let parsed = json_body(body)?;
  ensure(
    parsed["error"].as_str() == Some("access_denied"),
    format!("cross-client denial must be access_denied, got {body}"),
  )
}

/// RFC 7591 register → RFC 7592 read/update/delete, with the deleted client's
/// tokens no longer introspectable.
#[tokio::test]
async fn e2e_dcr_register_read_update_delete_lifecycle() -> Result<(), TestError> {
  let world = World::start_with(open_rate_limit(), json!({"dcr_redirect_policy": "open"})).await?;
  let iat = seed_iat(&world, 3).await?;
  let redirect = "https://app.example.test/dcr/lifecycle";
  let registered = register(&world, &iat, "lifecycle client", redirect).await?;
  ensure(
    !registered.client_id.is_empty(),
    "registration must mint a client_id",
  )?;
  ensure(
    !registered.registration_token.is_empty(),
    "registration must mint a management token",
  )?;
  ensure(
    !registered.client_secret.is_empty(),
    "registration must mint a client secret",
  )?;

  let auth = format!("Bearer {}", registered.registration_token);
  let (status, _, body) = world
    .get(
      &format!("/register/{}", registered.client_id),
      &[("Authorization", auth.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("GET /register/{{id}} must be 200, got {status}: {body}"),
  )?;
  let metadata = json_body(&body)?;
  ensure(
    metadata["client_id"].as_str() == Some(registered.client_id.as_str()),
    "read must echo the registered client_id",
  )?;
  ensure(
    metadata["client_name"].as_str() == Some("lifecycle client"),
    "read must echo the registered client_name",
  )?;
  ensure(
    metadata["dpop_bound_access_tokens"].as_bool() == Some(true),
    "read must echo the DPoP binding",
  )?;

  let renamed = registration_body("lifecycle client renamed", redirect);
  let (status, body) = put_json(
    &world,
    &format!("/register/{}", registered.client_id),
    &registered.registration_token,
    &renamed,
  )
  .await?;
  ensure(
    status == StatusCode::OK,
    format!("PUT /register/{{id}} must be 200, got {status}: {body}"),
  )?;
  let updated = json_body(&body)?;
  ensure(
    updated["client_name"].as_str() == Some("lifecycle client renamed"),
    "PUT must apply the new client_name",
  )?;
  let rotated = string_field(&updated, "registration_access_token")?.to_owned();
  ensure(
    rotated != registered.registration_token,
    "PUT must rotate the management token",
  )?;
  // A successful PUT also rotates a secret-method client's secret, so the
  // secret from the 201 body is stale from here on.
  let rotated_secret = string_field(&updated, "client_secret")?.to_owned();
  let minted = world
    .mint(&registered.client_id, "", ClientKind::Confidential, None)
    .await?;
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      Some((registered.client_id.as_str(), rotated_secret.as_str())),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("introspection must be 200, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["active"].as_bool() == Some(true),
    "the minted token must introspect active before delete",
  )?;

  let (status, _) = delete(
    &world,
    &format!("/register/{}", registered.client_id),
    &rotated,
  )
  .await?;
  ensure(
    status == StatusCode::NO_CONTENT,
    format!("DELETE /register/{{id}} must be 204, got {status}"),
  )?;

  let auth = format!("Bearer {rotated}");
  let (status, _, body) = world
    .get(
      &format!("/register/{}", registered.client_id),
      &[("Authorization", auth.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::UNAUTHORIZED,
    format!("management after delete must be 401, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["error"].as_str() == Some("invalid_client"),
    format!("management after delete must be invalid_client, got {body}"),
  )?;

  // `DELETE` revokes the records themselves. A foreign client's introspection
  // would answer inactive for any owner mismatch, so assert the store directly
  // and keep the cross-client check as a separate observable contract.
  let mut conn = world.state.redis.clone();
  let access = d_oauth::store::tokens::get_access(&mut conn, &world.store, &minted.access_hash)
    .await
    .map_err(|error| fail(format!("access lookup failed: {error}")))?;
  ensure(access.is_none(), "DELETE must revoke the access token")?;
  let refresh = d_oauth::store::tokens::get_refresh(&mut conn, &world.store, &minted.refresh_hash)
    .await
    .map_err(|error| fail(format!("refresh lookup failed: {error}")))?;
  ensure(refresh.is_none(), "DELETE must revoke the refresh token")?;

  let other_id = "e2e-dcr-introspector";
  let other_secret = "e2e-dcr-introspector-secret-aaaabbbbccccdddd";
  seed_client(
    &world.pool,
    &world.state.keys,
    other_id,
    Some(other_secret),
    &["authorization_code"],
    "",
    TokenEndpointAuthMethod::ClientSecretBasic,
  )
  .await?;
  let (status, _, body) = world
    .post_form(
      "/introspect",
      &[("token", minted.access_token.as_str())],
      Some((other_id, other_secret)),
      &[],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("foreign introspection must be 200, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["active"].as_bool() == Some(false),
    "the deleted client's token must introspect inactive",
  )
}

/// Every bad-metadata row renders its documented RFC 7591 error and creates
/// no client row.
#[tokio::test]
async fn e2e_dcr_rejects_bad_metadata_at_http() -> Result<(), TestError> {
  let world = World::start_with(open_rate_limit(), json!({})).await?;
  let iat = seed_iat(&world, 10).await?;

  let wildcard = json!({
    "redirect_uris": ["https://*.example.test/cb"],
    "token_endpoint_auth_method": "client_secret_basic",
    "dpop_bound_access_tokens": true,
  });
  let plain_http = json!({
    "redirect_uris": ["http://app.example.test/cb"],
    "token_endpoint_auth_method": "client_secret_basic",
    "dpop_bound_access_tokens": true,
  });
  let bad_method = json!({
    "redirect_uris": ["https://app.example.test/cb"],
    "token_endpoint_auth_method": "bogus",
    "dpop_bound_access_tokens": true,
  });
  let both_jwks = json!({
    "redirect_uris": ["https://app.example.test/cb"],
    "token_endpoint_auth_method": "client_secret_basic",
    "dpop_bound_access_tokens": true,
    "jwks": {"keys": []},
    "jwks_uri": "https://app.example.test/jwks.json",
  });

  let rows = [
    (&wildcard, "invalid_redirect_uri"),
    (&plain_http, "invalid_redirect_uri"),
    (&bad_method, "invalid_client_metadata"),
    (&both_jwks, "invalid_client_metadata"),
  ];
  for (body, expected) in rows {
    let (status, response_body) = post_json(&world, "/register", &iat, body).await?;
    ensure(
      status == StatusCode::BAD_REQUEST,
      format!("{expected} row must be 400, got {status}: {response_body}"),
    )?;
    let parsed = json_body(&response_body)?;
    ensure(
      parsed["error"].as_str() == Some(expected),
      format!("expected {expected}, got {response_body}"),
    )?;
  }

  let clients: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
    .fetch_one(&world.pool)
    .await?;
  ensure(
    clients == 0,
    format!("no rejected registration may persist a client row, found {clients}"),
  )
}

/// A management token is scoped to the client it was minted for.
#[tokio::test]
async fn e2e_dcr_management_token_is_client_scoped() -> Result<(), TestError> {
  let world = World::start_with(open_rate_limit(), json!({"dcr_redirect_policy": "open"})).await?;
  let iat = seed_iat(&world, 5).await?;
  let first = register(&world, &iat, "first client", "https://app.example.test/a").await?;
  let second = register(&world, &iat, "second client", "https://app.example.test/b").await?;

  let auth = format!("Bearer {}", second.registration_token);
  let (status, _, body) = world
    .get(
      &format!("/register/{}", first.client_id),
      &[("Authorization", auth.as_str())],
    )
    .await?;
  ensure_forbidden(status, &body)?;

  let rename = registration_body("attacker rename", "https://app.example.test/b");
  let (status, body) = put_json(
    &world,
    &format!("/register/{}", first.client_id),
    &second.registration_token,
    &rename,
  )
  .await?;
  ensure_forbidden(status, &body)?;

  let (status, body) = delete(
    &world,
    &format!("/register/{}", first.client_id),
    &second.registration_token,
  )
  .await?;
  ensure_forbidden(status, &body)?;

  let auth = format!("Bearer {}", first.registration_token);
  let (status, _, body) = world
    .get(
      &format!("/register/{}", first.client_id),
      &[("Authorization", auth.as_str())],
    )
    .await?;
  ensure(
    status == StatusCode::OK,
    format!("the victim client must stay manageable, got {status}: {body}"),
  )?;
  ensure(
    json_body(&body)?["client_name"].as_str() == Some("first client"),
    "cross-client calls must not mutate the victim client",
  )
}

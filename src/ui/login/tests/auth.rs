//! `test(login)` authentication suite: cookies, uniform rejects, replay, binding.

use axum::Extension;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum_extra::extract::CookieJar;
use sqlx::Row as _;

use super::super::LOGOUT_ACTION;
use super::{
  Harness, LoginAttempt, TestError, TestResult, TestUser, app_state, attempt, cookie_header,
  create_user, current_code, deps_of, harness, pending_request, presession, wrong_code,
};
use crate::{
  db::{
    client_repo::{self, NewClient},
    redirect_repo::{self, RedirectKind},
    user_repo,
  },
  error::{AppError, OAuthErrorCode},
  middleware::request_id::RequestId,
  store::{pending, sessions},
  ui::login::{
    CONSENT_PATH, LOCKOUT_THRESHOLD, LOCKOUT_WINDOW, LOGIN_SUCCESS_PATH, LoginForm, LoginOutcome,
    LoginPageQuery, LogoutForm, attempt_login, bind_pending_request, expired_session_cookie,
    form_token, get_login, get_logout, load_session, post_login, post_logout, session_cookie,
  },
};

/// `Err` shortcut for a failed test assertion.
fn unexpected(message: &str) -> TestError {
  TestError::Unexpected(message.to_owned())
}

/// Run one login attempt on a fresh pre-session.
async fn try_login(
  harness: &mut Harness,
  attempt: LoginAttempt,
) -> Result<LoginOutcome, TestError> {
  let mut deps = deps_of(harness);
  Ok(attempt_login(&mut deps, attempt).await?)
}

#[tokio::test]
async fn login_success_sets_session_cookie_and_bound_redirect() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-ok@example.test",
    "correct-horse-01",
    false,
    true,
  )
  .await?;
  let request_id = pending_request(&mut h).await?;
  let (pre, csrf) = presession(&mut h).await?;
  {
    let mut deps = deps_of(&mut h);
    bind_pending_request(&mut deps, &pre, &request_id, "login-test-client", None).await?;
  }
  let code = current_code(&user, &h)?;
  let outcome = try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await?;

  let (session_id, redirect_to) = match outcome {
    LoginOutcome::Authenticated {
      session_id,
      redirect_to,
    } => (session_id, redirect_to),
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  if redirect_to != CONSENT_PATH {
    return Err(unexpected(
      "post-login redirect must reach the bound record",
    ));
  }
  if session_id == pre {
    return Err(unexpected("the session id must rotate on login"));
  }
  let live = load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .ok_or_else(|| unexpected("the new session must be stored"))?;
  if live.record.subject != user.email || !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the session must be full and owned"));
  }
  if live.meta.pending_request_id.as_deref() != Some(request_id.as_str()) {
    return Err(unexpected("the pending binding must survive rotation"));
  }
  if live.meta.auth_time != h.now.unix_timestamp() {
    return Err(unexpected("auth_time must come from the clock"));
  }
  if live.meta.csrf_secret.len() != crate::crypto::TOKEN_STR_LEN {
    return Err(unexpected("the session must carry a fresh CSRF secret"));
  }
  if sessions::get(&mut h.conn, &h.store, &pre).await?.is_some() {
    return Err(unexpected("the pre-session must be gone after rotation"));
  }
  let header = cookie_header(&h, &session_id);
  for needle in [
    "session_id=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ] {
    if !header.contains(needle) {
      return Err(unexpected("the session cookie must be HttpOnly/Secure/Lax"));
    }
  }
  if !header.contains(&session_id) {
    return Err(unexpected("the cookie must carry the session id"));
  }
  Ok(())
}

async fn logout_csrf(harness: &mut Harness, session_id: &str) -> Result<String, TestError> {
  let live = load_session(&mut harness.conn, &harness.store, session_id)
    .await?
    .ok_or_else(|| unexpected("the session must be live"))?;
  Ok(form_token(&live.meta.csrf_secret, LOGOUT_ACTION))
}

#[tokio::test]
async fn post_logout_destroys_session_and_clears_cookie() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "logout-post@example.test",
    "correct-horse-03",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };

  let token = logout_csrf(&mut h, &session_id).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;

  if response.status() != StatusCode::OK {
    return Err(unexpected(
      "POST /logout must render a neutral page, not redirect",
    ));
  }
  if response.headers().get(header::LOCATION).is_some() {
    return Err(unexpected(
      "POST /logout must never auto-redirect (no CSRF bounce)",
    ));
  }
  let set_cookie = response
    .headers()
    .get(header::SET_COOKIE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  if !set_cookie.contains("session_id=") || !set_cookie.contains("Max-Age=0") {
    return Err(unexpected("POST /logout must expire the session cookie"));
  }
  if cookie_attr_names(&cookie_header(&h, &session_id)) != cookie_attr_names(set_cookie) {
    return Err(unexpected(
      "the clearing cookie must mirror the session cookie attributes",
    ));
  }
  if sessions::get(&mut h.conn, &h.store, &session_id)
    .await?
    .is_some()
  {
    return Err(unexpected(
      "POST /logout must destroy the server-side session",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_without_csrf_is_rejected_and_session_survives() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "logout-csrf@example.test",
    "correct-horse-31",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  for presented in [String::new(), "forged-token".to_owned()] {
    let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
    let response = post_logout(
      State(app_state(&h)),
      Extension(RequestId::new()),
      jar,
      Form(LogoutForm {
        csrf: presented.clone(),
      }),
    )
    .await;
    if response.status() != StatusCode::BAD_REQUEST {
      return Err(unexpected(
        "POST /logout without a valid token must be rejected",
      ));
    }
    if response.headers().contains_key(header::SET_COOKIE) {
      return Err(unexpected("a rejected sign-out must not touch cookies"));
    }
    if load_session(&mut h.conn, &h.store, &session_id)
      .await?
      .is_none()
    {
      return Err(unexpected(
        "a rejected sign-out must leave the session intact",
      ));
    }
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_rejects_other_sessions_form_token() -> TestResult {
  let mut h = harness().await?;
  let user_a = create_user(
    &mut h,
    "logout-cross-a@example.test",
    "correct-horse-32",
    false,
    true,
  )
  .await?;
  let user_b = create_user(
    &mut h,
    "logout-cross-b@example.test",
    "correct-horse-33",
    false,
    true,
  )
  .await?;
  let (pre_a, csrf_a) = presession(&mut h).await?;
  let code_a = current_code(&user_a, &h)?;
  let session_a = match try_login(&mut h, attempt(&pre_a, &csrf_a, &user_a, &code_a)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  let (pre_b, csrf_b) = presession(&mut h).await?;
  let code_b = current_code(&user_b, &h)?;
  let session_b = match try_login(&mut h, attempt(&pre_b, &csrf_b, &user_b, &code_b)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  // A form token minted for session B (action-separated per-session context)
  // must not authorize session A's sign-out.
  let foreign = logout_csrf(&mut h, &session_b).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_a));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: foreign }),
  )
  .await;
  if response.status() != StatusCode::BAD_REQUEST {
    return Err(unexpected(
      "POST /logout with another session's token must be rejected",
    ));
  }
  if response.headers().contains_key(header::SET_COOKIE) {
    return Err(unexpected("a rejected sign-out must not touch cookies"));
  }
  if load_session(&mut h.conn, &h.store, &session_a)
    .await?
    .is_none()
  {
    return Err(unexpected(
      "a rejected sign-out must leave the victim session intact",
    ));
  }
  if load_session(&mut h.conn, &h.store, &session_b)
    .await?
    .is_none()
  {
    return Err(unexpected(
      "a rejected sign-out must leave the other session intact",
    ));
  }
  // A token for a different action on the same session must also fail: form
  // tokens are action-separated, not interchangeable.
  let live_a = load_session(&mut h.conn, &h.store, &session_a)
    .await?
    .ok_or_else(|| unexpected("the session must be live"))?;
  let cross_action = form_token(&live_a.meta.csrf_secret, "change-password");
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_a));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: cross_action }),
  )
  .await;
  if response.status() != StatusCode::BAD_REQUEST {
    return Err(unexpected(
      "POST /logout with another action's token must be rejected",
    ));
  }
  if load_session(&mut h.conn, &h.store, &session_a)
    .await?
    .is_none()
  {
    return Err(unexpected(
      "a cross-action reject must leave the session intact",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_wrong_content_type_fails_closed() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "logout-ctype@example.test",
    "correct-horse-34",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  let token = logout_csrf(&mut h, &session_id).await?;
  let app = axum::Router::new()
    .route("/logout", axum::routing::post(post_logout))
    .with_state(app_state(&h))
    .layer(Extension(RequestId::new()));
  // A well-formed token sent under the wrong content type must fail closed:
  // the Form extractor rejects before any session state is touched.
  let body = format!("csrf={token}");
  let request = axum::http::Request::post("/logout")
    .header(axum::http::header::CONTENT_TYPE, "application/json")
    .header(
      axum::http::header::COOKIE,
      format!("session_id={session_id}"),
    )
    .body(axum::body::Body::from(body))
    .map_err(|_| unexpected("request build failed"))?;
  let response = tower::ServiceExt::oneshot(app, request)
    .await
    .map_err(|_| unexpected("router failed"))?;
  if !response.status().is_client_error() {
    return Err(unexpected(
      "POST /logout with the wrong content type must fail closed with 4xx",
    ));
  }
  if load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .is_none()
  {
    return Err(unexpected(
      "a content-type reject must leave the session intact",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_without_session_is_idempotent() -> TestResult {
  let h = harness().await?;
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    CookieJar::new(),
    Form(LogoutForm {
      csrf: String::new(),
    }),
  )
  .await;
  if response.status() != StatusCode::SEE_OTHER {
    return Err(unexpected(
      "POST /logout without a session must land on login",
    ));
  }
  let set_cookie = response
    .headers()
    .get(header::SET_COOKIE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  if !set_cookie.contains("session_id=") || !set_cookie.contains("Max-Age=0") {
    return Err(unexpected(
      "an anonymous sign-out must still expire the cookie",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn get_logout_without_session_is_idempotent() -> TestResult {
  let h = harness().await?;
  let response = get_logout(State(app_state(&h)), CookieJar::new()).await;
  if response.status() != StatusCode::OK {
    return Err(unexpected(
      "GET /logout without a session must still succeed",
    ));
  }
  if response.headers().get(header::LOCATION).is_some() {
    return Err(unexpected(
      "GET /logout must not redirect even when anonymous",
    ));
  }
  if response.headers().contains_key(header::SET_COOKIE) {
    return Err(unexpected("GET /logout must not touch cookies"));
  }
  Ok(())
}

/// Provision a client with one enabled post-logout URI attached, a matching
/// pending request, and a full session whose meta binds that URI.
async fn bind_logout_flow(
  h: &mut Harness,
  client_id: &str,
  email: &str,
  post_logout_uri: &str,
  enabled: bool,
) -> Result<String, TestError> {
  let client = client_repo::insert(
    &h.pool,
    &h.config.keys,
    false,
    &NewClient {
      id: uuid::Uuid::new_v4(),
      client_id: client_id.to_owned(),
      client_secret_hash: None,
      client_secret_expires_at: None,
      client_name: "Logout Test App".to_owned(),
      grant_types: vec!["authorization_code".to_owned()],
      response_types: vec!["code".to_owned()],
      scope: "orders:read".to_owned(),
      token_endpoint_auth_method: "none".to_owned(),
      jwks: None,
      jwks_uri: None,
      tls_client_auth_subject_dn: None,
      tls_client_auth_cert_thumbprint: None,
      request_uris: None,
      contacts: None,
      software_id: None,
      dpop_bound_access_tokens: false,
      registration_access_token_hash: None,
    },
  )
  .await?;
  let (row, _) = redirect_repo::upsert(
    &h.pool,
    &h.config.keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: uuid::Uuid::new_v4(),
      uri: post_logout_uri,
      kind: RedirectKind::PostLogout,
      description: "logout test",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(&h.pool, &client.client_id, row.id, None).await?;
  if !enabled {
    redirect_repo::disable(&h.pool, &h.config.keys, row.id).await?;
  }
  let request_id =
    pending::new_request_id().map_err(|_| TestError::Unexpected("rng".to_owned()))?;
  let record = pending::PendingAuth {
    client_id: client.client_id.clone(),
    redirect_uri: "https://client.example.test/cb".to_owned(),
    scope: "orders:read".to_owned(),
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
    state: Some("state-xyz".to_owned()),
    dpop_jkt: None,
    iss: "https://auth.example.test".to_owned(),
    post_logout_uri: Some(post_logout_uri.to_owned()),
  };
  pending::put(
    &mut h.conn,
    &h.store,
    &request_id,
    &record,
    std::time::Duration::from_secs(300),
  )
  .await?;
  let user = create_user(h, email, "correct-horse-04", false, true).await?;
  let (pre, csrf) = presession(h).await?;
  {
    let mut deps = deps_of(h);
    bind_pending_request(
      &mut deps,
      &pre,
      &request_id,
      &client.client_id,
      Some(post_logout_uri),
    )
    .await?;
  }
  let code = current_code(&user, h)?;
  match try_login(h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => Ok(session_id),
    _ => Err(unexpected("logout-flow login must authenticate")),
  }
}

#[tokio::test]
async fn post_logout_redirects_to_bound_post_logout_uri() -> TestResult {
  let mut h = harness().await?;
  let uri = "https://client.example.test/signed-out";
  let session_id = bind_logout_flow(
    &mut h,
    "logout-bound",
    "logout-bound@example.test",
    uri,
    true,
  )
  .await?;

  let token = logout_csrf(&mut h, &session_id).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;

  if response.status() != StatusCode::SEE_OTHER {
    return Err(unexpected("a bound logout must redirect"));
  }
  let location = response
    .headers()
    .get(header::LOCATION)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  if location != uri {
    return Err(unexpected(
      "the redirect must be exactly the registered post-logout URI",
    ));
  }
  if sessions::get(&mut h.conn, &h.store, &session_id)
    .await?
    .is_some()
  {
    return Err(unexpected("the session must still be destroyed"));
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_ignores_disabled_post_logout_uri() -> TestResult {
  let mut h = harness().await?;
  let uri = "https://client.example.test/disabled-out";
  let session_id = bind_logout_flow(
    &mut h,
    "logout-disabled",
    "logout-disabled@example.test",
    uri,
    false,
  )
  .await?;

  let token = logout_csrf(&mut h, &session_id).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;

  if response.status() != StatusCode::OK {
    return Err(unexpected("a disabled post-logout URI must not redirect"));
  }
  if response.headers().get(header::LOCATION).is_some() {
    return Err(unexpected("no redirect when the bound URI is disabled"));
  }
  Ok(())
}

#[tokio::test]
async fn post_logout_ignores_deactivated_client() -> TestResult {
  let mut h = harness().await?;
  let uri = "https://client.example.test/inactive-out";
  let session_id = bind_logout_flow(
    &mut h,
    "logout-inactive",
    "logout-inactive@example.test",
    uri,
    true,
  )
  .await?;
  client_repo::deactivate(&h.pool, "logout-inactive").await?;

  let token = logout_csrf(&mut h, &session_id).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;

  if response.status() != StatusCode::OK {
    return Err(unexpected(
      "a deactivated client must not receive a redirect",
    ));
  }
  if response.headers().get(header::LOCATION).is_some() {
    return Err(unexpected("no redirect when the owning client is inactive"));
  }
  Ok(())
}

#[tokio::test]
async fn login_wrong_password_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-badpw@example.test",
    "correct-horse-02",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let bad = LoginAttempt {
    password: "wrong-password-xyz".to_owned(),
    ..attempt(&pre, &csrf, &user, &code)
  };
  match try_login(&mut h, bad).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected("a wrong password must be rejected")),
  }?;
  let count = user_repo::login_failure_count(&mut h.conn, &h.store, &user.email).await?;
  if count != 1 {
    return Err(unexpected("a wrong password must count toward lockout"));
  }
  Ok(())
}

#[tokio::test]
async fn login_unknown_email_rejected_uniformly() -> TestResult {
  let mut h = harness().await?;
  let (pre, csrf) = presession(&mut h).await?;
  let ghost = TestUser {
    id: uuid::Uuid::new_v4(),
    email: "ghost-nobody@example.test".to_owned(),
    password: "some-password-01".to_owned(),
    totp_secret: None,
    recovery_codes: Vec::new(),
  };
  match try_login(&mut h, attempt(&pre, &csrf, &ghost, "000000")).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected(
      "an unknown email must be rejected like a wrong password",
    )),
  }
}

#[tokio::test]
async fn login_disabled_account_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-off@example.test",
    "correct-horse-03",
    false,
    true,
  )
  .await?;
  if !user_repo::disable_user(&h.pool, user.id).await? {
    return Err(unexpected("disable must update a row"));
  }
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected("a disabled account must be rejected")),
  }
}

#[tokio::test]
async fn login_locked_account_rejected_uniformly() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-lock@example.test",
    "correct-horse-04",
    false,
    true,
  )
  .await?;
  let code = current_code(&user, &h)?;
  for _ in 0..LOCKOUT_THRESHOLD {
    let (pre, csrf) = presession(&mut h).await?;
    let bad = LoginAttempt {
      password: "wrong-password-xyz".to_owned(),
      ..attempt(&pre, &csrf, &user, &code)
    };
    match try_login(&mut h, bad).await? {
      LoginOutcome::Rejected => {}
      _ => return Err(unexpected("wrong passwords must be rejected")),
    }
  }
  let policy = user_repo::LockoutPolicy {
    threshold: LOCKOUT_THRESHOLD,
    lock_duration: LOCKOUT_WINDOW,
  };
  if !user_repo::is_locked_out(&mut h.conn, &h.store, policy, &user.email).await? {
    return Err(unexpected("the threshold must lock the account"));
  }
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected(
      "correct credentials while locked must be rejected",
    )),
  }
}

#[tokio::test]
async fn login_wrong_totp_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-badcode@example.test",
    "correct-horse-05",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let bad_code = wrong_code(&user, &h)?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &bad_code)).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected("a wrong TOTP code must be rejected")),
  }
}

#[tokio::test]
async fn login_recovery_code_single_use() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-rec@example.test",
    "correct-horse-06",
    false,
    true,
  )
  .await?;
  let code = user
    .recovery_codes
    .first()
    .ok_or_else(|| unexpected("enrollment must mint recovery codes"))?
    .clone();
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { .. } => {}
    _ => return Err(unexpected("a fresh recovery code must authenticate")),
  }
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected("a consumed recovery code must be rejected")),
  }
}

#[tokio::test]
async fn login_replayed_totp_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-replay@example.test",
    "correct-horse-07",
    false,
    true,
  )
  .await?;
  let code = current_code(&user, &h)?;
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { .. } => {}
    _ => return Err(unexpected("the first presentation must authenticate")),
  }
  // Same fixed clock, same step: the second presentation is a replay.
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Rejected => Ok(()),
    _ => Err(unexpected("a replayed TOTP code must be rejected")),
  }
}

#[tokio::test]
async fn login_unbound_redirects_to_success() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-free@example.test",
    "correct-horse-08",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { redirect_to, .. } => {
      if redirect_to == LOGIN_SUCCESS_PATH {
        Ok(())
      } else {
        Err(unexpected("an unbound login must land on the success page"))
      }
    }
    _ => Err(unexpected("correct credentials must authenticate")),
  }
}

#[tokio::test]
async fn login_expired_pending_denied_without_redirect() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-stale@example.test",
    "correct-horse-09",
    false,
    true,
  )
  .await?;
  let request_id = pending_request(&mut h).await?;
  let (pre, csrf) = presession(&mut h).await?;
  {
    let mut deps = deps_of(&mut h);
    bind_pending_request(&mut deps, &pre, &request_id, "login-test-client", None).await?;
  }
  pending::consume(&mut h.conn, &h.store, &request_id)
    .await
    .map_err(|_| unexpected("consume"))?;
  let code = current_code(&user, &h)?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await {
    Err(TestError::App(error)) if error.code() == OAuthErrorCode::InvalidRequest => Ok(()),
    Err(_) => Err(unexpected("a stale binding must be invalid_request")),
    Ok(_) => Err(unexpected("a stale binding must never redirect")),
  }
}

#[tokio::test]
async fn login_cookie_secure_config_gated() -> TestResult {
  let mut h = harness().await?;
  let header = cookie_header(&h, "session-abc");
  if !header.contains("Secure") {
    return Err(unexpected("Secure must be set by default"));
  }
  let config = std::sync::Arc::get_mut(&mut h.config)
    .ok_or_else(|| unexpected("the harness config must be uniquely owned"))?;
  config.cookie_secure = false;
  config.cookie_domain = Some("auth.example.test".to_owned());
  let header = cookie_header(&h, "session-abc");
  if header.contains("Secure") {
    return Err(unexpected("Secure must follow the config gate"));
  }
  for needle in [
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    "Domain=auth.example.test",
  ] {
    if !header.contains(needle) {
      return Err(unexpected("domain/HttpOnly/Lax/Path must survive"));
    }
  }
  Ok(())
}

#[tokio::test]
async fn login_csrf_mismatch_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-csrf@example.test",
    "correct-horse-10",
    false,
    true,
  )
  .await?;
  let (pre, _) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let forged = attempt(&pre, "tampered-token", &user, &code);
  match try_login(&mut h, forged).await {
    Err(TestError::App(error)) if error.code() == OAuthErrorCode::InvalidRequest => Ok(()),
    Err(_) => Err(unexpected("a CSRF mismatch must be invalid_request")),
    Ok(_) => Err(unexpected("a CSRF mismatch must never authenticate")),
  }
}

#[tokio::test]
async fn login_authenticated_session_rebinds_fresh_request() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-rebind@example.test",
    "correct-horse-11",
    false,
    true,
  )
  .await?;
  // Authenticate once against an old request, then strand that session binding.
  let old_id = pending_request(&mut h).await?;
  let (pre, csrf) = presession(&mut h).await?;
  {
    let mut deps = deps_of(&mut h);
    bind_pending_request(&mut deps, &pre, &old_id, "login-test-client", None).await?;
  }
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  pending::consume(&mut h.conn, &h.store, &old_id)
    .await
    .map_err(|_| unexpected("consume"))?;
  let before = load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .ok_or_else(|| unexpected("the session must be live"))?;
  if before.meta.pending_request_id.as_deref() != Some(old_id.as_str()) {
    return Err(unexpected(
      "the session must start bound to the old request",
    ));
  }
  // A fresh authorization handoff for the same authenticated session.
  let new_id = pending_request(&mut h).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = get_login(
    State(app_state(&h)),
    jar,
    Query(LoginPageQuery {
      request_id: Some(new_id.clone()),
    }),
  )
  .await;
  if response.status() != StatusCode::SEE_OTHER {
    return Err(unexpected("an authenticated /login must redirect"));
  }
  let location = response
    .headers()
    .get(header::LOCATION)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  if location != CONSENT_PATH {
    return Err(unexpected("the authenticated redirect must reach consent"));
  }
  let after = load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .ok_or_else(|| unexpected("the session must still be live"))?;
  if after.meta.pending_request_id.as_deref() != Some(new_id.as_str()) {
    return Err(unexpected(
      "GET /login must rebind the session to the fresh request",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn login_attempt_success() -> TestResult {
  let mut h = harness().await?;
  // Mixed case on purpose: the session subject must be the normalized
  // plaintext email, while the stored row stays encrypt-only.
  let user = create_user(
    &mut h,
    "Login-Ok@Example.Test",
    "correct-horse-20",
    false,
    true,
  )
  .await?;
  let at_rest = sqlx::query("SELECT email, email_enc FROM users WHERE id = $1")
    .bind(user.id)
    .fetch_one(&h.pool)
    .await?;
  let plain: Option<String> = at_rest.try_get("email")?;
  let sealed: Option<Vec<u8>> = at_rest.try_get("email_enc")?;
  if plain.is_some() {
    return Err(unexpected("encrypt-only must blank the email plaintext"));
  }
  if sealed.is_none() {
    return Err(unexpected("the sealed email must be stored"));
  }
  let request_id = pending_request(&mut h).await?;
  let (pre, csrf) = presession(&mut h).await?;
  {
    let mut deps = deps_of(&mut h);
    bind_pending_request(&mut deps, &pre, &request_id, "login-test-client", None).await?;
  }
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated {
      session_id,
      redirect_to,
    } => {
      if redirect_to != CONSENT_PATH {
        return Err(unexpected("a bound login must reach consent"));
      }
      session_id
    }
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  let live = load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .ok_or_else(|| unexpected("the new session must be stored"))?;
  if live.record.subject != "login-ok@example.test" {
    return Err(unexpected(
      "the session subject must be the normalized plaintext email",
    ));
  }
  if !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the session must be full and owned"));
  }
  // A disabled user is rejected exactly as before.
  let off = create_user(
    &mut h,
    "login-off@example.test",
    "correct-horse-21",
    false,
    true,
  )
  .await?;
  if !user_repo::disable_user(&h.pool, off.id).await? {
    return Err(unexpected("disable must update a row"));
  }
  let (pre, csrf) = presession(&mut h).await?;
  let off_code = current_code(&off, &h)?;
  match try_login(&mut h, attempt(&pre, &csrf, &off, &off_code)).await? {
    LoginOutcome::Rejected => {}
    _ => return Err(unexpected("a disabled account must be rejected")),
  }
  // A wrong TOTP code is rejected exactly as before.
  let bad_code = wrong_code(&user, &h)?;
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &bad_code)).await? {
    LoginOutcome::Rejected => {}
    _ => return Err(unexpected("a wrong TOTP code must be rejected")),
  }
  // A corrupt stored ciphertext fails closed as `PiiDecrypt` (503): never a
  // 500, never an authentication, and the error carries no plaintext.
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE users SET email_enc = $1 WHERE id = $2")
    .bind(corrupt)
    .bind(user.id)
    .execute(&h.pool)
    .await?;
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await {
    Err(TestError::App(error)) => {
      if !matches!(error, AppError::PiiDecrypt) {
        return Err(unexpected("a corrupt email_enc must be PiiDecrypt"));
      }
      if error.status() != StatusCode::SERVICE_UNAVAILABLE {
        return Err(unexpected("a decrypt failure must be 503, never 500"));
      }
      if format!("{error:?}").contains("login-ok") {
        return Err(unexpected("a decrypt error must not leak plaintext"));
      }
    }
    Err(_) => return Err(unexpected("a corrupt email_enc must surface PiiDecrypt")),
    Ok(_) => return Err(unexpected("a corrupt row must never authenticate")),
  }
  Ok(())
}

#[tokio::test]
async fn logout_redirects_to_registered_uri() -> TestResult {
  let mut h = harness().await?;
  let uri = "https://client.example.test/signed-out";
  let session_id = bind_logout_flow(
    &mut h,
    "logout-registered",
    "logout-registered@example.test",
    uri,
    true,
  )
  .await?;
  // The logout path reads the DECRYPTED client row: plaintext is blanked.
  let at_rest = sqlx::query(
    "SELECT client_name, client_name_enc FROM oauth_clients WHERE client_id = 'logout-registered'",
  )
  .fetch_one(&h.pool)
  .await?;
  let plain: Option<String> = at_rest.try_get("client_name")?;
  let sealed: Option<Vec<u8>> = at_rest.try_get("client_name_enc")?;
  if plain.is_some() {
    return Err(unexpected("encrypt-only must blank the client name"));
  }
  if sealed.is_none() {
    return Err(unexpected("the sealed client name must be stored"));
  }
  let token = logout_csrf(&mut h, &session_id).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;
  if response.status() != StatusCode::SEE_OTHER {
    return Err(unexpected("a bound logout must redirect"));
  }
  let location = response
    .headers()
    .get(header::LOCATION)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  if location != uri {
    return Err(unexpected(
      "the redirect must be exactly the registered post-logout URI",
    ));
  }
  if sessions::get(&mut h.conn, &h.store, &session_id)
    .await?
    .is_some()
  {
    return Err(unexpected("the session must still be destroyed"));
  }
  // A corrupt stored client name fails closed with 503: no redirect to the
  // bound URI and no neutral page.
  let other_uri = "https://client.example.test/other-out";
  let other = bind_logout_flow(
    &mut h,
    "logout-corrupt",
    "logout-corrupt@example.test",
    other_uri,
    true,
  )
  .await?;
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE oauth_clients SET client_name_enc = $1 WHERE client_id = 'logout-corrupt'")
    .bind(corrupt)
    .execute(&h.pool)
    .await?;
  let token = logout_csrf(&mut h, &other).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &other));
  let response = post_logout(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(LogoutForm { csrf: token }),
  )
  .await;
  if response.status() != StatusCode::SERVICE_UNAVAILABLE {
    return Err(unexpected("a corrupt client row must fail closed with 503"));
  }
  if response.headers().get(header::LOCATION).is_some() {
    return Err(unexpected("a decrypt failure must never redirect"));
  }
  Ok(())
}

#[tokio::test]
async fn login_corrupt_totp_ciphertext_fails_closed_with_503() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "auth-corrupt-totp@example.test",
    "correct-horse-09",
    false,
    true,
  )
  .await?;
  let code = current_code(&user, &h)?;
  // Sanity: correct credentials authenticate before corruption.
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { .. } => {}
    _ => return Err(unexpected("correct credentials must authenticate")),
  }
  // Corrupt the stored TOTP blob at rest.
  let corrupt: &[u8] = b"corrupt-blob";
  sqlx::query("UPDATE users SET totp_secret_enc = $1 WHERE id = $2")
    .bind(corrupt)
    .bind(user.id)
    .execute(&h.pool)
    .await?;
  // The core path surfaces `PiiDecrypt` (503): never a 500, never an
  // authentication, and the error carries no plaintext.
  let (pre, csrf) = presession(&mut h).await?;
  match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await {
    Err(TestError::App(error)) => {
      if !matches!(error, AppError::PiiDecrypt) {
        return Err(unexpected("a corrupt totp_secret_enc must be PiiDecrypt"));
      }
      if error.status() != StatusCode::SERVICE_UNAVAILABLE {
        return Err(unexpected("a TOTP decrypt failure must be 503, never 500"));
      }
      if format!("{error:?}").contains(&user.email) {
        return Err(unexpected("a decrypt error must not leak plaintext"));
      }
    }
    Err(_) => {
      return Err(unexpected(
        "a corrupt totp_secret_enc must surface PiiDecrypt",
      ));
    }
    Ok(_) => return Err(unexpected("a corrupt row must never authenticate")),
  }
  // The HTTP layer renders 503 through the same `Err` arm that routes
  // `PiiDecrypt` into `emit_pii_decrypt` (`pii.decrypt_failure`).
  let (pre, csrf) = presession(&mut h).await?;
  let jar = CookieJar::new().add(session_cookie(&h.config, &pre));
  let form = LoginForm {
    email: user.email.clone(),
    password: user.password.clone(),
    code,
    csrf,
  };
  let response = post_login(
    State(app_state(&h)),
    Extension(RequestId::new()),
    jar,
    Form(form),
  )
  .await;
  if response.status() != StatusCode::SERVICE_UNAVAILABLE {
    return Err(unexpected("a corrupt TOTP row must render 503"));
  }
  Ok(())
}

/// Attribute names of a `Set-Cookie` value, minus the leading pair and any
/// expiry marker, lowercased and sorted for set comparison.
fn cookie_attr_names(header: &str) -> Vec<String> {
  let mut names = Vec::new();
  for part in header.split(';').skip(1) {
    let trimmed = part.trim();
    if trimmed.is_empty() {
      continue;
    }
    let name = match trimmed.split('=').next() {
      Some(name) => name.trim().to_ascii_lowercase(),
      None => continue,
    };
    if name == "max-age" || name == "expires" {
      continue;
    }
    names.push(name);
  }
  names.sort();
  names
}

#[tokio::test]
async fn get_logout_leaves_session_intact_and_renders_confirm() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "logout-readonly@example.test",
    "correct-horse-30",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let session_id = match try_login(&mut h, attempt(&pre, &csrf, &user, &code)).await? {
    LoginOutcome::Authenticated { session_id, .. } => session_id,
    _ => return Err(unexpected("correct credentials must authenticate")),
  };
  let jar = CookieJar::new().add(session_cookie(&h.config, &session_id));
  let response = get_logout(State(app_state(&h)), jar).await;
  if response.status() != StatusCode::OK {
    return Err(unexpected("GET /logout must render the confirm page"));
  }
  if response.headers().contains_key(header::SET_COOKIE) {
    return Err(unexpected("GET /logout must not touch cookies"));
  }
  let raw = http_body_util::BodyExt::collect(response.into_body())
    .await
    .map_err(|_| unexpected("the confirm body must read"))?
    .to_bytes();
  let body = String::from_utf8_lossy(&raw);
  if !body.contains("action=\"/logout\"") || !body.contains("name=\"csrf\"") {
    return Err(unexpected(
      "GET /logout must render the sign-out confirm form",
    ));
  }
  if load_session(&mut h.conn, &h.store, &session_id)
    .await?
    .is_none()
  {
    return Err(unexpected("GET /logout must never destroy the session"));
  }
  Ok(())
}

#[tokio::test]
async fn logout_clearing_cookie_mirrors_session_cookie_attrs() -> TestResult {
  let h = harness().await?;
  let session = session_cookie(&h.config, "logout-attr-session").to_string();
  let clearing = expired_session_cookie(&h.config).to_string();
  if !clearing.contains("Max-Age=0") {
    return Err(unexpected("the clearing cookie must expire immediately"));
  }
  if cookie_attr_names(&session) != cookie_attr_names(&clearing) {
    return Err(unexpected(
      "the clearing cookie must mirror the session cookie attributes",
    ));
  }
  Ok(())
}

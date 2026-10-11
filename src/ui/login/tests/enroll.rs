//! `test(login)` enrollment suite: bootstrap cycle, gating, password change.

use axum::Extension;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;

use super::super::TOTP_CONFIRM_ACTION;
use super::{
  Harness, LoginAttempt, LoginDeps, TEST_PEER_IP, TEST_PEER_SOCK, TestError, TestResult, app_state,
  attempt, create_user, current_code, deps_of, harness, pending_request, presession,
};
use crate::{
  crypto::totp,
  db::user_repo,
  error::OAuthErrorCode,
  middleware::request_id::RequestId,
  state::RedisConn,
  store::sessions,
  ui::login::{
    CHANGE_PASSWORD_PATH, CONSENT_PATH, ConfirmForm, ConfirmOutcome, LOCKOUT_THRESHOLD,
    LOCKOUT_WINDOW, LOGIN_SUCCESS_PATH, LoginOutcome, PasswordOutcome, attempt_login,
    bind_pending_request, change_password, confirm_totp, form_token, load_session, logout,
    post_totp_confirm, provision_totp, restricted_allows_path, session_cookie,
  },
};

/// `Err` shortcut for a failed test assertion.
fn unexpected(message: &str) -> TestError {
  TestError::Unexpected(message.to_owned())
}

/// A code guaranteed to differ from the live one for `secret`.
fn wrong_for_secret(secret: &str, counter: u64) -> Result<String, TestError> {
  let verifier = totp::build_totp(secret)?;
  let mut code = verifier
    .generate(counter * totp::TOTP_STEP_SECS)
    .to_string()
    .into_bytes();
  code[0] = if code[0] == b'0' { b'1' } else { b'0' };
  String::from_utf8(code).map_err(|_| TestError::Unexpected("code".to_owned()))
}

/// Log a must-change user in and return the restricted session id.
async fn restricted_login(
  harness: &mut Harness,
  email: &str,
  password: &str,
  request_id: Option<&str>,
) -> Result<String, TestError> {
  let (pre, csrf) = presession(harness).await?;
  if let Some(id) = request_id {
    let mut deps = deps_of(harness);
    bind_pending_request(&mut deps, &pre, id, "login-test-client", None).await?;
  }
  let attempt = LoginAttempt {
    presession_id: pre,
    email: email.to_owned(),
    password: password.to_owned(),
    code: String::new(),
    csrf,
    peer_ip: Some(TEST_PEER_IP),
  };
  let mut deps = deps_of(harness);
  match attempt_login(&mut deps, attempt).await? {
    LoginOutcome::Restricted {
      session_id,
      redirect_to,
    } => {
      if redirect_to != CHANGE_PASSWORD_PATH {
        return Err(unexpected(
          "restricted logins must start at change-password",
        ));
      }
      Ok(session_id)
    }
    _ => Err(unexpected("a must-change login must be restricted")),
  }
}

#[tokio::test]
async fn login_enrollment_wrong_confirmation_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "enroll-bad@example.test",
    "temp-password-01",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  if offer.recovery_codes.len() != totp::RECOVERY_CODE_COUNT {
    return Err(unexpected("enrollment must mint recovery codes"));
  }
  if !offer.otpauth_uri.contains(&offer.secret) {
    return Err(unexpected("the enrollment URI must carry the secret"));
  }
  let bad = wrong_for_secret(&offer.secret, h.counter)?;
  let outcome = {
    let mut deps = deps_of(&mut h);
    confirm_totp(&mut deps, &restricted, &bad, Some(TEST_PEER_IP)).await?
  };
  if !matches!(outcome, ConfirmOutcome::Rejected) {
    return Err(unexpected("a wrong confirmation code must be rejected"));
  }
  let live = load_session(&mut h.conn, &h.store, &restricted)
    .await?
    .ok_or_else(|| unexpected("the session must survive a bad confirm"))?;
  if !live.record.restricted {
    return Err(unexpected("the session must stay restricted"));
  }
  Ok(())
}

#[tokio::test]
async fn login_bootstrap_full_cycle_clears_restriction() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "boot-cycle@example.test",
    "temp-password-02",
    true,
    false,
  )
  .await?;
  let request_id = pending_request(&mut h).await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, Some(&request_id)).await?;

  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &restricted,
      "new-strong-password-01",
      "new-strong-password-01",
    )
    .await?
    {
      PasswordOutcome::StillRestricted { session_id } => {
        if session_id != restricted {
          return Err(unexpected("the session must not rotate yet"));
        }
      }
      PasswordOutcome::Promoted { .. } => {
        return Err(unexpected("promotion needs TOTP enrollment first"));
      }
    }
  }
  let fresh = user_repo::find_by_email(&h.pool, &h.config.keys, &user.email)
    .await?
    .ok_or_else(|| unexpected("the user must exist"))?;
  if fresh.must_change_password {
    return Err(unexpected("set_password must clear the flag"));
  }

  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  let verifier = totp::build_totp(&offer.secret)?;
  let code = verifier
    .generate(h.counter * totp::TOTP_STEP_SECS)
    .to_string();
  let (full, redirect_to) = {
    let mut deps = deps_of(&mut h);
    match confirm_totp(&mut deps, &restricted, &code, Some(TEST_PEER_IP)).await? {
      ConfirmOutcome::Completed {
        session_id,
        redirect_to,
      } => (session_id, redirect_to),
      _ => return Err(unexpected("a correct confirmation must complete bootstrap")),
    }
  };
  if redirect_to != CONSENT_PATH {
    return Err(unexpected("completion must reach the bound record"));
  }
  if full == restricted {
    return Err(unexpected("completion must re-issue the session"));
  }
  let live = load_session(&mut h.conn, &h.store, &full)
    .await?
    .ok_or_else(|| unexpected("the re-issued session must be stored"))?;
  if live.record.subject != user.email || !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the re-issued session must be full"));
  }
  if sessions::get(&mut h.conn, &h.store, &restricted)
    .await?
    .is_some()
  {
    return Err(unexpected("the restricted session must be gone"));
  }
  Ok(())
}

#[tokio::test]
async fn login_restricted_paths_gated() -> TestResult {
  for allowed in [
    "/login",
    "/login/success",
    "/login/change-password",
    "/login/totp/setup",
    "/login/totp/confirm",
    "/logout",
  ] {
    if !restricted_allows_path(allowed) {
      return Err(unexpected("bootstrap routes must stay reachable"));
    }
  }
  for denied in [
    "/authorize",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth/introspect",
    "/oauth/revoke",
    "/admin/users",
    "/consent",
    "/device",
    "/",
  ] {
    if restricted_allows_path(denied) {
      return Err(unexpected("protected routes must deny restricted sessions"));
    }
  }
  Ok(())
}

#[tokio::test]
async fn login_enrollment_requires_subject_session() -> TestResult {
  let mut h = harness().await?;
  let (pre, _) = presession(&mut h).await?;
  {
    let mut deps = deps_of(&mut h);
    match provision_totp(&mut deps, &pre).await {
      Err(error) if error.code() == OAuthErrorCode::InvalidRequest => {}
      Err(_) => {
        return Err(unexpected(
          "a pre-session provision must be invalid_request",
        ));
      }
      Ok(_) => return Err(unexpected("a pre-session must never enroll")),
    }
  }
  {
    let mut deps = deps_of(&mut h);
    match confirm_totp(&mut deps, &pre, "000000", Some(TEST_PEER_IP)).await {
      Err(error) if error.code() == OAuthErrorCode::InvalidRequest => Ok(()),
      Err(_) => Err(unexpected("a pre-session confirm must be invalid_request")),
      Ok(_) => Err(unexpected("a pre-session must never confirm")),
    }
  }
}

#[tokio::test]
async fn login_confirm_without_provision_rejected() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "enroll-nope@example.test",
    "temp-password-03",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let mut deps = deps_of(&mut h);
  match confirm_totp(&mut deps, &restricted, "000000", Some(TEST_PEER_IP)).await? {
    ConfirmOutcome::Rejected => Ok(()),
    _ => Err(unexpected("confirmation without a secret must be rejected")),
  }
}

#[tokio::test]
async fn login_password_change_validates() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "pw-change@example.test",
    "correct-horse-11",
    false,
    true,
  )
  .await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let full = {
    let mut deps = deps_of(&mut h);
    match attempt_login(&mut deps, attempt(&pre, &csrf, &user, &code)).await? {
      LoginOutcome::Authenticated { session_id, .. } => session_id,
      _ => return Err(unexpected("correct credentials must authenticate")),
    }
  };
  {
    let mut deps = deps_of(&mut h);
    match change_password(&mut deps, &full, "new-pw", "other-pw").await {
      Err(error) if error.code() == OAuthErrorCode::InvalidRequest => {}
      Err(_) => return Err(unexpected("a mismatch must be invalid_request")),
      Ok(_) => return Err(unexpected("a mismatch must never change")),
    }
  }
  {
    let mut deps = deps_of(&mut h);
    match change_password(&mut deps, &full, "short", "short").await {
      Err(error) if error.code() == OAuthErrorCode::InvalidRequest => {}
      Err(_) => return Err(unexpected("a short password must be invalid_request")),
      Ok(_) => return Err(unexpected("a short password must never change")),
    }
  }
  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &full,
      "new-strong-password-02",
      "new-strong-password-02",
    )
    .await?
    {
      PasswordOutcome::Promoted {
        session_id,
        redirect_to,
      } => {
        if session_id == full {
          return Err(unexpected("promotion must re-issue the session"));
        }
        if redirect_to != LOGIN_SUCCESS_PATH {
          return Err(unexpected("an unbound promotion lands on success"));
        }
        let live = load_session(&mut h.conn, &h.store, &session_id)
          .await?
          .ok_or_else(|| unexpected("the new session must be stored"))?;
        if live.record.restricted || !live.record.mfa_verified {
          return Err(unexpected("the new session must stay full"));
        }
      }
      PasswordOutcome::StillRestricted { .. } => {
        return Err(unexpected("an enrolled user must promote"));
      }
    }
  }
  Ok(())
}

#[tokio::test]
async fn login_logout_destroys_session() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(&mut h, "bye@example.test", "correct-horse-12", false, true).await?;
  let (pre, csrf) = presession(&mut h).await?;
  let code = current_code(&user, &h)?;
  let full = {
    let mut deps = deps_of(&mut h);
    match attempt_login(&mut deps, attempt(&pre, &csrf, &user, &code)).await? {
      LoginOutcome::Authenticated { session_id, .. } => session_id,
      _ => return Err(unexpected("correct credentials must authenticate")),
    }
  };
  logout(&mut h.conn, &h.store, &full).await?;
  if load_session(&mut h.conn, &h.store, &full).await?.is_some() {
    return Err(unexpected("logout must destroy the session"));
  }
  // Idempotent: a second logout still succeeds.
  logout(&mut h.conn, &h.store, &full).await?;
  Ok(())
}

#[tokio::test]
async fn login_totp_enrollment() -> TestResult {
  let mut h = harness().await?;
  // Mixed case on purpose: the promoted session subject must be the
  // normalized plaintext email.
  let user = create_user(
    &mut h,
    "Enroll-New@Example.Test",
    "temp-password-10",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &restricted,
      "new-strong-password-10",
      "new-strong-password-10",
    )
    .await?
    {
      PasswordOutcome::StillRestricted { .. } => {}
      PasswordOutcome::Promoted { .. } => {
        return Err(unexpected("promotion needs TOTP enrollment first"));
      }
    }
  }
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  if offer.recovery_codes.len() != totp::RECOVERY_CODE_COUNT {
    return Err(unexpected("enrollment must mint recovery codes"));
  }
  // A wrong confirmation code is rejected exactly as before.
  let bad = wrong_for_secret(&offer.secret, h.counter)?;
  {
    let mut deps = deps_of(&mut h);
    match confirm_totp(&mut deps, &restricted, &bad, Some(TEST_PEER_IP)).await? {
      ConfirmOutcome::Rejected => {}
      _ => return Err(unexpected("a wrong confirmation code must be rejected")),
    }
  }
  // The correct code completes enrollment and promotes the session.
  let verifier = totp::build_totp(&offer.secret)?;
  let code = verifier
    .generate(h.counter * totp::TOTP_STEP_SECS)
    .to_string();
  let full = {
    let mut deps = deps_of(&mut h);
    match confirm_totp(&mut deps, &restricted, &code, Some(TEST_PEER_IP)).await? {
      ConfirmOutcome::Completed {
        session_id,
        redirect_to,
      } => {
        if redirect_to != LOGIN_SUCCESS_PATH {
          return Err(unexpected("an unbound completion lands on success"));
        }
        session_id
      }
      _ => {
        return Err(unexpected(
          "a correct confirmation must complete enrollment",
        ));
      }
    }
  };
  if full == restricted {
    return Err(unexpected("completion must re-issue the session"));
  }
  let live = load_session(&mut h.conn, &h.store, &full)
    .await?
    .ok_or_else(|| unexpected("the re-issued session must be stored"))?;
  if live.record.subject != "enroll-new@example.test" {
    return Err(unexpected(
      "the session subject must be the normalized plaintext email",
    ));
  }
  if !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the re-issued session must be full"));
  }
  Ok(())
}

/// `change_password` must revoke the subject's sibling sessions while the
/// current session survives (re-issued by promotion).
#[tokio::test]
async fn login_password_change_revokes_sibling_sessions() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "pw-sweep@example.test",
    "correct-horse-31",
    false,
    true,
  )
  .await?;
  let code = current_code(&user, &h)?;
  let (pre_a, csrf_a) = presession(&mut h).await?;
  let current = {
    let mut deps = deps_of(&mut h);
    match attempt_login(&mut deps, attempt(&pre_a, &csrf_a, &user, &code)).await? {
      LoginOutcome::Authenticated { session_id, .. } => session_id,
      _ => return Err(unexpected("correct credentials must authenticate")),
    }
  };
  // A sibling session via a recovery code (the TOTP code is already claimed).
  let sibling_code = user
    .recovery_codes
    .first()
    .ok_or_else(|| unexpected("the user must hold recovery codes"))?
    .clone();
  let (pre_b, csrf_b) = presession(&mut h).await?;
  let sibling = {
    let mut deps = deps_of(&mut h);
    match attempt_login(&mut deps, attempt(&pre_b, &csrf_b, &user, &sibling_code)).await? {
      LoginOutcome::Authenticated { session_id, .. } => session_id,
      _ => return Err(unexpected("a recovery code must authenticate")),
    }
  };
  let promoted = {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &current,
      "new-strong-password-31",
      "new-strong-password-31",
    )
    .await?
    {
      PasswordOutcome::Promoted { session_id, .. } => session_id,
      PasswordOutcome::StillRestricted { .. } => {
        return Err(unexpected("an enrolled user must promote"));
      }
    }
  };
  if load_session(&mut h.conn, &h.store, &sibling)
    .await?
    .is_some()
  {
    return Err(unexpected("a password change must kill sibling sessions"));
  }
  let live = load_session(&mut h.conn, &h.store, &promoted)
    .await?
    .ok_or_else(|| unexpected("the current session must survive"))?;
  if live.record.subject != user.email || !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the surviving session must stay full"));
  }
  Ok(())
}

/// `change_password` on a still-restricted session (TOTP enrollment pending)
/// must still revoke the subject's sibling sessions: the sweep runs before
/// the promotion branch, so `StillRestricted` is not a revocation bypass.
#[tokio::test]
async fn login_password_change_restricted_still_revokes_siblings() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "pw-restricted-sweep@example.test",
    "temp-password-50",
    true,
    false,
  )
  .await?;
  let current = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let sibling = restricted_login(&mut h, &user.email, &user.password, None).await?;
  if load_session(&mut h.conn, &h.store, &sibling)
    .await?
    .is_none()
  {
    return Err(unexpected("the sibling session must start live"));
  }
  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &current,
      "new-strong-password-50",
      "new-strong-password-50",
    )
    .await?
    {
      PasswordOutcome::StillRestricted { session_id } => {
        if session_id != current {
          return Err(unexpected("a restricted change must keep the session id"));
        }
      }
      PasswordOutcome::Promoted { .. } => {
        return Err(unexpected("promotion needs TOTP enrollment first"));
      }
    }
  }
  if load_session(&mut h.conn, &h.store, &sibling)
    .await?
    .is_some()
  {
    return Err(unexpected(
      "a restricted password change must kill sibling sessions",
    ));
  }
  let sibling_meta = format!("{}:meta", h.store.session_key(&sibling));
  let meta_left: i64 = redis::cmd("EXISTS")
    .arg(&sibling_meta)
    .query_async(&mut h.conn)
    .await?;
  if meta_left != 0 {
    return Err(unexpected(
      "a restricted password change must delete the sibling :meta sidecar",
    ));
  }
  let live = load_session(&mut h.conn, &h.store, &current)
    .await?
    .ok_or_else(|| unexpected("the current session must survive"))?;
  if !live.record.restricted {
    return Err(unexpected("the surviving session must stay restricted"));
  }
  if live.record.subject != user.email {
    return Err(unexpected("the surviving session must keep its subject"));
  }
  Ok(())
}

/// `confirm_totp` must revoke the subject's sibling sessions while the
/// current session survives (re-issued by promotion).
#[tokio::test]
async fn login_confirm_totp_revokes_sibling_sessions() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "confirm-sweep@example.test",
    "temp-password-32",
    true,
    false,
  )
  .await?;
  let current = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let sibling = restricted_login(&mut h, &user.email, &user.password, None).await?;
  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &current,
      "new-strong-password-32",
      "new-strong-password-32",
    )
    .await?
    {
      PasswordOutcome::StillRestricted { .. } => {}
      PasswordOutcome::Promoted { .. } => {
        return Err(unexpected("promotion needs TOTP enrollment first"));
      }
    }
  }
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &current).await?
  };
  let verifier = totp::build_totp(&offer.secret)?;
  let code = verifier
    .generate(h.counter * totp::TOTP_STEP_SECS)
    .to_string();
  let promoted = {
    let mut deps = deps_of(&mut h);
    match confirm_totp(&mut deps, &current, &code, Some(TEST_PEER_IP)).await? {
      ConfirmOutcome::Completed { session_id, .. } => session_id,
      _ => return Err(unexpected("a correct confirmation must complete")),
    }
  };
  if load_session(&mut h.conn, &h.store, &sibling)
    .await?
    .is_some()
  {
    return Err(unexpected("a TOTP confirmation must kill sibling sessions"));
  }
  let live = load_session(&mut h.conn, &h.store, &promoted)
    .await?
    .ok_or_else(|| unexpected("the current session must survive"))?;
  if live.record.subject != user.email || !live.record.mfa_verified || live.record.restricted {
    return Err(unexpected("the surviving session must be full"));
  }
  Ok(())
}

/// Drive one `POST /login/totp/confirm` against a restricted session, returning
/// the status and body bytes of the rendered page.
async fn post_confirm(
  harness: &Harness,
  session_id: &str,
  csrf: &str,
  code: &str,
) -> Result<(StatusCode, Vec<u8>), TestError> {
  let jar = CookieJar::new().add(session_cookie(&harness.config, session_id));
  let response = post_totp_confirm(
    State(app_state(harness)),
    Extension(RequestId::new()),
    jar,
    Form(ConfirmForm {
      code: code.to_owned(),
      csrf: csrf.to_owned(),
    }),
    Some(ConnectInfo(TEST_PEER_SOCK)),
  )
  .await;
  let status = response.status();
  let body = axum::body::to_bytes(response.into_body(), usize::MAX)
    .await
    .map_err(|_| unexpected("response body"))?;
  Ok((status, body.to_vec()))
}

#[tokio::test]
async fn login_confirm_burst_locks_and_rejects_correct_code() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "confirm-lock@example.test",
    "temp-password-20",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  let bad = wrong_for_secret(&offer.secret, h.counter)?;
  for _ in 0..LOCKOUT_THRESHOLD {
    let outcome = {
      let mut deps = deps_of(&mut h);
      confirm_totp(&mut deps, &restricted, &bad, Some(TEST_PEER_IP)).await?
    };
    if !matches!(outcome, ConfirmOutcome::Rejected) {
      return Err(unexpected("a wrong confirmation code must be rejected"));
    }
  }
  let policy = user_repo::LockoutPolicy {
    threshold: LOCKOUT_THRESHOLD,
    account_threshold: LOCKOUT_THRESHOLD,
    lock_duration: LOCKOUT_WINDOW,
  };
  if !user_repo::is_locked_out(&mut h.conn, &h.store, policy, &user.email, None).await? {
    return Err(unexpected("a burst of wrong codes must lock the account"));
  }
  let verifier = totp::build_totp(&offer.secret)?;
  let correct = verifier
    .generate(h.counter * totp::TOTP_STEP_SECS)
    .to_string();
  let outcome = {
    let mut deps = deps_of(&mut h);
    confirm_totp(&mut deps, &restricted, &correct, Some(TEST_PEER_IP)).await?
  };
  if !matches!(outcome, ConfirmOutcome::Rejected) {
    return Err(unexpected(
      "a locked account must reject even a correct code",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn login_confirm_success_clears_failures() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "confirm-clear@example.test",
    "temp-password-21",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  {
    let mut deps = deps_of(&mut h);
    match change_password(
      &mut deps,
      &restricted,
      "new-strong-password-21",
      "new-strong-password-21",
    )
    .await?
    {
      PasswordOutcome::StillRestricted { .. } => {}
      PasswordOutcome::Promoted { .. } => {
        return Err(unexpected("promotion needs TOTP enrollment first"));
      }
    }
  }
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  let bad = wrong_for_secret(&offer.secret, h.counter)?;
  for _ in 1..LOCKOUT_THRESHOLD {
    let outcome = {
      let mut deps = deps_of(&mut h);
      confirm_totp(&mut deps, &restricted, &bad, Some(TEST_PEER_IP)).await?
    };
    if !matches!(outcome, ConfirmOutcome::Rejected) {
      return Err(unexpected("a wrong confirmation code must be rejected"));
    }
  }
  let count = user_repo::login_failure_count(&mut h.conn, &h.store, &user.email).await?;
  if count != LOCKOUT_THRESHOLD - 1 {
    return Err(unexpected("each wrong code must count toward lockout"));
  }
  let verifier = totp::build_totp(&offer.secret)?;
  let correct = verifier
    .generate(h.counter * totp::TOTP_STEP_SECS)
    .to_string();
  let outcome = {
    let mut deps = deps_of(&mut h);
    confirm_totp(&mut deps, &restricted, &correct, Some(TEST_PEER_IP)).await?
  };
  match outcome {
    ConfirmOutcome::Completed { .. } => {}
    _ => {
      return Err(unexpected(
        "a correct code below the threshold must complete enrollment",
      ));
    }
  }
  let count = user_repo::login_failure_count(&mut h.conn, &h.store, &user.email).await?;
  if count != 0 {
    return Err(unexpected(
      "a successful confirmation must clear the failure counter",
    ));
  }
  Ok(())
}

#[tokio::test]
async fn login_confirm_locked_page_matches_wrong_code() -> TestResult {
  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "confirm-oracle@example.test",
    "temp-password-22",
    true,
    false,
  )
  .await?;
  let restricted = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let offer = {
    let mut deps = deps_of(&mut h);
    provision_totp(&mut deps, &restricted).await?
  };
  let live = load_session(&mut h.conn, &h.store, &restricted)
    .await?
    .ok_or_else(|| unexpected("the restricted session must be live"))?;
  let csrf = form_token(&live.meta.csrf_secret, TOTP_CONFIRM_ACTION);
  let bad = wrong_for_secret(&offer.secret, h.counter)?;
  let (wrong_status, wrong_body) = post_confirm(&h, &restricted, &csrf, &bad).await?;
  for _ in 1..LOCKOUT_THRESHOLD {
    let _ = post_confirm(&h, &restricted, &csrf, &bad).await?;
  }
  let policy = user_repo::LockoutPolicy {
    threshold: LOCKOUT_THRESHOLD,
    account_threshold: LOCKOUT_THRESHOLD,
    lock_duration: LOCKOUT_WINDOW,
  };
  if !user_repo::is_locked_out(&mut h.conn, &h.store, policy, &user.email, None).await? {
    return Err(unexpected("the confirm burst must lock the account"));
  }
  let (locked_status, locked_body) = post_confirm(&h, &restricted, &csrf, &bad).await?;
  if wrong_status != locked_status {
    return Err(unexpected(
      "a locked rejection must keep the wrong-code status",
    ));
  }
  if wrong_body != locked_body {
    return Err(unexpected(
      "a locked rejection must render exactly like a wrong code",
    ));
  }
  Ok(())
}

/// A Redis write outage during `change_password` must fail closed with `503`
/// and leave the password unchanged (purge-before-write): the Postgres write
/// runs only after the sibling sweep succeeds, so a sweep failure costs only
/// a retry. The outage principal may read sessions (the load and the sweep
/// scan succeed) but may not delete them, so the first sweep `DEL` fails with
/// `NOPERM` exactly like a write outage at that step.
#[tokio::test]
async fn change_password_redis_outage_leaves_password_unchanged() -> TestResult {
  use std::time::Duration;

  let mut h = harness().await?;
  let user = create_user(
    &mut h,
    "pw-outage@example.test",
    "correct-horse-41",
    true,
    false,
  )
  .await?;
  let current = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let sibling = restricted_login(&mut h, &user.email, &user.password, None).await?;
  let acl_password = "outage-pw-01";
  let _: () = redis::cmd("ACL")
    .arg("SETUSER")
    .arg("outage-user")
    .arg("on")
    .arg(format!(">{acl_password}"))
    .arg("~*")
    .arg("+@all")
    .arg("-@write")
    .query_async(&mut h.conn)
    .await?;
  let port = h._redis.get_host_port_ipv4(6379).await?;
  let url = format!("redis://outage-user:{acl_password}@127.0.0.1:{port}");
  let client = redis::Client::open(url.as_str())?;
  let manager = redis::aio::ConnectionManager::new_lazy_with_config(
    client,
    redis::aio::ConnectionManagerConfig::new()
      .set_number_of_retries(0)
      .set_response_timeout(Some(Duration::from_millis(500)))
      .set_connection_timeout(Some(Duration::from_millis(500))),
  )?;
  let mut outage = RedisConn::Single(manager);
  {
    let mut deps = LoginDeps {
      pool: &h.pool,
      conn: &mut outage,
      store: &h.store,
      keys: &h.config.keys,
      config: &h.config,
      now: h.now,
    };
    match change_password(
      &mut deps,
      &current,
      "new-strong-password-41",
      "new-strong-password-41",
    )
    .await
    {
      Err(error)
        if error.code() == OAuthErrorCode::TemporarilyUnavailable
          && error.status().as_u16() == 503 => {}
      Err(_) => {
        return Err(unexpected(
          "a write outage during password change must fail closed with 503",
        ));
      }
      Ok(_) => {
        return Err(unexpected(
          "a write outage must never report a password change",
        ));
      }
    }
  }
  match user_repo::verify_password(&h.pool, &h.config.keys, &user.email, "correct-horse-41").await?
  {
    user_repo::PasswordVerdict::Matched => {}
    _ => return Err(unexpected("the old password must still verify")),
  }
  match user_repo::verify_password(
    &h.pool,
    &h.config.keys,
    &user.email,
    "new-strong-password-41",
  )
  .await?
  {
    user_repo::PasswordVerdict::Mismatched => {}
    _ => return Err(unexpected("the new password must not verify")),
  }
  let fresh = user_repo::find_by_email(&h.pool, &h.config.keys, &user.email)
    .await?
    .ok_or_else(|| unexpected("the user must exist"))?;
  if !fresh.must_change_password {
    return Err(unexpected("a failed change must keep the must-change flag"));
  }
  if load_session(&mut h.conn, &h.store, &current)
    .await?
    .is_none()
  {
    return Err(unexpected("a failed change must keep the current session"));
  }
  if load_session(&mut h.conn, &h.store, &sibling)
    .await?
    .is_none()
  {
    return Err(unexpected("a failed change must keep sibling sessions"));
  }
  Ok(())
}

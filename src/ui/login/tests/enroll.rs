//! `test(login)` enrollment suite: bootstrap cycle, gating, password change.

use super::{
  Harness, LoginAttempt, TestError, TestResult, attempt, create_user, current_code, deps_of,
  harness, pending_request, presession,
};
use crate::{
  crypto::totp,
  db::user_repo,
  error::OAuthErrorCode,
  store::sessions,
  ui::login::{
    CHANGE_PASSWORD_PATH, CONSENT_PATH, ConfirmOutcome, LOGIN_SUCCESS_PATH, LoginOutcome,
    PasswordOutcome, attempt_login, bind_pending_request, change_password, confirm_totp,
    load_session, logout, provision_totp, restricted_allows_path,
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
    confirm_totp(&mut deps, &restricted, &bad).await?
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
    match confirm_totp(&mut deps, &restricted, &code).await? {
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
    match confirm_totp(&mut deps, &pre, "000000").await {
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
  match confirm_totp(&mut deps, &restricted, "000000").await? {
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
    match confirm_totp(&mut deps, &restricted, &bad).await? {
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
    match confirm_totp(&mut deps, &restricted, &code).await? {
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

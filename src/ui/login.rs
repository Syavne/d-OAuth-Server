//! Login page: password + TOTP on a Redis-backed session.
//!
//! First-login users pass through forced password change + TOTP enrollment
//! in a restricted session that reaches nothing else.
//!
//! Flow: `GET /login` mints (or reuses) an empty pre-session and renders the
//! form with a stateless login-CSRF token. `POST /login` verifies the CSRF
//! token, the password (Argon2id), and the second factor (TOTP ±1 step with a
//! Redis replay claim, or a one-time recovery code), enforces the Redis
//! lockout, then rotates the pre-session into an authenticated session and
//! redirects strictly to the bound pending-auth record (task 24). Every
//! credential failure — wrong password, unknown email, disabled account,
//! lockout, wrong/replayed code — renders the same message and status, so no
//! response reveals whether an email exists. Passwords, codes, and secrets
//! never reach logs; pages are server-rendered with no `localStorage`.
//!
//! The session record itself is task 12's [`SessionRecord`]; the two fields
//! that record cannot hold (`auth_time`, CSRF secret, pending `request_id`)
//! ride a sidecar hash (`<session-key>:meta`, same `{state}` slot, same TTL)
//! instead of editing `store::sessions` — the task-29 sidecar precedent. The
//! pending `request_id` lives only in that sidecar after `GET /login`
//! validates it, so `POST /login` cannot be steered off-record.

use std::time::Duration;

use askama::Template;
use axum::{
  Form,
  extract::{Query, State},
  http::{StatusCode, header},
  response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{
  CookieJar,
  cookie::{Cookie, SameSite},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::{
  config::Config,
  crypto::{
    ct::ct_eq,
    secret::{Argon2Params, hash_secret},
    tokens::mint_token,
    totp,
  },
  db::{
    client_repo, redirect_repo,
    user_repo::{self, normalize_email},
  },
  error::AppError,
  keys::KeyRing,
  middleware::audit::AuditEvent,
  protocol::redirect_repo as redirect_match,
  state::{AppState, RedisConn},
  store::{self, Store, StoreError},
};

/// Session cookie name (also the rendezvous for task 26/29 readers).
pub const SESSION_COOKIE: &str = "session_id";
/// Login form page.
pub const LOGIN_PATH: &str = "/login";
/// Landing page for logins with no bound authorization request.
pub const LOGIN_SUCCESS_PATH: &str = "/login/success";
/// Restricted-session password-change page.
pub const CHANGE_PASSWORD_PATH: &str = "/login/change-password";
/// Restricted-session TOTP provisioning page.
pub const TOTP_SETUP_PATH: &str = "/login/totp/setup";
/// Restricted-session TOTP confirmation page.
pub const TOTP_CONFIRM_PATH: &str = "/login/totp/confirm";
/// Logout endpoint.
pub const LOGOUT_PATH: &str = "/logout";
/// Post-login target for a bound authorization request (owned by task 26).
pub const CONSENT_PATH: &str = "/consent";
/// Failed logins within [`LOCKOUT_WINDOW`] that lock an account.
pub const LOCKOUT_THRESHOLD: u64 = 5;
/// Window that doubles as the lock duration.
pub const LOCKOUT_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Minimum accepted password length on change.
pub const MIN_PASSWORD_LEN: usize = 12;
/// The single credential-failure message for every rejection reason.
pub const INVALID_CREDENTIALS: &str = "Invalid email, password, or code.";

#[cfg(test)]
mod tests;

/// Server-side session metadata the task-12 record cannot hold.
///
/// Stored as a hash at `<session-key>:meta` with the session TTL.
/// `pending_request_id` is the validated pending-auth id from `GET /login`;
/// `POST /login` and every later step read it only from here, never from the
/// client, so the post-login redirect cannot be steered off-record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
  /// Authentication instant (Unix seconds, from the injectable clock).
  pub auth_time: i64,
  /// Per-session CSRF secret (256-bit opaque); form tokens derive from it.
  pub csrf_secret: String,
  /// Validated pending-auth `request_id`, when the login serves a flow.
  pub pending_request_id: Option<String>,
  /// The client the last flow served, when known. Used at logout only to
  /// re-check the client is still active and still registers the bound
  /// post-logout URI before redirecting to it.
  pub post_logout_client_id: Option<String>,
  /// The client's post-logout return URI for the flow this session last
  /// served, frozen at binding time. Read only at logout, never from a request,
  /// so the logout redirect cannot be steered off-record.
  pub post_logout_uri: Option<String>,
}

/// Everything the login core needs, borrowed from the HTTP layer.
pub struct LoginDeps<'a> {
  /// Postgres pool for user lookups and updates.
  pub pool: &'a PgPool,
  /// Redis connection for sessions, lockout counters, and replay claims.
  pub conn: &'a mut RedisConn,
  /// Key layout plus retry/durability knobs.
  pub store: &'a Store,
  /// Versioned peppers and TOTP-encryption keys.
  pub keys: &'a KeyRing,
  /// Validated runtime configuration.
  pub config: &'a Config,
  /// Current time (injectable via [`AppState::clock`]).
  pub now: OffsetDateTime,
}

/// Input to a login attempt (one `POST /login`).
pub struct LoginAttempt {
  /// Pre-session id from the session cookie.
  pub presession_id: String,
  /// Raw email as typed.
  pub email: String,
  /// Raw password as typed.
  pub password: String,
  /// Raw second-factor code as typed (TOTP or recovery).
  pub code: String,
  /// Presented login-CSRF token.
  pub csrf: String,
}

/// Outcome of [`attempt_login`].
pub enum LoginOutcome {
  /// Fully authenticated: session minted, redirect to consent/success.
  Authenticated {
    /// New session id (already stored; the handler sets the cookie).
    session_id: String,
    /// Strictly bound redirect target.
    redirect_to: String,
  },
  /// Bootstrap required: restricted session minted, redirect to change-password.
  Restricted {
    /// New restricted session id (already stored).
    session_id: String,
    /// Always [`CHANGE_PASSWORD_PATH`].
    redirect_to: String,
  },
  /// Credentials rejected (uniform message; the handler renders 401).
  Rejected,
}

/// Whether a restricted session may touch `path`.
///
/// Restricted sessions reach the login/bootstrap/logout routes only.
/// `/authorize`, `/oauth/*`, and any admin action return `false`; their
/// handlers deny restricted sessions before any other check.
#[must_use]
pub fn restricted_allows_path(path: &str) -> bool {
  matches!(
    path,
    LOGIN_PATH
      | LOGIN_SUCCESS_PATH
      | CHANGE_PASSWORD_PATH
      | TOTP_SETUP_PATH
      | TOTP_CONFIRM_PATH
      | LOGOUT_PATH
  )
}

/// Build the session cookie: `HttpOnly`, `SameSite=Lax`, `Secure` exactly
/// when [`Config::cookie_secure`] is set (disabled for localhost development).
#[must_use]
pub fn session_cookie(config: &Config, session_id: &str) -> Cookie<'static> {
  let mut builder = Cookie::build((SESSION_COOKIE, session_id.to_owned()))
    .path("/")
    .http_only(true)
    .same_site(SameSite::Lax);
  if config.cookie_secure {
    builder = builder.secure(true);
  }
  if let Some(domain) = config.cookie_domain.clone() {
    builder = builder.domain(domain);
  }
  builder.build()
}

/// Build an expired session cookie for logout.
#[must_use]
pub fn expired_session_cookie() -> Cookie<'static> {
  Cookie::build((SESSION_COOKIE, String::new()))
    .path("/")
    .removal()
    .build()
}

/// Mint the stateless pre-login CSRF token: HMAC under the active token
/// pepper over `session_id || "|login"`. No server-side CSRF state is stored.
///
/// # Errors
///
/// Returns `server_error` when no pepper is configured.
pub fn login_csrf_token(keys: &KeyRing, session_id: &str) -> Result<String, AppError> {
  hmac_hex(active_pepper(keys)?, session_id.as_bytes(), b"|login")
}

/// Verify a pre-login CSRF token in constant time.
#[must_use]
pub fn verify_login_csrf(keys: &KeyRing, session_id: &str, presented: &str) -> bool {
  let Ok(expected) = login_csrf_token(keys, session_id) else {
    return false;
  };
  ct_eq(expected.as_bytes(), presented.as_bytes())
}

/// Mint a form token bound to the session CSRF secret for one action.
///
/// A key failure degrades to an empty token (which never verifies) rather
/// than an error, so form rendering stays infallible.
#[must_use]
pub fn form_token(csrf_secret: &str, action: &str) -> String {
  hmac_hex(csrf_secret.as_bytes(), action.as_bytes(), b"").unwrap_or_default()
}

/// Verify a session-bound form token in constant time.
#[must_use]
pub fn verify_form_token(csrf_secret: &str, action: &str, presented: &str) -> bool {
  let expected = form_token(csrf_secret, action);
  ct_eq(expected.as_bytes(), presented.as_bytes())
}

/// A live session: task-12 record plus the task-25 sidecar.
pub struct LiveSession {
  /// Authentication record (subject, MFA state, restriction flag).
  pub record: store::sessions::SessionRecord,
  /// Sidecar metadata (`auth_time`, CSRF secret, pending request).
  pub meta: SessionMeta,
}

/// Load a session; `Ok(None)` covers every non-actionable case (no record,
/// expired record, or missing sidecar) so callers bounce to login uniformly.
///
/// # Errors
///
/// Returns a masked `5xx` when either store read fails.
pub async fn load_session(
  conn: &mut RedisConn,
  store: &Store,
  session_id: &str,
) -> Result<Option<LiveSession>, AppError> {
  if session_id.is_empty() {
    return Ok(None);
  }
  let record = store::sessions::get(conn, store, session_id).await?;
  let meta = meta_get(conn, store, session_id).await?;
  match (record, meta) {
    (Some(record), Some(meta)) => Ok(Some(LiveSession { record, meta })),
    _ => Ok(None),
  }
}

/// Borrow shared state into core dependencies around one Redis connection.
fn deps_of<'a>(state: &'a AppState, conn: &'a mut RedisConn, store: &'a Store) -> LoginDeps<'a> {
  LoginDeps {
    pool: &state.pool,
    conn,
    store,
    keys: &state.keys,
    config: &state.config,
    now: state.clock.now(),
  }
}

/// Ensure a pre-session for `GET /login`: reuse the presented session id when
/// it names a live session, else mint an empty one. Returns the id and
/// whether it was freshly minted (the handler sets the cookie only then).
///
/// # Errors
///
/// Returns a masked `5xx` when minting or the session store fails.
pub async fn ensure_presession(
  deps: &mut LoginDeps<'_>,
  presented: Option<&str>,
) -> Result<(String, bool), AppError> {
  if let Some(id) = presented.filter(|id| !id.is_empty())
    && load_session(deps.conn, deps.store, id).await?.is_some()
  {
    return Ok((id.to_owned(), false));
  }
  let session_id = mint_token().map_err(AppError::internal)?;
  let record = store::sessions::SessionRecord {
    subject: String::new(),
    mfa_verified: false,
    restricted: false,
  };
  let meta = SessionMeta {
    auth_time: deps.now.unix_timestamp(),
    csrf_secret: mint_token().map_err(AppError::internal)?,
    pending_request_id: None,
    post_logout_client_id: None,
    post_logout_uri: None,
  };
  store::sessions::put(
    deps.conn,
    deps.store,
    &session_id,
    &record,
    deps.config.ttl.session,
  )
  .await?;
  meta_put(deps.conn, deps.store, deps.config, &session_id, &meta).await?;
  Ok((session_id, true))
}

/// Bind a validated pending-auth id to a pre-session (from `GET /login`).
///
/// The id must already be validated with `pending::get` by the caller; this
/// only records the server-side binding `POST /login` later trusts. The flow's
/// resolved `post_logout_uri` is frozen here too, overwriting any stale binding
/// so logout returns to the client the session last served.
///
/// # Errors
///
/// Returns a masked `5xx` when the session store fails.
pub async fn bind_pending_request(
  deps: &mut LoginDeps<'_>,
  presession_id: &str,
  request_id: &str,
  client_id: &str,
  post_logout_uri: Option<&str>,
) -> Result<(), AppError> {
  let Some(mut live) = load_session(deps.conn, deps.store, presession_id).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  live.meta.pending_request_id = Some(request_id.to_owned());
  live.meta.post_logout_client_id = Some(client_id.to_owned());
  live.meta.post_logout_uri = post_logout_uri.map(str::to_owned);
  meta_put(
    deps.conn,
    deps.store,
    deps.config,
    presession_id,
    &live.meta,
  )
  .await
}

/// Verify credentials and rotate the pre-session into an authenticated (or
/// restricted) session. See the module docs for the exact order.
///
/// # Errors
///
/// Returns `invalid_request` for a bad CSRF token, a missing pre-session, or
/// an expired/consumed pending record, and a masked `5xx` for store, crypto,
/// or database failures. Credential rejections are `Ok(Rejected)`, never an
/// error, so handlers render one uniform page for all of them.
pub async fn attempt_login(
  deps: &mut LoginDeps<'_>,
  attempt: LoginAttempt,
) -> Result<LoginOutcome, AppError> {
  if !verify_login_csrf(deps.keys, &attempt.presession_id, &attempt.csrf) {
    return Err(AppError::invalid_request("invalid form submission"));
  }
  let email = normalize_email(&attempt.email);
  let policy = user_repo::LockoutPolicy {
    threshold: LOCKOUT_THRESHOLD,
    lock_duration: LOCKOUT_WINDOW,
  };
  if user_repo::is_locked_out(deps.conn, deps.store, policy, &email).await? {
    audit_failure(None, None, "locked");
    return Ok(LoginOutcome::Rejected);
  }
  let (pending_id, post_logout_client_id, post_logout_uri) =
    match load_session(deps.conn, deps.store, &attempt.presession_id).await? {
      Some(live) => (
        live.meta.pending_request_id,
        live.meta.post_logout_client_id,
        live.meta.post_logout_uri,
      ),
      None => return Err(AppError::invalid_request("the login session has expired")),
    };
  match user_repo::verify_password(deps.pool, &email, &attempt.password).await? {
    user_repo::PasswordVerdict::Unknown => {
      burn_timing(deps.config, &attempt.password)?;
      user_repo::register_login_failure(deps.conn, deps.store, policy, &email).await?;
      audit_failure(pending_id.as_deref(), None, "bad_credentials");
      return Ok(LoginOutcome::Rejected);
    }
    user_repo::PasswordVerdict::Disabled => {
      user_repo::register_login_failure(deps.conn, deps.store, policy, &email).await?;
      audit_failure(pending_id.as_deref(), Some(&email), "disabled");
      return Ok(LoginOutcome::Rejected);
    }
    user_repo::PasswordVerdict::Mismatched => {
      user_repo::register_login_failure(deps.conn, deps.store, policy, &email).await?;
      audit_failure(pending_id.as_deref(), Some(&email), "bad_credentials");
      return Ok(LoginOutcome::Rejected);
    }
    user_repo::PasswordVerdict::Matched => {}
  }
  let Some(user) = user_repo::find_by_email(deps.pool, &email).await? else {
    audit_failure(pending_id.as_deref(), None, "bad_credentials");
    return Ok(LoginOutcome::Rejected);
  };
  let mut mfa_done = false;
  if user.totp_enabled {
    if !verify_second_factor(deps, user.id, &attempt.code).await? {
      user_repo::register_login_failure(deps.conn, deps.store, policy, &email).await?;
      audit_failure(pending_id.as_deref(), Some(&email), "bad_code");
      return Ok(LoginOutcome::Rejected);
    }
    mfa_done = true;
  }
  user_repo::clear_login_failures(deps.conn, deps.store, &email).await?;
  // Bind strictly: the pending record must still exist at login time, and the
  // redirect leaves from the stored record — never from client input.
  let redirect_to = match pending_id.as_deref() {
    Some(request_id) => {
      if store::pending::get(deps.conn, deps.store, request_id)
        .await?
        .is_none()
      {
        return Err(AppError::invalid_request(
          "the authorization request is unknown or has expired",
        ));
      }
      CONSENT_PATH.to_owned()
    }
    None => LOGIN_SUCCESS_PATH.to_owned(),
  };
  let restricted = user.must_change_password || !user.totp_enabled;
  let session_id = mint_token().map_err(AppError::internal)?;
  let record = store::sessions::SessionRecord {
    subject: email.clone(),
    mfa_verified: mfa_done,
    restricted,
  };
  let meta = SessionMeta {
    auth_time: deps.now.unix_timestamp(),
    csrf_secret: mint_token().map_err(AppError::internal)?,
    pending_request_id: pending_id.clone(),
    post_logout_client_id,
    post_logout_uri,
  };
  store::sessions::rotate(
    deps.conn,
    deps.store,
    &attempt.presession_id,
    &session_id,
    &record,
    deps.config.ttl.session,
  )
  .await?;
  if meta_put(deps.conn, deps.store, deps.config, &session_id, &meta)
    .await
    .is_err()
  {
    let _ = store::sessions::destroy(deps.conn, deps.store, &session_id).await;
    return Err(AppError::server_error());
  }
  meta_del(deps.conn, deps.store, &attempt.presession_id).await?;
  audit_success(pending_id.as_deref(), &email);
  if restricted {
    Ok(LoginOutcome::Restricted {
      session_id,
      redirect_to: CHANGE_PASSWORD_PATH.to_owned(),
    })
  } else {
    Ok(LoginOutcome::Authenticated {
      session_id,
      redirect_to,
    })
  }
}

/// Outcome of [`change_password`].
pub enum PasswordOutcome {
  /// Bootstrap complete and TOTP enrolled: full session re-issued.
  Promoted {
    /// New full session id (already stored).
    session_id: String,
    /// Consent page when bound, else the success page.
    redirect_to: String,
  },
  /// Password set; TOTP enrollment still pending (session stays restricted).
  StillRestricted {
    /// Unchanged session id.
    session_id: String,
  },
}

/// Set a new password on a restricted (or full) session.
///
/// Clears `must_change_password` in the database. When TOTP is already
/// enrolled the session is re-issued as full and the caller redirects on;
/// otherwise the session stays restricted for the enrollment step.
///
/// # Errors
///
/// Returns `invalid_request` for a missing session, mismatched confirmation,
/// or a weak password, and a masked `5xx` for store/crypto/database failures.
pub async fn change_password(
  deps: &mut LoginDeps<'_>,
  session_id: &str,
  new_password: &str,
  confirm: &str,
) -> Result<PasswordOutcome, AppError> {
  let Some(live) = load_session(deps.conn, deps.store, session_id).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  if live.record.subject.is_empty() {
    return Err(AppError::invalid_request("the login session has expired"));
  }
  if new_password != confirm {
    return Err(AppError::invalid_request("the passwords do not match"));
  }
  if new_password.len() < MIN_PASSWORD_LEN {
    return Err(AppError::invalid_request(
      "the password does not meet the length requirement",
    ));
  }
  let Some(user) = user_repo::find_by_email(deps.pool, &live.record.subject).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  let params = secret_params(deps.config)?;
  let hash = hash_secret(new_password, &params).map_err(AppError::internal)?;
  if !user_repo::set_password(deps.pool, user.id, &hash).await? {
    return Err(AppError::server_error());
  }
  let enrolled = user_repo::find_by_email(deps.pool, &live.record.subject)
    .await?
    .is_some_and(|user| user.totp_enabled);
  if !enrolled {
    return Ok(PasswordOutcome::StillRestricted {
      session_id: session_id.to_owned(),
    });
  }
  promote_to_full(deps, session_id, &live).await
}

/// One-time enrollment material: the secret is already stored encrypted; the
/// plaintext below is shown once and never stored.
pub struct EnrollmentOffer {
  /// The raw secret (for display alongside the URI).
  pub secret: String,
  /// `otpauth://` URI for authenticator apps.
  pub otpauth_uri: String,
  /// Plaintext recovery codes, shown exactly once.
  pub recovery_codes: Vec<String>,
}

/// Provision (or re-provision) a TOTP secret plus recovery codes.
///
/// Requires a session with a subject (never a pre-session). Overwrites any
/// previous secret and code set; the session stays restricted until
/// [`confirm_totp`] succeeds.
///
/// # Errors
///
/// Returns `invalid_request` without a subject session and a masked `5xx` for
/// store/crypto/database failures.
pub async fn provision_totp(
  deps: &mut LoginDeps<'_>,
  session_id: &str,
) -> Result<EnrollmentOffer, AppError> {
  let Some(live) = load_session(deps.conn, deps.store, session_id).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  if live.record.subject.is_empty() {
    return Err(AppError::invalid_request("the login session has expired"));
  }
  let Some(user) = user_repo::find_by_email(deps.pool, &live.record.subject).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  let secret = totp::generate_secret()?;
  let blob = totp::encrypt_secret(deps.keys, &secret)?;
  if !user_repo::set_totp_secret(deps.pool, user.id, &blob).await? {
    return Err(AppError::server_error());
  }
  let codes = totp::generate_recovery_codes()?;
  let params = secret_params(deps.config)?;
  let mut hashes = Vec::with_capacity(codes.len());
  for code in &codes {
    hashes.push(hash_secret(code, &params).map_err(AppError::internal)?);
  }
  if !user_repo::set_recovery_codes(deps.pool, user.id, &hashes).await? {
    return Err(AppError::server_error());
  }
  Ok(EnrollmentOffer {
    secret: secret.clone(),
    otpauth_uri: totp::otpauth_uri(&deps.config.issuer, &user.email, &secret),
    recovery_codes: codes,
  })
}

/// Outcome of [`confirm_totp`].
pub enum ConfirmOutcome {
  /// Authenticator proven and bootstrap complete: full session re-issued.
  Completed {
    /// New full session id (already stored).
    session_id: String,
    /// Consent page when bound, else the success page.
    redirect_to: String,
  },
  /// Authenticator proven but a password change is still required.
  StillRestricted,
  /// Wrong code: the session is unchanged and may retry.
  Rejected,
}

/// Confirm TOTP enrollment with an authenticator code (TOTP only: recovery
/// codes never confirm enrollment).
///
/// # Errors
///
/// Returns `invalid_request` without a subject session and a masked `5xx`
/// for store/crypto/database failures. A wrong code is `Ok(Rejected)`.
pub async fn confirm_totp(
  deps: &mut LoginDeps<'_>,
  session_id: &str,
  code: &str,
) -> Result<ConfirmOutcome, AppError> {
  let Some(live) = load_session(deps.conn, deps.store, session_id).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  if live.record.subject.is_empty() {
    return Err(AppError::invalid_request("the login session has expired"));
  }
  let Some(user) = user_repo::find_by_email(deps.pool, &live.record.subject).await? else {
    return Err(AppError::invalid_request("the login session has expired"));
  };
  let Some(blob) = user_repo::totp_secret_blob(deps.pool, user.id).await? else {
    return Ok(ConfirmOutcome::Rejected);
  };
  let secret = totp::decrypt_secret(deps.keys, &blob)?;
  let now_unix = u64::try_from(deps.now.unix_timestamp().max(0)).unwrap_or(0);
  let key_for = |step: u64| {
    deps.store.totp_replay_key(&totp::replay_fingerprint(
      &user.id.to_string(),
      code.trim(),
      step,
    ))
  };
  if !totp::verify_and_claim(
    deps.conn,
    key_for,
    &secret,
    code,
    now_unix,
    totp::USED_CODE_TTL,
  )
  .await?
  {
    audit_failure(
      live.meta.pending_request_id.as_deref(),
      Some(&live.record.subject),
      "bad_confirm_code",
    );
    return Ok(ConfirmOutcome::Rejected);
  }
  let fresh = user_repo::find_by_email(deps.pool, &live.record.subject).await?;
  if fresh.is_some_and(|user| !user.must_change_password) {
    let promoted = promote_to_full(deps, session_id, &live).await?;
    match promoted {
      PasswordOutcome::Promoted {
        session_id,
        redirect_to,
      } => Ok(ConfirmOutcome::Completed {
        session_id,
        redirect_to,
      }),
      PasswordOutcome::StillRestricted { .. } => Ok(ConfirmOutcome::StillRestricted),
    }
  } else {
    Ok(ConfirmOutcome::StillRestricted)
  }
}

/// Destroy a session and its sidecar; missing sessions destroy to success.
///
/// # Errors
///
/// Returns a masked `5xx` when the store fails.
pub async fn logout(conn: &mut RedisConn, store: &Store, session_id: &str) -> Result<(), AppError> {
  store::sessions::destroy(conn, store, session_id).await?;
  meta_del(conn, store, session_id).await?;
  Ok(())
}

/// Verify the second factor: TOTP first, else exactly one recovery code.
///
/// Returns `false` for a wrong, replayed, or already-consumed code. Only a
/// malformed stored secret or a store/database failure is an error.
async fn verify_second_factor(
  deps: &mut LoginDeps<'_>,
  user_id: uuid::Uuid,
  code: &str,
) -> Result<bool, AppError> {
  let user_label = user_id.to_string();
  if let Some(blob) = user_repo::totp_secret_blob(deps.pool, user_id).await? {
    let secret = totp::decrypt_secret(deps.keys, &blob)?;
    let now_unix = u64::try_from(deps.now.unix_timestamp().max(0)).unwrap_or(0);
    let key_for = |step: u64| {
      deps
        .store
        .totp_replay_key(&totp::replay_fingerprint(&user_label, code.trim(), step))
    };
    if totp::verify_and_claim(
      deps.conn,
      key_for,
      &secret,
      code,
      now_unix,
      totp::USED_CODE_TTL,
    )
    .await?
    {
      return Ok(true);
    }
  }
  let normalized = totp::normalize_recovery_code(code);
  if normalized.is_empty() {
    return Ok(false);
  }
  user_repo::consume_recovery_code(deps.pool, user_id, &normalized).await
}

/// Re-issue a session as full: MFA passed, not restricted, fresh CSRF secret.
/// The pending-request binding and original `auth_time` carry over.
async fn promote_to_full(
  deps: &mut LoginDeps<'_>,
  session_id: &str,
  live: &LiveSession,
) -> Result<PasswordOutcome, AppError> {
  let next_id = mint_token().map_err(AppError::internal)?;
  let record = store::sessions::SessionRecord {
    subject: live.record.subject.clone(),
    mfa_verified: true,
    restricted: false,
  };
  let meta = SessionMeta {
    auth_time: live.meta.auth_time,
    csrf_secret: mint_token().map_err(AppError::internal)?,
    pending_request_id: live.meta.pending_request_id.clone(),
    post_logout_client_id: live.meta.post_logout_client_id.clone(),
    post_logout_uri: live.meta.post_logout_uri.clone(),
  };
  store::sessions::rotate(
    deps.conn,
    deps.store,
    session_id,
    &next_id,
    &record,
    deps.config.ttl.session,
  )
  .await?;
  if meta_put(deps.conn, deps.store, deps.config, &next_id, &meta)
    .await
    .is_err()
  {
    let _ = store::sessions::destroy(deps.conn, deps.store, &next_id).await;
    return Err(AppError::server_error());
  }
  meta_del(deps.conn, deps.store, session_id).await?;
  let redirect_to = match live.meta.pending_request_id.as_deref() {
    Some(request_id) => {
      if store::pending::get(deps.conn, deps.store, request_id)
        .await?
        .is_none()
      {
        return Err(AppError::invalid_request(
          "the authorization request is unknown or has expired",
        ));
      }
      CONSENT_PATH.to_owned()
    }
    None => LOGIN_SUCCESS_PATH.to_owned(),
  };
  audit_success(
    live.meta.pending_request_id.as_deref(),
    &live.record.subject,
  );
  Ok(PasswordOutcome::Promoted {
    session_id: next_id,
    redirect_to,
  })
}

/// Hash once and discard: equalizes timing between unknown and known emails.
fn burn_timing(config: &Config, password: &str) -> Result<(), AppError> {
  let params = secret_params(config)?;
  hash_secret(password, &params).map_err(AppError::internal)?;
  Ok(())
}

/// Argon2id parameters from configuration for password/code hashing.
fn secret_params(config: &Config) -> Result<Argon2Params, AppError> {
  let raw = &config.argon2;
  Argon2Params::new(raw.memory_kib, raw.iterations, raw.parallelism, 32).map_err(AppError::internal)
}

/// The active token pepper's bytes for stateless HMACs.
fn active_pepper(keys: &KeyRing) -> Result<&[u8], AppError> {
  keys
    .active_pepper()
    .map(|(_, secret)| secret.expose_secret().as_bytes())
    .ok_or_else(AppError::server_error)
}

/// HMAC-SHA256 hex over joined parts; `server_error` only when the key is bad.
fn hmac_hex(key: &[u8], first: &[u8], second: &[u8]) -> Result<String, AppError> {
  let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AppError::server_error())?;
  mac.update(first);
  mac.update(second);
  Ok(hex_bytes(&mac.finalize().into_bytes()))
}

/// Lowercase hex encoding of raw bytes.
fn hex_bytes(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    out.push_str(&format!("{b:02x}"));
  }
  out
}

/// Audit a successful authentication (subject only; never secrets).
fn audit_success(request_id: Option<&str>, subject: &str) {
  AuditEvent::LoginSuccess {
    request_id,
    subject,
  }
  .emit();
}

/// Audit a rejected attempt: a short reason, the subject only when the
/// account exists, and never the presented credentials.
fn audit_failure(request_id: Option<&str>, subject: Option<&str>, reason: &str) {
  AuditEvent::LoginFailure {
    request_id,
    subject,
    reason,
  }
  .emit();
}

/// Sidecar key for a session id (same `{state}` slot as the record).
fn meta_key(store: &Store, session_id: &str) -> String {
  format!("{}:meta", store.session_key(session_id))
}

/// Write sidecar metadata with the session TTL (idempotent rewrite).
async fn meta_put(
  conn: &mut RedisConn,
  store: &Store,
  config: &Config,
  session_id: &str,
  meta: &SessionMeta,
) -> Result<(), AppError> {
  let key = meta_key(store, session_id);
  let pairs = vec![
    ("auth_time".to_owned(), meta.auth_time.to_string()),
    ("csrf_secret".to_owned(), meta.csrf_secret.clone()),
    (
      "pending_request_id".to_owned(),
      meta.pending_request_id.clone().unwrap_or_default(),
    ),
    (
      "post_logout_client_id".to_owned(),
      meta.post_logout_client_id.clone().unwrap_or_default(),
    ),
    (
      "post_logout_uri".to_owned(),
      meta.post_logout_uri.clone().unwrap_or_default(),
    ),
  ];
  let budget = store.retry_budget();
  let ttl = config.ttl.session;
  crate::store::retry_op!(conn, budget, async {
    store::hset_record(conn, &key, &pairs, ttl)
      .await
      .map_err(meta_redis)
  })
  .map_err(StoreError::Redis)?;
  Ok(())
}

/// Read sidecar metadata; `Ok(None)` when absent or malformed.
async fn meta_get(
  conn: &mut RedisConn,
  store: &Store,
  session_id: &str,
) -> Result<Option<SessionMeta>, AppError> {
  let key = meta_key(store, session_id);
  let budget = store.retry_budget();
  let fields = crate::store::retry_op!(conn, budget, async {
    store::hget_record(conn, &key).await.map_err(meta_redis)
  })
  .map_err(StoreError::Redis)?;
  let Some(fields) = fields else {
    return Ok(None);
  };
  let auth_time = fields
    .get("auth_time")
    .and_then(|value| value.parse::<i64>().ok());
  let csrf_secret = fields.get("csrf_secret").cloned();
  match (auth_time, csrf_secret) {
    (Some(auth_time), Some(csrf_secret)) => Ok(Some(SessionMeta {
      auth_time,
      csrf_secret,
      pending_request_id: fields
        .get("pending_request_id")
        .filter(|value| !value.is_empty())
        .cloned(),
      post_logout_client_id: fields
        .get("post_logout_client_id")
        .filter(|value| !value.is_empty())
        .cloned(),
      post_logout_uri: fields
        .get("post_logout_uri")
        .filter(|value| !value.is_empty())
        .cloned(),
    })),
    _ => Ok(None),
  }
}

/// Delete sidecar metadata; missing keys delete to success.
async fn meta_del(conn: &mut RedisConn, store: &Store, session_id: &str) -> Result<(), AppError> {
  let key = meta_key(store, session_id);
  let _: () = redis::cmd("DEL")
    .arg(&key)
    .query_async(conn)
    .await
    .map_err(StoreError::Redis)?;
  Ok(())
}

/// Convert a store error into a Redis error for the retry macro.
fn meta_redis(error: StoreError) -> redis::RedisError {
  match error {
    StoreError::Redis(inner) => inner,
    _ => redis::RedisError::from((redis::ErrorKind::Client, "store session meta failed")),
  }
}

// ---------------------------------------------------------------------------
// HTTP handlers (thin wrappers; task 40 mounts them in `routes.rs`)
// ---------------------------------------------------------------------------

/// Query string for `GET /login`: the opaque pending-auth id, if any.
#[derive(Debug, Deserialize)]
pub struct LoginPageQuery {
  /// Pending-auth `request_id` handed off from `/authorize`.
  #[serde(default)]
  pub request_id: Option<String>,
}

/// Form posted to `POST /login`.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
  /// Email as typed.
  #[serde(default)]
  pub email: String,
  /// Password as typed.
  #[serde(default)]
  pub password: String,
  /// TOTP or recovery code as typed.
  #[serde(default)]
  pub code: String,
  /// Login-CSRF token from the form.
  #[serde(default)]
  pub csrf: String,
}

/// Form posted to `POST /login/change-password`.
#[derive(Debug, Deserialize)]
pub struct PasswordForm {
  /// New password.
  #[serde(default)]
  pub new_password: String,
  /// New password, repeated.
  #[serde(default)]
  pub confirm: String,
  /// Session-bound form token.
  #[serde(default)]
  pub csrf: String,
}

/// Form posted to `POST /login/totp/confirm`.
#[derive(Debug, Deserialize)]
pub struct ConfirmForm {
  /// Authenticator code as typed.
  #[serde(default)]
  pub code: String,
  /// Session-bound form token.
  #[serde(default)]
  pub csrf: String,
}

/// Login page.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Sign in</title></head><body>\
  <h1>Sign in</h1>\
  {% if has_client %}<p>Continue to <strong>{{ client }}</strong>.</p>{% endif %}\
  {% if has_error %}<p role=\"alert\">{{ error }}</p>{% endif %}\
  <form method=\"post\" action=\"/login\">\
  <label for=\"email\">Email</label>\
  <input id=\"email\" name=\"email\" type=\"email\" value=\"{{ email }}\" autocomplete=\"username\">\
  <label for=\"password\">Password</label>\
  <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\">\
  <label for=\"code\">Authenticator code or recovery code</label>\
  <input id=\"code\" name=\"code\" autocomplete=\"one-time-code\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\">Sign in</button></form></body></html>",
  ext = "html"
)]
struct LoginTemplate {
  csrf: String,
  email: String,
  client: String,
  has_client: bool,
  error: String,
  has_error: bool,
}

/// Password-change page.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Change password</title></head><body>\
  <h1>Change your password</h1>\
  {% if has_error %}<p role=\"alert\">{{ error }}</p>{% endif %}\
  <form method=\"post\" action=\"/login/change-password\">\
  <label for=\"new_password\">New password (at least 12 characters)</label>\
  <input id=\"new_password\" name=\"new_password\" type=\"password\" autocomplete=\"new-password\">\
  <label for=\"confirm\">Confirm new password</label>\
  <input id=\"confirm\" name=\"confirm\" type=\"password\" autocomplete=\"new-password\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\">Change password</button></form></body></html>",
  ext = "html"
)]
struct PasswordTemplate {
  csrf: String,
  error: String,
  has_error: bool,
}

/// TOTP enrollment page: secret, URI, and one-time recovery codes.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Set up authenticator</title></head><body>\
  <h1>Set up your authenticator</h1>\
  <p>Scan the secret into your authenticator app, then confirm with a code.</p>\
  <p>Secret: <strong>{{ secret }}</strong></p>\
  <p>URI: {{ uri }}</p>\
  <p>Recovery codes (shown once, store them safely):</p>\
  <ul>{% for code in codes %}<li><strong>{{ code }}</strong></li>{% endfor %}</ul>\
  {% if has_error %}<p role=\"alert\">{{ error }}</p>{% endif %}\
  <form method=\"post\" action=\"/login/totp/confirm\">\
  <label for=\"code\">Authenticator code</label>\
  <input id=\"code\" name=\"code\" autocomplete=\"one-time-code\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\">Confirm</button></form></body></html>",
  ext = "html"
)]
struct SetupTemplate {
  csrf: String,
  secret: String,
  uri: String,
  codes: Vec<String>,
  error: String,
  has_error: bool,
}

/// TOTP confirmation retry page (codes were shown once already).
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Confirm authenticator</title></head><body>\
  <h1>Confirm your authenticator</h1>\
  {% if has_error %}<p role=\"alert\">{{ error }}</p>{% endif %}\
  <form method=\"post\" action=\"/login/totp/confirm\">\
  <label for=\"code\">Authenticator code</label>\
  <input id=\"code\" name=\"code\" autocomplete=\"one-time-code\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\">Confirm</button></form></body></html>",
  ext = "html"
)]
struct ConfirmTemplate {
  csrf: String,
  error: String,
  has_error: bool,
}

/// Signed-in landing page for logins with no bound request.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Signed in</title></head><body>\
  <h1>Signed in</h1><p>You are signed in.</p>\
  <form method=\"post\" action=\"/logout\">\
  <button type=\"submit\">Sign out</button></form></body></html>",
  ext = "html"
)]
struct SuccessTemplate;

/// Neutral landing page after an RP-initiated logout. Deliberately has no
/// auto-redirect and no form post: a forced navigation to `GET /logout` (for
/// example an `<img src="/logout">`) must only end the session, never bounce
/// the browser into a fresh login or an external target. This is a
/// server-specific session endpoint, not an OAuth 2.1 or OIDC defined feature.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <title>Signed out</title></head><body>\
  <h1>Signed out</h1><p>Your session has ended.</p>\
  <p><a href=\"/login\">Sign in again</a>.</p></body></html>",
  ext = "html"
)]
struct SignedOutTemplate;

/// `GET /login`: bind the presented `request_id` to the session — overwriting
/// any stale binding so an authenticated session serves the new flow — then
/// render the form, or redirect an already-authenticated session to its landing.
pub async fn get_login(
  State(state): State<AppState>,
  jar: CookieJar,
  Query(query): Query<LoginPageQuery>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let presented = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned());
  let (presession_id, fresh) = {
    let mut deps = deps_of(&state, &mut conn, &store);
    match ensure_presession(&mut deps, presented.as_deref()).await {
      Ok(pair) => pair,
      Err(error) => return error.into_response(),
    }
  };
  // Bind a fresh `?request_id=` (overwriting any stale binding) before deciding
  // the landing, so an already-authenticated session serves the new
  // authorization request instead of the one it carried from a prior flow.
  let mut client = String::new();
  if let Some(request_id) = query.request_id.as_deref() {
    match store::pending::get(&mut conn, &store, request_id).await {
      Ok(Some(record)) => {
        let mut deps = deps_of(&state, &mut conn, &store);
        if bind_pending_request(
          &mut deps,
          &presession_id,
          request_id,
          &record.client_id,
          record.post_logout_uri.as_deref(),
        )
        .await
        .is_err()
        {
          return AppError::server_error().into_response();
        }
        client = record.client_id;
      }
      Ok(None) => {
        return AppError::invalid_request("the authorization request is unknown or has expired")
          .into_response();
      }
      Err(error) => return AppError::from(error).into_response(),
    }
  }
  // A live authenticated session does not need the form again.
  if !fresh
    && let Some(live) = load_session(&mut conn, &store, &presession_id)
      .await
      .unwrap_or(None)
    && !live.record.subject.is_empty()
  {
    let target = login_landing(&live);
    return Redirect::to(&target).into_response();
  }
  let csrf = match login_csrf_token(&state.keys, &presession_id) {
    Ok(token) => token,
    Err(error) => return error.into_response(),
  };
  let template = LoginTemplate {
    csrf,
    email: String::new(),
    client: client.clone(),
    has_client: !client.is_empty(),
    error: String::new(),
    has_error: false,
  };
  let mut response = render(template);
  if fresh {
    response = (
      jar.add(session_cookie(&state.config, &presession_id)),
      response,
    )
      .into_response();
  }
  response
}

/// `POST /login`: verify credentials, rotate the session, redirect strictly.
pub async fn post_login(
  State(state): State<AppState>,
  jar: CookieJar,
  Form(form): Form<LoginForm>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let presession_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let attempt = LoginAttempt {
    presession_id,
    email: form.email.clone(),
    password: form.password,
    code: form.code,
    csrf: form.csrf,
  };
  let mut deps = deps_of(&state, &mut conn, &store);
  match attempt_login(&mut deps, attempt).await {
    Ok(LoginOutcome::Authenticated {
      session_id,
      redirect_to,
    })
    | Ok(LoginOutcome::Restricted {
      session_id,
      redirect_to,
    }) => (
      jar.add(session_cookie(&state.config, &session_id)),
      Redirect::to(&redirect_to),
    )
      .into_response(),
    Ok(LoginOutcome::Rejected) => (
      StatusCode::UNAUTHORIZED,
      [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
      login_rejected_page(&form.email),
    )
      .into_response(),
    Err(error) => error.into_response(),
  }
}

/// `GET /login/change-password`: the password-change form (session required).
pub async fn get_change_password(State(state): State<AppState>, jar: CookieJar) -> Response {
  gated_form(
    &state,
    &jar,
    CHANGE_PASSWORD_ACTION,
    BootstrapForm::Password,
  )
  .await
}

/// `POST /login/change-password`: set the password, promote when enrolled.
pub async fn post_change_password(
  State(state): State<AppState>,
  jar: CookieJar,
  Form(form): Form<PasswordForm>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let live = match load_session(&mut conn, &store, &session_id).await {
    Ok(Some(live)) => live,
    Ok(None) => return Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => return error.into_response(),
  };
  if !verify_form_token(&live.meta.csrf_secret, CHANGE_PASSWORD_ACTION, &form.csrf) {
    return AppError::invalid_request("invalid form submission").into_response();
  }
  let mut deps = deps_of(&state, &mut conn, &store);
  match change_password(&mut deps, &session_id, &form.new_password, &form.confirm).await {
    Ok(PasswordOutcome::Promoted {
      session_id,
      redirect_to,
    }) => (
      jar.add(session_cookie(&state.config, &session_id)),
      Redirect::to(&redirect_to),
    )
      .into_response(),
    Ok(PasswordOutcome::StillRestricted { .. }) => Redirect::to(TOTP_SETUP_PATH).into_response(),
    Err(error) => error.into_response(),
  }
}

/// `GET /login/totp/setup`: provision and display enrollment material once.
pub async fn get_totp_setup(State(state): State<AppState>, jar: CookieJar) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let live = match load_session(&mut conn, &store, &session_id).await {
    Ok(Some(live)) => live,
    Ok(None) => return Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => return error.into_response(),
  };
  if live.record.subject.is_empty() {
    return Redirect::to(LOGIN_PATH).into_response();
  }
  let mut deps = deps_of(&state, &mut conn, &store);
  match provision_totp(&mut deps, &session_id).await {
    Ok(offer) => render(SetupTemplate {
      csrf: form_token(&live.meta.csrf_secret, TOTP_CONFIRM_ACTION),
      secret: offer.secret,
      uri: offer.otpauth_uri,
      codes: offer.recovery_codes,
      error: String::new(),
      has_error: false,
    }),
    Err(error) => error.into_response(),
  }
}

/// `GET /login/totp/confirm`: the confirmation retry form (session required).
pub async fn get_totp_confirm(State(state): State<AppState>, jar: CookieJar) -> Response {
  gated_form(&state, &jar, TOTP_CONFIRM_ACTION, BootstrapForm::Confirm).await
}

/// `POST /login/totp/confirm`: verify the authenticator code, promote or stay.
pub async fn post_totp_confirm(
  State(state): State<AppState>,
  jar: CookieJar,
  Form(form): Form<ConfirmForm>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let live = match load_session(&mut conn, &store, &session_id).await {
    Ok(Some(live)) => live,
    Ok(None) => return Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => return error.into_response(),
  };
  if !verify_form_token(&live.meta.csrf_secret, TOTP_CONFIRM_ACTION, &form.csrf) {
    return AppError::invalid_request("invalid form submission").into_response();
  }
  let mut deps = deps_of(&state, &mut conn, &store);
  match confirm_totp(&mut deps, &session_id, &form.code).await {
    Ok(ConfirmOutcome::Completed {
      session_id,
      redirect_to,
    }) => (
      jar.add(session_cookie(&state.config, &session_id)),
      Redirect::to(&redirect_to),
    )
      .into_response(),
    Ok(ConfirmOutcome::StillRestricted) => Redirect::to(CHANGE_PASSWORD_PATH).into_response(),
    Ok(ConfirmOutcome::Rejected) => render(ConfirmTemplate {
      csrf: form_token(&live.meta.csrf_secret, TOTP_CONFIRM_ACTION),
      error: "That code was not accepted. Check your authenticator and try again.".to_owned(),
      has_error: true,
    }),
    Err(error) => error.into_response(),
  }
}

/// `POST /logout`: destroy the session and expire the cookie.
pub async fn post_logout(State(state): State<AppState>, jar: CookieJar) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  if logout(&mut conn, &store, &session_id).await.is_err() {
    return AppError::server_error().into_response();
  }
  (jar.add(expired_session_cookie()), Redirect::to(LOGIN_PATH)).into_response()
}

/// `GET /logout`: destroy the session, expire the cookie, then render a neutral
/// signed-out page or redirect to the flow's registered post-logout URI.
///
/// No query parameter is ever honored, so the target cannot be supplied by the
/// caller. The return URI was frozen in session meta when the authorization
/// flow was bound, and it is used only if the owning client is still active and
/// still registers that exact URI. If there is no session, no bound client, or
/// the client/URI is no longer valid, the neutral page is rendered and no
/// redirect is issued. The server session is destroyed idempotently; a missing
/// session is a no-op.
pub async fn get_logout(State(state): State<AppState>, jar: CookieJar) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let target = match load_session(&mut conn, &store, &session_id)
    .await
    .unwrap_or(None)
  {
    Some(live) => resolve_post_logout_target(&state, &live).await,
    None => None,
  };
  if logout(&mut conn, &store, &session_id).await.is_err() {
    return AppError::server_error().into_response();
  }
  let response = match target {
    Some(uri) => Redirect::to(&uri).into_response(),
    None => render(SignedOutTemplate),
  };
  (jar.add(expired_session_cookie()), response).into_response()
}

/// Resolve the session's bound post-logout target, if it is still trustworthy.
///
/// Returns the frozen URI only when the flow recorded both a client and a URI,
/// the client is still active, and that exact URI is still in the client's
/// effective post-logout set (exact-match or RFC 8252 loopback). Any miss or
/// database failure yields `None` (no redirect), never a guessed target.
async fn resolve_post_logout_target(state: &AppState, live: &LiveSession) -> Option<String> {
  let client_id = live.meta.post_logout_client_id.as_deref()?;
  let bound = live.meta.post_logout_uri.as_deref()?;
  client_repo::find_active_by_client_id(&state.pool, client_id)
    .await
    .ok()??;
  let effective = redirect_repo::effective_post_logout_for_client(&state.pool, client_id)
    .await
    .ok()?;
  let registered: Vec<&str> = effective.iter().map(String::as_str).collect();
  match redirect_match::match_redirect_uri(&registered, bound) {
    redirect_match::RedirectDecision::Exact | redirect_match::RedirectDecision::Loopback => {
      Some(bound.to_owned())
    }
    redirect_match::RedirectDecision::Reject => None,
  }
}

/// `GET /login/success`: landing page for logins with no bound request.
pub async fn get_login_success(State(state): State<AppState>, jar: CookieJar) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  match load_session(&mut conn, &store, &session_id).await {
    Ok(Some(live)) if !live.record.subject.is_empty() && !live.record.restricted => {
      render(SuccessTemplate)
    }
    Ok(_) => Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => error.into_response(),
  }
}

/// Form-token action for the password-change form.
const CHANGE_PASSWORD_ACTION: &str = "change-password";
/// Form-token action for the TOTP-confirmation form.
const TOTP_CONFIRM_ACTION: &str = "totp-confirm";

/// Which bootstrap form a gated `GET` renders.
enum BootstrapForm {
  /// The password-change form.
  Password,
  /// The TOTP-confirmation retry form.
  Confirm,
}

/// Render a session-gated bootstrap form, bouncing anonymous callers to login.
async fn gated_form(
  state: &AppState,
  jar: &CookieJar,
  action: &str,
  form: BootstrapForm,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let live = match load_session(&mut conn, &store, &session_id).await {
    Ok(Some(live)) => live,
    Ok(None) => return Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => return error.into_response(),
  };
  if live.record.subject.is_empty() {
    return Redirect::to(LOGIN_PATH).into_response();
  }
  let csrf = form_token(&live.meta.csrf_secret, action);
  match form {
    BootstrapForm::Password => render(PasswordTemplate {
      csrf,
      error: String::new(),
      has_error: false,
    }),
    BootstrapForm::Confirm => render(ConfirmTemplate {
      csrf,
      error: String::new(),
      has_error: false,
    }),
  }
}

/// Where an already-authenticated `GET /login` lands.
fn login_landing(live: &LiveSession) -> String {
  if live.record.restricted {
    CHANGE_PASSWORD_PATH.to_owned()
  } else if live.meta.pending_request_id.is_some() {
    CONSENT_PATH.to_owned()
  } else {
    LOGIN_SUCCESS_PATH.to_owned()
  }
}

/// Render an Askama template as `text/html`; a render failure is a masked 500.
fn render(template: impl Template) -> Response {
  match template.render() {
    Ok(body) => (
      StatusCode::OK,
      [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
      body,
    )
      .into_response(),
    Err(_) => AppError::server_error().into_response(),
  }
}

/// Uniform 401 page: identical for every credential-failure reason.
fn login_rejected_page(email: &str) -> String {
  format!(
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
    <title>Sign in</title></head><body>\
    <h1>Sign in</h1>\
    <p role=\"alert\">{INVALID_CREDENTIALS}</p>\
    <p>Attempted sign-in as {email} was rejected.</p>\
    <p><a href=\"{LOGIN_PATH}\">Try again</a>.</p></body></html>",
    email = html_escape(email)
  )
}

/// Minimal HTML escaping for reflected values in hand-built pages.
fn html_escape(value: &str) -> String {
  let mut out = String::with_capacity(value.len());
  for c in value.chars() {
    match c {
      '&' => out.push_str("&amp;"),
      '<' => out.push_str("&lt;"),
      '>' => out.push_str("&gt;"),
      '"' => out.push_str("&quot;"),
      _ => out.push(c),
    }
  }
  out
}

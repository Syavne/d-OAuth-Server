//! Device-verification page (RFC 8628 §3.3, user half).
//!
//! `GET /device` renders the code-entry form to anyone: it carries no device
//! state, so there is nothing to leak. Every mutating step requires a fully
//! authenticated session (subject present, MFA passed, not a restricted
//! bootstrap session); anonymous callers are bounced to `/login`.
//!
//! Brute-force protection sits on the lookup itself: each code-entry attempt
//! increments a fixed-window counter keyed by client IP (10 guesses/minute).
//! The 11th guess in a window is answered `429` with `Retry-After`, and an
//! unknown, expired, or already-decided code renders the same generic error
//! as any other miss, so guesses reveal nothing about code validity.
//!
//! The approve/deny form carries a stateless CSRF token: an HMAC of
//! (`session_id`, `device_hash`, `action`) under the active token pepper.
//! No server-side CSRF state is stored.
//!
//! Session-cookie assumption: the login flow (task 25) owns the `session_id`
//! cookie name used here. If that task lands a different name, this constant
//! is the single rendezvous to update.

use std::{net::SocketAddr, time::Duration};

use askama::Template;
use axum::{
  Form,
  extract::{ConnectInfo, Query, State},
  http::{StatusCode, header},
  response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use sha2::Sha256;

use crate::{
  crypto::ct::ct_eq,
  error::AppError,
  protocol::device::{
    display_user_code, hash_token, is_well_formed_user_code, normalize_user_code,
  },
  state::{AppState, RedisConn},
  store::{self, Store},
};

/// Session cookie name (owned by the login flow; see module docs).
pub const SESSION_COOKIE: &str = "session_id";
/// Where anonymous users are sent to authenticate first.
pub const LOGIN_PATH: &str = "/login";
/// Guess window for the user-code brute-force counter.
pub const GUESS_WINDOW: Duration = Duration::from_secs(60);
/// Guesses allowed per client IP per [`GUESS_WINDOW`].
pub const GUESS_LIMIT: u64 = 10;

/// Query string for `GET /device`: an optional pre-filled user code.
#[derive(Debug, Deserialize)]
pub struct DevicePageQuery {
  /// Pre-filled `user_code` (from `verification_uri_complete`).
  #[serde(default)]
  pub user_code: Option<String>,
}

/// Form posted by the code-entry and approve/deny pages.
#[derive(Debug, Deserialize)]
pub struct DeviceForm {
  /// The user-typed code.
  #[serde(default)]
  pub user_code: String,
  /// `approve` or `deny`; absent means "look up and show the review page".
  #[serde(default)]
  pub action: Option<String>,
  /// CSRF token minted for this (`session_id`, `device_hash`, `action`).
  #[serde(default)]
  pub csrf: Option<String>,
}

/// Outcome of the brute-force budget check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuessBudget {
  /// The attempt may proceed.
  Allow,
  /// The window is exhausted; retry after the given seconds.
  Limited {
    /// Whole seconds until the window resets (at least 1).
    retry_after_secs: u64,
  },
}

/// A pending device request safe to show its owner: client identity and
/// scope only, never codes, hashes, or bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDevice {
  /// Opaque device-hash key (never rendered; resubmitted opaquely).
  pub device_hash: String,
  /// Client the user is being asked to authorize.
  pub client_id: String,
  /// Space-joined scope the client requested (may be empty).
  pub scope: String,
  /// User code in display form, echoed for confirmation.
  pub user_code_display: String,
}

/// Enforce the per-IP guess budget for user-code lookups.
///
/// Every call increments the fixed-window counter, allowed or not, so valid
/// and invalid guesses cost the same. A store outage fails closed to
/// `temporarily_unavailable`.
///
/// # Errors
///
/// Returns a masked `5xx` when the counter store fails.
pub async fn check_guess_budget(
  conn: &mut RedisConn,
  store: &Store,
  client_ip: &str,
) -> Result<GuessBudget, AppError> {
  let bucket = format!("device-guess:{client_ip}");
  let decision =
    store::ratelimit::check_and_incr(conn, store, &bucket, GUESS_WINDOW, GUESS_LIMIT).await?;
  if decision.allowed {
    Ok(GuessBudget::Allow)
  } else {
    Ok(GuessBudget::Limited {
      retry_after_secs: decision.retry_after_secs.max(1),
    })
  }
}

/// Resolve the logged-in subject from the session cookie, if any.
///
/// `None` covers every anonymous case: no cookie, unknown or expired session,
/// in-progress login, failed MFA, or a restricted bootstrap session. Those
/// are all "not yet authenticated" to this page, never errors.
///
/// # Errors
///
/// Returns a masked `5xx` only when the session store itself fails.
pub async fn authenticated_subject(
  conn: &mut RedisConn,
  store: &Store,
  jar: &CookieJar,
) -> Result<Option<String>, AppError> {
  let Some(cookie) = jar.get(SESSION_COOKIE) else {
    return Ok(None);
  };
  let session_id = cookie.value();
  if session_id.is_empty() {
    return Ok(None);
  }
  let record = store::sessions::get(conn, store, session_id).await?;
  Ok(
    record
      .filter(|session| !session.subject.is_empty() && session.mfa_verified && !session.restricted)
      .map(|session| session.subject),
  )
}

/// Look up a user code for display/decision, without leaking state.
///
/// Returns `Ok(None)` for every non-actionable case — unknown code,
/// malformed shape, expired mapping, missing record, or an already decided
/// request — so callers can render one generic error for all of them.
///
/// # Errors
///
/// Returns a masked `5xx` when hashing has no pepper or a store read fails.
pub async fn lookup_pending(
  conn: &mut RedisConn,
  store: &Store,
  keys: &crate::keys::KeyRing,
  user_code_raw: &str,
) -> Result<Option<PendingDevice>, AppError> {
  let normalized = normalize_user_code(user_code_raw);
  if !is_well_formed_user_code(&normalized) {
    return Ok(None);
  }
  let user_hash = hash_token(keys, &normalized)?;
  let Some(device_hash) = store::device::resolve_user_code(conn, store, &user_hash).await? else {
    return Ok(None);
  };
  let Some(record) = store::device::poll(conn, store, &device_hash).await? else {
    return Ok(None);
  };
  if record.status != store::device::DeviceStatus::Pending {
    return Ok(None);
  }
  Ok(Some(PendingDevice {
    device_hash,
    client_id: record.client_id,
    scope: record.scope,
    user_code_display: display_user_code(&normalized),
  }))
}

/// Record the user's verdict on a pending device request.
///
/// Approval binds the grant to the approving subject with a fresh grant id;
/// denial records the subject with no grant. Returns `false` when the record
/// vanished between lookup and decision (the caller renders the generic miss
/// error).
///
/// # Errors
///
/// Returns a masked `5xx` when the decision write fails.
pub async fn decide_device(
  conn: &mut RedisConn,
  store: &Store,
  device_hash: &str,
  approve: bool,
  subject: &str,
) -> Result<bool, AppError> {
  let status = if approve {
    store::device::DeviceStatus::Approved
  } else {
    store::device::DeviceStatus::Denied
  };
  let grant_id = if approve {
    uuid::Uuid::now_v7().to_string()
  } else {
    String::new()
  };
  Ok(store::device::decide(conn, store, device_hash, status, subject, &grant_id).await?)
}

/// Mint the stateless CSRF token for one decision form.
///
/// HMAC-SHA256 under the active token pepper over
/// `session_id || device_hash || action`.
///
/// # Errors
///
/// Returns `server_error` when no pepper is configured.
pub fn csrf_token(
  keys: &crate::keys::KeyRing,
  session_id: &str,
  device_hash: &str,
  action: &str,
) -> Result<String, AppError> {
  let (_, pepper) = keys.active_pepper().ok_or_else(AppError::server_error)?;
  let mut mac = Hmac::<Sha256>::new_from_slice(pepper.expose_secret().as_bytes())
    .map_err(|_| AppError::server_error())?;
  mac.update(session_id.as_bytes());
  mac.update(b"|");
  mac.update(device_hash.as_bytes());
  mac.update(b"|");
  mac.update(action.as_bytes());
  Ok(hex_bytes(&mac.finalize().into_bytes()))
}

/// Verify a decision-form CSRF token in constant time.
#[must_use]
pub fn verify_csrf(
  keys: &crate::keys::KeyRing,
  session_id: &str,
  device_hash: &str,
  action: &str,
  presented: &str,
) -> bool {
  let Ok(expected) = csrf_token(keys, session_id, device_hash, action) else {
    return false;
  };
  let (Ok(a), Ok(b)) = (unhex(&expected), unhex(presented)) else {
    return false;
  };
  ct_eq(&a, &b)
}

/// Lowercase hex encoding of raw bytes.
fn hex_bytes(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    out.push_str(&format!("{b:02x}"));
  }
  out
}

/// Decode lowercase hex; `Err(())` on any malformed input.
fn unhex(text: &str) -> Result<Vec<u8>, ()> {
  if !text.len().is_multiple_of(2) {
    return Err(());
  }
  let mut out = Vec::with_capacity(text.len() / 2);
  let bytes = text.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    let pair = core::str::from_utf8(&bytes[i..i + 2]).map_err(|_| ())?;
    let byte = u8::from_str_radix(pair, 16).map_err(|_| ())?;
    out.push(byte);
    i += 2;
  }
  Ok(out)
}

/// Code-entry page: no state, safe for anonymous callers.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
  <link rel=\"stylesheet\" href=\"/assets/app.css\">\
  <title>Device verification</title></head><body>\
  <h1>Enter the code shown on your device</h1>\
  {% if has_error %}<p role=\"alert\">{{ error }}</p>{% endif %}\
  <form method=\"post\" action=\"/device\">\
  <label for=\"user_code\">Code</label>\
  <input id=\"user_code\" name=\"user_code\" value=\"{{ prefill }}\" \
  autocomplete=\"off\" autocapitalize=\"characters\" spellcheck=\"false\">\
  <button type=\"submit\">Continue</button></form></body></html>",
  ext = "html"
)]
struct EntryTemplate {
  prefill: String,
  error: String,
  has_error: bool,
}

/// Review page: shown only to authenticated users for a live request.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
  <link rel=\"stylesheet\" href=\"/assets/app.css\">\
  <title>Authorize device</title></head><body>\
  <h1>Authorize this device?</h1>\
  <p>Code <strong>{{ user_code_display }}</strong></p>\
  <p>Client <strong>{{ client_id }}</strong> requests access.</p>\
  {% if scope.is_empty() %}<p>No additional scope requested.</p>\
  {% else %}<p>Scope: {{ scope }}</p>{% endif %}\
  <form method=\"post\" action=\"/device\">\
  <input type=\"hidden\" name=\"user_code\" value=\"{{ user_code_display }}\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\" name=\"action\" value=\"approve\">Approve</button>\
  <button type=\"submit\" name=\"action\" value=\"deny\">Deny</button></form></body></html>",
  ext = "html"
)]
struct ReviewTemplate {
  user_code_display: String,
  client_id: String,
  scope: String,
  csrf: String,
}

/// Outcome page after a decision is recorded.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
  <link rel=\"stylesheet\" href=\"/assets/app.css\">\
  <title>Device {{ verdict }}</title></head><body>\
  {% if approved %}<h1>Device approved</h1>\
  <p>You may return to your device; it will pick up the authorization.</p>\
  {% else %}<h1>Device denied</h1>\
  <p>The device will not receive access.</p>{% endif %}</body></html>",
  ext = "html"
)]
struct DoneTemplate {
  approved: bool,
  verdict: &'static str,
}

/// Generic miss text: identical for unknown, expired, and decided codes.
const MISS_ERROR: &str = "That code was not recognized, has expired, or was already used.";

/// `GET /device`: the code-entry form (stateless; anonymous-safe).
pub async fn get_device(Query(query): Query<DevicePageQuery>) -> impl IntoResponse {
  let template = EntryTemplate {
    prefill: query.user_code.unwrap_or_default(),
    error: String::new(),
    has_error: false,
  };
  render(template)
}

/// `POST /device`: look up the code, then review or record the decision.
///
/// Anonymous callers are redirected to login before any state is touched.
/// Every reachable failure renders the generic miss text or a protocol error
/// with no device detail.
pub async fn post_device(
  State(state): State<AppState>,
  jar: CookieJar,
  peer: Option<ConnectInfo<SocketAddr>>,
  Form(form): Form<DeviceForm>,
) -> Response {
  let session_cookie = jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default();
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);

  let subject = match authenticated_subject(&mut conn, &store, &jar).await {
    Ok(Some(subject)) => subject,
    Ok(None) => return Redirect::to(LOGIN_PATH).into_response(),
    Err(error) => return error.into_response(),
  };

  let Some(ConnectInfo(addr)) = peer else {
    return AppError::temporarily_unavailable().into_response();
  };
  match check_guess_budget(&mut conn, &store, &addr.ip().to_string()).await {
    Ok(GuessBudget::Allow) => {}
    Ok(GuessBudget::Limited { retry_after_secs }) => {
      return rate_limited(retry_after_secs);
    }
    Err(error) => return error.into_response(),
  }

  let action = form.action.as_deref().unwrap_or("");
  if action.is_empty() {
    match lookup_pending(&mut conn, &store, &state.keys, &form.user_code).await {
      Ok(Some(pending)) => {
        let csrf = match csrf_token(&state.keys, &session_cookie, &pending.device_hash, "decide") {
          Ok(token) => token,
          Err(error) => return error.into_response(),
        };
        return render(ReviewTemplate {
          user_code_display: pending.user_code_display,
          client_id: pending.client_id,
          scope: pending.scope,
          csrf,
        });
      }
      Ok(None) => return render(miss(&form.user_code)),
      Err(error) => return error.into_response(),
    }
  }

  if action != "approve" && action != "deny" {
    return render(miss(&form.user_code));
  }
  let pending = match lookup_pending(&mut conn, &store, &state.keys, &form.user_code).await {
    Ok(Some(pending)) => pending,
    Ok(None) => return render(miss(&form.user_code)),
    Err(error) => return error.into_response(),
  };
  let presented = form.csrf.as_deref().unwrap_or("");
  if !verify_csrf(
    &state.keys,
    &session_cookie,
    &pending.device_hash,
    "decide",
    presented,
  ) {
    return AppError::invalid_request("invalid form submission").into_response();
  }
  match decide_device(
    &mut conn,
    &store,
    &pending.device_hash,
    action == "approve",
    &subject,
  )
  .await
  {
    Ok(true) => render(DoneTemplate {
      approved: action == "approve",
      verdict: if action == "approve" {
        "approved"
      } else {
        "denied"
      },
    }),
    Ok(false) => render(miss(&form.user_code)),
    Err(error) => error.into_response(),
  }
}

/// Entry page carrying the generic miss error.
fn miss(user_code: &str) -> EntryTemplate {
  EntryTemplate {
    prefill: user_code.to_owned(),
    error: MISS_ERROR.to_owned(),
    has_error: true,
  }
}

/// Render an Askama template as `text/html`; a render failure is a `500`
/// with no template detail.
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

/// `429 Too Many Requests` with a `Retry-After` hint, matching the middleware
/// error shape.
fn rate_limited(retry_after_secs: u64) -> Response {
  let mut response = (
    StatusCode::TOO_MANY_REQUESTS,
    axum::Json(serde_json::json!({
      "error": "rate_limited",
      "error_description": "Too many incorrect codes; retry after the indicated delay.",
    })),
  )
    .into_response();
  if let Ok(value) = retry_after_secs.to_string().parse() {
    response.headers_mut().insert(header::RETRY_AFTER, value);
  }
  response
}

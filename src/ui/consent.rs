//! Consent screen with CSRF and per-flow re-consent (RFC 9700 §4.7.1).
//!
//! `GET /consent` shows the authenticated user the client name and the
//! **effective scope** — `requested ∩ client-registered ∩ enabled ∩
//! user-entitled` — so a scope the user is not entitled to is never shown.
//! `POST /consent` approves or denies; the submitted `request_id` MUST match
//! the one bound to the logged-in session (task 25 sidecar), and the CSRF
//! token is an HMAC of the session CSRF secret over the request-bound action.
//!
//! Denial redirects to the validated `redirect_uri` with `error=access_denied`
//! (+ `state`, + `iss`). Approval hands the pending record's client/redirect/
//! challenge bindings, the authenticated subject, the **effective scope**, and
//! the user's entitled set to task 27's [`code::CodeIssuer::issue`], then
//! redirects to the location it returns. Consent never mints a code itself,
//! never auto-approves, and re-consents on every flow (no remembered grants),
//! so no durable grant store is involved.

use askama::Template;
use axum::{
  Form,
  body::Body,
  extract::State,
  http::{StatusCode, header},
  response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
  config::GrantKind,
  db::{client_repo, scope_repo, user_repo, user_scope_repo},
  error::AppError,
  middleware::audit::AuditEvent,
  protocol::{
    code,
    scope::{self, ScopeSet},
  },
  state::{AppState, RedisConn},
  store::{self, Store, pending::PendingAuth},
  ui::login::{self, LiveSession, SESSION_COOKIE, form_token, load_session, verify_form_token},
};

/// Form-token action prefix; the bound `request_id` is appended so a token
/// minted for one flow cannot be replayed on another.
const CONSENT_ACTION: &str = "consent";

/// The form-token action string bound to a pending `request_id`.
#[must_use]
pub fn consent_action(request_id: &str) -> String {
  format!("{CONSENT_ACTION}:{request_id}")
}

/// Form posted to `POST /consent`.
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
  /// Pending-auth id the decision applies to.
  #[serde(default)]
  pub request_id: String,
  /// Session-bound form token.
  #[serde(default)]
  pub csrf: String,
  /// `approve` or `deny`.
  #[serde(default)]
  pub decision: String,
}

/// The user's verdict on the consent screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
  /// Grant the (effective) scope and issue a code.
  Approve,
  /// Refuse; redirect back with `access_denied`.
  Deny,
}

impl ConsentDecision {
  /// Parse a submitted `decision`; anything else is a malformed request.
  fn parse(raw: &str) -> Result<Self, AppError> {
    match raw {
      "approve" => Ok(Self::Approve),
      "deny" => Ok(Self::Deny),
      _ => Err(AppError::invalid_request("invalid consent decision")),
    }
  }
}

/// One `POST /consent` submission.
pub struct ConsentSubmission<'a> {
  /// Session cookie value (must name a full authenticated session).
  pub session_id: &'a str,
  /// Pending-auth id the decision applies to (must match the session binding).
  pub request_id: &'a str,
  /// Presented session-bound form token.
  pub csrf: &'a str,
  /// Submitted verdict.
  pub decision: ConsentDecision,
}

/// Outcome of [`submit_consent`].
pub enum ConsentOutcome {
  /// Approved: the code issued by task 27 (`issued.location` is the redirect).
  Approved {
    /// Freshly issued code.
    issued: code::IssuedCode,
  },
  /// Denied: redirect location carrying `error=access_denied`.
  Denied {
    /// Full `Location` built here.
    redirect_to: String,
  },
  /// No usable authenticated session: send the user to login.
  NeedsLogin,
}

/// What the consent page renders after session/pending/entitlement checks.
pub struct ConsentView {
  /// Registered client display name.
  pub client_name: String,
  /// Effective (post-entitlement) scope tokens, in canonical order.
  pub scopes: Vec<String>,
  /// Pending-auth id the form must post back.
  pub request_id: String,
  /// Session-bound form token.
  pub csrf: String,
}

/// Everything the consent core needs, borrowed from the HTTP layer.
pub struct ConsentDeps<'a> {
  /// Postgres pool for client, user, and scope-catalog reads.
  pub pool: &'a PgPool,
  /// Redis connection for sessions and the pending record.
  pub conn: &'a mut RedisConn,
  /// Redis store handle (session/pending/code key layout).
  pub store: &'a Store,
}

/// Whether `live` is a full authenticated session (never a pre-session or a
/// restricted bootstrap session).
fn is_full_session(live: &LiveSession) -> bool {
  !live.record.subject.is_empty() && live.record.mfa_verified && !live.record.restricted
}

/// `GET /consent`: load the view, or `Ok(None)` when the caller must log in.
///
/// # Errors
///
/// Returns `invalid_request` when the session has no bound, live authorization
/// request, or the bound client/user is gone; a masked `5xx` when a store or
/// database read fails.
pub async fn load_consent_view(
  deps: &mut ConsentDeps<'_>,
  session_id: &str,
) -> Result<Option<ConsentView>, AppError> {
  let Some(live) = load_session(deps.conn, deps.store, session_id).await? else {
    return Ok(None);
  };
  if !is_full_session(&live) {
    return Ok(None);
  }
  let Some(request_id) = live.meta.pending_request_id.as_deref() else {
    return Err(AppError::invalid_request(
      "no authorization request is bound to this session",
    ));
  };
  let Some(pending) = store::pending::get(deps.conn, deps.store, request_id).await? else {
    return Err(AppError::invalid_request(
      "the authorization request is unknown or has expired",
    ));
  };
  let (client, user) = client_and_user(deps, &pending, &live.record.subject).await?;
  let entitled = user_entitlement(deps, user.id).await?;
  let enabled = enabled_catalog(deps).await?;
  let effective = narrow_for_consent(&pending.scope, &client, &entitled, &enabled)?;
  Ok(Some(ConsentView {
    client_name: client.client_name,
    scopes: wire_scopes(&effective),
    request_id: request_id.to_owned(),
    csrf: form_token(&live.meta.csrf_secret, &consent_action(request_id)),
  }))
}

/// Apply an approve/deny decision, enforcing session/request binding and CSRF.
///
/// # Errors
///
/// Returns `invalid_request` for a mismatched session/request pair, a bad or
/// missing CSRF token, an unknown pending record, a malformed decision, or a
/// now-inactive client/user; a masked `5xx` when a store, database, or issuer
/// call fails.
pub async fn submit_consent(
  deps: &mut ConsentDeps<'_>,
  submission: ConsentSubmission<'_>,
  issuer: &code::CodeIssuer,
) -> Result<ConsentOutcome, AppError> {
  let Some(live) = load_session(deps.conn, deps.store, submission.session_id).await? else {
    return Ok(ConsentOutcome::NeedsLogin);
  };
  if !is_full_session(&live) {
    return Ok(ConsentOutcome::NeedsLogin);
  }
  // The pending id comes from the session, never from client input, so a
  // submission for any other request cannot reach issuance.
  if live.meta.pending_request_id.as_deref() != Some(submission.request_id) {
    return Err(AppError::invalid_request(
      "the session is not bound to that authorization request",
    ));
  }
  if !verify_form_token(
    &live.meta.csrf_secret,
    &consent_action(submission.request_id),
    submission.csrf,
  ) {
    return Err(AppError::invalid_request("invalid form submission"));
  }
  let Some(pending) = store::pending::get(deps.conn, deps.store, submission.request_id).await?
  else {
    return Err(AppError::invalid_request(
      "the authorization request is unknown or has expired",
    ));
  };
  if submission.decision == ConsentDecision::Deny {
    audit(
      submission.request_id,
      &pending.client_id,
      &live.record.subject,
      false,
    );
    return Ok(ConsentOutcome::Denied {
      redirect_to: deny_redirect(&pending),
    });
  }
  let (client, user) = client_and_user(deps, &pending, &live.record.subject).await?;
  let entitled = user_entitlement(deps, user.id).await?;
  let enabled = enabled_catalog(deps).await?;
  let effective = narrow_for_consent(&pending.scope, &client, &entitled, &enabled)?;
  let request = code::CodeIssueRequest {
    client_id: &pending.client_id,
    client_kind: client_kind_of(&client),
    user_id: &live.record.subject,
    redirect_uri: &pending.redirect_uri,
    approved_scope: &effective,
    user_entitled: &entitled,
    code_challenge: &pending.code_challenge,
    dpop_jkt: pending.dpop_jkt.as_deref(),
    state: pending.state.as_deref(),
    issuer: &pending.iss,
  };
  let issued = issuer.issue(deps.conn, deps.store, &request).await?;
  audit(
    submission.request_id,
    &pending.client_id,
    &live.record.subject,
    true,
  );
  Ok(ConsentOutcome::Approved { issued })
}

/// Public client (no secret) vs confidential: selects the DPoP matrix.
fn client_kind_of(client: &client_repo::Client) -> code::CodeClientKind {
  match client.auth_method() {
    Ok(client_repo::TokenEndpointAuthMethod::None) => code::CodeClientKind::Public,
    _ => code::CodeClientKind::Confidential,
  }
}

/// Load the active client and the non-disabled user for a pending request.
async fn client_and_user(
  deps: &ConsentDeps<'_>,
  pending: &PendingAuth,
  subject: &str,
) -> Result<(client_repo::Client, user_repo::UserRecord), AppError> {
  let client = client_repo::find_active_by_client_id(deps.pool, &pending.client_id)
    .await?
    .ok_or_else(|| AppError::invalid_request("the client is no longer active"))?;
  let user = user_repo::find_by_email(deps.pool, subject)
    .await?
    .filter(|user| !user.disabled)
    .ok_or_else(|| AppError::invalid_request("the authenticated account is no longer active"))?;
  Ok((client, user))
}

/// The user's entitled scope set.
async fn user_entitlement(deps: &ConsentDeps<'_>, user_id: Uuid) -> Result<ScopeSet, AppError> {
  ScopeSet::from_names(&user_scope_repo::list_for_user(deps.pool, user_id).await?)
}

/// The enabled scope catalog as a set.
async fn enabled_catalog(deps: &ConsentDeps<'_>) -> Result<ScopeSet, AppError> {
  let names: Vec<String> = scope_repo::list_enabled(deps.pool)
    .await?
    .into_iter()
    .map(|row| row.name)
    .collect();
  ScopeSet::from_names(&names)
}

/// Narrow the (already validated) requested scope by the user's entitlements,
/// then re-enforce the client/catalog/user terms via `effective_scope`.
fn narrow_for_consent(
  requested_raw: &str,
  client: &client_repo::Client,
  user_entitled: &ScopeSet,
  enabled: &ScopeSet,
) -> Result<ScopeSet, AppError> {
  let client_registered = ScopeSet::parse(&client.scope).map_err(|_| AppError::server_error())?;
  let requested = ScopeSet::parse(requested_raw)?;
  // A user is never shown or granted an unentitled scope: narrow first so the
  // requested-but-unentitled tokens are dropped, then enforce the rest.
  let narrowed = requested.intersect(user_entitled);
  let narrowed_wire = narrowed.render();
  scope::effective_scope(&scope::ScopeInput {
    requested: Some(narrowed_wire.as_str()),
    client_registered: &client_registered,
    user_entitled,
    enabled,
    grant: GrantKind::AuthorizationCode,
    exchange_allowlist: &ScopeSet::empty(),
  })
}

/// Split a rendered scope set into its non-empty tokens.
fn wire_scopes(set: &ScopeSet) -> Vec<String> {
  set
    .render()
    .split(' ')
    .filter(|scope| !scope.is_empty())
    .map(str::to_owned)
    .collect()
}

/// Build the `access_denied` redirect with `state` (+ `iss`).
fn deny_redirect(pending: &PendingAuth) -> String {
  let error = AppError::access_denied("The resource owner denied the request.");
  let mut location = pending.redirect_uri.clone();
  location.push(if location.contains('?') { '&' } else { '?' });
  location.push_str("error=");
  location.push_str(error.code().as_str());
  location.push_str("&error_description=");
  push_percent_encoded(&mut location, error.description());
  if let Some(state) = pending.state.as_deref() {
    location.push_str("&state=");
    push_percent_encoded(&mut location, state);
  }
  location.push_str("&iss=");
  push_percent_encoded(&mut location, &pending.iss);
  location
}

/// Emit the consent audit event: request id, client, subject, verdict only.
fn audit(request_id: &str, client_id: &str, subject: &str, granted: bool) {
  AuditEvent::Consent {
    request_id: Some(request_id),
    client_id,
    subject,
    granted,
  }
  .emit();
}

/// Append `text` percent-encoded (unreserved characters pass through).
fn push_percent_encoded(out: &mut String, text: &str) {
  const HEX: &[u8; 16] = b"0123456789ABCDEF";
  for byte in text.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(byte as char);
    } else {
      out.push('%');
      out.push(HEX[usize::from(byte >> 4)] as char);
      out.push(HEX[usize::from(byte & 0x0F)] as char);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP handlers (thin wrappers; task 40 mounts them in `routes.rs`)
// ---------------------------------------------------------------------------

/// Consent page: client name and the effective scope.
#[derive(Template)]
#[template(
  source = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
  <link rel=\"stylesheet\" href=\"/assets/app.css\">\
  <title>Authorize</title></head><body>\
  <h1>Authorize {{ client_name }}</h1>\
  <p><strong>{{ client_name }}</strong> is requesting access.</p>\
  {% if has_scopes %}<p>It is requesting these scopes:</p><ul>\
  {% for scope in scopes %}<li>{{ scope }}</li>{% endfor %}</ul>\
  {% else %}<p>No additional access is requested.</p>{% endif %}\
  <form method=\"post\" action=\"/consent\">\
  <input type=\"hidden\" name=\"request_id\" value=\"{{ request_id }}\">\
  <input type=\"hidden\" name=\"csrf\" value=\"{{ csrf }}\">\
  <button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>\
  <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>\
  </form></body></html>",
  ext = "html"
)]
struct ConsentTemplate {
  client_name: String,
  scopes: Vec<String>,
  has_scopes: bool,
  request_id: String,
  csrf: String,
}

/// `GET /consent`: render the screen for the bound request; anonymous or
/// restricted callers are sent to login.
pub async fn get_consent(State(state): State<AppState>, jar: CookieJar) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = session_id_of(&jar);
  let mut deps = ConsentDeps {
    pool: &state.pool,
    conn: &mut conn,
    store: &store,
  };
  match load_consent_view(&mut deps, &session_id).await {
    Ok(Some(view)) => render(ConsentTemplate {
      has_scopes: !view.scopes.is_empty(),
      client_name: view.client_name,
      scopes: view.scopes,
      request_id: view.request_id,
      csrf: view.csrf,
    }),
    Ok(None) => Redirect::to(login::LOGIN_PATH).into_response(),
    Err(error) => error.into_response(),
  }
}

/// `POST /consent`: approve or deny the bound request.
///
/// Approval calls task 27's [`code::CodeIssuer`]; a missing pepper fails
/// closed before any decision is recorded.
pub async fn post_consent(
  State(state): State<AppState>,
  jar: CookieJar,
  Form(form): Form<ConsentForm>,
) -> Response {
  let decision = match ConsentDecision::parse(&form.decision) {
    Ok(decision) => decision,
    Err(error) => return error.into_response(),
  };
  let issuer = match code::CodeIssuer::new(&state.config.ttl, &state.keys) {
    Ok(issuer) => issuer,
    Err(error) => return AppError::from(error).into_response(),
  };
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let session_id = session_id_of(&jar);
  let mut deps = ConsentDeps {
    pool: &state.pool,
    conn: &mut conn,
    store: &store,
  };
  let submission = ConsentSubmission {
    session_id: &session_id,
    request_id: &form.request_id,
    csrf: &form.csrf,
    decision,
  };
  match submit_consent(&mut deps, submission, &issuer).await {
    Ok(ConsentOutcome::Approved { issued }) => redirect(&issued.location),
    Ok(ConsentOutcome::Denied { redirect_to }) => redirect(&redirect_to),
    Ok(ConsentOutcome::NeedsLogin) => Redirect::to(login::LOGIN_PATH).into_response(),
    Err(error) => error.into_response(),
  }
}

/// Session id from the cookie, or `""` when absent.
fn session_id_of(jar: &CookieJar) -> String {
  jar
    .get(SESSION_COOKIE)
    .map(|cookie| cookie.value().to_owned())
    .unwrap_or_default()
}

/// `302 Found` to `location`; an invalid header fails closed to a `500`.
fn redirect(location: &str) -> Response {
  match header::HeaderValue::from_str(location) {
    Ok(value) => Response::builder()
      .status(StatusCode::FOUND)
      .header(header::LOCATION, value)
      .body(Body::empty())
      .unwrap_or_else(|_| AppError::server_error().into_response()),
    Err(_) => AppError::server_error().into_response(),
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

#[cfg(test)]
mod tests;

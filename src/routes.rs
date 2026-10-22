//! Router assembly: public listener routes plus the middleware chain.
//!
//! [`build_router`] mounts every endpoint behind one [`tower::ServiceBuilder`]
//! whose execution order (outer-to-inner) is exactly {request-id → security
//! headers → CORS (when configured) → resilience (load-shed →
//! timeout → concurrency-limit) → rate-limit → body limit}:
//!
//! 1. [`middleware::request_id::RequestIdLayer`] mints/propagates
//!    `X-Request-Id` and opens the redacted `http_request` tracing span
//!    (tracing and redaction live in this layer).
//! 2. [`middleware::security_headers::SecurityHeadersLayer`] decorates
//!    responses with `Referrer-Policy`, `X-Content-Type-Options`, a CSP with
//!    `frame-ancestors 'none'` (plus a strict script policy on the
//!    login/consent/device pages), and HSTS on the TLS listener. Every response
//!    except `/.well-known/…` metadata and the public JWK Set is also
//!    `Cache-Control: no-store`; `/jwks.json` carries its own shorter window.
//! 3. [`middleware::security_headers::cors_layer`] answers CORS preflights
//!    from the explicit allowlist before the limiter can bill them; mounted
//!    only when `cors_allowed_origins` is non-empty (default empty: no CORS
//!    headers, browser clients unsupported).
//! 4. [`ResilienceLayer`] sheds excess load, then times out slow handlers,
//!    then caps concurrency, so overload returns a `503` before it can queue
//!    into `PoolTimedOut`; it sits outside the rate limiter and inside the
//!    request-id span.
//! 5. [`middleware::ratelimit::RateLimitLayer`] enforces per-IP/per-client
//!    budgets on every endpoint except health and metadata (those paths have
//!    no rule and pass through to handlers that fail closed on their own).
//!    The IP bucket uses the verified TCP peer unless the peer is a
//!    configured `rate_limit.trusted_proxies` entry, in which case the
//!    rightmost-untrusted `X-Forwarded-For` address is attributed instead
//!    (rate-limit bucket selection only; never client authentication).
//! 6. [`tower_http::limit::RequestBodyLimitLayer`] caps form bodies at
//!    [`MAX_BODY_BYTES`].
//!
//! Endpoint inventory: `GET /.well-known/oauth-authorization-server`
//! ([`protocol::metadata`]), `GET /authorize` ([`authorize_entry`] —
//! validates via [`protocol::authorize::validate`], verifies any DPoP proof
//! into the pending `jkt` binding, stashes the normalized request in
//! [`store::pending`], and 303-redirects to `/login`; never 307, so the
//! follow-up is always a credential-free `GET`), `POST /par`
//! ([`protocol::par`]), `POST /token` ([`protocol::token::handler`], the
//! five-grant dispatcher), `POST /device_authorization`
//! ([`protocol::device`]), the `/device` verification page ([`ui::device`]),
//! the `/login` family ([`ui::login`]), `/consent` ([`ui::consent`]),
//! `POST /register` plus `GET/PUT/DELETE /register/{client_id}`
//! ([`protocol::dcr`] and [`protocol::dcr::manage`]), `POST /introspect`
//! ([`protocol::introspect`]), `POST /revoke` ([`protocol::revoke`]), and
//! `/health/live` + `/health/ready` (merged from
//! [`state::health_router`]; the plaintext listener serves that router alone
//! in task 41).

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form};
use axum_extra::extract::CookieJar;
use rustls::ServerConfig;
use tower_http::limit::RequestBodyLimitLayer;

use crate::error::AppError;
use crate::jose::dpop::{DpopRequest, verify_dpop};
use crate::middleware::audit::AuditEvent;
use crate::middleware::ratelimit::RateLimitLayer;
use crate::middleware::request_id::{REQUEST_ID_HEADER, RequestId, RequestIdLayer};
use crate::middleware::security_headers::{SecurityHeadersLayer, cors_layer};
use crate::protocol::mtls::{self, MtlsError};
use crate::protocol::{authorize, dcr, device, introspect, jwks, metadata, par, revoke, token};
use crate::resilience::{ResilienceConfig, ResilienceLayer};
use crate::state::{AppState, health_router};
use crate::store::pending::PendingAuth;
use crate::store::{Store, pending};
use crate::ui::device::DeviceForm;
use crate::ui::login::{ConfirmForm, LoginForm};
use crate::ui::{assets, consent, device as device_page, login};

/// Largest accepted request body (2 MiB; DCR may carry an inline `jwks`).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// How long a validated authorize request waits for login/consent (300 s).
pub const PENDING_TTL: Duration = Duration::from_secs(300);

/// Router tuning owned by the listener bootstrap (task 41).
#[derive(Debug, Clone, Copy)]
pub struct RouterOptions {
  /// Emit `Strict-Transport-Security` (true on the TLS public listener).
  pub hsts: bool,
  /// Request-body cap applied by the body-limit layer.
  pub max_body_bytes: usize,
}

impl Default for RouterOptions {
  fn default() -> Self {
    Self {
      hsts: true,
      max_body_bytes: MAX_BODY_BYTES,
    }
  }
}

/// Build the public-listener router with the default options (HSTS on).
pub fn build_router(state: AppState) -> axum::Router {
  build_router_with_options(state, RouterOptions::default())
}

/// Build the public-listener router: all endpoints plus the middleware chain.
///
/// Layers below run outer-to-inner in declaration order here because each
/// [`axum::Router::layer`] call wraps everything added before it; the calls
/// are therefore issued innermost-first. The conditional CORS layer slots
/// into its spec position only when configured.
pub fn build_router_with_options(state: AppState, options: RouterOptions) -> axum::Router {
  let cors = cors_layer(&state.config.cors_allowed_origins);
  // Task 44 resilience insertion: timeout + concurrency-limit + load-shed sit
  // outside the rate limiter (so overload sheds 503 before it can queue into
  // `PoolTimedOut`) and inside request-id (so the span still covers them).
  // The security-headers layer sits just inside request-id (outside every
  // short-circuiting layer: CORS preflights, resilience 503s, limiter
  // 429/503s, body-limit 413s), so every rejection still carries the
  // hardening headers. Execution order outer-to-inner: request-id →
  // security-headers → load-shed → concurrency-limit → timeout → rate-limit
  // → body-limit; the `.layer` calls below read innermost-first.
  let resilience = ResilienceConfig::from_policy(&state.config.failure_policy);

  let router = axum::Router::new()
    .route("/assets/app.css", get(assets::stylesheet))
    .route(
      "/.well-known/oauth-authorization-server",
      get(metadata::metadata),
    )
    .route("/jwks.json", get(jwks::handler))
    .route("/authorize", get(authorize_entry))
    .route("/par", post(par::par_handler))
    .route("/token", post(token::handler))
    .route("/device_authorization", post(device::handler))
    .route(
      "/device",
      get(device_page::get_device).post(post_device_entry),
    )
    .route("/login", get(login::get_login).post(post_login_entry))
    .route("/login/success", get(login::get_login_success))
    .route(
      "/login/change-password",
      get(login::get_change_password).post(login::post_change_password),
    )
    .route("/login/totp/setup", get(login::get_totp_setup))
    .route(
      "/login/totp/confirm",
      get(login::get_totp_confirm).post(post_totp_confirm_entry),
    )
    .route("/logout", get(login::get_logout).post(login::post_logout))
    .route(
      "/consent",
      get(consent::get_consent).post(consent::post_consent),
    )
    .route("/register", post(dcr::register_handler))
    .route(
      "/register/{client_id}",
      get(dcr::manage::read_handler)
        .put(dcr::manage::update_handler)
        .delete(dcr::manage::delete_handler),
    )
    .route("/introspect", post(introspect::handler))
    .route("/revoke", post(revoke::revoke_handler))
    .with_state(state.clone())
    .merge(health_router(state.clone()))
    .layer(RequestBodyLimitLayer::new(options.max_body_bytes))
    .layer(RateLimitLayer::new(state))
    .layer(ResilienceLayer::from_config(&resilience));

  let router = match cors {
    Some(layer) => router.layer(layer),
    None => router,
  };
  router
    .layer(SecurityHeadersLayer::new(options.hsts))
    .layer(RequestIdLayer)
}

/// Build the rustls server config for the public TLS listener.
///
/// The server identity comes from the configured PEM chain/key. Client
/// certificates are accepted but never required at the TLS layer: with a
/// client-CA bundle the PKI verifier (`tls_client_auth`) is used, otherwise
/// the signature-checking self-signed verifier
/// (`self_signed_tls_client_auth`); per-client enforcement happens in
/// [`mtls`](crate::protocol::mtls) at the application layer.
///
/// # Errors
///
/// Returns [`MtlsError::TrustBundle`] when the chain, key, or CA bundle is
/// not valid PEM or the key does not match the chain.
pub fn build_server_config(
  cert_chain_pem: &[u8],
  key_pem: &[u8],
  client_ca_pem: Option<&[u8]>,
) -> Result<ServerConfig, MtlsError> {
  let verifier = match client_ca_pem {
    Some(bundle) => mtls::pki_verifier(bundle)?,
    None => mtls::self_signed_verifier(),
  };
  mtls::server_config(cert_chain_pem, key_pem, verifier)
}

/// `GET /authorize`: validate, stash the normalized request, 303 to login.
///
/// [`authorize::validate`] resolves PAR/JAR input and enforces the
/// client/redirect/response-type/scope/PKCE matrix. Failures render through
/// [`authorize::AuthorizeFailure`] (400 page or 302 error redirect per the
/// task-23 matrix — both carry no credentials). Success mints an opaque
/// `request_id`, stores the [`PendingAuth`] record server-side (the request
/// itself never travels in query or cookie), and answers `303 See Other` to
/// `/login?request_id=…` so the follow-up is always a credential-free `GET`.
/// A 307 would preserve the request method and body across the redirect and
/// is therefore never used for credential-carrying redirects.
async fn authorize_entry(
  State(state): State<AppState>,
  headers: HeaderMap,
  RawQuery(raw): RawQuery,
) -> Response {
  // `RawQuery` + a manual parse replaces `Query<HashMap>`: the extractor
  // consumed the raw query, hiding repeats — the repeated `resource`
  // indicator (RFC 8707) is captured in order by `params::values_of`
  // while the single-valued map keeps last-wins absorption. A malformed
  // query is the same 400 `Query` rendered.
  let raw = raw.as_deref().unwrap_or("");
  let pairs = match crate::protocol::params::query_pairs(Some(raw)) {
    Ok(pairs) => pairs,
    Err(reject) => return reject.into_response(),
  };
  let query = crate::protocol::params::single_valued_map(&pairs);
  let resources =
    crate::protocol::params::values_of(&pairs, crate::protocol::params::RESOURCE_PARAM);
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let input = authorize::AuthorizeInput {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut conn,
    store: &store,
    issuer: &state.config.issuer,
    allow_localhost_redirect: state.config.allow_localhost_redirect,
    cimd: state.config.cimd_enabled.then(|| authorize::CimdRequest {
      token_prefix: &state.config.redis.token_key_prefix,
      max_bytes: state.config.cimd_max_bytes,
      timeout: state.config.cimd_fetch_timeout,
    }),
    query: &query,
    resources,
    resource_indicators_enabled: state.config.resource_indicators_enabled,
  };
  let validated = match authorize::validate(input).await {
    Ok(validated) => validated,
    Err(failure) => {
      if failure.is_pii_decrypt() {
        let request_id = headers
          .get(REQUEST_ID_HEADER)
          .and_then(|value| value.to_str().ok())
          .and_then(RequestId::parse);
        AuditEvent::PiiDecryptFailure {
          request_id: request_id.as_ref().map(RequestId::as_str),
        }
        .emit();
      }
      return failure.into_response();
    }
  };
  let dpop_jkt = match headers.get("dpop").and_then(|value| value.to_str().ok()) {
    Some(proof) => {
      let htu = format!("{}/authorize", state.config.issuer);
      let request = DpopRequest {
        proof: Some(proof),
        htm: "GET",
        htu: &htu,
        access_token: None,
        now_unix: state.clock.now().unix_timestamp(),
      };
      match verify_dpop(&mut conn, &store, &request).await {
        Ok(verified) => Some(verified.jkt),
        Err(error) => return error.into_response(),
      }
    }
    None => None,
  };
  let request_id = match pending::new_request_id() {
    Ok(id) => id,
    Err(_) => return AppError::server_error().into_response(),
  };
  let record = PendingAuth {
    client_id: validated.client_id,
    redirect_uri: validated.redirect_uri,
    scope: validated.scope.render(),
    code_challenge: validated.code_challenge,
    state: validated.state,
    dpop_jkt,
    iss: state.config.issuer.clone(),
    post_logout_uri: validated.post_logout_uri,
    aud: validated.aud,
  };
  if let Err(error) = pending::put(&mut conn, &store, &request_id, &record, PENDING_TTL).await {
    return AppError::from(error).into_response();
  }
  (
    StatusCode::SEE_OTHER,
    [(header::LOCATION, format!("/login?request_id={request_id}"))],
  )
    .into_response()
}

/// `POST /device` adapter: [`ui::device::post_device`] takes
/// `Option<ConnectInfo<_>>`, which axum cannot use as an extractor
/// (`ConnectInfo` is a required extractor with no optional form), so this
/// thin entry takes the required extractor and forwards it as `Some`.
/// Served with `into_make_service_with_connect_info` (task 41) the peer is
/// always present; without it the handler fails closed via its `None` arm.
async fn post_device_entry(
  State(state): State<AppState>,
  jar: CookieJar,
  peer: ConnectInfo<SocketAddr>,
  Form(form): Form<DeviceForm>,
) -> Response {
  device_page::post_device(State(state), jar, Some(peer), Form(form)).await
}

/// `POST /login` adapter: [`ui::login::post_login`] takes
/// `Option<ConnectInfo<_>>` (not a handler extractor), so this thin entry
/// takes the required extractor and forwards it as `Some` for composite
/// lockout keying. Served with `into_make_service_with_connect_info` the
/// peer is always present; without it the request is rejected before the
/// handler runs.
async fn post_login_entry(
  State(state): State<AppState>,
  Extension(request_id): Extension<RequestId>,
  peer: ConnectInfo<SocketAddr>,
  jar: CookieJar,
  Form(form): Form<LoginForm>,
) -> Response {
  login::post_login(
    State(state),
    Extension(request_id),
    jar,
    Form(form),
    Some(peer),
  )
  .await
}

/// `POST /login/totp/confirm` adapter: mirrors [`post_login_entry`] for the
/// enrollment-confirmation lockout path.
async fn post_totp_confirm_entry(
  State(state): State<AppState>,
  Extension(request_id): Extension<RequestId>,
  peer: ConnectInfo<SocketAddr>,
  jar: CookieJar,
  Form(form): Form<ConfirmForm>,
) -> Response {
  login::post_totp_confirm(
    State(state),
    Extension(request_id),
    jar,
    Form(form),
    Some(peer),
  )
  .await
}

#[cfg(test)]
mod router_tests {
  use std::net::SocketAddr;
  use std::sync::Arc;
  use std::time::Duration;

  use axum::body::Body;
  use axum::extract::connect_info::MockConnectInfo;
  use axum::http::{HeaderMap, Request, StatusCode, header};
  use tower::ServiceExt as _;

  use super::{RouterOptions, build_router, build_router_with_options, build_server_config};
  use crate::config::Config;
  use crate::middleware::security_headers::{JWKS_CACHE_VALUE, METADATA_CACHE_VALUE, cors_layer};
  use crate::state::{AppState, Clock, RedisConn};

  /// Test body result (no `unwrap`/`expect` under the deny lints).
  type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
  /// One mounted route under test: method, URI, and extra headers.
  type Route<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

  /// Self-signed `localhost` server fixture (ECDSA P-256, end-entity with
  /// SAN `localhost` + `127.0.0.1`, valid 2026-10-04 through 2036-10-01).
  /// Generated once with `openssl req -x509` and embedded so the TLS test
  /// needs no new dependencies and no network.
  const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
    MIIBvDCCAWOgAwIBAgIUImK99ANKJsyjtrs8BAozgQGrnj0wCgYIKoZIzj0EAwIw\n\
    FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwNDAzNTEwMloXDTM2MTAwMTAz\n\
    NTEwMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n\
    AQcDQgAE62U9JpY6jrYLcoAX+WJ8zGxDSWpK9pTbqKX+FT/TB1MKjmYcBgo4G/tV\n\
    lpNb4WjFVoMYsEAytUBTBRa3dT7Pw6OBkjCBjzAdBgNVHQ4EFgQUAVS9S+6tF+en\n\
    s4SwbomL4rPgYOwwHwYDVR0jBBgwFoAUAVS9S+6tF+ens4SwbomL4rPgYOwwGgYD\n\
    VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/\n\
    BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0cAMEQCIHbY\n\
    KXR+2+TuMzeYzh1C2GuxXuvSzdRIwwVnpAU/0rOqAiAOpeArygErayxHAl27s7R+\n\
    Re/ypkNPjDUTtjCyvGmVQg==\n\
    -----END CERTIFICATE-----\n";
  /// Private key matching [`TEST_CERT_PEM`] (test-only material).
  const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWaGpohPjJPYOs+92\n\
    Eyf8hawQCvdtD6tRjVXY0MlB/FihRANCAATrZT0mljqOtgtygBf5YnzMbENJakr2\n\
    lNuopf4VP9MHUwqOZhwGCjgb+1WWk1vhaMVWgxiwQDK1QFMFFrd1Ps/D\n\
    -----END PRIVATE KEY-----\n";
  /// Self-signed `CA:TRUE` fixture for the client-CA acceptance case.
  const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
    MIIBljCCAT2gAwIBAgIUHmpGGg0eZayO4xWoWQ4ARhsgUz8wCgYIKoZIzj0EAwIw\n\
    GTEXMBUGA1UEAwwOcm91dGVyLXRlc3QtY2EwHhcNMjYxMDA0MDM1MTA4WhcNMzYx\n\
    MDAxMDM1MTA4WjAZMRcwFQYDVQQDDA5yb3V0ZXItdGVzdC1jYTBZMBMGByqGSM49\n\
    AgEGCCqGSM49AwEHA0IABMj+xkhvvlk4LNRAEBMVoKUVa9UQDY3pdhEqkRBrs7Pm\n\
    NyAw9Nfws/OjuLSGzCZ8XFlhlQaTdM+Gs0uhFJ5owwSjYzBhMB0GA1UdDgQWBBTi\n\
    PrALL/zQO+Rmt6uLlA6Vmp7qxzAfBgNVHSMEGDAWgBTiPrALL/zQO+Rmt6uLlA6V\n\
    mp7qxzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQD\n\
    AgNHADBEAiBzZ5xiYL9YVq0KQrHTV47RuuX3S+lASyBdJO8pOo4HRgIgcTisWcyG\n\
    jDv1sqQJQfa/sEESxFLyAw9BYwH7hOGgZTg=\n\
    -----END CERTIFICATE-----\n";

  /// The limiter's fail-closed body marker (distinct from every `AppError`
  /// description, so the test can tell "limiter engaged" apart from
  /// "handler failed closed on its own").
  const LIMITER_MARKER: &str = "temporarily unable to handle the request";

  /// Shared raw fixture over a dead Postgres URL and the given Redis URL.
  fn config_fixture(
    redis_url: &str,
    rate_limit: serde_json::Value,
    cors_origins: Vec<&str>,
  ) -> serde_json::Value {
    serde_json::json!({
      "issuer": "https://auth.example.test",
      "environment": "development",
      "tls": {"cert_path": "/tmp/router-test-cert.pem", "key_path": "/tmp/router-test-key.pem"},
      "database": {"url": "postgres://127.0.0.1:1/router?sslmode=disable"},
      "redis": {"url": redis_url, "durability": "waitaof"},
      "token_pepper": "router-test-pepper-0123456789abcdef",
      "totp_encryption_key": "router-test-totp-key-0123456789abcdef",
      "pii_encryption_key": "router-test-pii-key-0123456789abcdef",
      "rate_limit": rate_limit,
      "cors_allowed_origins": cors_origins,
    })
  }

  /// Validated config over a dead Postgres URL and the given Redis URL.
  fn test_config(
    redis_url: &str,
    rate_limit: serde_json::Value,
    cors_origins: Vec<&str>,
  ) -> Result<Config, crate::config::ConfigError> {
    let fixture = config_fixture(redis_url, rate_limit, cors_origins);
    Config::from_source(::config::Config::try_from(&fixture)?)
  }

  /// 32-byte ASCII JWT signing keys (valid non-zero P-256 scalars).
  const JWT_TEST_KEY: &str = "bcdefghijklmnopqrstuvwxyzabcdefg";
  /// Rotated-out verify-only key, distinct from [`JWT_TEST_KEY`].
  const JWT_PREVIOUS_KEY: &str = "cdefghijklmnopqrstuvwxyzabcdefgh";

  /// Validated config with the JWT switch on and a current + retained key.
  fn jwt_config(redis_url: &str) -> Result<Config, crate::config::ConfigError> {
    let mut fixture = config_fixture(redis_url, serde_json::json!({"enabled": false}), Vec::new());
    fixture["jwt_access_tokens_enabled"] = serde_json::Value::Bool(true);
    fixture["jwt_signing_key"] = serde_json::Value::String(JWT_TEST_KEY.to_owned());
    fixture["jwt_signing_kid"] = serde_json::Value::String("v2".to_owned());
    fixture["jwt_signing_previous_keys"] = serde_json::json!([
      {"kid": "v1", "key": JWT_PREVIOUS_KEY}
    ]);
    Config::from_source(::config::Config::try_from(&fixture)?)
  }

  /// State with a lazy Postgres pool (never connected; short acquire
  /// budget so fail-closed paths return fast) and a Redis manager pointed
  /// at `redis_url`.
  fn lazy_state(config: Config, redis_url: &str) -> TestResult<AppState> {
    let pool = sqlx::postgres::PgPoolOptions::new()
      .max_connections(1)
      .acquire_timeout(Duration::from_millis(300))
      .connect_lazy("postgres://127.0.0.1:1/router")?;
    let client = redis::Client::open(redis_url)?;
    let manager = redis::aio::ConnectionManager::new_lazy_with_config(
      client,
      redis::aio::ConnectionManagerConfig::new()
        .set_number_of_retries(0)
        .set_response_timeout(Some(Duration::from_millis(200)))
        .set_connection_timeout(Some(Duration::from_millis(200))),
    )?;
    let keys = Arc::new(config.keys.clone());
    Ok(AppState {
      pool,
      redis: RedisConn::Single(manager),
      config: Arc::new(config),
      keys,
      transition_unsafe: Arc::new(std::sync::atomic::AtomicBool::new(false)),
      clock: Clock::system(),
    })
  }

  /// Router whose limiter passes through (disabled) and whose backends are
  /// dead: handlers fail closed, but every route is reachable.
  fn passthrough_state() -> TestResult<AppState> {
    let config = test_config(
      "redis://127.0.0.1:1",
      serde_json::json!({"enabled": false}),
      Vec::new(),
    )?;
    lazy_state(config, "redis://127.0.0.1:1")
  }

  /// Router whose limiter is engaged against a refused Redis port: every
  /// protected endpoint fails closed with the limiter's 503 marker.
  fn limited_state(cors_origins: Vec<&str>) -> TestResult<AppState> {
    let config = test_config(
      "redis://127.0.0.1:1",
      serde_json::json!({"enabled": true}),
      cors_origins,
    )?;
    lazy_state(config, "redis://127.0.0.1:1")
  }

  /// Router whose limiter is engaged but every budget is zero: a request
  /// WITH a peer identity passes through to its handler; a request WITHOUT
  /// one still fails closed at the peer check.
  fn zero_limit_state() -> TestResult<AppState> {
    let config = test_config(
      "redis://127.0.0.1:1",
      serde_json::json!({
        "enabled": true,
        "per_ip": 0,
        "per_client": 0,
        "login_per_ip": 0,
        "token_per_client": 0,
      }),
      Vec::new(),
    )?;
    lazy_state(config, "redis://127.0.0.1:1")
  }

  /// Drive one request through the router with both peer-identity extensions
  /// the stack reads (`ConnectInfo` for the limiter, `MockConnectInfo` for
  /// the `ConnectInfo` extractor).
  async fn drive(
    router: axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Body>,
  ) -> TestResult<(StatusCode, HeaderMap, String)> {
    let peer = SocketAddr::from(([127, 0, 0, 1], 40_001));
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
      builder = builder.header(*name, *value);
    }
    let mut request = builder.body(body.into())?;
    request
      .extensions_mut()
      .insert(axum::extract::ConnectInfo(peer));
    request.extensions_mut().insert(MockConnectInfo(peer));
    let response = router.oneshot(request).await.map_err(|_| "router error")?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
      .await?
      .to_bytes();
    Ok((
      status,
      response_headers,
      String::from_utf8_lossy(&bytes).into_owned(),
    ))
  }

  /// Every mounted route answers something other than 404.
  #[tokio::test]
  async fn router_routes_are_reachable() -> TestResult {
    let router = build_router(passthrough_state()?);
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let routes: &[Route<'_>] = &[
      ("GET", "/assets/app.css", &[]),
      ("GET", "/.well-known/oauth-authorization-server", &[]),
      ("GET", "/authorize?client_id=nobody", &[]),
      ("POST", "/par", &form),
      ("POST", "/token", &form),
      ("POST", "/device_authorization", &form),
      ("GET", "/device", &[]),
      ("POST", "/device", &form),
      ("GET", "/login", &[]),
      ("POST", "/login", &form),
      ("GET", "/login/success", &[]),
      ("GET", "/login/change-password", &[]),
      ("POST", "/login/change-password", &form),
      ("GET", "/login/totp/setup", &[]),
      ("GET", "/login/totp/confirm", &[]),
      ("POST", "/login/totp/confirm", &form),
      ("GET", "/logout", &[]),
      ("POST", "/logout", &[]),
      ("GET", "/consent", &[]),
      ("POST", "/consent", &form),
      ("POST", "/register", &form),
      ("GET", "/register/some-client", &[]),
      ("PUT", "/register/some-client", &form),
      ("DELETE", "/register/some-client", &[]),
      ("POST", "/introspect", &form),
      ("POST", "/revoke", &form),
      ("GET", "/health/live", &[]),
      ("GET", "/health/ready", &[]),
    ];
    for (method, uri, headers) in routes {
      let (status, _, _) = drive(router.clone(), method, uri, headers, "").await?;
      if status == StatusCode::NOT_FOUND {
        return Err(format!("route {method} {uri} is not mounted").into());
      }
    }
    // The liveness probe is dependency-free and always 200.
    let (status, _, _) = drive(router, "GET", "/health/live", &[], "").await?;
    if status != StatusCode::OK {
      return Err(format!("GET /health/live must be 200, got {status}").into());
    }
    Ok(())
  }

  /// Security headers ride on a dependency-free page response.
  #[tokio::test]
  async fn router_security_headers_present_on_page() -> TestResult {
    let (status, headers, _) = drive(
      build_router(passthrough_state()?),
      "GET",
      "/device",
      &[],
      "",
    )
    .await?;
    if status != StatusCode::OK {
      return Err(format!("GET /device must be 200, got {status}").into());
    }
    let value = |name: header::HeaderName| {
      headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
    };
    if value(header::X_CONTENT_TYPE_OPTIONS) != "nosniff" {
      return Err("X-Content-Type-Options: nosniff is required".into());
    }
    if value(header::REFERRER_POLICY) != "no-referrer" {
      return Err("Referrer-Policy: no-referrer is required".into());
    }
    let csp = value(header::CONTENT_SECURITY_POLICY);
    if !csp.contains("frame-ancestors 'none'") {
      return Err(format!("page CSP must deny framing, got {csp}").into());
    }
    if !csp.contains("script-src 'none'") {
      return Err(format!("page CSP must forbid scripts, got {csp}").into());
    }
    if !value(header::STRICT_TRANSPORT_SECURITY).starts_with("max-age=") {
      return Err("HSTS is required on the TLS public router".into());
    }
    if headers.get("x-request-id").is_none() {
      return Err("X-Request-Id must be echoed".into());
    }
    Ok(())
  }

  /// API responses get the locked-down CSP; error responses keep headers too.
  #[tokio::test]
  async fn router_security_headers_present_on_api_error() -> TestResult {
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let (_, headers, _) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/introspect",
      &form,
      "",
    )
    .await?;
    let csp = headers
      .get(header::CONTENT_SECURITY_POLICY)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if !csp.contains("default-src 'none'") || !csp.contains("frame-ancestors 'none'") {
      return Err(format!("API CSP must lock down the resource, got {csp}").into());
    }
    if headers.get("x-request-id").is_none() {
      return Err("X-Request-Id must be echoed on API errors".into());
    }
    Ok(())
  }

  /// The login error page (dead backends) still carries the strict page CSP.
  #[tokio::test]
  async fn router_login_page_carries_strict_script_policy() -> TestResult {
    let (_, headers, _) =
      drive(build_router(passthrough_state()?), "GET", "/login", &[], "").await?;
    let csp = headers
      .get(header::CONTENT_SECURITY_POLICY)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if !csp.contains("script-src 'none'") {
      return Err(format!("login CSP must forbid scripts, got {csp}").into());
    }
    Ok(())
  }

  /// Every credential- or authorization-bearing response forbids caching.
  #[tokio::test]
  async fn router_cache_control_no_store_on_oauth_surface() -> TestResult {
    let router = build_router(passthrough_state()?);
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let sensitive: &[Route<'_>] = &[
      ("GET", "/login", &[]),
      ("GET", "/consent", &[]),
      ("GET", "/device", &[]),
      ("GET", "/authorize?client_id=nobody", &[]),
      ("POST", "/token", &form),
      ("POST", "/par", &form),
      ("POST", "/device_authorization", &form),
    ];
    for (method, uri, headers) in sensitive {
      let (_, response_headers, _) = drive(router.clone(), method, uri, headers, "").await?;
      let value = response_headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
      if value != "no-store" {
        return Err(format!("{method} {uri} must be no-store, got {value:?}").into());
      }
    }
    Ok(())
  }

  /// Metadata discovery is cacheable by design: an explicit positive
  /// `Cache-Control`, not browser heuristic freshness.
  #[tokio::test]
  async fn router_metadata_carries_explicit_positive_cache_control() -> TestResult {
    let (_, headers, _) = drive(
      build_router(passthrough_state()?),
      "GET",
      "/.well-known/oauth-authorization-server",
      &[],
      "",
    )
    .await?;
    let value = headers
      .get(header::CACHE_CONTROL)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if !value.starts_with("public") || !value.contains("max-age=") {
      return Err(format!("metadata must carry a positive public max-age, got {value:?}").into());
    }
    if value.contains("no-store") {
      return Err(format!("metadata must stay cacheable, got {value:?}").into());
    }
    Ok(())
  }

  /// The JWK Set advertises the current key first, then every retained key,
  /// with public members only (RFC 7517 §4/§5, RFC 7518 §6.2.1, RFC 8037 §2).
  #[tokio::test]
  async fn jwks_serves_current_and_retained() -> TestResult {
    let redis_url = "redis://127.0.0.1:1";
    let router = build_router(lazy_state(jwt_config(redis_url)?, redis_url)?);
    let (status, headers, body) = drive(router, "GET", "/jwks.json", &[], "").await?;
    if status != StatusCode::OK {
      return Err(format!("GET /jwks.json must be 200, got {status}: {body}").into());
    }
    let content_type = headers
      .get(header::CONTENT_TYPE)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if !content_type.starts_with("application/jwk-set+json") {
      return Err(format!("JWK Set media type must be pinned, got {content_type:?}").into());
    }
    let document: serde_json::Value = serde_json::from_str(&body)?;
    let keys = document
      .get("keys")
      .and_then(serde_json::Value::as_array)
      .ok_or("JWK Set must carry a keys array")?;
    if keys.len() != 2 {
      return Err(format!("expected current + retained key, got {}", keys.len()).into());
    }
    let current_kid = keys[0].get("kid").and_then(serde_json::Value::as_str);
    let retained_kid = keys[1].get("kid").and_then(serde_json::Value::as_str);
    if current_kid != Some("v2") || retained_kid != Some("v1") {
      return Err(
        format!("current key must come first, got {current_kid:?} then {retained_kid:?}").into(),
      );
    }
    for key in keys {
      if key.get("use").and_then(serde_json::Value::as_str) != Some("sig") {
        return Err("every JWK must declare use=sig".into());
      }
      if key.get("alg").and_then(serde_json::Value::as_str) != Some("ES256") {
        return Err("every JWK must carry the configured algorithm".into());
      }
      if key.get("kty").and_then(serde_json::Value::as_str) != Some("EC") {
        return Err("ES256 JWKs must be kty=EC".into());
      }
      if key.get("crv").and_then(serde_json::Value::as_str) != Some("P-256") {
        return Err("ES256 JWKs must be crv=P-256".into());
      }
      for coordinate in ["x", "y"] {
        if key
          .get(coordinate)
          .and_then(serde_json::Value::as_str)
          .is_none_or(str::is_empty)
        {
          return Err(format!("EC JWK must carry a non-empty {coordinate}").into());
        }
      }
      for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if key.get(private).is_some() {
          return Err(format!("JWK must never carry private member {private}").into());
        }
      }
    }
    Ok(())
  }

  /// `/jwks.json` gets its own short cache window (rotation/revocation bound),
  /// distinct from the one-hour metadata value and from the no-store default.
  #[tokio::test]
  async fn jwks_cache_control_value() -> TestResult {
    let redis_url = "redis://127.0.0.1:1";
    let router = build_router(lazy_state(jwt_config(redis_url)?, redis_url)?);
    let (_, jwks_headers, _) = drive(router.clone(), "GET", "/jwks.json", &[], "").await?;
    let jwks_cache = jwks_headers
      .get(header::CACHE_CONTROL)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if jwks_cache != JWKS_CACHE_VALUE {
      return Err(format!("expected pinned {JWKS_CACHE_VALUE:?}, got {jwks_cache:?}").into());
    }
    if jwks_cache == "no-store" || jwks_cache == METADATA_CACHE_VALUE {
      return Err(format!("JWKS cache must be its own value, got {jwks_cache:?}").into());
    }
    let (_, metadata_headers, _) = drive(
      router,
      "GET",
      "/.well-known/oauth-authorization-server",
      &[],
      "",
    )
    .await?;
    let metadata_cache = metadata_headers
      .get(header::CACHE_CONTROL)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if metadata_cache != METADATA_CACHE_VALUE {
      return Err(
        format!("metadata cache must stay {METADATA_CACHE_VALUE:?}, got {metadata_cache:?}").into(),
      );
    }
    Ok(())
  }

  /// With the switch off the endpoint still exists deterministically: an
  /// empty JWK Set, never a 404 (which would be cached for the short window)
  /// and never a 500.
  #[tokio::test]
  async fn jwks_empty_when_feature_disabled() -> TestResult {
    let (status, _, body) = drive(
      build_router(passthrough_state()?),
      "GET",
      "/jwks.json",
      &[],
      "",
    )
    .await?;
    if status != StatusCode::OK {
      return Err(format!("feature-off JWKS must be 200, got {status}: {body}").into());
    }
    let document: serde_json::Value = serde_json::from_str(&body)?;
    let keys = document
      .get("keys")
      .and_then(serde_json::Value::as_array)
      .ok_or("JWK Set must carry a keys array")?;
    if !keys.is_empty() {
      return Err(format!("feature-off JWK Set must be empty, got {} keys", keys.len()).into());
    }
    Ok(())
  }

  /// HSTS is emitted only when the TLS option is on (never plaintext).
  #[tokio::test]
  async fn router_hsts_disabled_when_plaintext() -> TestResult {
    let options = RouterOptions {
      hsts: false,
      ..RouterOptions::default()
    };
    let (_, headers, _) = drive(
      build_router_with_options(passthrough_state()?, options),
      "GET",
      "/device",
      &[],
      "",
    )
    .await?;
    if headers.contains_key(header::STRICT_TRANSPORT_SECURITY) {
      return Err("plaintext router must not emit HSTS".into());
    }
    if headers.get(header::X_CONTENT_TYPE_OPTIONS).is_none() {
      return Err("other security headers must still apply".into());
    }
    Ok(())
  }

  /// The engaged limiter fails every classified OAuth route closed (503 +
  /// limiter marker); metadata and liveness pass through untouched.
  #[tokio::test]
  async fn router_rate_limit_engaged_on_every_oauth_route() -> TestResult {
    let router = build_router(limited_state(Vec::new())?);
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let protected: &[Route<'_>] = &[
      ("GET", "/authorize?client_id=nobody", &[]),
      ("POST", "/par", &form),
      ("POST", "/token", &form),
      ("POST", "/device_authorization", &form),
      ("GET", "/device", &[]),
      ("POST", "/device", &form),
      ("GET", "/login", &[]),
      ("POST", "/login", &form),
      ("GET", "/login/success", &[]),
      ("GET", "/login/change-password", &[]),
      ("GET", "/login/totp/setup", &[]),
      ("GET", "/login/totp/confirm", &[]),
      ("GET", "/logout", &[]),
      ("GET", "/consent", &[]),
      ("POST", "/consent", &form),
      ("POST", "/register", &form),
      ("GET", "/register/some-client", &[]),
      ("POST", "/introspect", &form),
      ("POST", "/revoke", &form),
    ];
    for (method, uri, headers) in protected {
      let (status, _, body) = drive(router.clone(), method, uri, headers, "").await?;
      if status != StatusCode::SERVICE_UNAVAILABLE || !body.contains(LIMITER_MARKER) {
        return Err(
          format!("route {method} {uri} must fail closed via the limiter, got {status}: {body}")
            .into(),
        );
      }
    }
    // Metadata has no limiter rule: it reaches its handler (which fails
    // closed on its own with a different body), proving the exemption.
    let (_, _, meta_body) = drive(
      router.clone(),
      "GET",
      "/.well-known/oauth-authorization-server",
      &[],
      "",
    )
    .await?;
    if meta_body.contains(LIMITER_MARKER) {
      return Err("metadata must not be limiter-gated".into());
    }
    // Liveness never touches the limiter or any backend.
    let (live_status, _, _) = drive(router, "GET", "/health/live", &[], "").await?;
    if live_status != StatusCode::OK {
      return Err(format!("GET /health/live must be 200, got {live_status}").into());
    }
    Ok(())
  }

  /// Short-circuit rejections (limiter, CORS preflight, body limit,
  /// resilience shed) return before any handler, so they must still carry
  /// the hardening headers: `Cache-Control: no-store` +
  /// `X-Content-Type-Options: nosniff`.
  fn assert_hardening_headers(headers: &HeaderMap) -> TestResult {
    let no_store = headers
      .get(header::CACHE_CONTROL)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if no_store != "no-store" {
      return Err(format!("short-circuit must be no-store, got {no_store:?}").into());
    }
    let nosniff = headers
      .get(header::X_CONTENT_TYPE_OPTIONS)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if nosniff != "nosniff" {
      return Err("short-circuit must carry X-Content-Type-Options: nosniff".into());
    }
    Ok(())
  }

  /// Limiter short-circuits (429 over budget, 503 fail-closed) must still
  /// carry the hardening headers: `Cache-Control: no-store` +
  /// `X-Content-Type-Options: nosniff`. Both `too_many_requests` and
  /// `service_unavailable` return before the inner security layer, so this
  /// drives the deterministic fail-closed 503 path (same bypass as 429).
  #[tokio::test]
  async fn router_limiter_short_circuit_carries_security_headers() -> TestResult {
    let form = [("content-type", "application/x-www-form-urlencoded")];
    let (_, headers, body) = drive(
      build_router(limited_state(Vec::new())?),
      "POST",
      "/token",
      &form,
      "",
    )
    .await?;
    if !body.contains(LIMITER_MARKER) {
      return Err("expected the limiter fail-closed marker".into());
    }
    assert_hardening_headers(&headers)
  }

  /// CORS preflights short-circuit at the CORS layer (outside the limiter),
  /// but inside the security-headers layer, so an allowlisted preflight must
  /// echo the origin and still carry the hardening headers.
  #[tokio::test]
  async fn router_cors_preflight_carries_security_headers() -> TestResult {
    let router = build_router(limited_state(vec!["https://app.example.test"])?);
    let preflight = [
      ("origin", "https://app.example.test"),
      ("access-control-request-method", "POST"),
    ];
    let (_, headers, _) = drive(router, "OPTIONS", "/token", &preflight, "").await?;
    let allowed = headers
      .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if allowed != "https://app.example.test" {
      return Err(format!("allowlisted origin must be echoed, got {allowed}").into());
    }
    assert_hardening_headers(&headers)
  }

  /// Body-limit 413s return before any handler, inside the security-headers
  /// layer, so an oversized body must be rejected with the hardening headers.
  #[tokio::test]
  async fn router_body_limit_413_carries_security_headers() -> TestResult {
    let options = RouterOptions {
      max_body_bytes: 8,
      ..RouterOptions::default()
    };
    let form = [
      ("content-type", "application/x-www-form-urlencoded"),
      ("content-length", "24"),
    ];
    let (status, headers, _) = drive(
      build_router_with_options(passthrough_state()?, options),
      "POST",
      "/token",
      &form,
      "body-exceeds-eight-bytes",
    )
    .await?;
    if status != StatusCode::PAYLOAD_TOO_LARGE {
      return Err(format!("oversized body must be 413, got {status}").into());
    }
    assert_hardening_headers(&headers)
  }

  /// Resilience sheds (timeout/overload 503) return before any handler,
  /// inside the security-headers layer, so a timed-out request must fail
  /// closed with the hardening headers.
  #[tokio::test]
  async fn router_resilience_timeout_carries_security_headers() -> TestResult {
    let hanging = axum::Router::new().route(
      "/hang",
      axum::routing::get(|| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        "never"
      }),
    );
    let router = hanging
      .layer(crate::resilience::ResilienceLayer::new(
        Duration::from_millis(1),
        1024,
      ))
      .layer(crate::middleware::security_headers::SecurityHeadersLayer::new(false));
    let (status, headers, _) = drive(router, "GET", "/hang", &[], "").await?;
    if status != StatusCode::SERVICE_UNAVAILABLE {
      return Err(format!("resilience timeout must fail closed 503, got {status}").into());
    }
    assert_hardening_headers(&headers)
  }

  /// Every mounted sensitive route is classified by `Rule::for_path`, and the
  /// exempt routes are not. The list mirrors the mount table in
  /// `build_router_with_options`; a newly mounted sensitive endpoint that is
  /// not classified fails here.
  #[test]
  fn router_every_sensitive_route_has_a_rate_limit_rule() -> TestResult {
    let config = test_config(
      "redis://127.0.0.1:1",
      serde_json::json!({"enabled": true}),
      Vec::new(),
    )?;
    for path in [
      "/authorize",
      "/par",
      "/token",
      "/device_authorization",
      "/device",
      "/login",
      "/login/success",
      "/login/change-password",
      "/login/totp/setup",
      "/login/totp/confirm",
      "/logout",
      "/consent",
      "/register",
      "/register/some-client",
      "/introspect",
      "/revoke",
    ] {
      if crate::middleware::ratelimit::Rule::for_path(&config.rate_limit, path).is_none() {
        return Err(format!("sensitive route {path} must have a rate-limit rule").into());
      }
    }
    for path in [
      "/.well-known/oauth-authorization-server",
      "/health/live",
      "/health/ready",
      "/assets/app.css",
    ] {
      if crate::middleware::ratelimit::Rule::for_path(&config.rate_limit, path).is_some() {
        return Err(format!("exempt route {path} must not have a rate-limit rule").into());
      }
    }
    Ok(())
  }

  /// CORS default: a browser `Origin` gets no CORS headers back.
  #[tokio::test]
  async fn router_cors_default_deny() -> TestResult {
    let origin = [("origin", "https://evil.test")];
    let (_, headers, _) = drive(
      build_router(limited_state(Vec::new())?),
      "POST",
      "/token",
      &origin,
      "",
    )
    .await?;
    if headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
      return Err("default router must not emit CORS headers".into());
    }
    let preflight = [
      ("origin", "https://evil.test"),
      ("access-control-request-method", "POST"),
    ];
    let (_, pre_headers, _) = drive(
      build_router(limited_state(Vec::new())?),
      "OPTIONS",
      "/token",
      &preflight,
      "",
    )
    .await?;
    if pre_headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
      return Err("default router must not answer CORS preflights".into());
    }
    Ok(())
  }

  /// An explicitly allowlisted origin is echoed on preflight and absent for
  /// unlisted origins.
  #[tokio::test]
  async fn router_cors_allowlist_permits_configured_origin() -> TestResult {
    let router = build_router(limited_state(vec!["https://app.example.test"])?);
    let preflight = [
      ("origin", "https://app.example.test"),
      ("access-control-request-method", "POST"),
    ];
    let (_, headers, _) = drive(router.clone(), "OPTIONS", "/token", &preflight, "").await?;
    let allowed = headers
      .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default();
    if allowed != "https://app.example.test" {
      return Err(format!("allowlisted origin must be echoed, got {allowed}").into());
    }
    let foreign = [
      ("origin", "https://evil.test"),
      ("access-control-request-method", "POST"),
    ];
    let (_, foreign_headers, _) = drive(router, "OPTIONS", "/token", &foreign, "").await?;
    if foreign_headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
      return Err("unlisted origins must not be echoed".into());
    }
    Ok(())
  }

  /// The wildcard is never honored: `*` alone means "no CORS layer".
  #[test]
  fn router_no_wildcard_cors() -> TestResult {
    if cors_layer(&["*".to_owned()]).is_some() {
      return Err("wildcard CORS must be refused".into());
    }
    if cors_layer(&[]).is_some() {
      return Err("empty allowlist must yield no CORS layer".into());
    }
    Ok(())
  }

  /// `GET /authorize` with a lossy-encoded query value (`%FF` is a valid
  /// URI but decodes to U+FFFD, never a parse failure) reaches downstream
  /// validation: with no `client_id` the 400 page renders, proving the
  /// `RawQuery` switch neither silently accepts nor parse-rejects
  /// misencoded input. (A query `&str` is always valid UTF-8 and
  /// percent-decoding is infallible, so the query layer has no
  /// encoding-failure path left.)
  #[tokio::test]
  async fn router_authorize_malformed_query_is_400() -> TestResult {
    let (status, _, body) = drive(
      build_router(passthrough_state()?),
      "GET",
      "/authorize?state=%FF",
      &[],
      "",
    )
    .await?;
    if status != StatusCode::BAD_REQUEST || !body.contains("invalid_request") {
      return Err(
        format!("lossy authorize query must be invalid_request 400, got {status}: {body}").into(),
      );
    }
    Ok(())
  }

  /// `POST /par` preserves the transport contract after the `RawForm`
  /// switch: a structurally unreadable body (raw non-UTF-8 bytes) is 400
  /// (deliberately stricter than the old `Form`, which lossily accepted raw
  /// non-UTF-8 bytes), a lossy-encoded body (`%FF` decodes to
  /// U+FFFD) reaches downstream validation (`invalid_client`: no
  /// credentials name a client), and a non-urlencoded body is 415.
  #[tokio::test]
  async fn router_par_transport_contract_preserved() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let (bad_status, _, bad_body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/par",
      &urlencoded,
      vec![0xFFu8],
    )
    .await?;
    if bad_status != StatusCode::BAD_REQUEST || !bad_body.contains("Failed to deserialize form") {
      return Err(format!("non-UTF-8 PAR body must be 400, got {bad_status}: {bad_body}").into());
    }
    let (lossy_status, _, lossy_body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/par",
      &urlencoded,
      "scope=%FF",
    )
    .await?;
    if lossy_status != StatusCode::BAD_REQUEST || !lossy_body.contains("invalid_client") {
      return Err(
        format!("lossy PAR body must be invalid_client 400, got {lossy_status}: {lossy_body}")
          .into(),
      );
    }
    let json = [("content-type", "application/json")];
    let (ctype_status, _, _) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/par",
      &json,
      "client_id=nobody",
    )
    .await?;
    if ctype_status != StatusCode::UNSUPPORTED_MEDIA_TYPE {
      return Err(format!("non-form PAR body must be 415, got {ctype_status}").into());
    }
    Ok(())
  }

  /// `POST /token` preserves the documented duplicate-parameter mapping
  /// after the `RawForm` switch: a repeated known field is `invalid_request`
  /// (RFC 6749 §5.2), and a non-urlencoded body is 415.
  #[tokio::test]
  async fn router_token_duplicate_param_preserved() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let (status, _, body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/token",
      &urlencoded,
      "grant_type=authorization_code&grant_type=refresh_token",
    )
    .await?;
    if status != StatusCode::BAD_REQUEST || !body.contains("invalid_request") {
      return Err(
        format!("duplicate token param must be invalid_request, got {status}: {body}").into(),
      );
    }
    let json = [("content-type", "application/json")];
    let (ctype_status, _, _) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/token",
      &json,
      "grant_type=refresh_token",
    )
    .await?;
    if ctype_status != StatusCode::UNSUPPORTED_MEDIA_TYPE {
      return Err(format!("non-form token body must be 415, got {ctype_status}").into());
    }
    Ok(())
  }

  /// `POST /introspect` and `POST /device_authorization` preserve the
  /// transport contract after the `RawForm` switch: a structurally
  /// unreadable body (raw non-UTF-8 bytes) is 400 plain text (deliberately
  /// stricter than the old `Form`, which lossily accepted raw non-UTF-8
  /// bytes), a lossy-encoded body (`%FF` decodes to U+FFFD) reaches
  /// downstream validation, and non-urlencoded bodies are 415. A repeated
  /// known field is JSON `invalid_request` (the old `Form` returned 422
  /// `Failed to deserialize form body`, so the new JSON 400 is the intended
  /// contract, not parity). The
  /// downstream expectation differs per path: introspect has no
  /// credentials, so `invalid_client` (401); device has an empty
  /// `client_id`, so `invalid_request` (400).
  #[tokio::test]
  async fn router_introspect_and_device_transport_contract_preserved() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let json = [("content-type", "application/json")];
    for path in ["/introspect", "/device_authorization"] {
      let (bad_status, _, bad_body) = drive(
        build_router(passthrough_state()?),
        "POST",
        path,
        &urlencoded,
        vec![0xFFu8],
      )
      .await?;
      if bad_status != StatusCode::BAD_REQUEST || !bad_body.contains("Failed to deserialize form") {
        return Err(
          format!("non-UTF-8 {path} body must be 400, got {bad_status}: {bad_body}").into(),
        );
      }
      let (lossy_body, expected_status, expected_code) = match path {
        "/introspect" => ("token=%FF", StatusCode::UNAUTHORIZED, "invalid_client"),
        _ => (
          "client_id=&scope=%FF",
          StatusCode::BAD_REQUEST,
          "invalid_request",
        ),
      };
      let (lossy_status, _, lossy_response) = drive(
        build_router(passthrough_state()?),
        "POST",
        path,
        &urlencoded,
        lossy_body,
      )
      .await?;
      if lossy_status != expected_status || !lossy_response.contains(expected_code) {
        return Err(
          format!(
            "lossy {path} body must be {expected_code}, got {lossy_status}: {lossy_response}"
          )
          .into(),
        );
      }
      let (ctype_status, _, _) = drive(
        build_router(passthrough_state()?),
        "POST",
        path,
        &json,
        "token=abc",
      )
      .await?;
      if ctype_status != StatusCode::UNSUPPORTED_MEDIA_TYPE {
        return Err(format!("non-form {path} body must be 415, got {ctype_status}").into());
      }
    }
    Ok(())
  }

  /// A repeated known field on `POST /introspect` is JSON `invalid_request`
  /// (RFC 6749 §5.2), never the old `Form` 422 `Failed to deserialize form
  /// body` and never plain text.
  #[tokio::test]
  async fn router_introspect_duplicate_param_is_json_invalid_request() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let (status, _, body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/introspect",
      &urlencoded,
      "token=abc&token=def",
    )
    .await?;
    if status != StatusCode::BAD_REQUEST || !body.contains("invalid_request") {
      return Err(
        format!("duplicate introspect param must be invalid_request 400, got {status}: {body}")
          .into(),
      );
    }
    if body.contains("Failed to deserialize form") {
      return Err("duplicate introspect param must be JSON, not the plain-text form error".into());
    }
    Ok(())
  }

  /// A repeated known field on `POST /device_authorization` is JSON
  /// `invalid_request` (RFC 6749 §5.2), never the old `Form` 422 `Failed to
  /// deserialize form body` and never plain text.
  #[tokio::test]
  async fn router_device_duplicate_param_is_json_invalid_request() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let (status, _, body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/device_authorization",
      &urlencoded,
      "client_id=nobody&client_id=somebody",
    )
    .await?;
    if status != StatusCode::BAD_REQUEST || !body.contains("invalid_request") {
      return Err(
        format!("duplicate device param must be invalid_request 400, got {status}: {body}").into(),
      );
    }
    if body.contains("Failed to deserialize form") {
      return Err("duplicate device param must be JSON, not the plain-text form error".into());
    }
    Ok(())
  }

  /// `POST /revoke` preserves the transport contract after the `RawForm`
  /// switch: a repeated known field is JSON `invalid_request`, a
  /// non-urlencoded body is 415, and a well-formed unauthenticated body
  /// still parses and reaches authentication (`invalid_client` 401),
  /// proving the field mapping survived the `Form<HashMap>` migration.
  #[tokio::test]
  async fn router_revoke_transport_contract_preserved() -> TestResult {
    let urlencoded = [("content-type", "application/x-www-form-urlencoded")];
    let (dup_status, _, dup_body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/revoke",
      &urlencoded,
      "token=abc&token=def",
    )
    .await?;
    if dup_status != StatusCode::BAD_REQUEST || !dup_body.contains("invalid_request") {
      return Err(
        format!("duplicate revoke param must be invalid_request 400, got {dup_status}: {dup_body}")
          .into(),
      );
    }
    if dup_body.contains("Failed to deserialize form") {
      return Err("duplicate revoke param must be JSON, not the plain-text form error".into());
    }
    let json = [("content-type", "application/json")];
    let (ctype_status, _, _) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/revoke",
      &json,
      "token=abc",
    )
    .await?;
    if ctype_status != StatusCode::UNSUPPORTED_MEDIA_TYPE {
      return Err(format!("non-form revoke body must be 415, got {ctype_status}").into());
    }
    let (auth_status, _, auth_body) = drive(
      build_router(passthrough_state()?),
      "POST",
      "/revoke",
      &urlencoded,
      "token=abc",
    )
    .await?;
    if auth_status != StatusCode::UNAUTHORIZED || !auth_body.contains("invalid_client") {
      return Err(
        format!("well-formed unauthenticated revoke must be invalid_client 401, got {auth_status}: {auth_body}")
          .into(),
      );
    }
    Ok(())
  }

  /// `GET /authorize` with no usable client never redirects with 307/308.
  #[tokio::test]
  async fn router_authorize_entry_never_307() -> TestResult {
    let (status, headers, _) = drive(
      build_router(passthrough_state()?),
      "GET",
      "/authorize?client_id=nobody",
      &[],
      "",
    )
    .await?;
    if status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::PERMANENT_REDIRECT {
      return Err(format!("authorize must never 307/308, got {status}").into());
    }
    if headers.contains_key(header::LOCATION)
      && (status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::PERMANENT_REDIRECT)
    {
      return Err("credential-carrying redirect must be 303, not 307".into());
    }
    Ok(())
  }

  /// A rate-protected route served over the production TLS accept loop
  /// reaches its handler (200) instead of failing closed with the limiter's
  /// 503: [`crate::tls::serve_tls`] must inject the peer address.
  #[tokio::test]
  async fn router_tls_listener_injects_peer_for_rate_limiting() -> TestResult {
    use rustls::pki_types::pem::PemObject as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let router = build_router(zero_limit_state()?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_config =
      build_server_config(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes(), None)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let server = tokio::spawn(crate::tls::serve_tls(listener, acceptor, router));

    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(TEST_CERT_PEM.as_bytes())
      .collect::<Result<Vec<_>, _>>()?;
    let Some(leaf) = chain.into_iter().next() else {
      return Err("test certificate must parse".into());
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(leaf)?;
    let client_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
    let mut tls = connector.connect(server_name, stream).await?;
    tls
      .write_all(b"GET /device HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
      .await?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    server.abort();

    let response = String::from_utf8_lossy(&raw);
    let status_line = response.lines().next().unwrap_or_default();
    if !status_line.contains("200") {
      return Err(format!("TLS /device must reach its handler, got: {status_line}").into());
    }
    if !response.contains("Enter the code shown on your device") {
      return Err("TLS /device must return the device page".into());
    }
    Ok(())
  }

  /// The server config completes a TLS handshake with the test certificate.
  #[tokio::test]
  async fn router_tls_handshake_with_test_cert() -> TestResult {
    use rustls::pki_types::pem::PemObject as _;
    let server_config =
      build_server_config(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes(), None)?;
    let chain = rustls::pki_types::CertificateDer::pem_slice_iter(TEST_CERT_PEM.as_bytes())
      .collect::<Result<Vec<_>, _>>()?;
    let Some(leaf) = chain.into_iter().next() else {
      return Err("test certificate must parse".into());
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(leaf)?;
    let client_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();
    let (client_io, server_io) = tokio::io::duplex(65_536);
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(server_config)).accept(server_io);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
    let client = connector.connect(server_name, client_io);
    let (server_out, client_out) = tokio::join!(server, client);
    if server_out.is_err() || client_out.is_err() {
      return Err(format!("server: {server_out:?} client: {client_out:?}").into());
    }
    Ok(())
  }

  /// Bad TLS material fails closed: garbage chain, key, or CA bundle.
  #[tokio::test]
  async fn router_tls_rejects_bad_material() -> TestResult {
    if build_server_config(b"not pem", TEST_KEY_PEM.as_bytes(), None).is_ok() {
      return Err("garbage chain must be rejected".into());
    }
    if build_server_config(TEST_CERT_PEM.as_bytes(), b"not pem", None).is_ok() {
      return Err("garbage key must be rejected".into());
    }
    if build_server_config(
      TEST_CERT_PEM.as_bytes(),
      TEST_KEY_PEM.as_bytes(),
      Some(b"not pem"),
    )
    .is_ok()
    {
      return Err("garbage client-CA bundle must be rejected".into());
    }
    // A `CA:TRUE` bundle is accepted as the client-CA trust input.
    if build_server_config(
      TEST_CERT_PEM.as_bytes(),
      TEST_KEY_PEM.as_bytes(),
      Some(TEST_CA_PEM.as_bytes()),
    )
    .is_err()
    {
      return Err("valid client-CA bundle must be accepted".into());
    }
    Ok(())
  }

  /// draft-ietf-oauth-v2-1-16 §1.5 + §7.14: the public listener pins a
  /// TLS 1.2 minimum explicitly (not rustls defaults). The pinned set is
  /// exactly TLS 1.2 + TLS 1.3, so nothing older can be negotiated.
  #[test]
  fn tls_version_minimum_is_tls12() -> TestResult {
    use rustls::ProtocolVersion;
    let versions: Vec<ProtocolVersion> = crate::protocol::mtls::TLS_PROTOCOL_VERSIONS
      .iter()
      .map(|supported| supported.version)
      .collect();
    if !versions.contains(&ProtocolVersion::TLSv1_2) {
      return Err("pinned TLS versions must include TLS 1.2".into());
    }
    if !versions.contains(&ProtocolVersion::TLSv1_3) {
      return Err("pinned TLS versions must include TLS 1.3".into());
    }
    for version in &versions {
      if *version != ProtocolVersion::TLSv1_2 && *version != ProtocolVersion::TLSv1_3 {
        return Err("no protocol version below TLS 1.2 may be enabled".into());
      }
    }
    Ok(())
  }

  /// The pinned server config accepts TLS 1.3-only and TLS 1.2-only
  /// clients, negotiating the offered version each time.
  #[tokio::test]
  async fn tls_version_accepts_tls12_and_tls13() -> TestResult {
    use rustls::ProtocolVersion;
    use rustls::pki_types::pem::PemObject as _;
    for (pinned, expected) in [
      (&rustls::version::TLS13, ProtocolVersion::TLSv1_3),
      (&rustls::version::TLS12, ProtocolVersion::TLSv1_2),
    ] {
      let server_config =
        build_server_config(TEST_CERT_PEM.as_bytes(), TEST_KEY_PEM.as_bytes(), None)?;
      let chain = rustls::pki_types::CertificateDer::pem_slice_iter(TEST_CERT_PEM.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
      let Some(leaf) = chain.into_iter().next() else {
        return Err("test certificate must parse".into());
      };
      let mut roots = rustls::RootCertStore::empty();
      roots.add(leaf)?;
      let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[pinned])
        .with_root_certificates(roots)
        .with_no_client_auth();
      let (client_io, server_io) = tokio::io::duplex(65_536);
      let server = tokio_rustls::TlsAcceptor::from(Arc::new(server_config)).accept(server_io);
      let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
      let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
      let client = connector.connect(server_name, client_io);
      let (server_out, client_out) = tokio::join!(server, client);
      let server_tls = server_out.map_err(|err| format!("server handshake failed: {err:?}"))?;
      client_out.map_err(|err| format!("client handshake failed: {err:?}"))?;
      if server_tls.get_ref().1.protocol_version() != Some(expected) {
        return Err(
          format!(
            "expected negotiated {expected:?}, got {:?}",
            server_tls.get_ref().1.protocol_version()
          )
          .into(),
        );
      }
    }
    Ok(())
  }
}

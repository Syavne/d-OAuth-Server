//! Router assembly: public listener routes plus the middleware chain.
//!
//! [`build_router`] mounts every endpoint behind one [`tower::ServiceBuilder`]
//! whose execution order is exactly {request-id → tracing/redaction →
//! rate-limit → body limit → security headers}:
//!
//! 1. [`middleware::request_id::RequestIdLayer`] mints/propagates
//!    `X-Request-Id` and opens the redacted `http_request` tracing span
//!    (tracing and redaction live in this layer).
//! 2. [`middleware::security_headers::cors_layer`] answers CORS preflights
//!    from the explicit allowlist before the limiter can bill them — mounted
//!    only when `cors_allowed_origins` is non-empty (default empty: no CORS
//!    headers, browser clients unsupported).
//! 3. [`middleware::ratelimit::RateLimitLayer`] enforces per-IP/per-client
//!    budgets on every endpoint except health and metadata (those paths have
//!    no rule and pass through to handlers that fail closed on their own).
//! 4. [`tower_http::limit::RequestBodyLimitLayer`] caps form bodies at
//!    [`MAX_BODY_BYTES`].
//! 5. [`middleware::security_headers::SecurityHeadersLayer`] decorates
//!    responses with `Referrer-Policy`, `X-Content-Type-Options`, a CSP with
//!    `frame-ancestors 'none'` (plus a strict script policy on the
//!    login/consent/device pages), and HSTS on the TLS listener. Every response
//!    except `/.well-known/…` metadata is also `Cache-Control: no-store`.
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Form;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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
use crate::protocol::{authorize, dcr, device, introspect, metadata, par, revoke, token};
use crate::resilience::{ResilienceConfig, ResilienceLayer};
use crate::state::{AppState, health_router};
use crate::store::pending::PendingAuth;
use crate::store::{Store, pending};
use crate::ui::device::DeviceForm;
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
  // Execution order outer-to-inner: load-shed → concurrency-limit → timeout →
  // rate-limit → body-limit → security-headers; the `.layer` calls below read
  // innermost-first.
  let resilience = ResilienceConfig::from_policy(&state.config.failure_policy);

  let router = axum::Router::new()
    .route("/assets/app.css", get(assets::stylesheet))
    .route(
      "/.well-known/oauth-authorization-server",
      get(metadata::metadata),
    )
    .route("/authorize", get(authorize_entry))
    .route("/par", post(par::par_handler))
    .route("/token", post(token::handler))
    .route("/device_authorization", post(device::handler))
    .route(
      "/device",
      get(device_page::get_device).post(post_device_entry),
    )
    .route("/login", get(login::get_login).post(login::post_login))
    .route("/login/success", get(login::get_login_success))
    .route(
      "/login/change-password",
      get(login::get_change_password).post(login::post_change_password),
    )
    .route("/login/totp/setup", get(login::get_totp_setup))
    .route(
      "/login/totp/confirm",
      get(login::get_totp_confirm).post(login::post_totp_confirm),
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
    .layer(SecurityHeadersLayer::new(options.hsts))
    .layer(RequestBodyLimitLayer::new(options.max_body_bytes))
    .layer(RateLimitLayer::new(state))
    .layer(ResilienceLayer::from_config(&resilience));

  let router = match cors {
    Some(layer) => router.layer(layer),
    None => router,
  };
  router.layer(RequestIdLayer)
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
  Query(query): Query<HashMap<String, String>>,
) -> Response {
  let mut conn = state.redis.clone();
  let store = Store::from_config(&state.config.redis);
  let input = authorize::AuthorizeInput {
    pool: &state.pool,
    keys: &state.keys,
    conn: &mut conn,
    store: &store,
    issuer: &state.config.issuer,
    query: &query,
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
  use crate::middleware::security_headers::cors_layer;
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

  /// Validated config over a dead Postgres URL and the given Redis URL.
  fn test_config(
    redis_url: &str,
    rate_limit: serde_json::Value,
    cors_origins: Vec<&str>,
  ) -> Result<Config, crate::config::ConfigError> {
    let fixture = serde_json::json!({
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
    });
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
    body: &str,
  ) -> TestResult<(StatusCode, HeaderMap, String)> {
    let peer = SocketAddr::from(([127, 0, 0, 1], 40_001));
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
      builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::from(body.to_owned()))?;
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
      if crate::middleware::ratelimit::Rule::for_path(config.rate_limit, path).is_none() {
        return Err(format!("sensitive route {path} must have a rate-limit rule").into());
      }
    }
    for path in [
      "/.well-known/oauth-authorization-server",
      "/health/live",
      "/health/ready",
      "/assets/app.css",
    ] {
      if crate::middleware::ratelimit::Rule::for_path(config.rate_limit, path).is_some() {
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
}

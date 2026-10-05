//! Shared E2E harness for the task-43 conformance + abuse suites.
//!
//! Every test boots the REAL production router ([`d_oauth::routes::build_router`],
//! unmodified) over a REAL loopback TCP socket, against REAL testcontainers
//! Postgres + Redis with the shipped migrations applied. Nothing is mocked;
//! every assertion reads an HTTP status/header/body observed through `reqwest`.
//!
//! TLS termination is intentionally NOT re-proven here: the task-41
//! `bootstrap` suite already drives mutual-TLS through the production accept
//! loop. The router under test is byte-identical on either listener.
//!
//! Coverage split (plan requirement): the `oauth2` crate builds PKCE material,
//! authorization URLs, and baseline token-request shapes; every extension
//! (DPoP proofs, PAR pushes, device flow, introspection, revocation) is
//! hand-rolled `reqwest` so the suite never depends on crate support the
//! extensions do not have.

use std::net::SocketAddr;

use d_oauth::{
  config::{Config, ConfigError},
  crypto::secret::{Argon2Params, hash_secret},
  db::{NewClient, TokenEndpointAuthMethod, client_repo, redirect_repo, scope_repo},
  protocol::token::{ClientKind, MintRequest, MintedTokens, SenderProof, TokenService},
  routes::build_router,
  state::{AppState, RedisConn, StateError},
  store::Store,
};
use testcontainers::{
  ContainerAsync, GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

/// RAII owner of one testcontainer with synchronous removal on drop.
///
/// Under nextest each test is its own process, so the fire-and-forget removal
/// that `testcontainers` schedules on `Drop` never runs and the container
/// leaks. This guard takes the container out of itself, removes it on a fresh
/// OS thread + fresh current-thread runtime, and joins — the same pattern as
/// the crate's `test_guard`, inlined here so this suite owns every item it
/// compiles (no shared-module dead code, no suppressions).
pub struct E2EGuard {
  /// The live container, `None` only while `Drop` is running.
  inner: Option<ContainerAsync<GenericImage>>,
}

impl E2EGuard {
  /// Take ownership of a started container.
  pub fn new(container: ContainerAsync<GenericImage>) -> Self {
    Self {
      inner: Some(container),
    }
  }

  /// Host port mapped from a container port.
  pub async fn get_host_port_ipv4(
    &self,
    port: u16,
  ) -> Result<u16, testcontainers::TestcontainersError> {
    // `inner` is `None` only inside `Drop` on this same value (which holds
    // `&mut self`), so every observable call sees `Some`; a missing value
    // reports the mapping error rather than panicking.
    match &self.inner {
      Some(container) => container.get_host_port_ipv4(port).await,
      None => Err(testcontainers::TestcontainersError::Other(
        "container guard is being dropped".into(),
      )),
    }
  }
}

impl Drop for E2EGuard {
  fn drop(&mut self) {
    if let Some(container) = self.inner.take() {
      let id = container.id().to_string();
      let thread_id = id.clone();
      let outcome = std::thread::spawn(move || match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
      {
        Ok(runtime) => {
          if let Err(error) = runtime.block_on(container.rm()) {
            eprintln!("e2e guard: failed to remove container {thread_id}: {error}");
          }
        }
        Err(error) => {
          eprintln!("e2e guard: failed to build removal runtime for {thread_id}: {error}");
        }
      })
      .join();
      if outcome.is_err() {
        eprintln!("e2e guard: removal thread failed for container {id}");
      }
    }
  }
}
/// Argon2id work factor for seeded client secrets (fast: test-only).
const SEED_MEM_KIB: u32 = 8;
/// Throwaway Postgres superuser password (alphanumeric: safe in URLs).
const PG_PASSWORD: &str = "e2etask43secret";

/// Harness failure (no `unwrap`/`expect`/`panic` under the deny lints).
#[derive(Debug, thiserror::Error)]
pub enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A Redis operation failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// An I/O operation failed.
  #[error("io error: {0}")]
  Io(#[from] std::io::Error),
  /// An HTTP operation failed.
  #[error("http error: {0}")]
  Http(#[from] reqwest::Error),
  /// Configuration failed to validate.
  #[error("config error: {0}")]
  Config(#[from] ConfigError),
  /// Application state failed to connect.
  #[error("state error: {0}")]
  State(#[from] StateError),
  /// A test step observed an unexpected value.
  #[error("failed: {0}")]
  Failed(String),
}

/// Fail one test step with a message.
pub fn fail(message: impl Into<String>) -> TestError {
  TestError::Failed(message.into())
}

/// Assert `cond`, failing the test with `message` otherwise.
pub fn ensure(cond: bool, message: impl Into<String>) -> Result<(), TestError> {
  if cond { Ok(()) } else { Err(fail(message)) }
}

/// Live world for one E2E test: guarded containers, migrated DB, connected
/// state, the production router on a loopback socket, and a redirect-free
/// `reqwest` client pointed at it.
pub struct World {
  /// Postgres container (guarded: synchronously removed on drop).
  _postgres: E2EGuard,
  /// Redis container (guarded: synchronously removed on drop).
  _redis: E2EGuard,
  /// Migrated Postgres pool (same database the router serves).
  pub pool: sqlx::PgPool,
  /// Connected application state (same state the router serves).
  pub state: AppState,
  /// Key layout + durability knobs matching the router's store.
  pub store: Store,
  /// Token minting primitive (setup only: issues fixture tokens).
  pub service: TokenService,
  /// Redirect-free HTTP client for observing exact statuses/locations.
  pub client: reqwest::Client,
  /// Base URL of the live router (e.g. `http://127.0.0.1:43111`).
  pub base: String,
  /// Serving task (aborted on drop so no test leaks a listener).
  _server: tokio::task::JoinHandle<()>,
}

impl Drop for World {
  fn drop(&mut self) {
    self._server.abort();
  }
}

impl World {
  /// Start one world: containers, migrations, connected state, live router.
  ///
  /// `rate_limit` is the `rate_limit` table of the config fixture, so the
  /// abuse suite can pin tiny budgets while conformance runs wide open.
  pub async fn start(rate_limit: serde_json::Value) -> Result<Self, TestError> {
    let (postgres, pg_url) = start_postgres().await?;
    let (redis, redis_url) = start_redis().await?;
    let pool = sqlx::PgPool::connect(&pg_url).await?;
    d_oauth::state::MIGRATOR
      .run(&pool)
      .await
      .map_err(|error| TestError::Failed(format!("migrations failed to apply: {error}")))?;

    let fixture = serde_json::json!({
      "issuer": "https://auth.example.test",
      "environment": "development",
      "bind_addr": "127.0.0.1:0",
      "health_addr": "127.0.0.1:0",
      "tls": {"cert_path": "/tmp/e2e-cert.pem", "key_path": "/tmp/e2e-key.pem"},
      "database": {"url": pg_url},
      "redis": {"url": redis_url, "durability": "waitaof"},
      "token_pepper": "e2e-test-pepper-0123456789abcdef",
      "totp_encryption_key": "e2e-test-totp-key-0123456789abcdef",
      "rate_limit": rate_limit,
      "cors_allowed_origins": [],
    });
    let config =
      Config::from_source(::config::Config::try_from(&fixture).map_err(ConfigError::from)?)?;
    let state = AppState::connect(std::sync::Arc::new(config)).await?;
    let store = Store::from_config(&state.config.redis);
    let service = TokenService::new(&state.config.ttl, &state.keys)
      .map_err(|error| fail(format!("token service failed: {error}")))?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let router = build_router(state.clone());
    let server = tokio::spawn(async move {
      let _ = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
      )
      .await;
    });
    let client = reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .timeout(std::time::Duration::from_secs(10))
      .build()?;
    Ok(Self {
      _postgres: postgres,
      _redis: redis,
      pool,
      state,
      store,
      service,
      client,
      base: format!("http://127.0.0.1:{port}"),
      _server: server,
    })
  }

  /// `POST {path}` with a form body, optional Basic auth, and extra headers.
  pub async fn post_form(
    &self,
    path: &str,
    params: &[(&str, &str)],
    basic: Option<(&str, &str)>,
    headers: &[(&str, &str)],
  ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String), TestError> {
    let mut request = self.client.post(format!("{}{path}", self.base));
    if let Some((user, pass)) = basic {
      request = request.basic_auth(user, Some(pass));
    }
    for (name, value) in headers {
      request = request.header(*name, *value);
    }
    let response = request.form(params).send().await?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response.text().await?;
    Ok((status, response_headers, body))
  }

  /// `GET {path}` with extra headers (query string included in `path`).
  pub async fn get(
    &self,
    path: &str,
    headers: &[(&str, &str)],
  ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String), TestError> {
    let mut request = self.client.get(format!("{}{path}", self.base));
    for (name, value) in headers {
      request = request.header(*name, *value);
    }
    let response = request.send().await?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response.text().await?;
    Ok((status, response_headers, body))
  }

  /// Mint a fixture token pair through the REAL [`TokenService`] (setup, not
  /// behavior: every assertion still reads an HTTP response).
  pub async fn mint(
    &self,
    client_id: &str,
    scope: &str,
    kind: ClientKind,
    jkt: Option<&str>,
  ) -> Result<MintedTokens, TestError> {
    let mut conn: RedisConn = self.state.redis.clone();
    let minted = self
      .service
      .mint(
        &mut conn,
        &self.store,
        &MintRequest {
          client_id: client_id.to_owned(),
          client_kind: kind,
          subject: "e2e-subject".to_owned(),
          scope: scope.to_owned(),
          grant_id: uuid::Uuid::new_v4().to_string(),
          proof: SenderProof {
            dpop_jkt: jkt.map(str::to_owned),
            mtls_x5t_s256: None,
          },
        },
        time::OffsetDateTime::now_utc().unix_timestamp(),
      )
      .await
      .map_err(|error| fail(format!("fixture mint failed: {error}")))?;
    Ok(minted)
  }
}

/// Start Postgres and return the guard plus a plaintext URL.
async fn start_postgres() -> Result<(E2EGuard, String), TestError> {
  let container = GenericImage::new("postgres", "latest")
    .with_exposed_port(5432.tcp())
    .with_wait_for(WaitFor::message_on_stderr(
      "database system is ready to accept connections",
    ))
    .with_wait_for(WaitFor::message_on_stdout(
      "database system is ready to accept connections",
    ))
    .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
    .start()
    .await?;
  let guarded = E2EGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  Ok((guarded, url))
}

/// Start a single-node Redis with AOF on (satisfies the durability contract).
async fn start_redis() -> Result<(E2EGuard, String), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = E2EGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Default (wide-open) rate-limit table for conformance worlds.
pub fn open_rate_limit() -> serde_json::Value {
  serde_json::json!({
    "enabled": true, "window_secs": 60,
    "per_ip": 100_000, "per_client": 100_000,
    "login_per_ip": 100_000, "token_per_client": 100_000,
  })
}

/// Seed one client row (secret hashed with the REAL Argon2id verifier path).
pub async fn seed_client(
  pool: &sqlx::PgPool,
  client_id: &str,
  secret: Option<&str>,
  grants: &[&str],
  scope: &str,
  method: TokenEndpointAuthMethod,
) -> Result<(), TestError> {
  seed_client_bound(pool, client_id, secret, grants, scope, method, false).await
}

/// Seed one client row with an explicit DPoP-bound-access-tokens flag.
pub async fn seed_client_bound(
  pool: &sqlx::PgPool,
  client_id: &str,
  secret: Option<&str>,
  grants: &[&str],
  scope: &str,
  method: TokenEndpointAuthMethod,
  dpop_bound: bool,
) -> Result<(), TestError> {
  let params =
    Argon2Params::new(SEED_MEM_KIB, 1, 1, 32).map_err(|error| fail(format!("argon2: {error}")))?;
  let secret_hash = secret
    .map(|value| hash_secret(value, &params))
    .transpose()
    .map_err(|error| fail(format!("hash: {error}")))?;
  let new = NewClient {
    id: uuid::Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: secret_hash,
    client_secret_expires_at: None,
    client_name: format!("{client_id} e2e"),
    grant_types: grants.iter().map(ToString::to_string).collect(),
    response_types: vec!["code".to_owned()],
    scope: scope.to_owned(),
    token_endpoint_auth_method: method.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: dpop_bound,
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, &new).await?;
  Ok(())
}

/// Seed one catalog scope (enabled).
pub async fn seed_scope(pool: &sqlx::PgPool, name: &str) -> Result<(), TestError> {
  scope_repo::upsert(pool, name, &format!("e2e scope {name}"))
    .await
    .map_err(|error| fail(format!("scope upsert failed: {error}")))?;
  Ok(())
}

/// Register a redirect URI in the catalog and attach it to a client.
pub async fn attach_redirect(
  pool: &sqlx::PgPool,
  client_id: &str,
  uri: &str,
) -> Result<(), TestError> {
  let row = redirect_repo::upsert(
    pool,
    uuid::Uuid::new_v4(),
    uri,
    redirect_repo::RedirectKind::Authorize,
    "e2e",
    None,
  )
  .await?;
  redirect_repo::attach(pool, client_id, row.id, None).await?;
  Ok(())
}

/// Decode a JSON body, failing the test on malformed content.
pub fn json_body(body: &str) -> Result<serde_json::Value, TestError> {
  serde_json::from_str(body).map_err(|error| fail(format!("body is not JSON ({error}): {body}")))
}

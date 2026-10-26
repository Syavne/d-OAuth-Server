//! Shared E2E harness for the task-43 conformance + abuse suites.
//!
//! Every test boots the REAL production router ([`d_oauth::routes::build_router`],
//! unmodified) over a REAL loopback TCP socket, against the REAL shared
//! Postgres + Redis from `compose.test.yaml`
//! (`docker compose -f compose.test.yaml up -d`) with the shipped migrations
//! applied. Nothing is mocked; every assertion reads an HTTP
//! status/header/body observed through `reqwest`.
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
//!
//! Isolation: each `World` migrates a freshly created database on the shared
//! server and uses unique Redis key prefixes, so parallel tests never share
//! state (and never FLUSH shared state).
//!
//! [`Store`]: d_oauth::store::Store

use std::net::SocketAddr;

use d_oauth::{
  config::{Config, ConfigError},
  crypto::secret::{Argon2Params, hash_secret},
  db::{
    NewClient, TokenEndpointAuthMethod, client_repo, redirect_repo, scope_repo,
    user_repo::{self, NewUser},
    user_scope_repo,
  },
  protocol::token::{
    ClientKind, MintRequest, MintedTokens, SenderProof, TokenFormat, TokenService,
  },
  routes::build_router,
  state::{AppState, RedisConn, StateError},
  store::Store,
};

// `tests/common/mod.rs` is the single definition of the shared-service
// helpers (`pg_server_url`, `redis_url`, `unique_prefixes`); this `#[path]`
// include (relative to `tests/e2e/`) keeps the e2e harness on the same
// contract without duplicating it.
#[path = "../common/mod.rs"]
mod common;

use common::{pg_server_url, redis_url, unique_prefixes};
use sqlx::{Executor as _, postgres::PgPoolOptions};

/// Placeholder guard kept so [`World`]'s shape is unchanged.
///
/// With shared external services there is no per-test container to guard;
/// per-World isolation comes from a fresh database plus unique Redis key
/// prefixes instead. The fields exist only so every existing caller keeps
/// compiling unchanged.
pub struct E2EGuard {
  /// Unused; present only to preserve the struct shape.
  _placeholder: (),
}

/// Argon2id work factor for seeded client secrets (fast: test-only).
const SEED_MEM_KIB: u32 = 8;

/// Hint shown when the shared test services are unreachable.
const COMPOSE_HINT: &str = "run `docker compose -f compose.test.yaml up -d`";

/// Harness failure (no `unwrap`/`expect`/`panic` under the deny lints).
#[derive(Debug, thiserror::Error)]
pub enum TestError {
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
  /// An application error escaped where success was required.
  #[error("app error: {0}")]
  App(#[from] d_oauth::error::AppError),
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

/// Live world for one E2E test: shared-service handles, migrated DB, connected
/// state, the production router on a loopback socket, and a redirect-free
/// `reqwest` client pointed at it.
pub struct World {
  /// Placeholder (no per-test container under shared services).
  _postgres: E2EGuard,
  /// Placeholder (no per-test container under shared services).
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
  /// Start one world with the default config fixture.
  ///
  /// `rate_limit` is the `rate_limit` table of the config fixture, so the
  /// abuse suite can pin tiny budgets while conformance runs wide open.
  pub async fn start(rate_limit: serde_json::Value) -> Result<Self, TestError> {
    Self::start_with(rate_limit, serde_json::json!({})).await
  }

  /// Start one world with top-level config keys overridden.
  ///
  /// Every key in `overrides` replaces the matching top-level member of the
  /// config fixture (for example `resource_indicators_enabled`), so a suite
  /// can exercise a feature gate without duplicating the fixture. An empty
  /// object is exactly [`World::start`].
  pub async fn start_with(
    rate_limit: serde_json::Value,
    overrides: serde_json::Value,
  ) -> Result<Self, TestError> {
    Self::start_with_cimd_fetcher(
      rate_limit,
      overrides,
      d_oauth::protocol::cimd::ssrf_fetcher(),
    )
    .await
  }

  /// Start one world with an injected CIMD document fetcher.
  ///
  /// The production router always carries `state.cimd_fetcher`; this entry
  /// point swaps it for a test stub (for example a counting fetcher) while
  /// leaving every other fixture member identical to [`World::start_with`].
  pub async fn start_with_cimd_fetcher(
    rate_limit: serde_json::Value,
    overrides: serde_json::Value,
    fetcher: d_oauth::protocol::cimd::CimdFetcher,
  ) -> Result<Self, TestError> {
    let pg_url = fresh_db_url().await?;
    let redis_url = redis_url();
    let (token_prefix, ratelimit_prefix) = unique_prefixes();
    let pool = PgPoolOptions::new()
      .max_connections(4)
      .connect(&pg_url)
      .await
      .map_err(|error| {
        fail(format!(
          "cannot reach shared test Postgres at {pg_url}: {error}; {COMPOSE_HINT}"
        ))
      })?;
    d_oauth::state::MIGRATOR
      .run(&pool)
      .await
      .map_err(|error| TestError::Failed(format!("migrations failed to apply: {error}")))?;

    let mut fixture = serde_json::json!({
      "issuer": "https://auth.example.test",
      "environment": "development",
      "bind_addr": "127.0.0.1:0",
      "health_addr": "127.0.0.1:0",
      "tls": {"cert_path": "/tmp/e2e-cert.pem", "key_path": "/tmp/e2e-key.pem"},
      "database": {
        "url": pg_url,
        "lock_timeout_secs": 5,
        "statement_timeout_secs": 15,
        "acquire_timeout_secs": 20,
      },
      "failure_policy": {"request_timeout_secs": 60},
      "redis": {
        "url": redis_url,
        "durability": "waitaof",
        "token_key_prefix": token_prefix,
        "ratelimit_key_prefix": ratelimit_prefix,
      },
      "token_pepper": "e2e-test-pepper-0123456789abcdef",
      "totp_encryption_key": "e2e-test-totp-key-0123456789abcdef",
      "pii_encryption_key": "e2e-test-pii-key-0123456789abcdef",
      "rate_limit": rate_limit,
      "cors_allowed_origins": [],
    });
    if let (Some(base), Some(extra)) = (fixture.as_object_mut(), overrides.as_object()) {
      for (key, value) in extra {
        base.insert(key.clone(), value.clone());
      }
    }
    let config =
      Config::from_source(::config::Config::try_from(&fixture).map_err(ConfigError::from)?)?;
    let mut state = AppState::connect(std::sync::Arc::new(config))
      .await
      .map_err(|error| {
        fail(format!(
          "cannot connect shared test services ({COMPOSE_HINT}): {error}"
        ))
      })?;
    state.cimd_fetcher = fetcher;
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
      _postgres: E2EGuard { _placeholder: () },
      _redis: E2EGuard { _placeholder: () },
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
    self
      .mint_for_subject(client_id, "e2e-subject", scope, kind, jkt)
      .await
  }

  /// Mint a fixture token pair for a caller-supplied `subject`.
  ///
  /// [`World::mint`] pins `subject: "e2e-subject"`; token-exchange setup needs
  /// a real account's EMAIL here, because entitlement resolution re-reads the
  /// user with `user_repo::find_by_email` and an id-shaped subject resolves no
  /// entitlements (fails closed).
  pub async fn mint_for_subject(
    &self,
    client_id: &str,
    subject: &str,
    scope: &str,
    kind: ClientKind,
    jkt: Option<&str>,
  ) -> Result<MintedTokens, TestError> {
    self
      .mint_pair(client_id, subject, scope, kind, jkt, &[])
      .await
  }

  /// Mint a fixture token pair pinned to one RFC 8707 audit resource.
  ///
  /// [`World::mint`] hardcodes empty audiences; stale-catalog suites need a
  /// grant whose access AND refresh records carry the audience under test, so
  /// a later disable is observable at refresh.
  // Only the stale-catalog suite mints an audience-pinned fixture pair.
  #[allow(dead_code)]
  pub async fn mint_with_aud(
    &self,
    client_id: &str,
    scope: &str,
    kind: ClientKind,
    jkt: Option<&str>,
    resource: &str,
  ) -> Result<MintedTokens, TestError> {
    self
      .mint_for_subject_with_aud(client_id, "e2e-subject", scope, kind, jkt, resource)
      .await
  }

  /// [`World::mint_for_subject`] with an audience pinned on both records.
  // Only the stale-catalog suite mints an audience-pinned fixture pair.
  #[allow(dead_code)]
  pub async fn mint_for_subject_with_aud(
    &self,
    client_id: &str,
    subject: &str,
    scope: &str,
    kind: ClientKind,
    jkt: Option<&str>,
    resource: &str,
  ) -> Result<MintedTokens, TestError> {
    self
      .mint_pair(client_id, subject, scope, kind, jkt, &[resource.to_owned()])
      .await
  }

  /// Shared fixture mint: the audience set feeds `aud` and `refresh_aud`.
  async fn mint_pair(
    &self,
    client_id: &str,
    subject: &str,
    scope: &str,
    kind: ClientKind,
    jkt: Option<&str>,
    aud: &[String],
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
          dpop_required: kind == ClientKind::Public,
          subject: subject.to_owned(),
          scope: scope.to_owned(),
          access_scope: scope.to_owned(),
          grant_id: uuid::Uuid::new_v4().to_string(),
          proof: SenderProof {
            dpop_jkt: jkt.map(str::to_owned),
            mtls_x5t_s256: None,
          },
          aud: aud.to_vec(),
          refresh_aud: aud.to_vec(),
          format: TokenFormat::Opaque,
        },
        time::OffsetDateTime::now_utc().unix_timestamp(),
      )
      .await
      .map_err(|error| fail(format!("fixture mint failed: {error}")))?;
    Ok(minted)
  }
}

/// Create a uniquely named database on the shared Postgres server and return
/// a URL pointing at it (the caller connects and migrates).
async fn fresh_db_url() -> Result<String, TestError> {
  let server = pg_server_url();
  let admin = PgPoolOptions::new()
    .max_connections(1)
    .connect(&server)
    .await
    .map_err(|error| {
      fail(format!(
        "cannot reach shared test Postgres at {server}: {error}; {COMPOSE_HINT}"
      ))
    })?;
  let name = format!("e2e_{}", uuid::Uuid::new_v4().simple());
  // `CREATE DATABASE` cannot take a bind parameter, and `Pool`'s `Executor`
  // requires a `'static` query, so leak this one tiny test-only string.
  let ddl: &'static str = Box::leak(format!("CREATE DATABASE \"{name}\"").into_boxed_str());
  let created = admin
    .execute(ddl)
    .await
    .map_err(|error| fail(format!("failed to create test database {name}: {error}")));
  admin.close().await;
  created?;
  Ok(server.replacen("/postgres?", &format!("/{name}?"), 1))
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
  keys: &d_oauth::keys::KeyRing,
  client_id: &str,
  secret: Option<&str>,
  grants: &[&str],
  scope: &str,
  method: TokenEndpointAuthMethod,
) -> Result<(), TestError> {
  seed_client_bound(
    pool,
    keys,
    client_id,
    secret,
    &SeedClientOpts {
      grants,
      scope,
      method,
      dpop_bound: false,
    },
  )
  .await
}

/// Registration options for one seeded client row.
pub struct SeedClientOpts<'a> {
  /// Registered grant types.
  pub grants: &'a [&'a str],
  /// Space-delimited default scope string.
  pub scope: &'a str,
  /// Registered token-endpoint authentication method.
  pub method: TokenEndpointAuthMethod,
  /// Whether the client registers DPoP-bound access tokens.
  pub dpop_bound: bool,
}

/// Seed one client row with an explicit DPoP-bound-access-tokens flag.
pub async fn seed_client_bound(
  pool: &sqlx::PgPool,
  keys: &d_oauth::keys::KeyRing,
  client_id: &str,
  secret: Option<&str>,
  opts: &SeedClientOpts<'_>,
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
    grant_types: opts.grants.iter().map(ToString::to_string).collect(),
    response_types: vec!["code".to_owned()],
    scope: opts.scope.to_owned(),
    token_endpoint_auth_method: opts.method.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: None,
    tls_client_auth_cert_thumbprint: None,
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: opts.dpop_bound,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(pool, keys, false, &new).await?;
  Ok(())
}

/// Seed one `tls_client_auth` client row with its registered subject DN and
/// certificate thumbprint.
///
/// [`seed_client`] always writes `None` into both mTLS columns, so a
/// `tls_client_auth` client needs this seam to enroll the CA-signed identity
/// the token endpoint matches under RFC 8705 §2. The row registers the
/// `client_credentials` grant and the `api:read` scope (the mTLS grant suite
/// enables that scope in the catalog).
// Only the mTLS grant suite seeds an mTLS-enrolled client.
#[allow(dead_code)]
pub async fn seed_mtls_client(
  world: &World,
  client_id: &str,
  dn: &str,
  thumbprint: &str,
) -> Result<(), TestError> {
  let new = NewClient {
    id: uuid::Uuid::new_v4(),
    client_id: client_id.to_owned(),
    client_secret_hash: None,
    client_secret_expires_at: None,
    client_name: format!("{client_id} e2e"),
    grant_types: vec!["client_credentials".to_owned()],
    response_types: vec!["code".to_owned()],
    scope: "api:read".to_owned(),
    token_endpoint_auth_method: TokenEndpointAuthMethod::TlsClientAuth.as_str().to_owned(),
    jwks: None,
    jwks_uri: None,
    tls_client_auth_subject_dn: Some(dn.to_owned()),
    tls_client_auth_cert_thumbprint: Some(thumbprint.to_owned()),
    request_uris: None,
    contacts: None,
    software_id: None,
    dpop_bound_access_tokens: false,
    access_token_format: "opaque".to_owned(),
    registration_access_token_hash: None,
  };
  client_repo::insert(&world.pool, &world.state.keys, false, &new).await?;
  Ok(())
}

/// Seed one catalog scope (enabled).
pub async fn seed_scope(pool: &sqlx::PgPool, name: &str) -> Result<(), TestError> {
  scope_repo::upsert(pool, name, &format!("e2e scope {name}"))
    .await
    .map_err(|error| fail(format!("scope upsert failed: {error}")))?;
  Ok(())
}

/// Provision one enabled user (known password + TOTP secret, entitled to
/// `scope`) through the REAL repository path, using the server's own Argon2
/// parameters so verification matches production exactly.
///
/// Returns the user id and the plaintext TOTP secret. A token minted on the
/// user's behalf must carry the EMAIL as its `subject`: the id is only for
/// seeding entitlements and asserting the account, never a token subject.
///
/// # Errors
///
/// Returns a hashing, repository, or TOTP-sealing failure.
// Only the token-exchange suite drives a user-bound subject token.
#[allow(dead_code)]
pub async fn seed_entitled_user(
  world: &World,
  email: &str,
  password: &str,
  scope: &str,
) -> Result<(uuid::Uuid, String), TestError> {
  let raw = &world.state.config.argon2;
  let params = Argon2Params::new(raw.memory_kib, raw.iterations, raw.parallelism, 32)
    .map_err(|error| fail(format!("argon2 params: {error}")))?;
  let hash =
    hash_secret(password, &params).map_err(|error| fail(format!("hash password: {error}")))?;
  let created = user_repo::create_user(
    &world.pool,
    &world.state.keys,
    world.state.config.pii_dual_write,
    &NewUser {
      email: email.to_owned(),
      password_hash: hash,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  let secret = d_oauth::crypto::totp::generate_secret()
    .map_err(|error| fail(format!("totp secret: {error}")))?;
  let blob = d_oauth::crypto::totp::encrypt_secret(
    &world.state.keys,
    &secret,
    !world.state.config.pii_dual_write,
  )
  .map_err(|error| fail(format!("totp seal: {error}")))?;
  ensure(
    user_repo::set_totp_secret(&world.pool, created.id, &blob).await?,
    "totp enroll must update the user row",
  )?;
  user_scope_repo::entitle(&world.pool, created.id, scope, None).await?;
  Ok((created.id, secret))
}

/// Register a redirect URI in the catalog and attach it to a client.
pub async fn attach_redirect(
  pool: &sqlx::PgPool,
  keys: &d_oauth::keys::KeyRing,
  client_id: &str,
  uri: &str,
) -> Result<(), TestError> {
  let (row, _) = redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: uuid::Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::Authorize,
      description: "e2e",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(pool, client_id, row.id, None).await?;
  Ok(())
}

/// Register a post-logout URI in the catalog and attach it to a client.
#[allow(dead_code)]
pub async fn attach_post_logout(
  pool: &sqlx::PgPool,
  keys: &d_oauth::keys::KeyRing,
  client_id: &str,
  uri: &str,
) -> Result<(), TestError> {
  let (row, _) = redirect_repo::upsert(
    pool,
    keys,
    false,
    &redirect_repo::NewRedirectUri {
      id: uuid::Uuid::new_v4(),
      uri,
      kind: redirect_repo::RedirectKind::PostLogout,
      description: "e2e",
      created_by: None,
    },
  )
  .await?;
  redirect_repo::attach(pool, client_id, row.id, None).await?;
  Ok(())
}

/// Decode a JSON body, failing the test on malformed content.
pub fn json_body(body: &str) -> Result<serde_json::Value, TestError> {
  serde_json::from_str(body).map_err(|error| fail(format!("body is not JSON ({error}): {body}")))
}

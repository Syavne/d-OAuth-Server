//! `test(bootstrap)` — real `serve` bootstrap over live containers (plan todo 41).
//!
//! Both tests boot the actual `d-oauth-server` binary (never an in-process
//! router): `config check` first (fail-fast env smoke), then `migrate` (the
//! only path that applies migrations — `serve` never does), then `serve`
//! with a TLS public listener (PKI client-CA, the mTLS reachability
//! contract) plus the plaintext pod-IP health listener.
//!
//! * `bootstrap_serve_tls_mtls_registered_completes_unregistered_rejected`:
//!   `/health/ready` is 200 beforehand, mutual-TLS traffic flows through
//!   the production accept loop, the presented leaf completes
//!   `mtls::authenticate_by_id` for the registered `tls_client_auth`
//!   client (the injected peer chain reaches `mtls.rs`), and an
//!   unregistered self-signed cert fails the handshake and the matcher.
//! * `bootstrap_serve_sigterm_drains_ready_and_exits_zero`: after SIGTERM,
//!   `/health/ready` flips to 503 inside the propagation grace and the
//!   process exits 0 with the listeners closed.
//!
//! Test names contain `bootstrap` so
//! `cargo nextest run -E 'test(bootstrap)'` selects exactly them. Bodies use
//! `Result` + `?` (`unwrap`/`expect`/`panic` are denied workspace-wide).

#[path = "mtls/certs.rs"]
// The fixture module is shared per-target with `test(mtls)`: this target
// uses a subset (`der_b64` belongs to the proxy-header suite), so the
// include carries a scoped, documented allow instead of restructuring a
// peer-owned file.
#[allow(dead_code)]
mod certs;

#[path = "../src/test_guard.rs"]
#[allow(dead_code)]
mod test_guard;

use std::{
  net::SocketAddr,
  path::PathBuf,
  process::Stdio,
  sync::Arc,
  time::{Duration, Instant},
};

use d_oauth::protocol::mtls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};

use test_guard::ContainerGuard;

/// Throwaway Postgres superuser password (alphanumeric: safe in URLs).
const PG_PASSWORD: &str = "bootstraptestsecret";
/// Registered `tls_client_auth` client for the mTLS test.
const CLIENT_ID: &str = "bootstrap-tls-client";
/// Subject DN of the CA-signed fixture, in [`mtls::subject_dn`] rendering.
const PKI_DN: &str = "CN=mtls-pki-client, O=Example";
/// `x5t#S256` of the CA-signed fixture (locked by `test(mtls)` too).
const PKI_THUMBPRINT: &str = "PC8ir71uIdRIdw1XFkMmoFvGC8Ud4CANxkk4x3BWqAc";

/// Test-body error.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// A testcontainers operation failed.
  #[error("container error: {0}")]
  Containers(#[from] testcontainers::TestcontainersError),
  /// A sqlx operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// An mTLS operation failed.
  #[error("mtls error: {0}")]
  Mtls(#[from] mtls::MtlsError),
  /// A fixture did not decode.
  #[error("fixture error: {0}")]
  Fixture(#[from] certs::FixtureError),
  /// A rustls operation failed.
  #[error("tls error: {0}")]
  Tls(#[from] rustls::Error),
  /// A DNS name was invalid.
  #[error("dns error: {0}")]
  Dns(#[from] rustls::pki_types::InvalidDnsNameError),
  /// A response was not UTF-8.
  #[error("encoding error: {0}")]
  Encoding(#[from] std::string::FromUtf8Error),
  /// An I/O operation failed.
  #[error("io error: {0}")]
  Io(#[from] std::io::Error),
  /// An async deadline elapsed.
  #[error("timeout: {0}")]
  Timeout(String),
  /// A socket address did not parse.
  #[error("address error: {0}")]
  Addr(#[from] std::net::AddrParseError),
  /// A test step failed.
  #[error("failed: {0}")]
  Failed(String),
}

type TestResult<T = ()> = Result<T, TestError>;

/// Live world for one test: guarded containers, ports, fixture files, and
/// the config file the child `serve` process boots from.
struct World {
  _postgres: ContainerGuard,
  _redis: ContainerGuard,
  pg_url: String,
  tls_port: u16,
  health_port: u16,
  config_path: String,
}

/// Locate the compiled server binary (cargo sets one of these spellings for
/// integration targets; otherwise resolve next to the test executable).
fn server_binary() -> Result<PathBuf, TestError> {
  for var in [
    "CARGO_BIN_EXE_d-oauth-server",
    "CARGO_BIN_EXE_d_oauth_server",
  ] {
    if let Ok(path) = std::env::var(var) {
      return Ok(PathBuf::from(path));
    }
  }
  let mut path = std::env::current_exe()?;
  if !path.pop() {
    return Err(TestError::Failed(
      "test executable has no parent".to_owned(),
    ));
  }
  if path.ends_with("deps") && !path.pop() {
    return Err(TestError::Failed("cannot leave deps dir".to_owned()));
  }
  path.push("d-oauth-server");
  Ok(path)
}

/// An unused loopback port (TOCTOU-tolerated: the child binds it right away).
async fn free_port() -> Result<u16, TestError> {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
  Ok(listener.local_addr()?.port())
}

/// Start Postgres and return the guard plus a plaintext URL.
async fn start_postgres() -> Result<(ContainerGuard, String), TestError> {
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
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(5432).await?;
  let url = format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
  Ok((guarded, url))
}

/// Start a single-node Redis with AOF on (satisfies the durability contract).
async fn start_redis() -> Result<(ContainerGuard, String), TestError> {
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  Ok((guarded, format!("redis://127.0.0.1:{port}")))
}

/// Build one test world: containers, ports, PEM fixture files, config file.
async fn build_world() -> Result<World, TestError> {
  let (postgres, pg_url) = start_postgres().await?;
  let (redis, redis_url) = start_redis().await?;
  let tls_port = free_port().await?;
  let health_port = free_port().await?;
  let dir = std::env::temp_dir().join(format!("bootstrap-test-{}", uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&dir)?;
  let cert_path = write_file(&dir, "server-cert.pem", certs::SERVER_CERT_PEM)?;
  let key_path = write_file(&dir, "server-key.pem", certs::SERVER_KEY_PEM)?;
  let ca_path = write_file(&dir, "client-ca.pem", certs::CA_CERT_PEM)?;
  // Layered env (`D_OAUTH_TLS__CERT_PATH`, …) does not reach nested tables,
  // so the child boots from a JSON file via `D_OAUTH_CONFIG` (the extension
  // is omitted: `File::with_name` probes supported formats).
  let config = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "bind_addr": format!("127.0.0.1:{tls_port}"),
    "health_addr": format!("0.0.0.0:{health_port}"),
    "tls": {
      "cert_path": path_string(&cert_path)?,
      "key_path": path_string(&key_path)?,
      "client_ca_path": path_string(&ca_path)?,
    },
    "database": {"url": pg_url.clone()},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "bootstrap-test-pepper-0123456789abcdef",
    "totp_encryption_key": "bootstrap-test-totp-key-0123456789abcdef",
  });
  let config_file = dir.join("d-oauth.json");
  std::fs::write(
    &config_file,
    serde_json::to_string_pretty(&config)
      .map_err(|error| TestError::Failed(format!("config JSON failed: {error}")))?,
  )?;
  let stem = config_file.with_extension("");
  Ok(World {
    _postgres: postgres,
    _redis: redis,
    pg_url,
    tls_port,
    health_port,
    config_path: path_string(&stem)?,
  })
}

/// Write one fixture file, returning its path.
fn write_file(dir: &std::path::Path, name: &str, contents: &str) -> Result<PathBuf, TestError> {
  let path = dir.join(name);
  std::fs::write(&path, contents)?;
  Ok(path)
}

/// A filesystem path as UTF-8 (temp dirs always are here).
fn path_string(path: &std::path::Path) -> Result<String, TestError> {
  path
    .to_str()
    .map(str::to_owned)
    .ok_or_else(|| TestError::Failed(format!("non-UTF-8 temp path: {}", path.display())))
}

/// A child command for the server binary with the world config applied.
fn child_command(world: &World, args: &[&str]) -> Result<tokio::process::Command, TestError> {
  let mut command = tokio::process::Command::new(server_binary()?);
  command
    .args(args)
    .env("D_OAUTH_CONFIG", &world.config_path)
    .stdin(Stdio::null());
  Ok(command)
}

/// Run a one-shot subcommand (`config check`, `migrate`) to completion.
async fn run_once(world: &World, args: &[&str]) -> Result<(), TestError> {
  let output = child_command(world, args)?
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .await?;
  if output.status.success() {
    return Ok(());
  }
  Err(TestError::Failed(format!(
    "{} failed: {} {}",
    args.join(" "),
    output.status,
    String::from_utf8_lossy(&output.stderr)
  )))
}

/// Spawn the long-lived `serve` child (killed with the test on drop).
fn spawn_serve(world: &World) -> Result<tokio::process::Child, TestError> {
  let mut child = child_command(world, &["serve"])?;
  child
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()
    .map_err(TestError::from)
}

/// Raw plaintext `GET` over TCP, returning `(status, body)`.
async fn http_get_plain(addr: SocketAddr, path: &str) -> Result<(u16, String), TestError> {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut stream =
    tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
      .await
      .map_err(|_| TestError::Timeout("health connect timed out".to_owned()))??;
  let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
  stream.write_all(request.as_bytes()).await?;
  let mut raw = Vec::new();
  stream.read_to_end(&mut raw).await?;
  parse_response(&raw)
}

/// Split a raw HTTP/1.1 response into `(status, body)`.
fn parse_response(raw: &[u8]) -> Result<(u16, String), TestError> {
  let text = String::from_utf8(raw.to_vec())?;
  let (head, body) = text
    .split_once("\r\n\r\n")
    .map_or((text.as_str(), ""), |(head, body)| (head, body));
  let line = head
    .lines()
    .next()
    .ok_or_else(|| TestError::Failed("empty HTTP response".to_owned()))?;
  let code = line
    .split_whitespace()
    .nth(1)
    .ok_or_else(|| TestError::Failed(format!("bad status line: {line}")))?;
  let status: u16 = code
    .parse()
    .map_err(|_| TestError::Failed(format!("bad status code: {code}")))?;
  Ok((status, body.to_owned()))
}

/// Health listener address (reachable via loopback; bound to the pod-IP wildcard).
fn health_addr(world: &World) -> Result<SocketAddr, TestError> {
  Ok(SocketAddr::from(([127, 0, 0, 1], world.health_port)))
}

/// Poll `/health/ready` until it answers 200 (fails fast if the child dies).
async fn poll_ready(world: &World, child: &mut tokio::process::Child) -> Result<(), TestError> {
  let addr = health_addr(world)?;
  let deadline = Instant::now() + Duration::from_secs(90);
  loop {
    if let Some(status) = child.try_wait()? {
      return Err(TestError::Failed(format!("serve exited early: {status}")));
    }
    match http_get_plain(addr, "/health/ready").await {
      Ok((200, _)) => return Ok(()),
      Ok(_) | Err(_) if Instant::now() < deadline => {}
      Ok((status, body)) => {
        return Err(TestError::Failed(format!(
          "ready never 200: {status} {body}"
        )));
      }
      Err(error) => {
        return Err(TestError::Failed(format!("ready never reachable: {error}")));
      }
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
  }
}

/// Poll `/health/ready` until it flips to 503 after SIGTERM.
async fn poll_not_ready(world: &World) -> Result<(), TestError> {
  let addr = health_addr(world)?;
  let deadline = Instant::now() + Duration::from_secs(20);
  loop {
    match http_get_plain(addr, "/health/ready").await {
      Ok((503, _)) => return Ok(()),
      Ok(_) | Err(_) if Instant::now() < deadline => {}
      Ok((status, body)) => {
        return Err(TestError::Failed(format!(
          "ready never flipped: {status} {body}"
        )));
      }
      Err(error) => {
        return Err(TestError::Failed(format!(
          "ready unreachable post-TERM: {error}"
        )));
      }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
}

/// Raw mutual-TLS `GET` through the production listener, returning `(status, body)`.
async fn tls_get(
  world: &World,
  client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
  path: &str,
) -> Result<(u16, String), TestError> {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certs::cert_der(certs::SERVER_CERT_PEM)?)?;
  let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
  let config = match client {
    Some((chain, key)) => builder.with_client_auth_cert(chain, key)?,
    None => builder.with_no_client_auth(),
  };
  let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
  let stream =
    tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], world.tls_port))).await?;
  let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
  let mut tls = connector.connect(server_name, stream).await?;
  let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
  tls.write_all(request.as_bytes()).await?;
  let mut raw = Vec::new();
  tls.read_to_end(&mut raw).await?;
  parse_response(&raw)
}

/// Whether a full mutual-TLS request with the given client identity is
/// rejected: no valid HTTP response is ever served for it.
///
/// The rejection may surface during the handshake or on the first request
/// (in TLS 1.3 the client can finish its flight before the server's alert
/// arrives), so this drives a complete `GET` and requires "not served".
async fn tls_request_rejected(
  world: &World,
  cert_pem: &str,
  key_pem: &str,
) -> Result<bool, TestError> {
  let attempt = tls_get(
    world,
    Some((
      vec![certs::cert_der(cert_pem)?],
      certs::private_key(key_pem)?,
    )),
    "/health/live",
  )
  .await;
  Ok(!matches!(attempt, Ok((200, _))))
}

/// Register one `tls_client_auth` client row (runtime query: no `.sqlx` cache).
async fn insert_tls_client(pool: &sqlx::PgPool) -> Result<(), TestError> {
  sqlx::query(
    "INSERT INTO oauth_clients (id, client_id, client_id_issued_at, client_name,
       grant_types, response_types, scope, token_endpoint_auth_method,
       tls_client_auth_subject_dn, tls_client_auth_cert_thumbprint,
       created_at, updated_at)
     VALUES ($1, $2, now(), 'Bootstrap Test',
       ARRAY['client_credentials'], ARRAY['token'], 'api:read',
       'tls_client_auth', $3, NULL, now(), now())",
  )
  .bind(uuid::Uuid::new_v4())
  .bind(CLIENT_ID)
  .bind(PKI_DN)
  .execute(pool)
  .await?;
  Ok(())
}

/// SIGTERM the child and wait for exit 0 (bounded well under the drain budget).
async fn terminate(mut child: tokio::process::Child) -> Result<(), TestError> {
  let pid = child
    .id()
    .ok_or_else(|| TestError::Failed("serve has no pid".to_owned()))?;
  let status = tokio::process::Command::new("kill")
    .args(["-TERM", &pid.to_string()])
    .status()
    .await?;
  if !status.success() {
    return Err(TestError::Failed("kill -TERM failed".to_owned()));
  }
  let exit = tokio::time::timeout(Duration::from_secs(45), child.wait())
    .await
    .map_err(|_| TestError::Timeout("serve did not exit after SIGTERM".to_owned()))??;
  if exit.success() {
    return Ok(());
  }
  Err(TestError::Failed(format!("serve exited dirty: {exit}")))
}

/// The real `serve` serves mutual-TLS traffic, the registered client
/// completes mTLS against `mtls.rs`, and the rogue cert is rejected.
#[tokio::test]
async fn bootstrap_serve_tls_mtls_registered_completes_unregistered_rejected() -> TestResult {
  let world = build_world().await?;
  run_once(&world, &["config", "check"]).await?;
  run_once(&world, &["migrate"]).await?;
  let pool = sqlx::PgPool::connect(&world.pg_url).await?;
  insert_tls_client(&pool).await?;
  let mut child = spawn_serve(&world)?;
  poll_ready(&world, &mut child).await?;

  let registered = Some((
    vec![certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?],
    certs::private_key(certs::CLIENT_PKI_KEY_PEM)?,
  ));
  let (status, body) = tls_get(&world, registered, "/health/live").await?;
  if status != 200 || !body.contains("live") {
    return Err(TestError::Failed(format!(
      "mTLS /health/live failed: {status} {body}"
    )));
  }
  let (status, _) = tls_get(
    &world,
    Some((
      vec![certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?],
      certs::private_key(certs::CLIENT_PKI_KEY_PEM)?,
    )),
    "/.well-known/oauth-authorization-server",
  )
  .await?;
  if status != 200 {
    return Err(TestError::Failed(format!("mTLS metadata failed: {status}")));
  }

  let leaf = certs::cert_der(certs::CLIENT_PKI_CERT_PEM)?;
  let cnf = mtls::authenticate_by_id(&pool, CLIENT_ID, Some(&leaf)).await?;
  if cnf.x5t_s256 != PKI_THUMBPRINT {
    return Err(TestError::Failed(format!(
      "unexpected cnf: {}",
      cnf.x5t_s256
    )));
  }

  if !tls_request_rejected(
    &world,
    certs::CLIENT_SELF_CERT_PEM,
    certs::CLIENT_SELF_KEY_PEM,
  )
  .await?
  {
    return Err(TestError::Failed(
      "unregistered self-signed cert was served".to_owned(),
    ));
  }
  let foreign = certs::cert_der(certs::CLIENT_ROGUE_CERT_PEM)?;
  if mtls::authenticate_by_id(&pool, CLIENT_ID, Some(&foreign))
    .await
    .is_ok()
  {
    return Err(TestError::Failed(
      "unregistered cert authenticated".to_owned(),
    ));
  }

  terminate(child).await
}

/// After SIGTERM, `/health/ready` flips to 503 and the process exits 0.
#[tokio::test]
async fn bootstrap_serve_sigterm_drains_ready_and_exits_zero() -> TestResult {
  let world = build_world().await?;
  run_once(&world, &["config", "check"]).await?;
  run_once(&world, &["migrate"]).await?;
  let mut child = spawn_serve(&world)?;
  poll_ready(&world, &mut child).await?;

  let pid = child
    .id()
    .ok_or_else(|| TestError::Failed("serve has no pid".to_owned()))?;
  let status = tokio::process::Command::new("kill")
    .args(["-TERM", &pid.to_string()])
    .status()
    .await?;
  if !status.success() {
    return Err(TestError::Failed("kill -TERM failed".to_owned()));
  }
  poll_not_ready(&world).await?;
  let exit = tokio::time::timeout(Duration::from_secs(45), child.wait())
    .await
    .map_err(|_| TestError::Timeout("serve did not exit after SIGTERM".to_owned()))??;
  if !exit.success() {
    return Err(TestError::Failed(format!("serve exited dirty: {exit}")));
  }
  // The listeners are closed: fresh connections are refused.
  if http_get_plain(health_addr(&world)?, "/health/live")
    .await
    .is_ok()
  {
    return Err(TestError::Failed(
      "health listener still open after exit".to_owned(),
    ));
  }
  Ok(())
}

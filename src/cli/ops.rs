//! Non-domain operator commands: `serve`, `migrate`, `config check`, `keygen`,
//! `healthcheck`, `initial-access-token`, and the `admin bootstrap` placeholder.

use std::{path::Path, sync::Arc, time::Duration};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

use super::context::{CliError, audit, open_pool};
use super::{KeyAlg, secret};
use crate::{
  config::{Config, ConfigError},
  state::{AppState, MIGRATOR},
};

/// Validate a loaded configuration, trimming the error into [`CliError`].
///
/// # Errors
/// Returns [`CliError::Config`] when `result` is an error.
pub fn ensure_config(result: Result<Config, ConfigError>) -> Result<Config, CliError> {
  result.map_err(CliError::from)
}

/// `config check`: validate configuration and exit non-zero when invalid.
///
/// # Errors
/// Returns [`CliError::Config`] when configuration is invalid.
pub fn config_check() -> Result<(), CliError> {
  let config = ensure_config(Config::load())?;
  println!("config ok: issuer={}", config.issuer);
  Ok(())
}

/// `migrate`: apply forward-only migrations under sqlx's advisory lock.
///
/// `sqlx::Migrator::run` takes a Postgres advisory lock for the duration, so
/// concurrent migration jobs serialize; a checksum mismatch or dirty migration
/// fails fast.
///
/// # Errors
/// Returns [`CliError`] for configuration, connection, or migration failures.
pub async fn migrate() -> Result<(), CliError> {
  let config = Arc::new(Config::load()?);
  let pool = open_pool(&config).await?;
  MIGRATOR.run(&pool).await?;
  audit("migrate", "schema");
  println!(
    "schema current: {} known migration(s)",
    MIGRATOR.migrations.len()
  );
  Ok(())
}

/// `serve`: load config, connect state, and run both listeners.
///
/// This NEVER migrates (the `migrate` subcommand owns that). The bootstrap
/// itself lives in [`crate::serve::run`]: TLS public listener via the custom
/// hyper-util/tokio-rustls accept loop plus the plaintext pod-IP health
/// listener, with SIGTERM drain semantics.
///
/// # Errors
/// Returns [`CliError`] for configuration, state, bind, or serve failures.
pub async fn serve() -> Result<(), CliError> {
  crate::serve::run().await
}

/// `keygen`: emit an ES256 keypair for test fixtures / client DPoP keys.
///
/// # Errors
/// Returns [`CliError::Crypto`] when key generation or serialization fails.
pub fn keygen(alg: KeyAlg) -> Result<(), CliError> {
  match alg {
    KeyAlg::Es256 => {
      let keypair = secret::generate_es256()?;
      let public_jwk: serde_json::Value = serde_json::from_str(&keypair.public_jwk)
        .map_err(|error| CliError::Crypto(error.to_string()))?;
      let output = serde_json::json!({
        "purpose": crate::keys::KEYGEN_PURPOSE,
        "alg": "ES256",
        "private_key_pem": keypair.private_key_pem,
        "public_jwk": public_jwk,
      });
      println!(
        "{}",
        serde_json::to_string_pretty(&output)
          .map_err(|error| CliError::Crypto(error.to_string()))?
      );
      Ok(())
    }
  }
}

/// `healthcheck`: probe `/health/live` over HTTP/loopback, exit 0 or 1.
///
/// A minimal container has no shell or curl, so this speaks raw HTTP/1.1 over
/// a TCP socket. Any connect/read failure or a non-200 status exits `1`.
///
/// # Errors
/// Returns [`CliError::Input`] only for an unparseable URL; connectivity
/// failures are reported as exit code `1`, not an error.
pub async fn healthcheck(url: &str) -> Result<i32, CliError> {
  let (host, port, path) = parse_health_url(url)?;
  let probe = async {
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok::<_, std::io::Error>(response)
  };
  let live = matches!(
    tokio::time::timeout(Duration::from_secs(2), probe).await,
    Ok(Ok(response)) if is_http_ok(&response)
  );
  Ok(if live { 0 } else { 1 })
}

/// `initial-access-token issue`: mint a token and store only its hash.
///
/// The raw token is held in [`Zeroizing`] and printed exactly once by the
/// caller; Redis stores the keyed hash plus the bounded-use record and TTL.
///
/// # Errors
/// Returns [`CliError`] for invalid budgets, config/state failures, or a store
/// write failure.
pub async fn issue_initial_access_token(
  uses: u64,
  ttl_secs: u64,
  label: &str,
) -> Result<Zeroizing<String>, CliError> {
  let config = Arc::new(Config::load()?);
  issue_with(config, uses, ttl_secs, label).await
}

/// Mint and store an initial-access token against an injected configuration.
///
/// # Errors
/// Returns [`CliError`] for invalid budgets, state failures, or a store write
/// failure.
pub async fn issue_with(
  config: Arc<Config>,
  uses: u64,
  ttl_secs: u64,
  label: &str,
) -> Result<Zeroizing<String>, CliError> {
  if uses == 0 {
    return Err(CliError::Input("--uses must be at least 1".to_owned()));
  }
  if ttl_secs == 0 {
    return Err(CliError::Input(
      "--ttl must be at least 1 second".to_owned(),
    ));
  }
  let state = AppState::connect(config.clone()).await?;
  let token = Zeroizing::new(crate::crypto::tokens::mint_token()?);
  let hash = secret::token_hash(&config, token.as_str())?;
  let store = crate::store::Store::from_config(&config.redis);
  let mut conn = state.redis.clone();
  let record = crate::store::dcr::InitialAccessRecord {
    uses_remaining: uses,
    label: label.to_owned(),
  };
  crate::store::dcr::issue(
    &mut conn,
    &store,
    &hash,
    &record,
    Duration::from_secs(ttl_secs),
  )
  .await?;
  audit("initial_access_token.issue", label);
  Ok(token)
}

/// `admin bootstrap`: create the first admin, refusing while one exists.
///
/// The password comes from `--password-file`, from stdin, or — when neither
/// yields a value — a generated 256-bit password printed exactly once, and
/// only to a TTY (a non-TTY stdout with a generated password is an error, so
/// the secret can never leak into Job logs). Nothing here accepts a password
/// via argv and nothing logs one.
///
/// # Errors
/// Returns [`CliError`] for configuration, connection, input, refusal, or
/// database failures.
pub async fn admin_bootstrap(
  email: &str,
  password_file: Option<&Path>,
  force: bool,
) -> Result<(), CliError> {
  use std::io::IsTerminal as _;
  let config = Arc::new(Config::load()?);
  let pool = open_pool(&config).await?;
  let password = super::admin::resolve_password(password_file)?;
  if matches!(password, super::admin::BootstrapPassword::Generate)
    && !std::io::stdout().is_terminal()
  {
    return Err(CliError::Input(
      "no password supplied and stdout is not a TTY: re-run attached to a \
       terminal or supply --password-file so the generated secret is shown \
       once and never logged"
        .to_owned(),
    ));
  }
  let outcome = super::admin::bootstrap(&config, &pool, email, password, force).await?;
  println!("bootstrapped admin {} (id {})", outcome.email, outcome.id);
  if let Some(generated) = outcome.generated_password {
    println!(
      "generated one-time bootstrap password (shown once): {}",
      generated.as_str()
    );
  }
  println!("first login must change the password and enroll TOTP before full access");
  Ok(())
}

fn is_http_ok(response: &[u8]) -> bool {
  let head = String::from_utf8_lossy(response);
  head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
}

fn parse_health_url(url: &str) -> Result<(String, u16, String), CliError> {
  let rest = url
    .strip_prefix("http://")
    .or_else(|| url.strip_prefix("https://"))
    .ok_or_else(|| CliError::Input(format!("unsupported health url: {url}")))?;
  let (authority, path) = match rest.split_once('/') {
    Some((authority, path)) => (authority, format!("/{path}")),
    None => (rest, "/health/live".to_owned()),
  };
  let (host, port) = match authority.rsplit_once(':') {
    Some((host, port)) if !host.is_empty() => (
      host.to_owned(),
      port
        .parse::<u16>()
        .map_err(|_| CliError::Input(format!("invalid port in health url: {url}")))?,
    ),
    _ => (authority.to_owned(), 80),
  };
  if host.is_empty() {
    return Err(CliError::Input(format!(
      "missing host in health url: {url}"
    )));
  }
  Ok((host, port, path))
}

//! `test(cli_user_disable)` — the real `user disable` CLI purges the account's
//! Redis token state before flipping `users.disabled` (plan todo 12).
//!
//! The test drives the shipped `d-oauth-server` binary as a child process
//! (`user disable --email <email>` with `D_OAUTH_CONFIG` pointing at a JSON
//! file generated from the live [`World`]'s validated config). No shell is
//! involved and no production code is modified.
//!
//! Setup mints a token pair through the REAL [`d_oauth::protocol::token::TokenService`]
//! with the seeded user's **id** as its `subject`, because `purge_subject`
//! matches the stored record subject against the user id (the CLI passes
//! `record.id.to_string()`); [`World::mint`] hardcodes `e2e-subject` and would
//! leave the token behind.
//!
//! Assertions:
//! * the seeded user starts enabled and both token keys are live;
//! * the child exits 0;
//! * both the access and refresh Redis keys are gone (the purge ran);
//! * `users.disabled` is true only after that purge (exit-0 path).

#[allow(dead_code)]
#[path = "e2e/harness.rs"]
mod harness;

use std::path::PathBuf;

use d_oauth::{
  config::RedisTopology,
  protocol::token::{ClientKind, MintRequest, SenderProof, TokenFormat},
  state::RedisConn,
};
use harness::{TestError, World, ensure, fail, open_rate_limit, seed_entitled_user, seed_scope};
use secrecy::ExposeSecret as _;

/// Seeded account email (canonical form the CLI resolves).
const EMAIL: &str = "cli-disable@example.test";
/// Seeded account password (never printed; the CLI path does not use it).
const PASSWORD: &str = "correct-horse-28-cli-disable";
/// Catalog scope the seeded account is entitled to.
const SCOPE: &str = "cli:disable:read";
/// Fixture client id the token pair is minted for.
const CLIENT_ID: &str = "cli-disable-client";

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
    return Err(fail("test executable has no parent"));
  }
  if path.ends_with("deps") && !path.pop() {
    return Err(fail("cannot leave deps dir"));
  }
  path.push("d-oauth-server");
  Ok(path)
}

/// Temp directory holding the generated config; removed on drop so the
/// secret-bearing file never outlives the test.
struct TempConfig {
  /// Directory created for this test (removed recursively on drop).
  dir: PathBuf,
}

impl Drop for TempConfig {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.dir);
  }
}

/// Write a JSON config carrying the SAME validated values as `world`
/// (database URL, Redis URL from the single-node topology, both key prefixes,
/// issuer, and the active key ring), returning the guard plus the path stem.
///
/// The extension is omitted from the returned path because `Config::load`
/// resolves `D_OAUTH_CONFIG` through `File::with_name`, which probes supported
/// formats (`tests/bootstrap.rs` uses the same pattern).
fn write_config(world: &World) -> Result<(TempConfig, String), TestError> {
  write_config_with_redis(world, None)
}

/// Like [`write_config`], but an explicit Redis URL overrides the world's, so
/// the fail-closed test can point the CLI at an unavailable server.
fn write_config_with_redis(
  world: &World,
  redis_override: Option<&str>,
) -> Result<(TempConfig, String), TestError> {
  let config = &world.state.config;
  let redis_url = match redis_override {
    Some(url) => url.to_owned(),
    None => match &config.redis.topology {
      RedisTopology::Single { url } => url.expose_secret().to_owned(),
      _ => {
        return Err(fail(
          "CLI config fixture requires the single-node Redis topology",
        ));
      }
    },
  };
  let (pepper_id, pepper) = config
    .keys
    .active_pepper()
    .ok_or_else(|| fail("active token pepper is missing"))?;
  let (totp_id, totp) = config
    .keys
    .active_totp_key()
    .ok_or_else(|| fail("active TOTP key is missing"))?;
  let (pii_id, pii) = config
    .keys
    .active_pii_key()
    .ok_or_else(|| fail("active PII key is missing"))?;

  let fixture = serde_json::json!({
    "issuer": config.issuer,
    "environment": "development",
    "bind_addr": "127.0.0.1:0",
    "health_addr": "127.0.0.1:0",
    "tls": {"cert_path": "/tmp/e2e-cert.pem", "key_path": "/tmp/e2e-key.pem"},
    "database": {"url": config.database.url.expose_secret()},
    "redis": {
      "url": redis_url,
      "durability": "waitaof",
      "token_key_prefix": config.redis.token_key_prefix,
      "ratelimit_key_prefix": config.redis.ratelimit_key_prefix,
    },
    "token_pepper": pepper.expose_secret(),
    "token_pepper_id": pepper_id.as_str(),
    "totp_encryption_key": totp.expose_secret(),
    "totp_key_id": totp_id.as_str(),
    "pii_encryption_key": pii.expose_secret(),
    "pii_key_id": pii_id.as_str(),
    "pii_dual_write": config.pii_dual_write,
    "rate_limit": open_rate_limit(),
  });

  let dir = std::env::temp_dir().join(format!("cli-disable-{}", uuid::Uuid::new_v4()));
  std::fs::create_dir_all(&dir)?;
  let file = dir.join("d-oauth.json");
  std::fs::write(
    &file,
    serde_json::to_vec(&fixture).map_err(|error| fail(format!("config JSON failed: {error}")))?,
  )?;
  // The fixture carries live key material; keep it owner-only on disk.
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
  }
  let stem = file.with_extension("");
  let path = stem
    .to_str()
    .map(str::to_owned)
    .ok_or_else(|| fail(format!("non-UTF-8 temp path: {}", stem.display())))?;
  Ok((TempConfig { dir }, path))
}

/// Whether one Redis key still exists.
async fn key_exists(conn: &mut RedisConn, key: &str) -> Result<bool, TestError> {
  let count: i64 = redis::cmd("EXISTS").arg(key).query_async(conn).await?;
  Ok(count > 0)
}

/// Read the Postgres `users.disabled` flag for one user.
async fn user_disabled(world: &World, user_id: uuid::Uuid) -> Result<bool, TestError> {
  let disabled: bool = sqlx::query_scalar("SELECT disabled FROM users WHERE id = $1")
    .bind(user_id)
    .fetch_one(&world.pool)
    .await?;
  Ok(disabled)
}

/// Mint one opaque pair whose subject is the seeded user's id, so the CLI's
/// `purge_subject(email, user_id)` sweep matches it.
async fn mint_subject_pair(
  world: &World,
  conn: &mut RedisConn,
  user_id: uuid::Uuid,
) -> Result<(String, String), TestError> {
  let minted = world
    .service
    .mint(
      conn,
      &world.store,
      &MintRequest {
        client_id: CLIENT_ID.to_owned(),
        client_kind: ClientKind::Confidential,
        dpop_required: false,
        subject: user_id.to_string(),
        scope: SCOPE.to_owned(),
        access_scope: SCOPE.to_owned(),
        grant_id: uuid::Uuid::new_v4().to_string(),
        proof: SenderProof {
          dpop_jkt: None,
          mtls_x5t_s256: None,
        },
        aud: Vec::new(),
        refresh_aud: Vec::new(),
        format: TokenFormat::Opaque,
      },
      time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(|error| fail(format!("fixture mint failed: {error}")))?;
  Ok((minted.access_hash, minted.refresh_hash))
}

/// The real CLI purges the user's Redis tokens, then flips `users.disabled`.
#[tokio::test]
async fn cli_user_disable_purges_redis_and_flips_the_flag() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_scope(&world.pool, SCOPE).await?;
  let (user_id, _totp_secret) = seed_entitled_user(&world, EMAIL, PASSWORD, SCOPE).await?;

  let mut conn = world.state.redis.clone();
  let (access_hash, refresh_hash) = mint_subject_pair(&world, &mut conn, user_id).await?;

  let access_key = world.store.access_key(&access_hash);
  let refresh_key = world.store.refresh_key(&refresh_hash);
  ensure(
    key_exists(&mut conn, &access_key).await?,
    "seeded access token must be live before disable",
  )?;
  ensure(
    key_exists(&mut conn, &refresh_key).await?,
    "seeded refresh token must be live before disable",
  )?;
  ensure(
    !user_disabled(&world, user_id).await?,
    "seeded user must start enabled",
  )?;

  let (_config_guard, config_path) = write_config(&world)?;
  let output = tokio::process::Command::new(server_binary()?)
    .args(["user", "disable", "--email", EMAIL])
    .env("D_OAUTH_CONFIG", &config_path)
    .output()
    .await?;
  ensure(
    output.status.success(),
    format!(
      "user disable must exit 0: {} {}",
      output.status,
      String::from_utf8_lossy(&output.stderr)
    ),
  )?;

  ensure(
    !key_exists(&mut conn, &access_key).await?,
    "the purge must delete the access-token key",
  )?;
  ensure(
    !key_exists(&mut conn, &refresh_key).await?,
    "the purge must delete the refresh-token key",
  )?;
  ensure(
    user_disabled(&world, user_id).await?,
    "users.disabled must be true after the purge (exit-0 path)",
  )?;
  Ok(())
}

/// A Redis outage during the purge must leave the account enabled and the
/// tokens live: the flag flips only after a successful purge.
#[tokio::test]
async fn cli_user_disable_fails_closed_when_redis_is_down() -> Result<(), TestError> {
  let world = World::start(open_rate_limit()).await?;
  seed_scope(&world.pool, SCOPE).await?;
  let (user_id, _totp_secret) = seed_entitled_user(&world, EMAIL, PASSWORD, SCOPE).await?;

  let mut conn = world.state.redis.clone();
  let (access_hash, refresh_hash) = mint_subject_pair(&world, &mut conn, user_id).await?;
  let access_key = world.store.access_key(&access_hash);
  let refresh_key = world.store.refresh_key(&refresh_hash);

  let (_config_guard, config_path) = write_config_with_redis(&world, Some("redis://127.0.0.1:1"))?;
  let output = tokio::process::Command::new(server_binary()?)
    .args(["user", "disable", "--email", EMAIL])
    .env("D_OAUTH_CONFIG", &config_path)
    .output()
    .await?;
  ensure(
    !output.status.success(),
    format!(
      "a Redis outage must fail the CLI: {} {}",
      output.status,
      String::from_utf8_lossy(&output.stderr)
    ),
  )?;

  ensure(
    !user_disabled(&world, user_id).await?,
    "a failed purge must leave users.disabled false",
  )?;
  ensure(
    key_exists(&mut conn, &access_key).await?,
    "a failed purge must leave the access token live",
  )?;
  ensure(
    key_exists(&mut conn, &refresh_key).await?,
    "a failed purge must leave the refresh token live",
  )?;
  Ok(())
}

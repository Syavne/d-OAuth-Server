//! `test(cli)` suite: config validation, user provisioning, token issuance,
//! TOTP encryption, scope grants, idempotent config sync, and audit emission.

use std::sync::Arc;

use base64::Engine as _;
use clap::Parser as _;
use testcontainers::{
  GenericImage, ImageExt,
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
};
use time::OffsetDateTime;

use super::{
  Cli, ScopeCommand, admin, ops, scope, secret,
  sync::{RedirectEntry, ScopeEntry, SyncFile},
  test_support::{self, TestError},
  user,
};
use crate::{
  config::Config,
  crypto::totp,
  db::user_repo,
  state::{AppState, RedisConn},
  ui::login::{
    CHANGE_PASSWORD_PATH, ConfirmOutcome, LoginAttempt, LoginDeps, LoginOutcome, PasswordOutcome,
    attempt_login, change_password, confirm_totp, ensure_presession, load_session,
    login_csrf_token, provision_totp, restricted_allows_path,
  },
};

/// Fresh migrated database plus a fast-argon2 config for bootstrap tests.
///
/// Each test owns its database (via the shared Postgres server), so parallel
/// bootstrap tests stay isolated and every test starts with zero admins.
/// The config's database URL is a dummy: bootstrap and login cores take the
/// pool directly and only read hashing/key/TTL settings from the config.
async fn bootstrap_setup(
  redis_url: &str,
) -> Result<
  (
    crate::test_guard::Lease<crate::db::test_support::Db>,
    sqlx::PgPool,
    Arc<Config>,
  ),
  TestError,
> {
  let (db, pool) = crate::db::test_support::migrated_pool()
    .await
    .map_err(|error| TestError::Harness(error.to_string()))?;
  let fixture = serde_json::json!({
    "issuer": "https://auth.example.test",
    "environment": "development",
    "tls": {"cert_path": "/tmp/bootstrap-test-cert.pem", "key_path": "/tmp/bootstrap-test-key.pem"},
    "database": {"url": "postgres://127.0.0.1:1/bootstrap"},
    "redis": {"url": redis_url, "durability": "waitaof"},
    "token_pepper": "bootstrap-test-pepper-0123456789abcdef",
    "totp_encryption_key": "bootstrap-test-totp-key-0123456789abcdef",
    "argon2": {"memory_kib": 8192, "iterations": 1, "parallelism": 1},
  });
  let source = ::config::Config::try_from(&fixture)?;
  let config = Arc::new(Config::from_source(source)?);
  Ok((db, pool, config))
}

const PASSWORD: &str = "correct-horse-battery-staple";

#[test]
fn cli_config_check_exits_nonzero_on_bad_config() {
  let result = ops::ensure_config(Err(crate::config::ConfigError::MissingIssuer));
  assert!(result.is_err());
}

#[tokio::test]
async fn cli_user_create_inserts_user() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("create");
  user::create(&context, &email, true, PASSWORD).await?;

  let (admin, must_change, hash): (bool, bool, String) = sqlx::query_as(
    "SELECT is_admin, must_change_password, password_hash
       FROM users WHERE email = $1::citext",
  )
  .bind(&email)
  .fetch_one(context.pool())
  .await?;

  assert!(admin);
  assert!(must_change);
  assert!(hash.starts_with("$argon2id$"));
  assert!(!hash.contains(PASSWORD));
  Ok(())
}

#[tokio::test]
async fn cli_user_create_duplicate_email_fails() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("duplicate");
  user::create(&context, &email, false, PASSWORD).await?;
  let upper = email.to_uppercase();
  let second = user::create(&context, &upper, false, PASSWORD).await;
  assert!(matches!(
    second,
    Err(super::context::CliError::AlreadyExists(_))
  ));
  Ok(())
}

#[tokio::test]
async fn cli_initial_access_token_stores_only_hash() -> Result<(), TestError> {
  let harness = test_support::harness().await?;
  let token = ops::issue_with(harness.config.clone(), 3, 600, "cli-test").await?;
  let hash = secret::token_hash(&harness.config, &token)?;
  assert_ne!(hash, token);

  let store = crate::store::Store::from_config(&harness.config.redis);
  let mut conn = AppState::connect(harness.config.clone())
    .await?
    .redis
    .clone();

  let key = store.dcr_iat_key(&hash);
  let present: i64 = redis::cmd("EXISTS")
    .arg(&key)
    .query_async(&mut conn)
    .await?;
  assert_eq!(present, 1);

  let raw_key = store.dcr_iat_key(&token);
  let raw_present: i64 = redis::cmd("EXISTS")
    .arg(&raw_key)
    .query_async(&mut conn)
    .await?;
  assert_eq!(raw_present, 0);

  let fields: Vec<String> = redis::cmd("HGETALL")
    .arg(&key)
    .query_async(&mut conn)
    .await?;
  assert!(fields.iter().all(|field| !field.contains(&token)));
  Ok(())
}

#[tokio::test]
async fn cli_user_enroll_totp_stores_encrypted_secret() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("totp");
  user::create(&context, &email, false, PASSWORD).await?;

  let enrollment = user::enroll_totp(&context, &email).await?;
  let (blob, enabled): (Option<Vec<u8>>, bool) =
    sqlx::query_as("SELECT totp_secret_enc, totp_enabled FROM users WHERE email = $1::citext")
      .bind(&email)
      .fetch_one(context.pool())
      .await?;

  let blob = blob.ok_or(TestError::Missing("totp_secret_enc"))?;
  assert!(enabled);
  assert!(!blob.is_empty());
  assert!(
    !blob
      .windows(enrollment.secret.len())
      .any(|window| window == enrollment.secret.as_bytes()),
    "plaintext TOTP secret found in stored blob"
  );
  let decrypted = secret::decrypt_totp(context.config(), &blob)?;
  assert_eq!(decrypted, enrollment.secret);
  assert!(enrollment.uri.starts_with("otpauth://totp/"));
  Ok(())
}

#[tokio::test]
async fn cli_scope_create_and_grant_take_effect() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let email = test_support::unique_email("grant");
  let scope_name = test_support::unique_name("orders:read");
  user::create(&context, &email, false, PASSWORD).await?;

  scope::run(
    &context,
    ScopeCommand::Create {
      name: scope_name.clone(),
      description: Some("read orders".to_owned()),
    },
  )
  .await?;
  user::grant_scope(&context, &email, &scope_name).await?;

  let scopes = user::list_scopes(&context, &email).await?;
  assert_eq!(scopes, vec![scope_name.clone()]);

  user::revoke_scope(&context, &email, &scope_name).await?;
  assert!(user::list_scopes(&context, &email).await?.is_empty());
  Ok(())
}

#[tokio::test]
async fn cli_config_sync_is_idempotent() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let scope_name = test_support::unique_name("sync");
  let uri = format!("https://{}.example.test/cb", uuid::Uuid::new_v4());
  let file = SyncFile {
    scopes: vec![ScopeEntry {
      name: scope_name.clone(),
      description: Some("synced".to_owned()),
      enabled: true,
    }],
    redirect_uris: vec![RedirectEntry {
      uri: uri.clone(),
      kind: "authorize".to_owned(),
      description: None,
      enabled: true,
    }],
    user_scopes: Vec::new(),
    client_redirect_uris: Vec::new(),
  };

  let first = super::sync::apply(&context, &file).await?;
  assert_eq!(first.scopes_created, 1);
  assert_eq!(first.redirects_created, 1);

  let before: OffsetDateTime = sqlx::query_scalar("SELECT updated_at FROM scopes WHERE name = $1")
    .bind(&scope_name)
    .fetch_one(context.pool())
    .await?;

  let second = super::sync::apply(&context, &file).await?;
  assert!(second.is_noop(), "second sync changed rows: {second}");

  let after: OffsetDateTime = sqlx::query_scalar("SELECT updated_at FROM scopes WHERE name = $1")
    .bind(&scope_name)
    .fetch_one(context.pool())
    .await?;
  assert_eq!(before, after, "idempotent sync must not touch updated_at");
  Ok(())
}

#[tokio::test]
async fn cli_mutations_emit_audit_events() -> Result<(), TestError> {
  let (_harness, context) = test_support::context().await?;
  let scope_name = test_support::unique_name("audit");
  let capture = test_support::install_capture()?;

  scope::run(
    &context,
    ScopeCommand::Create {
      name: scope_name.clone(),
      description: None,
    },
  )
  .await?;
  drop(capture.guard);

  let log = test_support::captured(&capture.buffer);
  assert!(log.contains("cli.mutation"), "missing audit event: {log}");
  assert!(log.contains("scope.create"), "missing operation: {log}");
  assert!(log.contains(&scope_name), "missing subject: {log}");
  Ok(())
}

#[test]
fn cli_keygen_es256_emits_pem() -> Result<(), TestError> {
  let keypair = secret::generate_es256()?;
  assert!(keypair.private_key_pem.contains("BEGIN PRIVATE KEY"));
  let jwk: serde_json::Value = serde_json::from_str(&keypair.public_jwk)?;
  assert_eq!(jwk["kty"], "EC");
  assert_eq!(jwk["crv"], "P-256");
  assert_eq!(jwk["alg"], "ES256");
  Ok(())
}

#[tokio::test]
async fn cli_healthcheck_exits_one_when_unreachable() -> Result<(), TestError> {
  let code = ops::healthcheck("http://127.0.0.1:1/health/live").await?;
  assert_eq!(code, 1);
  Ok(())
}

// ---------------------------------------------------------------------------
// `test(admin_bootstrap)` suite (task 47)
// ---------------------------------------------------------------------------

const BOOTSTRAP_PASSWORD: &str = "bootstrap-correct-horse-01";

#[tokio::test]
async fn admin_bootstrap_creates_first_admin_must_change() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let email = test_support::unique_email("bootstrap");
  let capture = test_support::install_capture()?;

  let outcome = admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
    false,
  )
  .await?;
  drop(capture.guard);

  assert_eq!(outcome.email, email.to_lowercase());
  assert!(outcome.generated_password.is_none());

  let row: (bool, bool, bool, Option<OffsetDateTime>) = sqlx::query_as(
    "SELECT is_admin, must_change_password, totp_enabled, password_changed_at
       FROM users WHERE email = $1::citext",
  )
  .bind(&email)
  .fetch_one(&pool)
  .await?;
  assert!(row.0, "bootstrap must create an admin");
  assert!(row.1, "bootstrap must force a password change");
  assert!(!row.2, "bootstrap must not enable TOTP");
  assert!(
    row.3.is_none(),
    "password_changed_at stays NULL until rotation"
  );

  let verdict = user_repo::verify_password(&pool, &email, BOOTSTRAP_PASSWORD).await?;
  assert_eq!(verdict, user_repo::PasswordVerdict::Matched);
  assert!(user_repo::has_any_admin(&pool).await?);

  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.created"),
    "missing audit: {log}"
  );
  assert!(log.contains("admin.count.changed"), "missing audit: {log}");
  assert!(
    !log.contains(BOOTSTRAP_PASSWORD),
    "password leaked into logs"
  );
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_concurrent_creates_exactly_one() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let prefix = uuid::Uuid::new_v4().simple().to_string();

  let mut handles = Vec::new();
  for index in 0..8 {
    let pool = pool.clone();
    let config = config.clone();
    let email = format!("racer-{index}-{prefix}@example.test");
    handles.push(tokio::spawn(async move {
      admin::bootstrap(
        &config,
        &pool,
        &email,
        admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
        false,
      )
      .await
      .map(|outcome| outcome.email)
    }));
  }
  let mut created = 0;
  let mut refused = 0;
  for handle in handles {
    match handle
      .await
      .map_err(|error| TestError::Harness(error.to_string()))?
    {
      Ok(_) => created += 1,
      Err(super::context::CliError::AlreadyExists(_)) => refused += 1,
      Err(error) => return Err(TestError::Cli(error)),
    }
  }
  assert_eq!(created, 1, "exactly one racer must win");
  assert_eq!(refused, 7, "every loser must refuse");

  let admins: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
      .fetch_one(&pool)
      .await?;
  assert_eq!(admins, 1, "the advisory lock must serialize bootstrap");
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_second_refuses_and_force_is_audited() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let first = test_support::unique_email("bootstrap-first");
  let second = test_support::unique_email("bootstrap-second");

  admin::bootstrap(
    &config,
    &pool,
    &first,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
    false,
  )
  .await?;

  let capture = test_support::install_capture()?;
  let refused = admin::bootstrap(
    &config,
    &pool,
    &second,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
    false,
  )
  .await;
  drop(capture.guard);
  assert!(
    matches!(refused, Err(super::context::CliError::AlreadyExists(_))),
    "a second bootstrap must refuse"
  );
  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.refused"),
    "missing audit: {log}"
  );
  assert!(
    !log.contains(BOOTSTRAP_PASSWORD),
    "password leaked into logs"
  );

  let capture = test_support::install_capture()?;
  admin::bootstrap(
    &config,
    &pool,
    &second,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
    true,
  )
  .await?;
  drop(capture.guard);
  let log = test_support::captured(&capture.buffer);
  assert!(
    log.contains("admin.bootstrap.force"),
    "missing audit: {log}"
  );

  let admins: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT disabled")
      .fetch_one(&pool)
      .await?;
  assert_eq!(admins, 2, "--force creates the second admin explicitly");
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_generated_password_is_256_bit_and_unlogged() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  let email = test_support::unique_email("bootstrap-gen");
  let capture = test_support::install_capture()?;
  let outcome = admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Generate,
    false,
  )
  .await?;
  drop(capture.guard);

  let generated = outcome
    .generated_password
    .ok_or(TestError::Missing("generated password"))?;
  let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(&generated)
    .map_err(|_| TestError::Missing("generated password must be base64"))?;
  assert_eq!(raw.len(), 32, "generated passwords are 256-bit");

  let verdict = user_repo::verify_password(&pool, &email, &generated).await?;
  assert_eq!(verdict, user_repo::PasswordVerdict::Matched);

  let log = test_support::captured(&capture.buffer);
  assert!(
    !log.contains(&generated),
    "generated password leaked into logs"
  );
  assert!(
    log.contains("admin.bootstrap.created"),
    "missing audit: {log}"
  );
  Ok(())
}

#[tokio::test]
async fn admin_bootstrap_first_login_restricted_until_rotation() -> Result<(), TestError> {
  let (_db, pool, config) = bootstrap_setup("redis://127.0.0.1:9").await?;
  let container = GenericImage::new("redis", "7.2-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd(vec!["redis-server", "--appendonly", "yes"])
    .start()
    .await?;
  let guarded = crate::test_guard::ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let client = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str())?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(std::time::Duration::from_secs(10)))
    .set_connection_timeout(Some(std::time::Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config).await?;
  let mut conn = RedisConn::Single(manager);
  let store = crate::store::Store::from_config(&config.redis);

  let email = test_support::unique_email("bootstrap-login");
  admin::bootstrap(
    &config,
    &pool,
    &email,
    admin::BootstrapPassword::Provided(BOOTSTRAP_PASSWORD.to_owned()),
    false,
  )
  .await?;

  let wall = OffsetDateTime::now_utc().unix_timestamp().max(0);
  let wall = u64::try_from(wall).map_err(|_| TestError::Missing("clock"))?;
  let counter = wall / totp::TOTP_STEP_SECS;
  let now = OffsetDateTime::from_unix_timestamp(
    counter
      .saturating_mul(totp::TOTP_STEP_SECS)
      .saturating_add(totp::TOTP_STEP_SECS / 2) as i64,
  )
  .map_err(|_| TestError::Missing("clock"))?;
  macro_rules! deps {
    () => {
      LoginDeps {
        pool: &pool,
        conn: &mut conn,
        store: &store,
        keys: &config.keys,
        config: &config,
        now,
      }
    };
  }

  let (presession_id, _fresh) = ensure_presession(&mut deps!(), None).await?;
  let csrf = login_csrf_token(&config.keys, &presession_id)?;
  let restricted = match attempt_login(
    &mut deps!(),
    LoginAttempt {
      presession_id,
      email: email.clone(),
      password: BOOTSTRAP_PASSWORD.to_owned(),
      code: String::new(),
      csrf,
    },
  )
  .await?
  {
    LoginOutcome::Restricted {
      session_id,
      redirect_to,
    } => {
      assert_eq!(redirect_to, CHANGE_PASSWORD_PATH);
      session_id
    }
    LoginOutcome::Authenticated { .. } => {
      return Err(TestError::Missing("login must be restricted"));
    }
    LoginOutcome::Rejected => return Err(TestError::Missing("login must succeed")),
  };

  for denied in [
    "/authorize",
    "/oauth/token",
    "/oauth/introspect",
    "/admin/users",
  ] {
    assert!(
      !restricted_allows_path(denied),
      "{denied} must deny restricted sessions"
    );
  }
  for allowed in ["/login/change-password", "/login/totp/setup", "/logout"] {
    assert!(
      restricted_allows_path(allowed),
      "{allowed} must stay reachable"
    );
  }

  match change_password(
    &mut deps!(),
    &restricted,
    "new-strong-password-77",
    "new-strong-password-77",
  )
  .await?
  {
    PasswordOutcome::StillRestricted { .. } => {}
    PasswordOutcome::Promoted { .. } => {
      return Err(TestError::Missing("promotion needs TOTP enrollment first"));
    }
  }
  let user = user_repo::find_by_email(&pool, &email)
    .await?
    .ok_or(TestError::Missing("bootstrap admin"))?;
  assert!(!user.must_change_password);
  assert!(user.password_changed_at.is_some());

  let offer = provision_totp(&mut deps!(), &restricted).await?;
  let code = totp::build_totp(&offer.secret)?
    .generate(counter * totp::TOTP_STEP_SECS)
    .to_string();
  let full = match confirm_totp(&mut deps!(), &restricted, &code).await? {
    ConfirmOutcome::Completed { session_id, .. } => session_id,
    _ => {
      return Err(TestError::Missing(
        "correct confirmation must complete bootstrap",
      ));
    }
  };
  assert_ne!(full, restricted);
  let live = load_session(&mut conn, &store, &full)
    .await?
    .ok_or(TestError::Missing("re-issued session"))?;
  assert!(
    !live.record.restricted,
    "completion re-issues a full session"
  );
  assert!(live.record.mfa_verified);
  Ok(())
}

#[test]
fn admin_bootstrap_has_no_password_argv_and_migrate_seeds_no_admin() {
  let parsed = Cli::try_parse_from([
    "d-oauth-server",
    "admin",
    "bootstrap",
    "--email",
    "ops@example.test",
    "--password-file",
    "/run/secrets/bootstrap-password",
    "--force",
  ]);
  assert!(parsed.is_ok(), "documented flags must parse");

  let rejected = Cli::try_parse_from([
    "d-oauth-server",
    "admin",
    "bootstrap",
    "--email",
    "ops@example.test",
    "--password",
    "hunter2",
  ]);
  assert!(rejected.is_err(), "passwords must never travel via argv");
}

#[tokio::test]
async fn admin_bootstrap_migrate_seeds_no_admin() -> Result<(), TestError> {
  let (_db, pool, _config) = bootstrap_setup("redis://127.0.0.1:1").await?;
  assert!(
    !user_repo::has_any_admin(&pool).await?,
    "migrations must seed zero users"
  );
  let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
    .fetch_one(&pool)
    .await?;
  assert_eq!(users, 0, "nothing auto-creates an admin");
  Ok(())
}

#[test]
fn admin_bootstrap_runbook_matches_cli() -> Result<(), TestError> {
  let runbook =
    std::fs::read_to_string("RUNBOOK.md").map_err(|_| TestError::Missing("RUNBOOK.md"))?;
  for command in [
    "admin bootstrap --email",
    "--password-file",
    "--force",
    "user create --admin",
    "user disable",
  ] {
    assert!(
      runbook.contains(command),
      "runbook must document `{command}`"
    );
  }
  Ok(())
}

//! Operator CLI: `serve`, `migrate`, `user`, `scope`, `redirect-uri`,
//! `client`, `config`, `admin`, `initial-access-token`, `keygen`, `healthcheck`.
//!
//! Administration is CLI + declarative config only (no HTTP admin API). No
//! default credential ships and nothing is auto-created at startup: users,
//! scopes, redirect URIs, and initial-access tokens exist only because an
//! operator asked for them. Passwords, TOTP secrets, and tokens are read from
//! stdin/env/file, **never argv**, and a secret is printed only when the
//! operator explicitly asked for a one-time value (a new user's password must
//! be supplied; `user enroll-totp` prints the enrollment secret once;
//! `initial-access-token issue` prints the token once). One-time prints go
//! only to an interactive terminal unless the explicit `--show-secret` flag
//! acknowledges the disclosure, and password files must not be world-readable.
//!
//! `migrate` is forward-only and applies `sqlx::migrate!` under sqlx's own
//! Postgres advisory lock; `serve` never migrates. Mutations are audited on the
//! dedicated `audit` tracing target.
//!
//! Storage: the database repository modules are owned by sibling tasks, so the
//! CLI (which owns operator provisioning end-to-end) uses runtime `sqlx`
//! queries against the migrated schema rather than `query!` macros, keeping the
//! command surface independent of the `.sqlx` cache. See
//! `.omo/evidence/task-14-rust-oauth21-server.md`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

mod admin;
mod context;
mod ops;
mod pii;
mod redirect;
mod scope;
mod secret;
mod sync;
mod totp;
mod user;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use context::CliError;

/// ES256 is the only `keygen` algorithm (P-256 / SHA-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeyAlg {
  /// ECDSA P-256 with SHA-256 (`ES256`).
  Es256,
}

/// `d-oauth-server` operator command tree.
#[derive(Debug, Parser)]
#[command(
  name = "d-oauth-server",
  version,
  about = "OAuth 2.1-only authorization server operator CLI",
  propagate_version = true
)]
pub struct Cli {
  /// Subcommand to run.
  #[command(subcommand)]
  pub command: Command,
}

/// Top-level operator commands.
#[derive(Debug, Subcommand)]
pub enum Command {
  /// Run the HTTP server. Never applies migrations.
  Serve,
  /// Apply forward-only migrations under sqlx's advisory lock.
  Migrate,
  /// Manage admin-provisioned users.
  User {
    /// User subcommand.
    #[command(subcommand)]
    command: UserCommand,
  },
  /// Manage the runtime scope catalog.
  Scope {
    /// Scope subcommand.
    #[command(subcommand)]
    command: ScopeCommand,
  },
  /// Manage the runtime redirect-URI catalog.
  RedirectUri {
    /// Redirect-URI subcommand.
    #[command(subcommand)]
    command: RedirectUriCommand,
  },
  /// Manage per-client redirect-URI attachments.
  Client {
    /// Client subcommand.
    #[command(subcommand)]
    command: ClientCommand,
  },
  /// Validate configuration or apply a declarative file.
  Config {
    /// Config subcommand.
    #[command(subcommand)]
    command: ConfigCommand,
  },
  /// Bootstrap operations (admin bootstrap lands in a later task).
  Admin {
    /// Admin subcommand.
    #[command(subcommand)]
    command: AdminCommand,
  },
  /// Re-wrap v3 TOTP secret DEKs under the active TOTP-encryption key.
  Totp {
    /// TOTP subcommand.
    #[command(subcommand)]
    command: TotpCommand,
  },
  /// Backfill and verify sealed PII (migration-role DSN; counts only).
  Pii {
    /// PII subcommand.
    #[command(subcommand)]
    command: PiiCommand,
  },
  /// Issue a one-time DCR initial-access token.
  InitialAccessToken {
    /// Initial-access-token subcommand.
    #[command(subcommand)]
    command: InitialAccessTokenCommand,
  },
  /// Generate an ES256 keypair for test fixtures / client DPoP keys only.
  ///
  /// This is NEVER an authorization-server signing key: the server publishes
  /// no JWKS and signs no AS artifact.
  Keygen {
    /// Key algorithm (ES256 only).
    #[arg(long, value_enum, default_value = "es256")]
    alg: KeyAlg,
  },
  /// Self-probe `/health/live` over HTTP/loopback; exits 0 (live) or 1.
  ///
  /// Used as the container `HEALTHCHECK` because a minimal image has no
  /// shell or curl.
  Healthcheck {
    /// Health URL (loopback by default).
    #[arg(long, default_value = "http://127.0.0.1:8081/health/live")]
    url: String,
  },
}

/// `user` subcommands.
#[derive(Debug, Subcommand)]
pub enum UserCommand {
  /// Create a user; password comes from stdin or a file, never argv.
  Create {
    /// User email (case-insensitive).
    #[arg(long)]
    email: String,
    /// Grant the `is_admin` flag.
    #[arg(long)]
    admin: bool,
    /// Read the password from stdin (default when `--password-file` is absent).
    #[arg(long)]
    password_stdin: bool,
    /// Read the password from a file (trailing newline trimmed).
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
  },
  /// Enroll TOTP: generates, encrypts, and stores a secret, printing it once.
  EnrollTotp {
    /// User email.
    #[arg(long)]
    email: String,
    /// Print the one-time secret even when stdout is not a TTY. Without this
    /// flag the secret prints only to an interactive terminal, so it can
    /// never leak into job logs or pipes by accident.
    #[arg(long)]
    show_secret: bool,
  },
  /// Disable a user account.
  Disable {
    /// User email.
    #[arg(long)]
    email: String,
  },
  /// Clear a user's login lockout counters (account plus per-IP buckets).
  Unlock {
    /// User email.
    #[arg(long)]
    email: String,
  },
  /// Grant a catalog scope entitlement to a user.
  GrantScope {
    /// User email.
    #[arg(long)]
    email: String,
    /// Scope name (must exist in the catalog).
    #[arg(long)]
    scope: String,
  },
  /// Revoke a catalog scope entitlement from a user.
  RevokeScope {
    /// User email.
    #[arg(long)]
    email: String,
    /// Scope name.
    #[arg(long)]
    scope: String,
  },
  /// List a user's scope entitlements.
  Scopes {
    /// User email.
    #[arg(long)]
    email: String,
  },
}

/// `scope` subcommands.
#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
  /// Create a scope (or update its description when it exists).
  Create {
    /// Scope name.
    name: String,
    /// Optional human description.
    #[arg(long)]
    description: Option<String>,
  },
  /// List the scope catalog.
  List,
  /// Enable a scope.
  Enable {
    /// Scope name.
    name: String,
  },
  /// Disable a scope.
  Disable {
    /// Scope name.
    name: String,
  },
  /// Delete a scope (referenced scopes are disabled instead).
  Delete {
    /// Scope name.
    name: String,
  },
}

/// `redirect-uri` subcommands.
#[derive(Debug, Subcommand)]
pub enum RedirectUriCommand {
  /// Create a redirect URI (or update its description when it exists).
  Create {
    /// Absolute redirect URI.
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
    /// Optional human description.
    #[arg(long)]
    description: Option<String>,
  },
  /// List the redirect-URI catalog.
  List,
  /// Enable a redirect URI.
  Enable {
    /// Redirect URI.
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
  },
  /// Disable a redirect URI.
  Disable {
    /// Redirect URI.
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
  },
  /// Delete a redirect URI (referenced URIs are disabled instead).
  Delete {
    /// Redirect URI.
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
  },
}

/// `client` subcommands.
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
  /// Attach a catalog redirect URI to a client.
  AttachRedirectUri {
    /// OAuth client identifier.
    #[arg(long)]
    client_id: String,
    /// Redirect URI from the catalog.
    #[arg(long)]
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
  },
  /// Detach a catalog redirect URI from a client.
  DetachRedirectUri {
    /// OAuth client identifier.
    #[arg(long)]
    client_id: String,
    /// Redirect URI.
    #[arg(long)]
    uri: String,
    /// Catalog kind: `authorize` (default) or `post_logout`.
    #[arg(long, default_value = "authorize", value_parser = ["authorize", "post_logout"])]
    kind: String,
  },
  /// List a client's attached redirect URIs.
  RedirectUris {
    /// OAuth client identifier.
    #[arg(long)]
    client_id: String,
  },
}

/// `config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
  /// Apply a declarative file idempotently (scopes, redirect URIs, entitlements).
  Sync {
    /// JSON declarative file.
    #[arg(long, value_name = "PATH")]
    file: PathBuf,
  },
  /// Validate configuration; exits non-zero when invalid.
  Check,
}

/// `admin` subcommands.
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
  /// Bootstrap the first admin. Refuses while any enabled admin exists
  /// unless `--force` is given (loud warning + audit event).
  Bootstrap {
    /// Admin email.
    #[arg(long)]
    email: String,
    /// Read the password from a file (else stdin; empty stdin generates one).
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
    /// Create another admin even though one already exists (audited).
    #[arg(long)]
    force: bool,
  },
}

/// `totp` subcommands.
#[derive(Debug, Subcommand)]
pub enum TotpCommand {
  /// Re-wrap every v3 DEK under the active TOTP-encryption key.
  Rewrap,
}

/// `pii` subcommands.
#[derive(Debug, Subcommand)]
pub enum PiiCommand {
  /// Seal remaining plaintext PII and upgrade TOTP blobs to v3. Refuses while
  /// `pii_dual_write=true`; run only with the app tier scaled to zero.
  Backfill,
  /// Report the four cutover checks; exits non-zero when any is dirty.
  Verify,
  /// Re-encrypt sealed PII under the active key and recompute blind indexes.
  /// Run under a write freeze with the previous key retained; idempotent.
  Rotate,
}

/// `initial-access-token` subcommands.
#[derive(Debug, Subcommand)]
pub enum InitialAccessTokenCommand {
  /// Issue an initial-access token with a bounded use budget.
  Issue {
    /// Registration calls this token authorizes.
    #[arg(long)]
    uses: u64,
    /// Lifetime in seconds.
    #[arg(long)]
    ttl: u64,
    /// Operator label for audit (never a secret).
    #[arg(long, default_value = "cli")]
    label: String,
    /// Print the one-time token even when stdout is not a TTY. Without this
    /// flag the token prints only to an interactive terminal, so it can
    /// never leak into job logs or pipes by accident.
    #[arg(long)]
    show_secret: bool,
  },
}

/// Parse and execute the CLI, returning the process exit code.
///
/// `--help`/`--version` print and return `0`; an unknown command prints usage
/// to stderr and returns `2`; a command failure prints a clear message to
/// stderr and returns `1`.
pub async fn main_entry() -> i32 {
  let cli = match Cli::try_parse() {
    Ok(cli) => cli,
    Err(error) => {
      let code = if error.use_stderr() { 2 } else { 0 };
      let _ = error.print();
      return code;
    }
  };
  match run(cli).await {
    Ok(code) => code,
    Err(error) => {
      eprintln!("error: {error}");
      1
    }
  }
}

/// Execute a parsed command.
///
/// # Errors
/// Returns [`CliError`] for any configuration, database, store, or I/O
/// failure; the caller maps that to a non-zero exit code.
pub async fn run(cli: Cli) -> Result<i32, CliError> {
  match cli.command {
    Command::Serve => {
      ops::serve().await?;
      Ok(0)
    }
    Command::Migrate => {
      ops::migrate().await?;
      Ok(0)
    }
    Command::User { command } => {
      let context = context::Context::from_env().await?;
      run_user(&context, command).await?;
      Ok(0)
    }
    Command::Scope { command } => {
      let context = context::Context::from_env().await?;
      scope::run(&context, command).await?;
      Ok(0)
    }
    Command::RedirectUri { command } => {
      let context = context::Context::from_env().await?;
      redirect::run_uri(&context, command).await?;
      Ok(0)
    }
    Command::Client { command } => {
      let context = context::Context::from_env().await?;
      redirect::run_client(&context, command).await?;
      Ok(0)
    }
    Command::Config { command } => match command {
      ConfigCommand::Check => {
        ops::config_check()?;
        Ok(0)
      }
      ConfigCommand::Sync { file } => {
        let report = sync::run(&file).await?;
        if report.is_noop() {
          println!("config sync: no changes");
        } else {
          println!("{report}");
        }
        Ok(0)
      }
    },
    Command::Admin { command } => {
      run_admin(command).await?;
      Ok(0)
    }
    Command::Totp { command } => {
      let context = context::Context::from_env().await?;
      run_totp(&context, command).await?;
      Ok(0)
    }
    Command::Pii { command } => {
      let context = context::Context::from_env().await?;
      run_pii(&context, command).await?;
      Ok(0)
    }
    Command::InitialAccessToken { command } => {
      run_initial_access_token(command).await?;
      Ok(0)
    }
    Command::Keygen { alg } => {
      ops::keygen(alg)?;
      Ok(0)
    }
    Command::Healthcheck { url } => ops::healthcheck(&url).await,
  }
}

async fn run_user(context: &context::Context, command: UserCommand) -> Result<(), CliError> {
  match command {
    UserCommand::Create {
      email,
      admin,
      password_stdin,
      password_file,
    } => {
      let password = context::read_secret(password_stdin, password_file.as_deref())?;
      user::create(context, &email, admin, password.as_str()).await
    }
    UserCommand::EnrollTotp { email, show_secret } => {
      require_secret_output(show_secret)?;
      let enrollment = user::enroll_totp(context, &email).await?;
      println!("totp secret (shown once): {}", enrollment.secret.as_str());
      println!("otpauth uri: {}", enrollment.uri.as_str());
      Ok(())
    }
    UserCommand::Disable { email } => user::disable(context, &email).await,
    UserCommand::Unlock { email } => {
      let removed = user::unlock(context, &email).await?;
      println!("unlocked user {email} (cleared {removed} lockout counter(s))");
      Ok(())
    }
    UserCommand::GrantScope { email, scope } => user::grant_scope(context, &email, &scope).await,
    UserCommand::RevokeScope { email, scope } => user::revoke_scope(context, &email, &scope).await,
    UserCommand::Scopes { email } => {
      let scopes = user::list_scopes(context, &email).await?;
      if scopes.is_empty() {
        println!("{email} has no scope entitlements");
      } else {
        for scope in scopes {
          println!("{scope}");
        }
      }
      Ok(())
    }
  }
}

async fn run_admin(command: AdminCommand) -> Result<(), CliError> {
  match command {
    AdminCommand::Bootstrap {
      email,
      password_file,
      force,
    } => ops::admin_bootstrap(&email, password_file.as_deref(), force).await,
  }
}

async fn run_totp(context: &context::Context, command: TotpCommand) -> Result<(), CliError> {
  match command {
    TotpCommand::Rewrap => {
      let report = totp::rewrap(context).await?;
      println!("{report}");
      Ok(())
    }
  }
}

async fn run_pii(context: &context::Context, command: PiiCommand) -> Result<(), CliError> {
  match command {
    PiiCommand::Backfill => {
      pii::backfill(context).await?;
      Ok(())
    }
    PiiCommand::Verify => {
      pii::verify(context).await?;
      Ok(())
    }
    PiiCommand::Rotate => {
      pii::rotate(context).await?;
      Ok(())
    }
  }
}

async fn run_initial_access_token(command: InitialAccessTokenCommand) -> Result<(), CliError> {
  match command {
    InitialAccessTokenCommand::Issue {
      uses,
      ttl,
      label,
      show_secret,
    } => {
      require_secret_output(show_secret)?;
      let token = ops::issue_initial_access_token(uses, ttl, &label).await?;
      println!("initial access token (shown once): {}", token.as_str());
      Ok(())
    }
  }
}

/// Refuse a one-time secret print that would land anywhere but an operator's
/// terminal, unless the operator passed the explicit `--show-secret` flag.
///
/// A redirected stdout (pipe, file, or job log) without the flag is an error
/// so enrollment secrets and initial-access tokens can never leak into logs
/// by accident; the error carries no secret material.
///
/// # Errors
/// Returns [`CliError::Input`] when stdout is not a TTY and `show_secret` is
/// false.
pub fn require_secret_output(show_secret: bool) -> Result<(), CliError> {
  use std::io::IsTerminal as _;
  check_secret_output(show_secret, std::io::stdout().is_terminal())
}

/// Flag logic behind [`require_secret_output`], with the TTY probe as an
/// explicit parameter so the matrix is unit-testable without a terminal.
fn check_secret_output(show_secret: bool, is_tty: bool) -> Result<(), CliError> {
  if show_secret || is_tty {
    Ok(())
  } else {
    Err(CliError::Input(
      "refusing to print a one-time secret to a non-TTY stdout: re-run attached \
       to a terminal or pass --show-secret to acknowledge the disclosure"
        .to_owned(),
    ))
  }
}

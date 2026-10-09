//! `user` subcommands: create, enroll TOTP, disable, and scope entitlements.

use uuid::Uuid;

use super::{
  context::{CliError, Context, audit, require_nonempty},
  secret,
};
use crate::{db::user_repo, error::AppError};

/// The one-time TOTP enrollment material printed to the operator.
pub struct Enrollment {
  /// Base32 TOTP secret (shown once).
  pub secret: String,
  /// `otpauth://` URI for authenticator apps.
  pub uri: String,
}

/// Create an admin-provisioned user.
///
/// The password is hashed with the configured Argon2id parameters. New users
/// must change their password on first login.
///
/// # Errors
/// Returns [`CliError`] for invalid input, a duplicate email, or a database
/// failure.
pub async fn create(
  context: &Context,
  email: &str,
  admin: bool,
  password: &str,
) -> Result<(), CliError> {
  let email = normalized_email(email)?;
  require_nonempty(password, "password")?;
  let password_hash = secret::hash_password(context.config(), password)?;

  let record = user_repo::create_user(
    context.pool(),
    &context.config().keys,
    context.config().pii_dual_write,
    &user_repo::NewUser {
      email: email.clone(),
      password_hash,
      is_admin: admin,
      must_change_password: true,
    },
  )
  .await
  .map_err(map_user_repo_error)?;

  audit("user.create", &email);
  println!("created user {email} (id {})", record.id);
  Ok(())
}

/// Enroll TOTP for a user, returning the one-time secret to print.
///
/// # Errors
/// Returns [`CliError`] when the user is missing or the write fails.
pub async fn enroll_totp(context: &Context, email: &str) -> Result<Enrollment, CliError> {
  let email = normalized_email(email)?;
  let id = find_user_id(context, &email).await?;
  let totp_secret = secret::generate_totp_secret()?;
  let blob = secret::encrypt_totp(
    context.config(),
    &totp_secret,
    !context.config().pii_dual_write,
  )?;

  let updated = user_repo::set_totp_secret(context.pool(), id, &blob)
    .await
    .map_err(map_user_repo_error)?;
  if !updated {
    return Err(CliError::NotFound("user not found".to_owned()));
  }

  audit("user.enroll_totp", &email);
  Ok(Enrollment {
    uri: secret::otpauth_uri(&context.config().issuer, &email, &totp_secret),
    secret: totp_secret,
  })
}

/// Disable a user account.
///
/// The user's Redis ephemeral state (sessions, tokens, grants, codes, device
/// records, and the lockout counter) is purged BEFORE the Postgres `disabled`
/// flag flips, mirroring the DCR `DELETE` ordering. A Redis or connect failure
/// fails closed: the command errors and the user stays enabled.
///
/// # Errors
/// Returns [`CliError`] when the user is missing, when Redis is unavailable,
/// or when a write fails.
pub async fn disable(context: &Context, email: &str) -> Result<(), CliError> {
  let email = email.trim();
  require_nonempty(email, "email")?;
  let record = user_repo::find_by_email(context.pool(), &context.config().keys, email)
    .await
    .map_err(map_user_repo_error)?
    .ok_or_else(|| CliError::NotFound("user not found".to_owned()))?;
  let state = crate::state::AppState::connect(context.config().clone()).await?;
  let store = crate::store::Store::from_config(&context.config().redis);
  let mut conn = state.redis.clone();
  crate::protocol::purge::purge_subject(&mut conn, &store, &record.email, &record.id.to_string())
    .await
    .map_err(CliError::from)?;
  let updated = user_repo::disable_user(context.pool(), record.id)
    .await
    .map_err(map_user_repo_error)?;
  if !updated {
    return Err(CliError::NotFound("user not found".to_owned()));
  }
  audit("user.disable", &record.email);
  println!("disabled user {}", record.email);
  Ok(())
}

/// Grant a catalog scope entitlement to a user.
///
/// # Errors
/// Returns [`CliError`] when the user or scope is missing, or on a write
/// failure.
pub async fn grant_scope(context: &Context, email: &str, scope: &str) -> Result<(), CliError> {
  let email = normalized_email(email)?;
  let user_id = find_user_id(context, &email).await?;
  ensure_scope_exists(context, scope).await?;

  sqlx::query(
    "INSERT INTO user_scopes (user_id, scope_name, granted_at, granted_by)
     VALUES ($1, $2, now(), $1)
     ON CONFLICT (user_id, scope_name) DO NOTHING",
  )
  .bind(user_id)
  .bind(scope)
  .execute(context.pool())
  .await?;

  audit("user.grant_scope", &format!("{email}:{scope}"));
  println!("granted scope {scope} to {email}");
  Ok(())
}

/// Revoke a catalog scope entitlement from a user (idempotent).
///
/// # Errors
/// Returns [`CliError`] when the user is missing or the delete fails.
pub async fn revoke_scope(context: &Context, email: &str, scope: &str) -> Result<(), CliError> {
  let email = normalized_email(email)?;
  let user_id = find_user_id(context, &email).await?;

  sqlx::query("DELETE FROM user_scopes WHERE user_id = $1 AND scope_name = $2")
    .bind(user_id)
    .bind(scope)
    .execute(context.pool())
    .await?;

  audit("user.revoke_scope", &format!("{email}:{scope}"));
  println!("revoked scope {scope} from {email}");
  Ok(())
}

/// List a user's scope entitlements.
///
/// # Errors
/// Returns [`CliError`] when the user is missing or the read fails.
pub async fn list_scopes(context: &Context, email: &str) -> Result<Vec<String>, CliError> {
  let email = normalized_email(email)?;
  let user_id = find_user_id(context, &email).await?;
  let scopes: Vec<String> =
    sqlx::query_scalar("SELECT scope_name FROM user_scopes WHERE user_id = $1 ORDER BY scope_name")
      .bind(user_id)
      .fetch_all(context.pool())
      .await?;
  Ok(scopes)
}

/// Resolve a user id by email through the repository's encrypted lookup
/// (blind index with a legacy plaintext fallback for rows with no ciphertext).
///
/// # Errors
/// Returns [`CliError::NotFound`] when no such user exists. The message is
/// payload-free: it never echoes the submitted email.
pub async fn find_user_id(context: &Context, email: &str) -> Result<Uuid, CliError> {
  user_repo::find_by_email(context.pool(), &context.config().keys, email)
    .await
    .map_err(map_user_repo_error)?
    .map(|record| record.id)
    .ok_or_else(|| CliError::NotFound("user not found".to_owned()))
}

/// Map a repository failure: the typed payload-free duplicate becomes
/// `AlreadyExists`; anything else converts without carrying PII.
pub(super) fn map_user_repo_error(error: AppError) -> CliError {
  match error {
    AppError::DuplicateEmail => CliError::AlreadyExists("user email already exists".to_owned()),
    other => CliError::App(other),
  }
}

async fn ensure_scope_exists(context: &Context, scope: &str) -> Result<(), CliError> {
  let name: Option<String> = sqlx::query_scalar("SELECT name FROM scopes WHERE name = $1")
    .bind(scope)
    .fetch_optional(context.pool())
    .await?;
  name
    .map(|_| ())
    .ok_or_else(|| CliError::NotFound(format!("scope {scope}")))
}

fn normalized_email(email: &str) -> Result<String, CliError> {
  let email = email.trim();
  require_nonempty(email, "email")?;
  Ok(email.to_owned())
}

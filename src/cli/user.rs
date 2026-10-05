//! `user` subcommands: create, enroll TOTP, disable, and scope entitlements.

use uuid::Uuid;

use super::{
  context::{CliError, Context, audit, require_nonempty},
  secret,
};

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
  let id = Uuid::new_v4();

  let result = sqlx::query(
    "INSERT INTO users (
       id, email, password_hash, is_admin, must_change_password, created_at, updated_at
     ) VALUES ($1, $2::citext, $3, $4, true, now(), now())",
  )
  .bind(id)
  .bind(&email)
  .bind(&password_hash)
  .bind(admin)
  .execute(context.pool())
  .await;

  match result {
    Ok(_) => {
      audit("user.create", &email);
      println!("created user {email} (id {id})");
      Ok(())
    }
    Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
      Err(CliError::AlreadyExists(format!("user {email}")))
    }
    Err(error) => Err(error.into()),
  }
}

/// Enroll TOTP for a user, returning the one-time secret to print.
///
/// # Errors
/// Returns [`CliError`] when the user is missing or the write fails.
pub async fn enroll_totp(context: &Context, email: &str) -> Result<Enrollment, CliError> {
  let email = normalized_email(email)?;
  let id = find_user_id(context, &email).await?;
  let totp_secret = secret::generate_totp_secret()?;
  let blob = secret::encrypt_totp(context.config(), &totp_secret)?;

  sqlx::query(
    "UPDATE users
        SET totp_secret_enc = $2, totp_enabled = true, updated_at = now()
      WHERE id = $1",
  )
  .bind(id)
  .bind(&blob)
  .execute(context.pool())
  .await?;

  audit("user.enroll_totp", &email);
  Ok(Enrollment {
    uri: secret::otpauth_uri(&context.config().issuer, &email, &totp_secret),
    secret: totp_secret,
  })
}

/// Disable a user account.
///
/// # Errors
/// Returns [`CliError`] when the user is missing or the write fails.
pub async fn disable(context: &Context, email: &str) -> Result<(), CliError> {
  let email = normalized_email(email)?;
  let id = find_user_id(context, &email).await?;
  sqlx::query("UPDATE users SET disabled = true, updated_at = now() WHERE id = $1")
    .bind(id)
    .execute(context.pool())
    .await?;
  audit("user.disable", &email);
  println!("disabled user {email}");
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

/// Resolve a user id by case-insensitive email.
///
/// # Errors
/// Returns [`CliError::NotFound`] when no such user exists.
pub async fn find_user_id(context: &Context, email: &str) -> Result<Uuid, CliError> {
  let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1::citext")
    .bind(email)
    .fetch_optional(context.pool())
    .await?;
  id.ok_or_else(|| CliError::NotFound(format!("user {email}")))
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

//! `test(user_repo_subject_status)` — use-time disabled-user lookup.
//!
//! Covers the fail-closed helper behind token introspection and the
//! refresh-token grant: an email subject (any casing) or a UUID subject that
//! resolves to a disabled user reports `Disabled`; enabled users report
//! `Enabled`; empty, unknown, and synthetic subjects report `Unmapped` and
//! must never fail a live token. Every test gets a fresh migrated database
//! from [`crate::db::test_support`].

use secrecy::SecretString;
use sqlx::PgPool;
use uuid::Uuid;

use super::{NewUser, SubjectAccountStatus, create_user, disable_user, subject_account_status};
use crate::crypto::secret::{Argon2Params, hash_secret};
use crate::db::test_support::{TestError, migrated_pool};
use crate::keys::{KeyId, KeyRing};

/// Test PII key ring (the blind-index candidates must derive from it).
fn test_keys() -> Result<KeyRing, TestError> {
  Ok(KeyRing::from_parts(
    vec![(
      KeyId::new("v1"),
      SecretString::from("user-repo-test-pepper"),
    )],
    vec![(KeyId::new("v1"), SecretString::from("user-repo-test-totp"))],
    vec![(KeyId::new("v1"), SecretString::from("user-repo-test-pii"))],
  )?)
}

/// Provision one enabled user; returns its id.
async fn provision(pool: &PgPool, keys: &KeyRing, email: &str) -> Result<Uuid, TestError> {
  let params = Argon2Params::new(8, 1, 1, 32)?;
  let record = create_user(
    pool,
    keys,
    false,
    &NewUser {
      email: email.to_owned(),
      password_hash: hash_secret("correct-horse-01", &params)?,
      is_admin: false,
      must_change_password: false,
    },
  )
  .await?;
  Ok(record.id)
}

#[tokio::test]
async fn user_repo_subject_status_empty_is_unmapped() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  for subject in ["", "   "] {
    let status = subject_account_status(&pool, &keys, subject).await?;
    assert_eq!(
      status,
      SubjectAccountStatus::Unmapped,
      "an empty subject is a client-credentials token and must never resolve"
    );
  }
  Ok(())
}

#[tokio::test]
async fn user_repo_subject_status_email_enabled_then_disabled() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let id = provision(&pool, &keys, "status-user@example.test").await?;
  // Any casing normalizes to the same blind-index candidates.
  let status = subject_account_status(&pool, &keys, "  Status-User@Example.Test ").await?;
  assert_eq!(status, SubjectAccountStatus::Enabled);
  assert!(disable_user(&pool, id).await?);
  let status = subject_account_status(&pool, &keys, "status-user@example.test").await?;
  assert_eq!(status, SubjectAccountStatus::Disabled);
  Ok(())
}

#[tokio::test]
async fn user_repo_subject_status_uuid_enabled_then_disabled() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  let id = provision(&pool, &keys, "uuid-user@example.test").await?;
  let subject = id.to_string();
  let status = subject_account_status(&pool, &keys, &subject).await?;
  assert_eq!(status, SubjectAccountStatus::Enabled);
  assert!(disable_user(&pool, id).await?);
  let status = subject_account_status(&pool, &keys, &subject).await?;
  assert_eq!(status, SubjectAccountStatus::Disabled);
  Ok(())
}

#[tokio::test]
async fn user_repo_subject_status_unknown_is_unmapped() -> Result<(), TestError> {
  let (_db, pool) = migrated_pool().await?;
  let keys = test_keys()?;
  // Synthetic subjects (never provisioned) must stay live.
  let status = subject_account_status(&pool, &keys, "synthetic-subject-1").await?;
  assert_eq!(status, SubjectAccountStatus::Unmapped);
  let status = subject_account_status(&pool, &keys, &Uuid::new_v4().to_string()).await?;
  assert_eq!(status, SubjectAccountStatus::Unmapped);
  let status = subject_account_status(&pool, &keys, "ghost@example.test").await?;
  assert_eq!(status, SubjectAccountStatus::Unmapped);
  Ok(())
}

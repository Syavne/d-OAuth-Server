//! Postgres repositories over `query!`/`query_as!` macros.
//!
//! Six domain tables: `oauth_clients`, `users`, `scopes`, `user_scopes`,
//! `redirect_uris`, `client_redirect_uris`. No failed-login columns here
//! (those counters are Redis-ephemeral).

pub mod client_repo;
pub mod redirect_repo;
pub mod resource_repo;
pub mod scope_repo;
pub mod user_repo;
pub mod user_scope_repo;

pub use client_repo::{Client, ClientMetadata, NewClient, TokenEndpointAuthMethod};
pub use redirect_repo::{NewRedirectUri, RedirectKind, RedirectUri, UpsertOutcome};

/// Test-only scaffolding shared by the repository suites.
///
/// Compose-first: the pool is built on the shared external Postgres started by
/// `docker compose -f compose.test.yaml up -d`, using a fresh database per call
/// from [`crate::test_support::fresh_database_pool`]. No container is started
/// here. The [`Shared`]/[`Lease`] pair is retained only so the many callers
/// that bind `_db: Lease<Db>` compile unchanged.
#[cfg(test)]
pub(crate) mod test_support {
  use sqlx::PgPool;

  use crate::test_guard::{Lease, Shared};

  /// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
  pub(crate) type TestError = Box<dyn std::error::Error + Send + Sync>;

  /// URL-only holder of the shared Postgres lease.
  ///
  /// It owns no external resource; the lease merely satisfies the caller
  /// signatures.
  pub(crate) struct Db {
    /// Retained only for the `Lease<Db>` type the callers bind; the URL is
    /// intentionally never dereferenced.
    #[allow(dead_code)]
    url: String,
  }

  static DB: Shared<Db> = Shared::new();

  /// A fresh database on the shared compose server with every embedded
  /// migration applied, pooled for the calling test.
  ///
  /// Acquires the (resource-free) shared [`Db`] lease, creates a uniquely named
  /// database via [`crate::test_support::fresh_database_pool`], applies the
  /// migrations here, and returns the lease plus the pool. Bind the lease
  /// (usually as `_db`) for the duration of the test.
  pub(crate) async fn migrated_pool() -> Result<(Lease<Db>, PgPool), TestError> {
    let db = DB
      .lease::<TestError>(async {
        Ok(Db {
          url: crate::test_support::test_postgres_admin_url(),
        })
      })
      .await?;
    let (_fresh_url, pool) = crate::test_support::fresh_database_pool().await?;
    crate::state::MIGRATOR.run(&pool).await?;
    Ok((db, pool))
  }
}

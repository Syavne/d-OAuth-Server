//! Postgres repositories over `query!`/`query_as!` macros.
//!
//! Six domain tables: `oauth_clients`, `users`, `scopes`, `user_scopes`,
//! `redirect_uris`, `client_redirect_uris`. No failed-login columns here
//! (those counters are Redis-ephemeral).

pub mod client_repo;
pub mod redirect_repo;
pub mod scope_repo;
pub mod user_repo;
pub mod user_scope_repo;

pub use client_repo::{Client, ClientMetadata, NewClient, TokenEndpointAuthMethod};
pub use redirect_repo::{RedirectKind, RedirectUri};

/// Test-only scaffolding shared by the repository suites.
///
/// One `postgres:16-alpine` container is started lazily and reused by every test
/// in the lib test binary; each test gets a freshly created database with all
/// embedded migrations applied, so parallel tests stay isolated at one
/// container cost. Integration tests under `tests/` cannot reach this
/// `#[cfg(test)]` module and carry their own container helper instead.
#[cfg(test)]
pub(crate) mod test_support {
  use sqlx::{Executor as _, PgPool, postgres::PgPoolOptions};
  use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
  };

  use crate::test_guard::{ContainerGuard, Lease, Shared};

  /// Boxed test error (no `unwrap`/`expect` under the crate deny lints).
  pub(crate) type TestError = Box<dyn std::error::Error + Send + Sync>;

  /// Test Postgres superuser password.
  const PG_PASSWORD: &str = "db-repo-secret";

  /// The shared Postgres server plus the container keeping it alive.
  ///
  /// The container is a [`ContainerGuard`], so the last test releasing the
  /// shared slot removes it synchronously instead of orphaning it.
  pub(crate) struct Db {
    _container: ContainerGuard,
    url: String,
  }

  static DB: Shared<Db> = Shared::new();

  /// Start (once) and return a lease on the shared Postgres server.
  ///
  /// The lease must stay alive as long as the returned reference is used;
  /// dropping the last lease removes the shared container deterministically.
  async fn shared_db() -> Result<Lease<Db>, TestError> {
    DB.lease::<TestError>(async {
      let container = GenericImage::new("postgres", "16-alpine")
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
      let url =
        format!("postgres://postgres:{PG_PASSWORD}@127.0.0.1:{port}/postgres?sslmode=disable");
      Ok(Db {
        _container: guarded,
        url,
      })
    })
    .await
  }

  /// A fresh database on the shared server with every embedded migration
  /// applied, pooled for the calling test.
  ///
  /// The returned lease keeps the shared container alive; bind it (usually
  /// as `_db`) for the duration of the test.
  pub(crate) async fn migrated_pool() -> Result<(Lease<Db>, PgPool), TestError> {
    let db = shared_db().await?;
    let admin = PgPoolOptions::new()
      .max_connections(1)
      .connect(&db.url)
      .await?;
    let name = format!("repo_{}", uuid::Uuid::new_v4().simple());
    // `CREATE DATABASE` cannot take a bind parameter and `&Pool`'s `Executor`
    // requires a `'static` query; leak this one tiny test-only string.
    let ddl: &'static str = Box::leak(format!("CREATE DATABASE \"{name}\"").into_boxed_str());
    admin.execute(ddl).await?;
    admin.close().await;
    let target = db.url.replacen("/postgres?", &format!("/{name}?"), 1);
    let pool = PgPoolOptions::new()
      .max_connections(4)
      .connect(&target)
      .await?;
    crate::state::MIGRATOR.run(&pool).await?;
    Ok((db, pool))
  }
}

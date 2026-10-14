//! Deterministic testcontainers teardown for the test harness.
//!
//! `testcontainers` 0.27 removes containers in `ContainerAsync::drop` via
//! `async_drop`, which schedules the `docker rm` on a background task. Under
//! `cargo nextest` (and `cargo test`) each test runs in its own process that
//! exits as soon as the test body returns, so the background removal never
//! runs and the container is orphaned. Relying on `Drop` alone therefore leaks
//! one container per test process.
//!
//! This module provides the two primitives the remaining container harnesses
//! use instead:
//!
//! * [`ContainerGuard`] owns one `GenericImage` container and removes it
//!   synchronously in its `Drop`: the container is taken out of the guard,
//!   moved to a short-lived OS thread (which is unaffected by the state of
//!   the surrounding Tokio runtime), removed there with
//!   `ContainerAsync::rm` on a fresh current-thread runtime, and `join`ed.
//!   Because `Drop` runs before the test process exits, removal is
//!   deterministic. Failures are reported on stderr; `Drop` never panics.
//! * [`Shared`] is a process-wide slot for a value that is expensive to start
//!   (a shared Postgres/Redis container holder). Tests acquire a [`Lease`];
//!   the last lease to drop evicts the value under a mutex *before* teardown
//!   runs, so a concurrently starting test can never observe a container that
//!   is already being removed. Sharing across tests in one process is
//!   preserved, and under `nextest` (one test per process) each process still
//!   removes exactly the containers it started.
//!
//! There is exactly one source file for this module. Unit-test harnesses use
//! it as `crate::test_guard` (declared `#[cfg(test)]` in `lib.rs` because
//! integration-test binaries cannot see `#[cfg(test)]` items, and the guard
//! depends on the `testcontainers` dev-dependency which is unavailable to the
//! production build). Integration tests under `tests/` include this same file
//! with `#[path = "../src/test_guard.rs"] mod test_guard;` (or
//! `"../../src/test_guard.rs"` from `tests/common/`), so every compilation
//! unit compiles its own copy from a single implementation.
//!
//! Most `src/**` unit tests no longer containerize: they use the compose-first
//! helpers in `src/test_support.rs`. This module is retained only for the
//! remaining testcontainers keep-list: the lifecycle/resilience suite, the
//! topology suite, the `--appendfsync always` refresh-token suite, the two
//! Redis-specific tests in `src/store/tests_store.rs`, and the
//! private-container `dcr_manage_token_survives_redis_flush`.

use std::{ops::Deref, sync::Arc};

use testcontainers::{ContainerAsync, GenericImage};

/// RAII owner of one `GenericImage` testcontainer.
///
/// Hold the guard for the whole test (usually with a `_container` binding);
/// dropping it removes the container synchronously before the test process
/// can exit, so no container is orphaned.
pub struct ContainerGuard {
  inner: Option<ContainerAsync<GenericImage>>,
}

impl ContainerGuard {
  /// Take ownership of a started container.
  #[must_use]
  pub fn new(container: ContainerAsync<GenericImage>) -> Self {
    Self {
      inner: Some(container),
    }
  }

  /// Borrow the inner container.
  ///
  /// The option is only ever `None` while `Drop` is running on this same
  /// value (which holds `&mut self` and therefore excludes any concurrent
  /// borrow), so every observable call sees `Some`.
  fn container(&self) -> &ContainerAsync<GenericImage> {
    // `expect`/`unwrap` are denied crate-wide; the `None` arm is unreachable
    // for the reason above, and the only non-panicking way to satisfy the
    // return type there is to diverge without output.
    if let Some(container) = self.inner.as_ref() {
      container
    } else {
      // Park forever rather than panic or return a bogus reference. This
      // branch cannot execute without `unsafe` elsewhere (forbidden
      // crate-wide); a hang here would signal a soundness bug, never a
      // routine failure.
      std::thread::park();
      self.container()
    }
  }

  /// Host port mapped from a container port (see `RawContainer`).
  ///
  /// # Errors
  ///
  /// Returns the testcontainers error when the mapping is missing.
  pub async fn get_host_port_ipv4(
    &self,
    port: u16,
  ) -> Result<u16, testcontainers::TestcontainersError> {
    self.container().get_host_port_ipv4(port).await
  }

  /// Bridge IP of the container (see `RawContainer`).
  ///
  /// # Errors
  ///
  /// Returns the testcontainers error when the network cannot be inspected.
  pub async fn get_bridge_ip_address(
    &self,
  ) -> Result<std::net::IpAddr, testcontainers::TestcontainersError> {
    self.container().get_bridge_ip_address().await
  }

  /// Docker id of the container.
  #[must_use]
  pub fn id(&self) -> &str {
    self.container().id()
  }

  /// Stop with a timeout before `SIGKILL` (see `ContainerAsync`).
  ///
  /// # Errors
  ///
  /// Returns the testcontainers error when the stop fails.
  pub async fn stop_with_timeout(
    &self,
    timeout_seconds: Option<i32>,
  ) -> Result<(), testcontainers::TestcontainersError> {
    self.container().stop_with_timeout(timeout_seconds).await
  }

  /// Start a stopped container (see `ContainerAsync`).
  ///
  /// # Errors
  ///
  /// Returns the testcontainers error when the start fails.
  pub async fn start(&self) -> Result<(), testcontainers::TestcontainersError> {
    self.container().start().await
  }
}

impl Drop for ContainerGuard {
  fn drop(&mut self) {
    if let Some(container) = self.inner.take() {
      let id = container.id().to_string();
      let thread_id = id.clone();
      // A fresh OS thread plus a fresh runtime: `Handle::block_on` would
      // panic inside a Tokio runtime context, and `block_in_place` panics on
      // the current-thread runtime that `#[tokio::test]` uses by default.
      // The new thread has no runtime, so building one always succeeds in
      // principle; every failure below is reported, never panicked on.
      let outcome = std::thread::spawn(move || match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
      {
        Ok(runtime) => {
          if let Err(error) = runtime.block_on(container.rm()) {
            eprintln!("test_guard: failed to remove container {thread_id}: {error}");
          }
        }
        Err(error) => {
          eprintln!("test_guard: failed to build removal runtime for {thread_id}: {error}");
        }
      })
      .join();
      if outcome.is_err() {
        eprintln!("test_guard: removal thread failed for container {id}");
      }
    }
  }
}

/// Process-wide shareable slot with deterministic teardown.
///
/// The slot holds at most one live value plus a user count. Each test holds a
/// [`Lease`]; the last lease to drop evicts the value under the mutex before
/// teardown runs, so teardown is race-free and sharing is preserved while at
/// least one test still uses the value.
///
/// Acquisition is serialized by an async build lock, so concurrently starting
/// tests share one build instead of each starting (and then deterministically
/// dropping) a spare value.
pub struct Shared<T: Send + Sync + 'static> {
  inner: std::sync::Mutex<Slot<T>>,
  build: tokio::sync::Mutex<()>,
}

/// The value shared through a [`Shared`] slot plus its live-lease count.
struct Slot<T: Send + Sync + 'static> {
  /// The live shared value, if any.
  value: Option<Arc<T>>,
  /// Live leases; `value.is_some()` exactly when this is nonzero.
  users: usize,
}

impl<T: Send + Sync + 'static> Shared<T> {
  /// An empty slot, for `static` initializers.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      inner: std::sync::Mutex::new(Slot {
        value: None,
        users: 0,
      }),
      build: tokio::sync::Mutex::const_new(()),
    }
  }
}

impl<T: Send + Sync + 'static> Shared<T> {
  /// Acquire a [`Lease`] on the shared value, starting it first if needed.
  ///
  /// The starter future is lazy: when a live value already exists it is never
  /// polled and no container is started. When two tests race to start, the
  /// loser drops its spare value, whose `Drop` removes it deterministically.
  ///
  /// # Errors
  ///
  /// Returns the starter's error when starting fails.
  pub async fn lease<E>(
    &'static self,
    start: impl std::future::Future<Output = Result<T, E>>,
  ) -> Result<Lease<T>, E> {
    // Serialize acquisition: the first test builds the value while the rest
    // wait, then share it, instead of each building (and dropping) a spare.
    // The guard is released before returning; steady-state leases never block
    // on it, and `release` does not take it, so no lock ordering exists.
    let _build = self.build.lock().await;
    let fast = {
      let mut slot = lock(&self.inner);
      match slot.value.clone() {
        Some(value) => {
          slot.users += 1;
          Some(value)
        }
        None => None,
      }
    };
    if let Some(value) = fast {
      Ok(Lease {
        shared: Some(self),
        inner: value,
      })
    } else {
      let started = start.await?;
      let mut slot = lock(&self.inner);
      if let Some(value) = slot.value.clone() {
        slot.users += 1;
        drop(started);
        Ok(Lease {
          shared: Some(self),
          inner: value,
        })
      } else {
        let value = Arc::new(started);
        slot.value = Some(value.clone());
        slot.users = 1;
        Ok(Lease {
          shared: Some(self),
          inner: value,
        })
      }
    }
  }

  /// Release one lease; evict the value when the last lease goes away.
  ///
  /// The evicted `Arc` is returned so the caller drops (and thereby tears
  /// down) the value *after* releasing the mutex.
  fn release(&'static self) -> Option<Arc<T>> {
    let mut slot = lock(&self.inner);
    slot.users = slot.users.saturating_sub(1);
    if slot.users == 0 {
      slot.value.take()
    } else {
      None
    }
  }
}

/// Lock a [`Shared`] slot, recovering from poisoning.
///
/// Poisoning requires a panic while locked; test code forbids `panic!`, and
/// this function itself never panics, so poisoning is not expected. Recovering
/// (rather than skipping removal) keeps teardown deterministic in all cases.
fn lock<'a, T: Send + Sync + 'static>(
  mutex: &'a std::sync::Mutex<Slot<T>>,
) -> std::sync::MutexGuard<'a, Slot<T>> {
  match mutex.lock() {
    Ok(slot) => slot,
    Err(poison) => poison.into_inner(),
  }
}

/// A single test's hold on a [`Shared`] value.
///
/// Dereferences to the shared value. Dropping the last live lease evicts the
/// value from the slot first, then tears it down, so no later test can
/// observe a value that is already being removed.
pub struct Lease<T: Send + Sync + 'static> {
  /// Back-pointer for the user-count decrement, if the lease is shared.
  shared: Option<&'static Shared<T>>,
  /// Keeps the shared value alive for the lease's lifetime.
  inner: Arc<T>,
}

impl<T: Send + Sync + 'static> Deref for Lease<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl<T: Send + Sync + 'static> Drop for Lease<T> {
  fn drop(&mut self) {
    if let Some(shared) = self.shared {
      let evicted = shared.release();
      drop(evicted);
    }
    // `self.inner` drops here; when it was the last `Arc`, the value's own
    // `Drop` (e.g. `ContainerGuard`'s synchronous `docker rm`) runs now.
  }
}

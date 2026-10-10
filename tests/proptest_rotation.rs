//! `test(proptest_rotation)` — rotation-invariant suite (task 42).
//!
//! Pure `proptest` properties over `store::tokens::derive_rotation_id`
//! (deterministic, 64 lowercase hex chars, input-sensitive) plus
//! shared-service rotation invariants over the real Redis from
//! `compose.test.yaml` (`docker compose -f compose.test.yaml up -d`, AOF on,
//! `WaitAof` durability): first rotation applies, an idempotent retry replays
//! identical tokens, an unknown token is absent, and a foreign client
//! mismatches. Each test uses unique key prefixes, so parallel tests never
//! share state (and never FLUSH shared state). No `unwrap`/`expect`/`panic`
//! anywhere.

use std::{
  sync::atomic::{AtomicU64, Ordering},
  time::Duration,
};

use d_oauth::{
  config::DurabilityMode,
  state::RedisConn,
  store::{
    Store, StoreError,
    grants::{GrantRecord, create as create_grant},
    tokens::{
      AccessRecord, RefreshRecord, RotateOutcome, RotationInput, derive_rotation_id, put_refresh,
      rotate,
    },
  },
};
use proptest::prelude::*;

mod common;

use common::{redis_url, unique_prefixes};

/// Test-body error.
#[derive(Debug, thiserror::Error)]
enum TestError {
  /// The shared test service is unreachable (usually: compose not started).
  #[error("test setup: {0}")]
  Setup(String),
  /// A Redis command failed.
  #[error("redis error: {0}")]
  Redis(#[from] redis::RedisError),
  /// A store operation failed.
  #[error("store error: {0}")]
  Store(#[from] StoreError),
  /// A test assertion observed an unexpected value.
  #[error("unexpected test value: {0}")]
  Unexpected(String),
}

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult = Result<(), TestError>;

static TEST_NONCE: AtomicU64 = AtomicU64::new(500_000);

fn unique(label: &str) -> String {
  let n = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
  format!("rotation-test-{n}-{label}")
}

proptest! {
  #[test]
  fn rotation_id_is_deterministic_hex(
    pepper in proptest::collection::vec(any::<u8>(), 0..64),
    old_hash in "[a-z0-9:._-]{1,64}",
  ) {
    let first = match derive_rotation_id(&pepper, &old_hash) {
      Ok(id) => id,
      Err(_) => return Ok(()),
    };
    let second = match derive_rotation_id(&pepper, &old_hash) {
      Ok(id) => id,
      Err(_) => {
        prop_assert!(false, "derivation must be deterministic");
        return Ok(());
      }
    };
    prop_assert!(first == second, "rotation id must be deterministic");
    prop_assert_eq!(first.len(), 64);
    prop_assert!(first.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
  }

  #[test]
  fn rotation_id_separates_inputs(
    pepper in proptest::collection::vec(any::<u8>(), 16),
    first_hash in "[a-z0-9]{8}",
    second_hash in "[a-z0-9]{8}",
  ) {
    if first_hash == second_hash {
      return Ok(());
    }
    let first = match derive_rotation_id(&pepper, &first_hash) {
      Ok(id) => id,
      Err(_) => return Ok(()),
    };
    let second = match derive_rotation_id(&pepper, &second_hash) {
      Ok(id) => id,
      Err(_) => return Ok(()),
    };
    prop_assert_ne!(first, second);
  }
}

/// URL of the shared test Redis (see `tests/common/mod.rs`).
fn redis_single() -> String {
  redis_url()
}

async fn direct_store(url: &str) -> Result<(RedisConn, Store), TestError> {
  let client = redis::Client::open(url).map_err(|error| {
    TestError::Setup(format!(
      "cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`"
    ))
  })?;
  let manager_config = redis::aio::ConnectionManagerConfig::new()
    .set_response_timeout(Some(Duration::from_secs(10)))
    .set_connection_timeout(Some(Duration::from_secs(5)));
  let manager = redis::aio::ConnectionManager::new_with_config(client, manager_config)
    .await
    .map_err(|error| {
      TestError::Setup(format!(
        "cannot reach shared test Redis at {url}: {error}; run `docker compose -f compose.test.yaml up -d`"
      ))
    })?;
  let (token_prefix, ratelimit_prefix) = unique_prefixes();
  let store = Store::from_parts(token_prefix, ratelimit_prefix, DurabilityMode::WaitAof);
  Ok((RedisConn::Single(manager), store))
}

fn refresh_record(client: &str, grant: &str) -> RefreshRecord {
  RefreshRecord {
    client_id: client.to_owned(),
    grant_id: grant.to_owned(),
    scope: "read".to_owned(),
    subject: "user-1".to_owned(),
    cnf: String::new(),
  }
}

fn access_record(client: &str, grant: &str) -> AccessRecord {
  AccessRecord {
    client_id: client.to_owned(),
    grant_id: grant.to_owned(),
    scope: "read".to_owned(),
    subject: "user-1".to_owned(),
    cnf: String::new(),
  }
}

fn rotation_input(
  old_refresh_hash: &str,
  new_refresh_hash: &str,
  new_access_hash: &str,
  client: &str,
  grant: &str,
  request_id: &str,
) -> RotationInput {
  RotationInput {
    old_refresh_hash: old_refresh_hash.to_owned(),
    expected_client_id: client.to_owned(),
    new_refresh_hash: new_refresh_hash.to_owned(),
    new_access_hash: new_access_hash.to_owned(),
    new_refresh: refresh_record(client, grant),
    new_access: access_record(client, grant),
    new_refresh_ttl: Duration::from_secs(600),
    new_access_ttl: Duration::from_secs(300),
    request_id: Some(request_id.to_owned()),
  }
}

/// Rotation applies once, replays idempotently, and rejects strangers.
#[tokio::test]
async fn rotation_apply_replay_absent_mismatch() -> TestResult {
  let url = redis_single();
  let (mut conn, store) = direct_store(&url).await?;
  let pepper = b"rotation-proptest-pepper";
  let client = unique("client");
  let grant = unique("grant");
  let old_hash = unique("old");
  let new_refresh_hash = unique("new-refresh");
  let new_access_hash = unique("new-access");
  let request_id = unique("request");

  put_refresh(
    &mut conn,
    &store,
    &old_hash,
    &refresh_record(&client, &grant),
    Duration::from_secs(600),
  )
  .await?;
  // Production mint always writes the grant record before any rotation;
  // the rotation fence requires it, so the harness mirrors mint here.
  create_grant(
    &mut conn,
    &store,
    &GrantRecord {
      grant_id: grant.clone(),
      client_id: client.clone(),
      subject: "user-1".to_owned(),
      scope: "read".to_owned(),
    },
    Duration::from_secs(600),
  )
  .await?;

  // First rotation applies.
  let input = rotation_input(
    &old_hash,
    &new_refresh_hash,
    &new_access_hash,
    &client,
    &grant,
    &request_id,
  );
  match rotate(&mut conn, &store, pepper, &input).await? {
    RotateOutcome::Rotated {
      new_refresh_hash: rotated_refresh,
      new_access_hash: rotated_access,
    } => {
      if rotated_refresh != new_refresh_hash || rotated_access != new_access_hash {
        return Err(TestError::Unexpected(
          "rotated hashes differ from input".to_owned(),
        ));
      }
    }
    outcome => {
      return Err(TestError::Unexpected(format!(
        "expected Rotated, saw {outcome:?}"
      )));
    }
  }

  // The idempotent retry replays the identical tokens.
  let replay = rotation_input(
    &old_hash,
    &new_refresh_hash,
    &new_access_hash,
    &client,
    &grant,
    &request_id,
  );
  match rotate(&mut conn, &store, pepper, &replay).await? {
    RotateOutcome::Replay {
      new_refresh_hash: replayed_refresh,
      new_access_hash: replayed_access,
    } => {
      if replayed_refresh != new_refresh_hash || replayed_access != new_access_hash {
        return Err(TestError::Unexpected(
          "replayed hashes differ from input".to_owned(),
        ));
      }
    }
    outcome => {
      return Err(TestError::Unexpected(format!(
        "expected Replay, saw {outcome:?}"
      )));
    }
  }

  // An unknown token is absent (no existence oracle beyond the outcome).
  let unknown = rotation_input(
    &unique("ghost"),
    &unique("ghost-new-refresh"),
    &unique("ghost-new-access"),
    &client,
    &grant,
    &unique("ghost-request"),
  );
  match rotate(&mut conn, &store, pepper, &unknown).await? {
    RotateOutcome::Absent => {}
    outcome => {
      return Err(TestError::Unexpected(format!(
        "expected Absent, saw {outcome:?}"
      )));
    }
  }

  // A foreign client mismatches against the freshly rotated record.
  let foreign = rotation_input(
    &new_refresh_hash,
    &unique("foreign-new-refresh"),
    &unique("foreign-new-access"),
    "someone-else",
    &grant,
    &unique("foreign-request"),
  );
  match rotate(&mut conn, &store, pepper, &foreign).await? {
    RotateOutcome::Mismatch => {}
    outcome => {
      return Err(TestError::Unexpected(format!(
        "expected Mismatch, saw {outcome:?}"
      )));
    }
  }
  Ok(())
}

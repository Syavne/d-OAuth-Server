//! Failover: a restart never resurrects the rotated token.

use testcontainers::{
  GenericImage, ImageExt as _,
  core::{IntoContainerPort as _, WaitFor},
  runners::AsyncRunner as _,
};

use super::{TestError, TestResult, connect, dpop_proof, input, is_invalid_grant, ring, unique};
use crate::{
  config::{DurabilityMode, TtlConfig},
  protocol::{
    scope::ScopeSet,
    token::{ClientKind, MintRequest, TokenService, grants::refresh_token::refresh},
  },
  store::Store,
  test_guard::ContainerGuard,
};

/// Across a Redis restart the tombstone and mapping survive (AOF +
/// `WAITAOF` barrier): presenting the old token again never rotates twice,
/// and the current pair stays live.
#[tokio::test]
async fn grant_refresh_failover_no_double_rotation() -> TestResult {
  let container = GenericImage::new("redis", "8-alpine")
    .with_exposed_port(6379.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
    .with_cmd([
      "redis-server",
      "--appendonly",
      "yes",
      "--appendfsync",
      "always",
    ])
    .start()
    .await?;
  let guarded = ContainerGuard::new(container);
  let port = guarded.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let mut conn = connect(&url).await?;
  let store = Store::from_parts(
    "oauth:{state}:".to_owned(),
    "oauth:{rl}:".to_owned(),
    DurabilityMode::WaitAof,
  );
  let service = TokenService::new(&TtlConfig::default(), &ring()?).map_err(TestError::from)?;
  let client = unique("failover-client");
  let proof = dpop_proof(&unique("failover-jkt"));
  let minted = service
    .mint(
      &mut conn,
      &store,
      &MintRequest {
        client_id: client.clone(),
        client_kind: ClientKind::Public,
        subject: unique("failover-subject"),
        scope: "read".to_owned(),
        grant_id: unique("failover-grant"),
        proof: proof.clone(),
      },
      super::now_unix(),
    )
    .await?;
  let enabled = ScopeSet::parse("read")?;
  let current = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await?;
  drop(conn);

  guarded.stop_with_timeout(Some(10)).await?;
  guarded.start().await?;
  let port = guarded.get_host_port_ipv4(6379).await?;
  let url = format!("redis://127.0.0.1:{port}");
  let mut conn = connect(&url).await?;

  let again = refresh(
    &mut conn,
    &store,
    &service,
    &input(
      &client,
      ClientKind::Public,
      &minted.refresh_token,
      None,
      &proof,
      &enabled,
    ),
  )
  .await;
  let error = match again {
    Ok(_) => {
      return Err(TestError::Unexpected(
        "post-failover double rotation".to_owned(),
      ));
    }
    Err(error) => error,
  };
  if !is_invalid_grant(&error) {
    return Err(TestError::Unexpected(format!(
      "failover code: {}",
      error.code()
    )));
  }
  let live = service
    .find_refresh(&mut conn, &store, &current.refresh_token)
    .await?;
  if live.is_none() {
    return Err(TestError::Unexpected(
      "failover locked out the current pair".to_owned(),
    ));
  }
  Ok(())
}

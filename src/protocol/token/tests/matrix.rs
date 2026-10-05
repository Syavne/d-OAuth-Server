//! Sender-constraint matrix: public clients hard-require a `jkt`,
//! confidential clients record whatever was proven.

use super::{
  super::{ClientKind, SenderProof},
  TestError, TestResult, mint_request, now_unix, service, test_redis, unique,
};

/// Public mint without a `jkt` is rejected; confidential mint is not.
#[tokio::test]
async fn token_service_public_mint_requires_jkt() -> TestResult {
  let (_redis, mut conn, store) = test_redis().await?;
  let service = service(&[("v1", "token-service-pepper-one")])?;
  let grant = unique("grant");
  let client = unique("client");
  let now = now_unix();

  let bare = SenderProof::none();
  if service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, ClientKind::Public, &grant, bare),
      now,
    )
    .await
    .is_ok()
  {
    return Err(TestError::Unexpected(
      "public mint without a jkt must fail".to_owned(),
    ));
  }
  let empty_jkt = SenderProof {
    dpop_jkt: Some(String::new()),
    mtls_x5t_s256: None,
  };
  if service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, ClientKind::Public, &grant, empty_jkt),
      now,
    )
    .await
    .is_ok()
  {
    return Err(TestError::Unexpected(
      "public mint with an empty jkt must fail".to_owned(),
    ));
  }

  let bound = SenderProof {
    dpop_jkt: Some("public-dpop-jkt".to_owned()),
    mtls_x5t_s256: None,
  };
  let public = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, ClientKind::Public, &grant, bound),
      now,
    )
    .await?;
  if public.cnf.jkt.as_deref() != Some("public-dpop-jkt") {
    return Err(TestError::Unexpected(
      "public cnf must carry the proven jkt".to_owned(),
    ));
  }
  let found = service
    .find_access(&mut conn, &store, &public.access_token)
    .await?;
  if found.is_none_or(|located| located.record.cnf.is_empty()) {
    return Err(TestError::Unexpected(
      "public record must persist its cnf".to_owned(),
    ));
  }

  let both = SenderProof {
    dpop_jkt: Some("conf-dpop-jkt".to_owned()),
    mtls_x5t_s256: Some("conf-x5t-value".to_owned()),
  };
  let confidential = service
    .mint(
      &mut conn,
      &store,
      &mint_request(&client, ClientKind::Confidential, &grant, both),
      now,
    )
    .await?;
  if confidential.cnf.jkt.as_deref() != Some("conf-dpop-jkt")
    || confidential.cnf.x5t_s256.as_deref() != Some("conf-x5t-value")
  {
    return Err(TestError::Unexpected(
      "confidential cnf must record both proven bindings".to_owned(),
    ));
  }
  Ok(())
}

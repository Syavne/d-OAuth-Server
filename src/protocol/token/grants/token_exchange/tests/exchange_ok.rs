//! Happy path: allowlisted exchange mints a scoped, `act`-bound token.

use super::super::{exchange, exchange_ttl, read_act};
use super::{Ctx, TestError, TestResult, dpop_proof, input, mint_subject, now_unix, service};
use super::{test_redis, unique};
use crate::config::TokenExchangeRule;
use crate::protocol::scope::ScopeSet;

#[tokio::test]
async fn grant_token_exchange_allowlisted_succeeds() -> TestResult {
  let (mut conn, store) = test_redis().await?;
  let service = service()?;
  let caller = unique("caller");
  let subject_client = unique("subject-client");
  let subject_raw = mint_subject(
    &service,
    &mut conn,
    &store,
    &subject_client,
    "user-1",
    "api:read api:write",
    dpop_proof("subject-jkt"),
  )
  .await?;
  let caller_registered = ScopeSet::parse("api:read api:write")?;
  let entitled = ScopeSet::parse("api:read api:write")?;
  let enabled = ScopeSet::parse("api:read api:write")?;
  let allowlist = vec![TokenExchangeRule {
    caller: caller.clone(),
    subject: subject_client.clone(),
    scopes: vec!["api:read".to_owned(), "api:write".to_owned()],
  }];
  let proof = dpop_proof("subject-jkt");
  let ctx = Ctx {
    caller_registered: &caller_registered,
    entitled: &entitled,
    enabled: &enabled,
    allowlist: &allowlist,
    proof: &proof,
  };
  let exchanged = exchange(
    &mut conn,
    &store,
    &service,
    &input(&caller, &subject_raw, Some("api:read"), &ctx),
  )
  .await?;
  if exchanged.scope != "api:read" {
    return Err(TestError::Unexpected(
      "issued scope must be the requested subset".to_owned(),
    ));
  }
  if exchanged.subject != "user-1" {
    return Err(TestError::Unexpected(
      "subject must carry over from the subject token".to_owned(),
    ));
  }
  if exchanged.act.sub != subject_client {
    return Err(TestError::Unexpected(
      "act.sub must name the subject token client".to_owned(),
    ));
  }
  if exchanged.token_type != "DPoP" {
    return Err(TestError::Unexpected(
      "jkt-bound exchange must report DPoP".to_owned(),
    ));
  }
  if exchanged.cnf.jkt.as_deref() != Some("subject-jkt") {
    return Err(TestError::Unexpected(
      "new token must carry the proven subject key".to_owned(),
    ));
  }
  let ttl_secs = exchange_ttl(&service).as_secs() as i64;
  if exchange_ttl(&service) >= service.access_ttl() {
    return Err(TestError::Unexpected(
      "exchange TTL must be shorter than the access TTL".to_owned(),
    ));
  }
  let skew = exchanged.access_expires_at - now_unix();
  if skew > ttl_secs || skew < ttl_secs - 10 {
    return Err(TestError::Unexpected(
      "exchanged token must expire on the shortened TTL".to_owned(),
    ));
  }
  if read_act(&mut conn, &store, &exchanged.access_hash)
    .await?
    .is_none()
  {
    return Err(TestError::Unexpected(
      "act sidecar must be readable after exchange".to_owned(),
    ));
  }
  let members: Vec<String> = redis::cmd("SMEMBERS")
    .arg(store.grant_tokens_key(&exchanged.grant_id))
    .query_async(&mut conn)
    .await?;
  if members != vec![exchanged.access_hash.clone()] {
    return Err(TestError::Unexpected(
      "grant set must hold only the access token (no refresh issued)".to_owned(),
    ));
  }
  Ok(())
}

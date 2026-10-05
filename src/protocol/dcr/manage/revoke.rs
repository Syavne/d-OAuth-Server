//! Per-client token revocation for RFC 7592 `DELETE`.
//!
//! Token records carry no per-client index (the grant set is the only
//! index), so revocation scans the access and refresh keyspaces with
//! `SCAN MATCH <prefix>* COUNT 100`, filters on the record's `client_id`
//! field, and deletes what it owns. Refresh-owned families cascade through
//! [`grants::revoke`]; owned access keys delete directly (plus their grant
//! membership). Tombstoned refresh keys still carry `client_id` and are
//! deleted outright. `DELETE` is an rare administrative call, so a bounded
//! linear scan is proportionate; on Cluster topologies the scan covers the
//! contacted node only (documented limit — Single and Sentinel scan fully).

use std::collections::{HashMap, HashSet};

use crate::error::AppError;
use crate::state::RedisConn;
use crate::store::{Store, StoreError, grants};

/// How many records one revocation pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevokedTokens {
  /// Access-token records deleted.
  pub access: u64,
  /// Refresh-token records (live or tombstoned) deleted.
  pub refresh: u64,
  /// Grant families cascade-revoked.
  pub grants: u64,
}

/// Revoke every access and refresh token owned by `client_id`.
///
/// # Errors
///
/// Returns a fail-closed store failure when Redis is unavailable.
pub async fn revoke_client_tokens(
  conn: &mut RedisConn,
  store: &Store,
  client_id: &str,
) -> Result<RevokedTokens, AppError> {
  let mut summary = RevokedTokens::default();

  let refresh_keys = scan_keys(conn, &store.refresh_key_prefix()).await?;
  let mut grant_ids: HashSet<String> = HashSet::new();
  let mut owned_refresh: Vec<String> = Vec::new();
  for key in refresh_keys {
    let fields = read_fields(conn, &key).await?;
    if is_owned(&fields, client_id) {
      if let Some(grant) = fields.get("grant_id").cloned()
        && !grant.is_empty()
      {
        grant_ids.insert(grant);
      }
      owned_refresh.push(key);
    }
  }
  for grant_id in &grant_ids {
    grants::revoke(conn, store, grant_id)
      .await
      .map_err(AppError::from)?;
    summary.grants += 1;
  }
  for key in &owned_refresh {
    del_key(conn, key).await?;
    summary.refresh += 1;
  }

  let access_keys = scan_keys(conn, &store.access_key_prefix()).await?;
  for key in access_keys {
    let fields = read_fields(conn, &key).await?;
    if is_owned(&fields, client_id) {
      if let (Some(hash), Some(grant)) = (
        key.strip_prefix(&store.access_key_prefix()),
        fields.get("grant_id"),
      ) {
        let _: () = redis::cmd("SREM")
          .arg(store.grant_tokens_key(grant))
          .arg(hash)
          .query_async(conn)
          .await
          .map_err(store_mapped)?;
      }
      del_key(conn, &key).await?;
      summary.access += 1;
    }
  }
  Ok(summary)
}

/// List every key under `prefix` with a bounded `SCAN` loop.
async fn scan_keys(conn: &mut RedisConn, prefix: &str) -> Result<Vec<String>, AppError> {
  let pattern = format!("{prefix}*");
  let mut cursor = "0".to_owned();
  let mut out = Vec::new();
  loop {
    let (next, batch): (String, Vec<String>) = redis::cmd("SCAN")
      .arg(&cursor)
      .arg("MATCH")
      .arg(&pattern)
      .arg("COUNT")
      .arg(100)
      .query_async(conn)
      .await
      .map_err(store_mapped)?;
    out.extend(batch);
    if next == "0" {
      break;
    }
    cursor = next;
  }
  Ok(out)
}

/// Read one record's hash fields; a missing key reads as empty.
async fn read_fields(conn: &mut RedisConn, key: &str) -> Result<HashMap<String, String>, AppError> {
  redis::cmd("HGETALL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(store_mapped)
}

/// Whether a record's `client_id` field names this client.
fn is_owned(fields: &HashMap<String, String>, client_id: &str) -> bool {
  fields
    .get("client_id")
    .is_some_and(|owner| owner == client_id)
}

/// Delete one key.
async fn del_key(conn: &mut RedisConn, key: &str) -> Result<(), AppError> {
  let _: () = redis::cmd("DEL")
    .arg(key)
    .query_async(conn)
    .await
    .map_err(store_mapped)?;
  Ok(())
}

/// Map a Redis failure onto the fail-closed store policy (transient outages
/// render `503`, everything else is masked).
fn store_mapped(error: redis::RedisError) -> AppError {
  AppError::from(StoreError::Redis(error))
}

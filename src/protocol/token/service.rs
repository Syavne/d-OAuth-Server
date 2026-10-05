//! Opaque token service: minting, hash-at-rest lookup, and revocation.
//!
//! Low-level records and atomic rotation live in [`crate::store::tokens`]
//! (task 12); this layer adds minting (raw token plus versioned keyed hash),
//! the fixed sender-constraint matrix ([`super::types`]), pepper-retried
//! lookup, single-token and grant revocation, and idempotent rotation keyed
//! by request id.
//!
//! Raw tokens never touch storage: only
//! [`crypto::tokens::TokenHash::to_storage_string`] values are persisted or
//! used as keys. `iat`/`exp` are enforced by the Redis TTL on each record
//! (task-12 pattern) and reported on [`MintedTokens`] for response shaping.

use std::time::Duration;

use secrecy::ExposeSecret;

use super::types::{
  FoundAccess, FoundRefresh, MintRequest, MintedTokens, TokenServiceError, resolve_cnf,
};
use crate::{
  config::TtlConfig,
  crypto::tokens as crypto_tokens,
  keys::KeyRing,
  state::RedisConn,
  store::{Store, StoreError, durability_barrier, grants, tokens as low},
};

/// One retained pepper generation, newest-first.
#[derive(Debug, Clone)]
struct PepperKey {
  /// Numeric generation for [`crypto_tokens::token_hash`].
  generation: crypto_tokens::KeyId,
  /// String label (`v<N>`) for audit.
  label: String,
  /// Raw pepper bytes.
  secret: Vec<u8>,
}

/// Token minting plus hash-at-rest lookup, revocation, and rotation.
#[derive(Debug, Clone)]
pub struct TokenService {
  /// Access-token lifetime.
  access_ttl: Duration,
  /// Refresh-token lifetime.
  refresh_ttl: Duration,
  /// Retained peppers, newest-first, bounded by
  /// [`crypto_tokens::MAX_RETAINED_KEYS`].
  keys: Vec<PepperKey>,
}

impl TokenService {
  /// Build a service from the validated TTLs and key ring.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::NoPepper`] when the ring holds no pepper.
  pub fn new(ttl: &TtlConfig, ring: &KeyRing) -> Result<Self, TokenServiceError> {
    let mut keys = Vec::new();
    for (id, secret) in ring
      .peppers_newest_first()
      .take(crypto_tokens::MAX_RETAINED_KEYS)
    {
      let generation = id
        .as_str()
        .trim_start_matches('v')
        .parse::<u32>()
        .unwrap_or(1);
      keys.push(PepperKey {
        generation: crypto_tokens::KeyId::new(generation),
        label: id.as_str().to_owned(),
        secret: secret.expose_secret().as_bytes().to_vec(),
      });
    }
    if keys.is_empty() {
      return Err(TokenServiceError::NoPepper);
    }
    Ok(Self {
      access_ttl: ttl.access,
      refresh_ttl: ttl.refresh,
      keys,
    })
  }

  /// The access-token lifetime.
  #[must_use]
  pub const fn access_ttl(&self) -> Duration {
    self.access_ttl
  }

  /// The refresh-token lifetime.
  #[must_use]
  pub const fn refresh_ttl(&self) -> Duration {
    self.refresh_ttl
  }

  /// The active (newest) pepper; minting always hashes under it.
  fn active(&self) -> Result<&PepperKey, TokenServiceError> {
    self.keys.first().ok_or(TokenServiceError::NoPepper)
  }

  /// Hash a raw token under one retained generation for store lookup.
  fn hash_under(&self, key: &PepperKey, raw: &str) -> String {
    crypto_tokens::token_hash(&key.generation, &key.secret, raw).to_storage_string()
  }
}

impl TokenService {
  /// Mint an access plus refresh pair and persist only their hashes.
  ///
  /// Also ensures the grant-chain record exists (idempotent rewrite) and
  /// indexes both hashes in the per-grant set, so reuse anywhere in the
  /// chain can cascade.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::MissingDpopBinding`] for a public client
  /// without a `jkt`, or the crypto/store failure.
  pub async fn mint(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    request: &MintRequest,
    now_unix: i64,
  ) -> Result<MintedTokens, TokenServiceError> {
    let cnf = resolve_cnf(request.client_kind, &request.proof)?;
    let cnf_json = cnf.to_storage()?;
    let access_raw = crypto_tokens::mint_token()?;
    let refresh_raw = crypto_tokens::mint_token()?;
    let active = self.active()?;
    let access_hash = self.hash_under(active, &access_raw);
    let refresh_hash = self.hash_under(active, &refresh_raw);
    let access = low::AccessRecord {
      client_id: request.client_id.clone(),
      grant_id: request.grant_id.clone(),
      scope: request.scope.clone(),
      subject: request.subject.clone(),
      cnf: cnf_json.clone(),
    };
    let refresh = low::RefreshRecord {
      client_id: request.client_id.clone(),
      grant_id: request.grant_id.clone(),
      scope: request.scope.clone(),
      subject: request.subject.clone(),
      cnf: cnf_json,
    };
    grants::create(
      conn,
      store,
      &grants::GrantRecord {
        grant_id: request.grant_id.clone(),
        client_id: request.client_id.clone(),
        subject: request.subject.clone(),
        scope: request.scope.clone(),
      },
      self.refresh_ttl,
    )
    .await?;
    low::put_access(conn, store, &access_hash, &access, self.access_ttl).await?;
    low::put_refresh(conn, store, &refresh_hash, &refresh, self.refresh_ttl).await?;
    Ok(MintedTokens {
      access_token: access_raw,
      refresh_token: refresh_raw,
      access_hash,
      refresh_hash,
      cnf,
      issued_at: now_unix,
      access_expires_at: now_unix.saturating_add(self.access_ttl.as_secs() as i64),
      refresh_expires_at: now_unix.saturating_add(self.refresh_ttl.as_secs() as i64),
    })
  }

  /// Find an access token, retrying retained peppers newest-first.
  ///
  /// # Errors
  ///
  /// Returns the store failure; absence is `Ok(None)`.
  pub async fn find_access(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    raw_token: &str,
  ) -> Result<Option<FoundAccess>, TokenServiceError> {
    for key in &self.keys {
      let hash = self.hash_under(key, raw_token);
      if let Some(record) = low::get_access(conn, store, &hash).await? {
        return Ok(Some(FoundAccess {
          record,
          hash,
          key_label: key.label.clone(),
        }));
      }
    }
    Ok(None)
  }

  /// Find a refresh token, retrying retained peppers newest-first.
  ///
  /// # Errors
  ///
  /// Returns the store failure; absence is `Ok(None)`.
  pub async fn find_refresh(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    raw_token: &str,
  ) -> Result<Option<FoundRefresh>, TokenServiceError> {
    for key in &self.keys {
      let hash = self.hash_under(key, raw_token);
      if let Some(record) = low::get_refresh(conn, store, &hash).await? {
        return Ok(Some(FoundRefresh {
          record,
          hash,
          key_label: key.label.clone(),
        }));
      }
    }
    Ok(None)
  }

  /// Revoke one token by its raw value: delete both record slots (a hash may
  /// legally sit in either) and drop the hash from the grant set.
  ///
  /// # Errors
  ///
  /// Returns the store failure; unknown tokens report `Ok(false)`.
  pub async fn revoke_token(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    raw_token: &str,
  ) -> Result<bool, TokenServiceError> {
    let located = if let Some(found) = self.find_access(conn, store, raw_token).await? {
      Some((found.hash, found.record.grant_id))
    } else if let Some(found) = self.find_refresh(conn, store, raw_token).await? {
      Some((found.hash, found.record.grant_id))
    } else {
      None
    };
    let (hash, grant_id) = match located {
      Some(pair) => pair,
      None => return Ok(false),
    };
    let access_key = store.access_key(&hash);
    let refresh_key = store.refresh_key(&hash);
    let set_key = store.grant_tokens_key(&grant_id);
    let _: () = redis::cmd("DEL")
      .arg(&access_key)
      .arg(&refresh_key)
      .query_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    let _: () = redis::cmd("SREM")
      .arg(&set_key)
      .arg(&hash)
      .query_async(conn)
      .await
      .map_err(StoreError::Redis)?;
    durability_barrier(conn, store).await?;
    Ok(true)
  }

  /// Cascade-revoke a grant chain: delete every member token plus the grant
  /// set and record (single-slot Lua, no `KEYS` scan).
  ///
  /// # Errors
  ///
  /// Returns the store failure.
  pub async fn revoke_grant(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    grant_id: &str,
  ) -> Result<u64, TokenServiceError> {
    grants::revoke(conn, store, grant_id)
      .await
      .map_err(TokenServiceError::from)
  }

  /// Derive the deterministic `rotation_request_id` for an old refresh hash
  /// under the active pepper.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::NoPepper`] when the ring is empty.
  pub fn request_id_for(&self, old_refresh_hash: &str) -> Result<String, TokenServiceError> {
    let active = self.active()?;
    low::derive_rotation_id(&active.secret, old_refresh_hash).map_err(TokenServiceError::from)
  }

  /// Atomically rotate a refresh token (compare-and-set with reuse signal).
  ///
  /// The caller mints the new pair first and fixes `request_id`; a replay of
  /// the same request id returns the SAME hashes
  /// ([`low::RotateOutcome::Replay`]), while a tombstoned old token without a
  /// mapping triggers the grant-cascade reuse path.
  ///
  /// # Errors
  ///
  /// Returns the store failure.
  pub async fn rotate(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    input: &low::RotationInput,
  ) -> Result<low::RotateOutcome, TokenServiceError> {
    let active = self.active()?;
    low::rotate(conn, store, &active.secret, input)
      .await
      .map_err(TokenServiceError::from)
  }

  /// Inspect the rotation tombstone for a raw refresh token: `Ok(Some(target))`
  /// when it was rotated (to `target` hash), `Ok(None)` when live or absent.
  ///
  /// The lookup retries retained peppers newest-first like [`Self::find_refresh`].
  ///
  /// # Errors
  ///
  /// Returns the store failure.
  pub async fn consume_tombstone(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    raw_token: &str,
  ) -> Result<Option<String>, TokenServiceError> {
    for key in &self.keys {
      let hash = self.hash_under(key, raw_token);
      if let Some(target) = low::tombstone_of(conn, store, &hash).await? {
        return Ok(Some(target));
      }
    }
    Ok(None)
  }
}

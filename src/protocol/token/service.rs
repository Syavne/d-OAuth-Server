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

use std::{fmt, time::Duration};

use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::types::{
  FoundAccess, FoundRefresh, MintRequest, MintedTokens, TokenFormat, TokenServiceError, resolve_cnf,
};
use crate::{
  config::TtlConfig,
  crypto::tokens as crypto_tokens,
  jose::jwt_access::{JwtAccessSigner, JwtClaims, jti_hash},
  keys::KeyRing,
  state::RedisConn,
  store::{Store, StoreError, durability_barrier, grants, tokens as low},
};

/// One retained pepper generation, newest-first.
///
/// The raw pepper never reaches `Debug`: only the generation, label, and
/// material length are printed (the [`KeyRing`] ids-only pattern).
#[derive(Clone)]
struct PepperKey {
  /// Verbatim generation for [`crypto_tokens::token_hash`].
  generation: crypto_tokens::KeyId,
  /// String label (`v<N>`) for audit.
  label: String,
  /// Raw pepper bytes, wiped on drop.
  secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PepperKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("PepperKey")
      .field("generation", &self.generation)
      .field("label", &self.label)
      .field("secret", &"[REDACTED]")
      .field("secret_len", &self.secret.len())
      .finish()
  }
}

/// Token minting plus hash-at-rest lookup, revocation, and rotation.
///
/// `Debug` prints lifetimes plus the retained pepper ids and material
/// lengths only, never raw pepper bytes or token strings.
#[derive(Clone)]
pub struct TokenService {
  /// Access-token lifetime.
  access_ttl: Duration,
  /// Refresh-token lifetime.
  refresh_ttl: Duration,
  /// Retained peppers, newest-first, bounded by
  /// [`crypto_tokens::MAX_RETAINED_KEYS`].
  keys: Vec<PepperKey>,
  /// JWT signer for `TokenFormat::Jwt` mints, attached per request by the
  /// dispatcher (which owns the config). `None` mints opaque only; a `Jwt`
  /// mint without a signer fails closed instead of minting opaque.
  jwt: Option<JwtAccessSigner>,
}

impl fmt::Debug for TokenService {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let key_labels: Vec<&str> = self.keys.iter().map(|key| key.label.as_str()).collect();
    let secret_lens: Vec<usize> = self.keys.iter().map(|key| key.secret.len()).collect();
    f.debug_struct("TokenService")
      .field("access_ttl", &self.access_ttl)
      .field("refresh_ttl", &self.refresh_ttl)
      .field("key_labels", &key_labels)
      .field("secret_lens", &secret_lens)
      .field("jwt_configured", &self.jwt.is_some())
      .finish()
  }
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
      keys.push(PepperKey {
        generation: crypto_tokens::KeyId::new(id.as_str()),
        label: id.as_str().to_owned(),
        secret: Zeroizing::new(secret.expose_secret().as_bytes().to_vec()),
      });
    }
    if keys.is_empty() {
      return Err(TokenServiceError::NoPepper);
    }
    Ok(Self {
      access_ttl: ttl.access,
      refresh_ttl: ttl.refresh,
      keys,
      jwt: None,
    })
  }

  /// Attach the JWT signer for `TokenFormat::Jwt` mints on this request.
  ///
  /// The dispatcher builds the signer from the validated config; the service
  /// never touches [`crate::config::Config`], so key selection stays in one
  /// place. Opaque mints ignore the signer.
  #[must_use]
  pub fn with_jwt_signer(mut self, signer: JwtAccessSigner) -> Self {
    self.jwt = Some(signer);
    self
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
    crypto_tokens::token_hash(&key.generation, key.secret.as_slice(), raw).to_storage_string()
  }
}

/// Minted tokens are 32 random bytes base64url-encoded without padding
/// ([`crypto_tokens::TOKEN_STR_LEN`] chars); anything else cannot resolve to
/// a stored hash, so reject it before HMAC and Redis work. This is a cost
/// guard only: well-formed lookups still retry retained peppers
/// newest-first, so the gate does not mask generation probing.
fn is_well_formed_token(raw: &str) -> bool {
  raw.len() == crypto_tokens::TOKEN_STR_LEN
    && raw
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    self.mint_inner(conn, store, request, now_unix, true).await
  }

  /// Mint a rotation-candidate pair, deferring the durability barrier to the
  /// rotation that commits it.
  ///
  /// Only [`Self::rotate`] (via the refresh grant) may use this: the pair is
  /// unreachable until the rotation script commits it, and the rotation's own
  /// barrier runs on the same connection afterwards, so it covers these
  /// writes before any response. A barrier failure after the originating
  /// write applied then resolves to the minted pair instead of locking out.
  ///
  /// # Errors
  ///
  /// Returns [`TokenServiceError::MissingDpopBinding`] for a public client
  /// without a `jkt`, or the crypto/store failure.
  pub async fn mint_for_rotation(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    request: &MintRequest,
    now_unix: i64,
  ) -> Result<MintedTokens, TokenServiceError> {
    self.mint_inner(conn, store, request, now_unix, false).await
  }

  /// Mint body shared by [`Self::mint`] (barriered) and
  /// [`Self::mint_for_rotation`] (barrier deferred to the rotation).
  async fn mint_inner(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    request: &MintRequest,
    now_unix: i64,
    apply_barrier: bool,
  ) -> Result<MintedTokens, TokenServiceError> {
    if request.format == TokenFormat::Jwt {
      return self
        .mint_jwt(conn, store, request, now_unix, apply_barrier)
        .await;
    }
    let cnf = resolve_cnf(request.client_kind, &request.proof, request.dpop_required)?;
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
      aud: request.aud.clone(),
    };
    let refresh = low::RefreshRecord {
      client_id: request.client_id.clone(),
      grant_id: request.grant_id.clone(),
      scope: request.scope.clone(),
      subject: request.subject.clone(),
      cnf: cnf_json,
      aud: request.refresh_aud.clone(),
    };
    grants::create(
      conn,
      store,
      &grants::GrantRecord {
        grant_id: request.grant_id.clone(),
        client_id: request.client_id.clone(),
        subject: request.subject.clone(),
        scope: request.scope.clone(),
        aud: request.refresh_aud.clone(),
      },
      self.refresh_ttl,
    )
    .await?;
    if apply_barrier {
      low::put_access(conn, store, &access_hash, &access, self.access_ttl).await?;
      low::put_refresh(conn, store, &refresh_hash, &refresh, self.refresh_ttl).await?;
    } else {
      low::put_access_pending(conn, store, &access_hash, &access, self.access_ttl).await?;
      low::put_refresh_pending(conn, store, &refresh_hash, &refresh, self.refresh_ttl).await?;
    }
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

  /// Mint the JWT branch: the access token returned to the client is a
  /// signed RFC 9068 `at+jwt` (JOSE header `typ`/`kid`/`alg` from the
  /// signer, claims `iss`/`sub`/`aud`/`scope`/`exp`/`iat`/`jti`/`client_id`
  /// plus `cnf` when the sender-constraint matrix bound one; RFC 9068
  /// §2.1/§2.2/§4, audience from RFC 8707 §2). `aud` is the narrowed access
  /// set ([`MintRequest::aud`]), never the refresh/grant set.
  ///
  /// Storage design: the access RECORD is still written (same fields as the
  /// opaque path) under the member identity `jwt:<jti-hash>` — a value
  /// derived from the returned token's own `jti`, never a pepper hash of a
  /// value the client never sees — plus the grant-set `SADD` and the
  /// `jwt:<jti-hash>` allowlist marker hash (`grant_id`/`client_id`/`subject`,
  /// TTL = `access_ttl`), all in ONE Lua script on the barriered fresh path
  /// ([`low::put_access_jwt`]). The rotation pre-mint
  /// (`apply_barrier == false`) writes the record plus the `SADD` through
  /// the pending pair and writes NO marker: a marker must only exist next to
  /// a committed membership, so the pre-mint cannot create one for a pair a
  /// later REUSE/REPLAY/ABSENT/MISMATCH outcome discards. The refresh half
  /// stays an opaque token in every format; rotation semantics are
  /// unchanged. The `jti` comes from the existing token RNG (never a
  /// counter or a value predictable from the record), and the marker stores
  /// the raw subject string (empty for client-credentials) with no JWT bytes.
  async fn mint_jwt(
    &self,
    conn: &mut RedisConn,
    store: &Store,
    request: &MintRequest,
    now_unix: i64,
    apply_barrier: bool,
  ) -> Result<MintedTokens, TokenServiceError> {
    let signer = self
      .jwt
      .as_ref()
      .ok_or(TokenServiceError::JwtSignerMissing)?;
    let cnf = resolve_cnf(request.client_kind, &request.proof, request.dpop_required)?;
    let cnf_json = cnf.to_storage()?;
    let jti_raw = crypto_tokens::mint_token()?;
    let member = format!("jwt:{}", jti_hash(&jti_raw));
    let issued_at = now_unix;
    let access_expires_at = now_unix.saturating_add(self.access_ttl.as_secs() as i64);
    let claims = JwtClaims {
      iss: signer.issuer().to_owned(),
      sub: request.subject.clone(),
      aud: request.aud.clone(),
      scope: request.scope.clone(),
      exp: access_expires_at,
      iat: issued_at,
      jti: jti_raw,
      client_id: request.client_id.clone(),
      cnf: if cnf.is_bound() {
        Some(cnf.clone())
      } else {
        None
      },
      act: None,
    };
    let access_token = signer.sign(&claims)?;
    let refresh_raw = crypto_tokens::mint_token()?;
    let active = self.active()?;
    let refresh_hash = self.hash_under(active, &refresh_raw);
    let access = low::AccessRecord {
      client_id: request.client_id.clone(),
      grant_id: request.grant_id.clone(),
      scope: request.scope.clone(),
      subject: request.subject.clone(),
      cnf: cnf_json.clone(),
      aud: request.aud.clone(),
    };
    let refresh = low::RefreshRecord {
      client_id: request.client_id.clone(),
      grant_id: request.grant_id.clone(),
      scope: request.scope.clone(),
      subject: request.subject.clone(),
      cnf: cnf_json,
      aud: request.refresh_aud.clone(),
    };
    grants::create(
      conn,
      store,
      &grants::GrantRecord {
        grant_id: request.grant_id.clone(),
        client_id: request.client_id.clone(),
        subject: request.subject.clone(),
        scope: request.scope.clone(),
        aud: request.refresh_aud.clone(),
      },
      self.refresh_ttl,
    )
    .await?;
    if apply_barrier {
      low::put_access_jwt(conn, store, &member, &access, self.access_ttl).await?;
      low::put_refresh(conn, store, &refresh_hash, &refresh, self.refresh_ttl).await?;
    } else {
      low::put_access_pending(conn, store, &member, &access, self.access_ttl).await?;
      low::put_refresh_pending(conn, store, &refresh_hash, &refresh, self.refresh_ttl).await?;
    }
    Ok(MintedTokens {
      access_token,
      refresh_token: refresh_raw,
      access_hash: member,
      refresh_hash,
      cnf,
      issued_at,
      access_expires_at,
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
    if !is_well_formed_token(raw_token) {
      return Ok(None);
    }
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
    if !is_well_formed_token(raw_token) {
      return Ok(None);
    }
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
    if !is_well_formed_token(raw_token) {
      return Ok(false);
    }
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
    low::derive_rotation_id(active.secret.as_slice(), old_refresh_hash)
      .map_err(TokenServiceError::from)
  }

  /// Atomically rotate a refresh token (compare-and-set with reuse signal).
  ///
  /// The caller mints the new pair first and fixes `request_id`; a replay of
  /// the same request id returns the SAME hashes
  /// ([`low::RotateOutcome::Replay`]), while a tombstoned old token without a
  /// mapping triggers the grant-cascade reuse path. A barrier failure after
  /// the originating write applied returns the minted pair as
  /// [`low::RotateOutcome::RotatedUnbarriered`] instead of a lockout error.
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
    low::rotate(conn, store, active.secret.as_slice(), input)
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
    if !is_well_formed_token(raw_token) {
      return Ok(None);
    }
    for key in &self.keys {
      let hash = self.hash_under(key, raw_token);
      if let Some(target) = low::tombstone_of(conn, store, &hash).await? {
        return Ok(Some(target));
      }
    }
    Ok(None)
  }
}

#[cfg(test)]
mod debug_redaction_tests {
  use secrecy::SecretString;

  use super::super::types::{Cnf, MintedTokens};
  use super::*;
  use crate::{
    config::TtlConfig,
    keys::{KeyId, KeyRing},
    store::tokens::{AccessRecord, RefreshRecord},
  };

  #[test]
  fn token_debug_redacts_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let access_sentinel = "access-sentinel-7f3a9c2e";
    let refresh_sentinel = "refresh-sentinel-4b8d1f6a";
    let minted = MintedTokens {
      access_token: access_sentinel.to_owned(),
      refresh_token: refresh_sentinel.to_owned(),
      access_hash: "v1.test-access-hash".to_owned(),
      refresh_hash: "v1.test-refresh-hash".to_owned(),
      cnf: Cnf::default(),
      issued_at: 1_700_000_000,
      access_expires_at: 1_700_003_600,
      refresh_expires_at: 1_700_086_400,
    };
    let minted_debug = format!("{minted:?}");
    assert!(
      minted_debug.contains("[REDACTED]"),
      "MintedTokens Debug must carry the redaction marker"
    );
    assert!(
      !minted_debug.contains(access_sentinel),
      "MintedTokens Debug leaked the raw access token"
    );
    assert!(
      !minted_debug.contains(refresh_sentinel),
      "MintedTokens Debug leaked the raw refresh token"
    );
    assert!(minted_debug.contains("v1.test-access-hash"));
    assert!(minted_debug.contains("v1.test-refresh-hash"));

    let ttl = TtlConfig {
      access: Duration::from_secs(3600),
      refresh: Duration::from_secs(86_400),
      ..TtlConfig::default()
    };
    let ring = KeyRing::from_parts(
      vec![(
        KeyId::new("v1"),
        SecretString::from("redact-pepper-sentinel-0123456789abcdef"),
      )],
      vec![(KeyId::new("v1"), SecretString::from("totp-secret"))],
      vec![(KeyId::new("v1"), SecretString::from("pii-secret"))],
    )?;
    let service = TokenService::new(&ttl, &ring)?;
    let service_debug = format!("{service:?}");
    assert!(
      service_debug.contains("v1"),
      "TokenService Debug must keep the pepper id"
    );
    assert!(
      !service_debug.contains("redact-pepper-sentinel"),
      "TokenService Debug leaked raw pepper bytes"
    );
    assert!(
      !service_debug.contains("secret: ["),
      "TokenService Debug leaked raw pepper byte array"
    );

    // The pepper itself redacts through the `[REDACTED]` marker: assert the
    // marker is present (positive lock), not just that the sentinel is
    // absent.
    let pepper = PepperKey {
      generation: crypto_tokens::KeyId::new("v1"),
      label: "v1".to_owned(),
      secret: Zeroizing::new(b"redact-pepper-sentinel-0123456789abcdef".to_vec()),
    };
    let pepper_debug = format!("{pepper:?}");
    assert!(
      pepper_debug.contains("[REDACTED]"),
      "PepperKey Debug must carry the redaction marker"
    );
    assert!(
      !pepper_debug.contains("redact-pepper-sentinel"),
      "PepperKey Debug leaked raw pepper bytes"
    );

    // `FoundAccess`/`FoundRefresh` carry no raw token, so their `Debug`
    // has no `[REDACTED]` marker by design; redaction is transitive through
    // the identifier-only record `Debug` (see `AccessRecord`/`RefreshRecord`).
    let found_access = FoundAccess {
      record: AccessRecord {
        client_id: "client-a".to_owned(),
        grant_id: "grant-a".to_owned(),
        scope: "orders:read".to_owned(),
        subject: "user-a".to_owned(),
        cnf: String::new(),
        aud: Vec::new(),
      },
      hash: "v1.test-access-hash".to_owned(),
      key_label: "v1".to_owned(),
    };
    let access_debug = format!("{found_access:?}");
    assert!(access_debug.contains("v1"));
    assert!(!access_debug.contains(access_sentinel));
    assert!(!access_debug.contains(refresh_sentinel));

    let found_refresh = FoundRefresh {
      record: RefreshRecord {
        client_id: "client-a".to_owned(),
        grant_id: "grant-a".to_owned(),
        scope: "orders:read".to_owned(),
        subject: "user-a".to_owned(),
        cnf: String::new(),
        aud: Vec::new(),
      },
      hash: "v1.test-refresh-hash".to_owned(),
      key_label: "v1".to_owned(),
    };
    let refresh_debug = format!("{found_refresh:?}");
    assert!(refresh_debug.contains("v1"));
    assert!(!refresh_debug.contains(access_sentinel));
    assert!(!refresh_debug.contains(refresh_sentinel));
    Ok(())
  }
}

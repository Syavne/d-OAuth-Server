//! Versioned [`KeyRing`] for token peppers, TOTP-encryption keys, and PII keys.
//!
//! Holds versioned key ids for the token pepper, the TOTP-encryption key, and
//! the PII field-encryption key
//! (newest first, bounded retry across retained ids). Opaque tokens are stored
//! under `v<N>` key ids and verification retries across retained key ids,
//! ordered newest-first. Sessions are opaque Redis ids, so there is no session
//! signing key, and — because this server signs nothing — there is no AS
//! JWT-signing key and no `jwks_uri`.
//!
//! # `keygen` purpose
//!
//! The `keygen` CLI subcommand (todo 14) generates an **ES256 keypair for test
//! fixtures and client-side DPoP keys only**. It is never an AS signing key:
//! the server publishes no JWKS (`jwks_uri`) and emits no AS-signed artifact.
//! See [`KEYGEN_PURPOSE`].
//!
//! Key material never appears in logs: [`KeyRing::fmt`] prints key ids only.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

/// Machine-readable statement of the `keygen` command's purpose.
///
/// `keygen` emits an ES256 keypair for **test fixtures and client-side DPoP
/// keys only**. It is never an authorization-server signing key, and the
/// server publishes no `jwks_uri`.
pub const KEYGEN_PURPOSE: &str =
  "test-fixtures/client-dpop-only; never an AS signing key; no jwks_uri";

/// Stable identifier for a versioned key (for example `v1`, `v2`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
  /// Construct a key id from any string-like value.
  pub fn new(id: impl Into<String>) -> Self {
    Self(id.into())
  }

  /// Borrow the id as a string slice.
  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }

  /// Whether the id is empty.
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

/// Whether `id` is storage-safe: non-empty `[A-Za-z0-9_-]+`.
///
/// A `.` would collide with the `<kid>.<digest>` storage format and split
/// stored hashes at the wrong boundary, so it is rejected here and at config
/// load; empty and whitespace-only values never reach this check as valid.
#[must_use]
pub fn is_valid_key_id(id: &str) -> bool {
  !id.is_empty()
    && id
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl fmt::Display for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.0)
  }
}

impl fmt::Debug for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "KeyId({})", self.0)
  }
}

impl From<&str> for KeyId {
  fn from(value: &str) -> Self {
    Self::new(value)
  }
}

impl From<String> for KeyId {
  fn from(value: String) -> Self {
    Self::new(value)
  }
}

/// A single secret bound to a [`KeyId`].
#[derive(Clone)]
pub struct VersionedSecret {
  id: KeyId,
  secret: SecretString,
}

impl VersionedSecret {
  /// The key id this secret is stored under.
  #[must_use]
  pub fn id(&self) -> &KeyId {
    &self.id
  }

  /// The wrapped secret (call [`ExposeSecret::expose_secret`] to read bytes).
  #[must_use]
  pub fn secret(&self) -> &SecretString {
    &self.secret
  }

  /// Borrow the secret's bytes as a string slice.
  #[must_use]
  pub fn expose(&self) -> &str {
    self.secret.expose_secret()
  }
}

impl fmt::Debug for VersionedSecret {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VersionedSecret")
      .field("id", &self.id)
      .field("secret", &"[REDACTED]")
      .finish()
  }
}

/// Errors constructing a [`KeyRing`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyRingError {
  /// No token-pepper key material was supplied.
  #[error("token pepper key material is required")]
  MissingTokenPepper,
  /// No TOTP-encryption key material was supplied.
  #[error("TOTP encryption key material is required")]
  MissingTotpKey,
  /// No PII field-encryption key material was supplied.
  #[error("PII encryption key material is required")]
  MissingPiiKey,
  /// A key id was empty.
  #[error("key id must not be empty")]
  EmptyKeyId,
  /// A key id contained characters outside `[A-Za-z0-9_-]`.
  #[error("invalid key id: {id}")]
  InvalidKeyId {
    /// The rejected value.
    id: String,
  },
  /// The same key id was supplied twice within one purpose chain.
  #[error("duplicate key id: {id}")]
  DuplicateKeyId {
    /// The duplicated id.
    id: String,
  },
}

/// Versioned key ring for token peppers, TOTP-encryption keys, and PII keys.
///
/// Every chain is ordered newest-first; the first element is the active key.
/// The `Debug` impl never prints key material.
#[derive(Clone)]
pub struct KeyRing {
  peppers: Vec<VersionedSecret>,
  totp_keys: Vec<VersionedSecret>,
  pii_keys: Vec<VersionedSecret>,
}

impl KeyRing {
  /// Build a key ring from newest-first pepper, TOTP-encryption, and PII chains.
  ///
  /// Each chain must be non-empty and free of duplicate ids.
  pub fn from_parts(
    peppers: Vec<(KeyId, SecretString)>,
    totp_keys: Vec<(KeyId, SecretString)>,
    pii_keys: Vec<(KeyId, SecretString)>,
  ) -> Result<Self, KeyRingError> {
    Ok(Self {
      peppers: build_chain(peppers, KeyRingError::MissingTokenPepper)?,
      totp_keys: build_chain(totp_keys, KeyRingError::MissingTotpKey)?,
      pii_keys: build_chain(pii_keys, KeyRingError::MissingPiiKey)?,
    })
  }

  /// The active token pepper (newest key id), if any.
  #[must_use]
  pub fn active_pepper(&self) -> Option<(&KeyId, &SecretString)> {
    self.peppers.first().map(|k| (k.id(), k.secret()))
  }

  /// Look up a retained token pepper by key id.
  #[must_use]
  pub fn pepper_by_id(&self, id: &str) -> Option<&SecretString> {
    find(&self.peppers, id)
  }

  /// Iterate token peppers ordered newest-first.
  pub fn peppers_newest_first(&self) -> impl Iterator<Item = (&KeyId, &SecretString)> {
    self.peppers.iter().map(|k| (k.id(), k.secret()))
  }

  /// The active TOTP-encryption key (newest key id), if any.
  #[must_use]
  pub fn active_totp_key(&self) -> Option<(&KeyId, &SecretString)> {
    self.totp_keys.first().map(|k| (k.id(), k.secret()))
  }

  /// Look up a retained TOTP-encryption key by key id.
  #[must_use]
  pub fn totp_key_by_id(&self, id: &str) -> Option<&SecretString> {
    find(&self.totp_keys, id)
  }

  /// Iterate TOTP-encryption keys ordered newest-first.
  pub fn totp_keys_newest_first(&self) -> impl Iterator<Item = (&KeyId, &SecretString)> {
    self.totp_keys.iter().map(|k| (k.id(), k.secret()))
  }

  /// The active PII-encryption key (newest key id), if any.
  #[must_use]
  pub fn active_pii_key(&self) -> Option<(&KeyId, &SecretString)> {
    self.pii_keys.first().map(|k| (k.id(), k.secret()))
  }

  /// Look up a retained PII-encryption key by key id.
  #[must_use]
  pub fn pii_key_by_id(&self, id: &str) -> Option<&SecretString> {
    find(&self.pii_keys, id)
  }

  /// Iterate PII-encryption keys ordered newest-first.
  pub fn pii_keys_newest_first(&self) -> impl Iterator<Item = (&KeyId, &SecretString)> {
    self.pii_keys.iter().map(|k| (k.id(), k.secret()))
  }
}

impl fmt::Debug for KeyRing {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let pepper_ids: Vec<&str> = self.peppers.iter().map(|k| k.id().as_str()).collect();
    let totp_ids: Vec<&str> = self.totp_keys.iter().map(|k| k.id().as_str()).collect();
    let pii_ids: Vec<&str> = self.pii_keys.iter().map(|k| k.id().as_str()).collect();
    f.debug_struct("KeyRing")
      .field("token_pepper_ids", &pepper_ids)
      .field("totp_key_ids", &totp_ids)
      .field("pii_key_ids", &pii_ids)
      .finish()
  }
}

fn build_chain(
  chain: Vec<(KeyId, SecretString)>,
  empty_error: KeyRingError,
) -> Result<Vec<VersionedSecret>, KeyRingError> {
  if chain.is_empty() {
    return Err(empty_error);
  }
  let mut out: Vec<VersionedSecret> = Vec::with_capacity(chain.len());
  for (id, secret) in chain {
    if id.is_empty() {
      return Err(KeyRingError::EmptyKeyId);
    }
    if !is_valid_key_id(id.as_str()) {
      return Err(KeyRingError::InvalidKeyId {
        id: id.as_str().to_owned(),
      });
    }
    if out.iter().any(|existing| existing.id() == &id) {
      return Err(KeyRingError::DuplicateKeyId {
        id: id.as_str().to_owned(),
      });
    }
    out.push(VersionedSecret { id, secret });
  }
  Ok(out)
}

fn find<'a>(chain: &'a [VersionedSecret], id: &str) -> Option<&'a SecretString> {
  chain
    .iter()
    .find(|k| k.id().as_str() == id)
    .map(VersionedSecret::secret)
}

#[cfg(test)]
mod tests {
  use secrecy::ExposeSecret;

  use super::*;

  fn pepper(id: &str, value: &str) -> (KeyId, SecretString) {
    (KeyId::new(id), SecretString::from(value))
  }

  #[test]
  fn keyring_requires_a_token_pepper() -> Result<(), KeyRingError> {
    let result = KeyRing::from_parts(
      Vec::new(),
      vec![pepper("v1", "totp-secret")],
      vec![pepper("v1", "pii-secret")],
    );
    assert!(matches!(result, Err(KeyRingError::MissingTokenPepper)));
    Ok(())
  }

  #[test]
  fn keyring_requires_a_totp_key() -> Result<(), KeyRingError> {
    let result = KeyRing::from_parts(
      vec![pepper("v1", "pepper-secret")],
      Vec::new(),
      vec![pepper("v1", "pii-secret")],
    );
    assert!(matches!(result, Err(KeyRingError::MissingTotpKey)));
    Ok(())
  }

  #[test]
  fn keyring_requires_a_pii_key() -> Result<(), KeyRingError> {
    let result = KeyRing::from_parts(
      vec![pepper("v1", "pepper-secret")],
      vec![pepper("v1", "totp-secret")],
      Vec::new(),
    );
    assert!(matches!(result, Err(KeyRingError::MissingPiiKey)));
    Ok(())
  }

  #[test]
  fn keyring_rejects_duplicate_ids() {
    let duplicate_pepper = KeyRing::from_parts(
      vec![pepper("v1", "a"), pepper("v1", "b")],
      vec![pepper("v1", "c")],
      vec![pepper("v1", "d")],
    );
    assert!(matches!(
      duplicate_pepper,
      Err(KeyRingError::DuplicateKeyId { .. })
    ));
    // A duplicate inside the PII chain is rejected the same way.
    let duplicate_pii = KeyRing::from_parts(
      vec![pepper("v1", "a")],
      vec![pepper("v1", "b")],
      vec![pepper("v2", "c"), pepper("v2", "d")],
    );
    assert!(matches!(
      duplicate_pii,
      Err(KeyRingError::DuplicateKeyId { .. })
    ));
  }

  #[test]
  fn keyring_resolves_retained_ids_newest_first() -> Result<(), KeyRingError> {
    let ring = KeyRing::from_parts(
      vec![pepper("v2", "new"), pepper("v1", "old")],
      vec![pepper("v1", "totp")],
      vec![pepper("v1", "pii")],
    )?;
    let active = ring.active_pepper();
    assert!(matches!(active, Some((id, _)) if id.as_str() == "v2"));
    let retained = ring.pepper_by_id("v1");
    assert!(matches!(retained, Some(secret) if secret.expose_secret() == "old"));
    assert!(ring.pepper_by_id("v9").is_none());
    Ok(())
  }

  #[test]
  fn keyring_resolves_retained_pii_id() -> Result<(), KeyRingError> {
    let ring = KeyRing::from_parts(
      vec![pepper("v1", "pepper-secret")],
      vec![pepper("v1", "totp-secret")],
      vec![
        pepper("v2", "new-pii-secret"),
        pepper("v1", "old-pii-secret"),
      ],
    )?;
    let active = ring.active_pii_key();
    assert!(matches!(active, Some((id, _)) if id.as_str() == "v2"));
    let retained = ring.pii_key_by_id("v1");
    assert!(matches!(retained, Some(secret) if secret.expose_secret() == "old-pii-secret"));
    assert!(ring.pii_key_by_id("v9").is_none());
    let ids: Vec<&str> = ring
      .pii_keys_newest_first()
      .map(|(id, _)| id.as_str())
      .collect();
    assert_eq!(ids, vec!["v2", "v1"]);
    // `Debug` exposes ids only, never material from any chain.
    let debug = format!("{ring:?}");
    assert!(debug.contains("v2"), "debug must include the pii key id");
    assert!(!debug.contains("new-pii-secret") && !debug.contains("old-pii-secret"));
    assert!(!debug.contains("pepper-secret") && !debug.contains("totp-secret"));
    Ok(())
  }

  #[test]
  fn keyring_rejects_dotted_ids() {
    let dotted = KeyRing::from_parts(
      vec![pepper("v1.evil", "a")],
      vec![pepper("v1", "b")],
      vec![pepper("v1", "c")],
    );
    assert!(matches!(dotted, Err(KeyRingError::InvalidKeyId { .. })));
  }

  #[test]
  fn keygen_purpose_documents_no_as_signing_key() {
    assert!(KEYGEN_PURPOSE.contains("never an AS signing key"));
    assert!(KEYGEN_PURPOSE.contains("no jwks_uri"));
  }
}

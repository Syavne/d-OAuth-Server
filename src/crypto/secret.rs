//! Argon2id hashing for user passwords and client secrets.
//!
//! Secrets (both user passwords and OAuth client secrets) are hashed with the
//! Argon2id variant and stored as a PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
//! Cost parameters come from config via [`Argon2Params`]; [`needs_rehash`]
//! reports when a stored hash was produced with weaker parameters so callers
//! can upgrade it on the next successful verify.
//!
//! Fast hashes are never used for secrets, and no error variant ever carries
//! the secret or its hash.

use argon2::{
  ARGON2ID_IDENT, Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier,
  Version, password_hash::Error as PasswordHashError,
};

/// Argon2id cost parameters, sourced from configuration.
///
/// Build with [`Argon2Params::new`] to validate the values up front; the
/// production defaults ([`Argon2Params::default`]) match the crate-recommended
/// costs (m=19456 KiB, t=2, p=1, 32-byte output).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Params {
  /// Memory size in kibibytes.
  m_cost: u32,
  /// Number of passes (iterations).
  t_cost: u32,
  /// Degree of parallelism (lanes).
  p_cost: u32,
  /// Length of the derived hash output in bytes.
  output_len: usize,
}

impl Argon2Params {
  /// Validate and construct Argon2id cost parameters.
  ///
  /// # Errors
  /// Returns [`SecretHashError::InvalidParams`] when the values violate
  /// Argon2's bounds (e.g. memory below `8 * p_cost`).
  pub fn new(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
  ) -> Result<Self, SecretHashError> {
    Params::new(m_cost, t_cost, p_cost, Some(output_len))?;
    Ok(Self {
      m_cost,
      t_cost,
      p_cost,
      output_len,
    })
  }

  /// Memory size in kibibytes.
  #[must_use]
  pub const fn m_cost(&self) -> u32 {
    self.m_cost
  }

  /// Number of passes (iterations).
  #[must_use]
  pub const fn t_cost(&self) -> u32 {
    self.t_cost
  }

  /// Degree of parallelism (lanes).
  #[must_use]
  pub const fn p_cost(&self) -> u32 {
    self.p_cost
  }

  /// Length of the derived hash output in bytes.
  #[must_use]
  pub const fn output_len(&self) -> usize {
    self.output_len
  }

  /// Build the Argon2id context for these parameters.
  fn argon2(&self) -> Result<Argon2<'static>, SecretHashError> {
    let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(self.output_len))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
  }
}

impl Default for Argon2Params {
  fn default() -> Self {
    Self {
      m_cost: Params::DEFAULT_M_COST,
      t_cost: Params::DEFAULT_T_COST,
      p_cost: Params::DEFAULT_P_COST,
      output_len: Params::DEFAULT_OUTPUT_LEN,
    }
  }
}

/// Errors from hashing or verifying a secret.
///
/// No variant carries the secret or its computed hash.
#[derive(Debug, thiserror::Error)]
pub enum SecretHashError {
  /// The supplied Argon2 cost parameters are invalid.
  #[error("invalid argon2 parameters: {0}")]
  InvalidParams(#[from] argon2::Error),
  /// Hashing or verification failed.
  #[error("secret hashing failed: {0}")]
  Hashing(#[from] PasswordHashError),
  /// The stored PHC string could not be parsed.
  #[error("stored secret hash is malformed")]
  MalformedHash,
}

/// Hash a secret (user password or client secret) into a PHC string.
///
/// A random 128-bit salt is generated per call, so hashing the same secret
/// twice yields different strings. The returned string is safe to store
/// verbatim.
///
/// # Errors
/// Returns [`SecretHashError::InvalidParams`] if the configured parameters are
/// invalid, or [`SecretHashError::Hashing`] if the hash cannot be computed.
pub fn hash_secret(secret: &str, params: &Argon2Params) -> Result<String, SecretHashError> {
  let argon2 = params.argon2()?;
  let hash = argon2.hash_password(secret.as_bytes())?;
  Ok(hash.to_string())
}

/// Verify a secret against a stored PHC hash.
///
/// The cost parameters embedded in the PHC string are used for verification,
/// so hashes produced with older parameters still verify. Comparison is
/// constant-time inside `password-hash`.
///
/// Returns `Ok(true)` on a match and `Ok(false)` for a wrong secret. A
/// malformed or unsupported stored hash is an error, never a panic.
///
/// # Errors
/// Returns [`SecretHashError::MalformedHash`] if `phc_hash` is not a valid PHC
/// string, and [`SecretHashError::Hashing`] for other algorithm-level failures
/// (e.g. an unsupported algorithm).
pub fn verify_secret(secret: &str, phc_hash: &str) -> Result<bool, SecretHashError> {
  let parsed = PasswordHash::new(phc_hash).map_err(|_| SecretHashError::MalformedHash)?;
  match Argon2::default().verify_password(secret.as_bytes(), &parsed) {
    Ok(()) => Ok(true),
    Err(PasswordHashError::PasswordInvalid) => Ok(false),
    Err(err) => Err(SecretHashError::Hashing(err)),
  }
}

/// Report whether a stored PHC hash was produced with parameters weaker or
/// different from `params`.
///
/// Returns `true` for malformed hashes, non-Argon2id algorithms, or older
/// algorithm versions, so callers can transparently upgrade the hash after the
/// next successful verify. Returns `false` only when the stored parameters
/// match `params` exactly.
#[must_use]
pub fn needs_rehash(phc_hash: &str, params: &Argon2Params) -> bool {
  let Ok(parsed) = PasswordHash::new(phc_hash) else {
    return true;
  };

  if parsed.algorithm != ARGON2ID_IDENT {
    return true;
  }

  if parsed.version != Some(u32::from(Version::V0x13)) {
    return true;
  }

  let Ok(stored) = Params::try_from(&parsed) else {
    return true;
  };

  stored.m_cost() != params.m_cost()
    || stored.t_cost() != params.t_cost()
    || stored.p_cost() != params.p_cost()
    || stored.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN) != params.output_len()
}

#[cfg(test)]
mod tests {
  use super::{Argon2Params, SecretHashError, hash_secret, needs_rehash, verify_secret};

  /// Low-cost parameters keep the unit tests fast; production costs are
  /// exercised once in `secret_hash_production_defaults_roundtrip`.
  fn fast_params() -> Result<Argon2Params, SecretHashError> {
    Argon2Params::new(8, 1, 1, 32)
  }

  #[test]
  fn secret_hash_verifies_correct_secret() -> Result<(), SecretHashError> {
    let params = fast_params()?;
    let phc = hash_secret("correct horse battery staple", &params)?;
    assert!(verify_secret("correct horse battery staple", &phc)?);
    Ok(())
  }

  #[test]
  fn secret_hash_rejects_wrong_secret() -> Result<(), SecretHashError> {
    let params = fast_params()?;
    let phc = hash_secret("s3cret", &params)?;
    assert!(!verify_secret("nope", &phc)?);
    Ok(())
  }

  #[test]
  fn secret_hash_is_salted_and_unique() -> Result<(), SecretHashError> {
    let params = fast_params()?;
    let first = hash_secret("same-secret", &params)?;
    let second = hash_secret("same-secret", &params)?;
    assert_ne!(first, second);
    assert!(verify_secret("same-secret", &first)?);
    assert!(verify_secret("same-secret", &second)?);
    Ok(())
  }

  #[test]
  fn secret_hash_malformed_phc_is_error_not_panic() -> Result<(), SecretHashError> {
    let params = fast_params()?;
    assert!(verify_secret("x", "not-a-phc").is_err());
    assert!(verify_secret("x", "").is_err());
    assert!(needs_rehash("not-a-phc", &params));
    Ok(())
  }

  #[test]
  fn secret_hash_needs_rehash_on_param_change() -> Result<(), SecretHashError> {
    let weak = fast_params()?;
    let strong = Argon2Params::new(16, 2, 1, 32)?;
    let phc = hash_secret("rotate-me", &weak)?;
    assert!(!needs_rehash(&phc, &weak));
    assert!(needs_rehash(&phc, &strong));
    Ok(())
  }

  #[test]
  fn secret_hash_production_defaults_roundtrip() -> Result<(), SecretHashError> {
    let params = Argon2Params::default();
    let phc = hash_secret("production-secret", &params)?;
    assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(!needs_rehash(&phc, &params));
    assert!(verify_secret("production-secret", &phc)?);
    Ok(())
  }
}

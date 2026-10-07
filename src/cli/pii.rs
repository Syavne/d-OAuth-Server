//! `pii backfill` and `pii verify`: cutover tooling for PII envelope encryption.
//!
//! The expansion migration (todo 8) adds every `_enc`/`_index` column and makes
//! the plaintext columns nullable; writers seal new rows while `pii_dual_write`
//! holds. The MANDATORY cutover order is exact: (0) apply the expansion
//! migration with the PII key configured, (1) set `pii_dual_write=true`,
//! (2) roll all replicas, (3) set `pii_dual_write=false` and SCALE THE APP TIER
//! TO ZERO, (4) run `pii backfill`, (5) run `pii verify`, (6) scale the app
//! back up (now encrypt-only and ready). `pii backfill` refuses to run while
//! `pii_dual_write=true`, and the startup guard (todo 18) is the safety net
//! that prevents serving the unsafe mix.
//!
//! Both commands run against the migration-role DSN (the same
//! [`Context`] pool `migrate` uses) and print COUNTS only: never a value, a
//! blob, or key material.

mod backfill;
mod clients;
mod rotate;
mod rotate_clients;
mod verify;

#[cfg(test)]
mod tests;

use std::fmt;

use super::context::{CliError, Context};

/// Counts from one `pii backfill` run (counts only, never values or keys).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct BackfillReport {
  /// `users` rows whose plaintext email was sealed and blanked.
  pub(super) users_sealed: u64,
  /// `oauth_clients` rows with at least one sealed-and-blanked PII column.
  pub(super) clients_sealed: u64,
  /// `redirect_uris` rows whose plaintext URI was sealed and blanked.
  pub(super) redirects_sealed: u64,
  /// TOTP blobs converted from v1/v2 to the v3 envelope format.
  pub(super) totp_upgraded: u64,
}

impl fmt::Display for BackfillReport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "pii backfill: users_sealed={} clients_sealed={} redirects_sealed={} totp_upgraded={}",
      self.users_sealed, self.clients_sealed, self.redirects_sealed, self.totp_upgraded
    )
  }
}

/// Counts from one `pii verify` run (counts only, never values or keys).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct VerifyReport {
  /// Rows with any plaintext PII column still non-NULL.
  pub(super) plaintext: u64,
  /// Sealed values that fail to open under any retained key.
  pub(super) undecryptable: u64,
  /// TOTP blobs still below the v3 envelope format.
  pub(super) totp_below_v3: u64,
  /// Sealed indexed rows with a NULL or mismatched `_index`.
  pub(super) index_mismatch: u64,
}

impl VerifyReport {
  /// Whether every check is clean (all four counts are zero).
  #[must_use]
  pub(super) fn is_clean(&self) -> bool {
    self.plaintext == 0
      && self.undecryptable == 0
      && self.totp_below_v3 == 0
      && self.index_mismatch == 0
  }
}

impl fmt::Display for VerifyReport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "pii verify: plaintext={} undecryptable={} totp_below_v3={} index_mismatch={}",
      self.plaintext, self.undecryptable, self.totp_below_v3, self.index_mismatch
    )
  }
}

/// `pii backfill`: seal every remaining plaintext PII value and upgrade every
/// pre-v3 TOTP blob, in bounded batches under `pg_advisory_xact_lock`.
///
/// # Errors
/// Returns [`CliError::Input`] while `pii_dual_write` holds (refusal),
/// [`CliError::Crypto`] when no active PII key is configured, a stored
/// ciphertext cannot be opened (the batch rolls back, plaintext intact), or a
/// seal fails, and [`CliError::Database`] for PostgreSQL failures.
pub(super) async fn backfill(context: &Context) -> Result<BackfillReport, CliError> {
  let report = backfill::backfill_with(
    context.pool(),
    &context.config().keys,
    context.config().pii_dual_write,
  )
  .await?;
  println!("{report}");
  Ok(report)
}

/// Counts from one `pii rotate` run (counts only, never values or keys).
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct RotateReport {
  /// `users` rows re-encrypted under the active PII key.
  pub(super) users_rotated: u64,
  /// `oauth_clients` rows re-encrypted under the active PII key.
  pub(super) clients_rotated: u64,
  /// `redirect_uris` rows re-encrypted under the active PII key.
  pub(super) redirects_rotated: u64,
}

impl fmt::Display for RotateReport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "pii rotate: users_rotated={} clients_rotated={} redirects_rotated={}",
      self.users_rotated, self.clients_rotated, self.redirects_rotated
    )
  }
}

/// `pii rotate`: re-encrypt every stale PII blob under the active key.
///
/// # Errors
/// Returns [`CliError::Crypto`] when no active PII key is configured or a
/// stored blob cannot be opened, and [`CliError::Database`] for PostgreSQL
/// failures (including unique-index collisions, which roll the batch back).
pub(super) async fn rotate(context: &Context) -> Result<RotateReport, CliError> {
  let report = rotate::rotate_with(context.pool(), &context.config().keys).await?;
  println!("{report}");
  Ok(report)
}

/// `pii verify`: report the four cutover checks and fail when any is dirty.
///
/// The four checks are (1) any plaintext PII column still non-NULL,
/// (2) any `_enc` that fails to open under a retained key, (3) any TOTP blob
/// still below v3, and (4) any sealed indexed row with a NULL or mismatched
/// `_index`.
///
/// # Errors
/// Returns [`CliError::Input`] when any check reports a non-zero count and
/// [`CliError::Database`] for PostgreSQL failures.
pub(super) async fn verify(context: &Context) -> Result<VerifyReport, CliError> {
  let report = verify::verify_with(context.pool(), &context.config().keys).await?;
  println!("{report}");
  ensure_clean(&report)?;
  Ok(report)
}

/// Map a dirty [`VerifyReport`] to a non-zero exit (the counts are the message).
///
/// # Errors
/// Returns [`CliError::Input`] carrying the four counts when any is non-zero.
pub(super) fn ensure_clean(report: &VerifyReport) -> Result<(), CliError> {
  if report.is_clean() {
    Ok(())
  } else {
    Err(CliError::Input(format!("pii verify failed: {report}")))
  }
}

/// Build a payload-free abort error: a stored ciphertext that no longer opens
/// rolls the batch back, leaving the plaintext intact for retry. The column
/// name is schema, never a value or key material.
pub(super) fn malformed(column: &str) -> CliError {
  CliError::Crypto(format!(
    "pii backfill aborted: stored ciphertext for {column} cannot be opened; batch rolled back"
  ))
}

/// Build a payload-free sealing error (never carries key or value material).
pub(super) fn seal_failed() -> CliError {
  CliError::Crypto("PII field sealing failed".to_owned())
}

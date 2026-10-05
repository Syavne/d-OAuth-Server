//! Scope parsing, rendering, and effective-scope enforcement (RFC 6749 §3.3).
//!
//! The deployment owns a runtime-managed catalog (`scopes` table). The single
//! source of truth for `scopes_supported` is the enabled rows of that table.
//! Callers MUST load `enabled` via `db::scope_repo` and `user_entitled` via
//! `db::user_scope_repo` at issuance time (fresh read per issuance, so CLI
//! `scope create|enable|disable` changes propagate immediately), then pass the
//! materialized sets in. This module is pure and performs no I/O itself: the
//! `ScopeSet` inputs of [`ScopeInput`] are the seam standing in for the
//! task-11 repositories.
//!
//! Effective scope is `requested ∩ client-registered ∩ user-entitled ∩
//! enabled` for user-bound grants; `client_credentials` and token exchange
//! carry no user term, but token exchange additionally requires the
//! (caller, subject, scope) allowlist. Refresh may only narrow.

use std::collections::BTreeSet;

use crate::config::GrantKind;
use crate::error::{AppError, OAuthErrorCode};

/// Maximum number of scopes in one set.
pub const MAX_SCOPE_COUNT: usize = 32;
/// Maximum bytes of a rendered (space-joined) scope value.
pub const MAX_SCOPE_TOTAL_LEN: usize = 1024;
/// Maximum bytes of a single scope name (matches `config::scope` validation).
pub const MAX_SCOPE_NAME_LEN: usize = 128;

/// A deduped, canonically ordered set of scope tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
  scopes: BTreeSet<String>,
}

impl ScopeSet {
  /// An empty scope set.
  pub fn empty() -> Self {
    Self {
      scopes: BTreeSet::new(),
    }
  }

  /// Build a set from pre-split names, validating grammar and caps.
  pub fn from_names(names: &[String]) -> Result<Self, AppError> {
    Self::parse(&names.join(" "))
  }

  /// Parse a raw `scope` parameter value: tokens split on single `0x20`
  /// spaces with no empty tokens, deduped and ordered. `""` is the empty set.
  pub fn parse(raw: &str) -> Result<Self, AppError> {
    if raw.len() > MAX_SCOPE_TOTAL_LEN {
      return Err(AppError::invalid_scope("scope value too long"));
    }
    let mut scopes = BTreeSet::new();
    if !raw.is_empty() {
      for token in raw.split(' ') {
        check_token(token)?;
        scopes.insert(token.to_owned());
      }
    }
    if scopes.len() > MAX_SCOPE_COUNT {
      return Err(AppError::invalid_scope("too many scopes requested"));
    }
    check_rendered_len(&scopes)?;
    Ok(Self { scopes })
  }

  /// Render the canonical wire form: single-space-joined, sorted, deduped.
  pub fn render(&self) -> String {
    self.scopes.iter().cloned().collect::<Vec<_>>().join(" ")
  }

  /// Whether every member is also a member of `other`.
  pub fn is_subset_of(&self, other: &Self) -> bool {
    self.scopes.is_subset(&other.scopes)
  }

  /// Intersection of two sets.
  pub fn intersect(&self, other: &Self) -> Self {
    Self {
      scopes: self.scopes.intersection(&other.scopes).cloned().collect(),
    }
  }

  /// Number of scopes.
  pub fn len(&self) -> usize {
    self.scopes.len()
  }

  /// Whether the set holds no scopes.
  pub fn is_empty(&self) -> bool {
    self.scopes.is_empty()
  }
}

/// Whether the grant is bound to a resource owner (needs the user term).
pub fn is_user_bound_grant(grant: GrantKind) -> bool {
  match grant {
    GrantKind::AuthorizationCode | GrantKind::DeviceCode | GrantKind::RefreshToken => true,
    GrantKind::ClientCredentials | GrantKind::TokenExchange => false,
  }
}

/// Inputs to [`effective_scope`]; see the module docs for the Postgres seam.
#[derive(Debug)]
pub struct ScopeInput<'a> {
  /// Raw `scope` parameter, or `None` when omitted (defaults to the
  /// client's registered set).
  pub requested: Option<&'a str>,
  /// Scopes registered to the client.
  pub client_registered: &'a ScopeSet,
  /// Scopes the user is entitled to (empty when the grant has no user term;
  /// a new user has none). Ignored for non-user-bound grants.
  pub user_entitled: &'a ScopeSet,
  /// Enabled catalog rows, freshly read from Postgres at issuance.
  pub enabled: &'a ScopeSet,
  /// Grant the token is minted under.
  pub grant: GrantKind,
  /// Token-exchange (caller, subject, scope) allowlist (empty when the grant
  /// is not token exchange).
  pub exchange_allowlist: &'a ScopeSet,
}

/// Compute the effective scope for an issuance.
///
/// Explicit requests must name only enabled, client-registered (and, for
/// user-bound grants, user-entitled; for token exchange, allowlisted)
/// scopes, else `invalid_scope`. An omitted scope defaults to the client's
/// registered set narrowed silently by the enabled catalog (and the user or
/// exchange term). Reserved names (`openid`, `offline_access`) pass only
/// when present and enabled in the catalog.
pub fn effective_scope(input: &ScopeInput<'_>) -> Result<ScopeSet, AppError> {
  match input.requested {
    Some(raw) => {
      let candidate = ScopeSet::parse(raw)?;
      require_subset(&candidate, input.enabled, "unknown or disabled scope")?;
      require_subset(
        &candidate,
        input.client_registered,
        "scope exceeds client registration",
      )?;
      enforce_grant_term(&candidate, input)?;
      Ok(candidate)
    }
    None => {
      let mut candidate = input.client_registered.intersect(input.enabled);
      if input.grant == GrantKind::TokenExchange {
        candidate = candidate.intersect(input.exchange_allowlist);
      } else if is_user_bound_grant(input.grant) {
        candidate = candidate.intersect(input.user_entitled);
      }
      Ok(candidate)
    }
  }
}

/// Refresh may narrow but never widen: `None` keeps the previous grant
/// (re-checked against the current catalog), `Some` must be a subset of it.
pub fn narrow_on_refresh(
  previous: &ScopeSet,
  requested: Option<&str>,
  enabled: &ScopeSet,
) -> Result<ScopeSet, AppError> {
  match requested {
    None => {
      require_subset(previous, enabled, "granted scope no longer enabled")?;
      Ok(previous.clone())
    }
    Some(raw) => {
      let candidate = ScopeSet::parse(raw)?;
      require_subset(&candidate, enabled, "unknown or disabled scope")?;
      require_subset(&candidate, previous, "refresh must not widen scope")?;
      Ok(candidate)
    }
  }
}

fn enforce_grant_term(candidate: &ScopeSet, input: &ScopeInput<'_>) -> Result<(), AppError> {
  if input.grant == GrantKind::TokenExchange {
    require_subset(
      candidate,
      input.exchange_allowlist,
      "scope not allowed for this exchange",
    )?;
  } else if is_user_bound_grant(input.grant) {
    require_subset(candidate, input.user_entitled, "scope not granted to user")?;
  }
  Ok(())
}

fn require_subset(
  candidate: &ScopeSet,
  allowed: &ScopeSet,
  why: &'static str,
) -> Result<(), AppError> {
  if candidate.is_subset_of(allowed) {
    Ok(())
  } else {
    Err(AppError::new(OAuthErrorCode::InvalidScope, why))
  }
}

fn check_token(token: &str) -> Result<(), AppError> {
  if token.is_empty() || token.len() > MAX_SCOPE_NAME_LEN || !token.chars().all(is_scope_char) {
    return Err(AppError::invalid_scope("scope value is malformed"));
  }
  Ok(())
}

fn check_rendered_len(scopes: &BTreeSet<String>) -> Result<(), AppError> {
  let mut total = 0_usize;
  for scope in scopes {
    total = total.saturating_add(scope.len()).saturating_add(1);
  }
  if total > MAX_SCOPE_TOTAL_LEN.saturating_add(1) {
    return Err(AppError::invalid_scope("scope value too long"));
  }
  Ok(())
}

/// RFC 6749 scope-token: `%x21 / %x23-5B / %x5D-7E` (no space, `"`, `\`).
fn is_scope_char(c: char) -> bool {
  let code = u32::from(c);
  code == 0x21 || (0x23..=0x5B).contains(&code) || (0x5D..=0x7E).contains(&code)
}

//! `test(scope)` — scope parsing, rendering, and effective-scope enforcement.
//!
//! Pure unit coverage for `protocol::scope` (no database): the suite pins the
//! RFC 6749 §3.3 grammar, the catalog/client/user/exchange subset terms, the
//! omitted-scope default, the count/length caps, refresh narrowing, and a
//! `proptest` parse∘render idempotence check. Test bodies use `Result` + `?`
//! (`unwrap`/`expect`/`panic` are denied workspace-wide).
//!
//! The `enabled` / `user_entitled` sets stand in for the task-11 repository
//! reads: at issuance the caller loads them fresh from Postgres via
//! `db::scope_repo` / `db::user_scope_repo`, so CLI catalog changes apply
//! immediately.

use d_oauth::{
  config::GrantKind,
  error::{AppError, OAuthErrorCode},
  protocol::scope::{
    MAX_SCOPE_COUNT, MAX_SCOPE_NAME_LEN, MAX_SCOPE_TOTAL_LEN, ScopeInput, ScopeSet,
    effective_scope, narrow_on_refresh, refresh_scopes,
  },
};
use proptest::prelude::*;

/// Test-body error.
type TestResult = Result<(), AppError>;

fn names(words: &[&str]) -> ScopeSet {
  match ScopeSet::parse(&words.join(" ")) {
    Ok(set) => set,
    Err(_) => ScopeSet::empty(),
  }
}

fn is_invalid_scope<T>(result: Result<T, AppError>) -> bool {
  matches!(
    result,
    Err(AppError::OAuth {
      code: OAuthErrorCode::InvalidScope,
      ..
    })
  )
}

#[test]
fn scope_parse_renders_canonical_and_rejects_malformed_or_capped() -> TestResult {
  assert_eq!(ScopeSet::parse("b a b")?.render(), "a b");
  assert_eq!(ScopeSet::parse("a b")?.render(), "a b");
  assert!(ScopeSet::parse("")?.is_empty());
  for raw in ["a  b", " a", "a ", "a\tb", "a\"b", "a\\b", "café"] {
    assert!(
      is_invalid_scope(ScopeSet::parse(raw)),
      "must reject {raw:?}"
    );
  }
  let many: Vec<String> = (0..MAX_SCOPE_COUNT + 8).map(|i| format!("s{i}")).collect();
  assert!(is_invalid_scope(ScopeSet::from_names(&many)));
  assert!(is_invalid_scope(ScopeSet::parse(
    &"x".repeat(MAX_SCOPE_TOTAL_LEN + 1)
  )));
  assert!(is_invalid_scope(ScopeSet::parse(
    &"y".repeat(MAX_SCOPE_NAME_LEN + 1)
  )));
  Ok(())
}

#[test]
fn scope_effective_enforces_subset_default_and_grant_terms() -> TestResult {
  let enabled = names(&["read", "write"]);
  let registered = names(&["read", "write"]);
  let entitled = names(&["read"]);
  let allow = names(&["read"]);
  let none = ScopeSet::empty();
  let ask =
    |raw, reg: &ScopeSet, user: &ScopeSet, en: &ScopeSet, grant: GrantKind, list: &ScopeSet| {
      effective_scope(&ScopeInput {
        requested: raw,
        client_registered: reg,
        user_entitled: user,
        enabled: en,
        grant,
        exchange_allowlist: list,
      })
    };
  let code = GrantKind::AuthorizationCode;
  assert_eq!(
    ask(Some("read"), &registered, &entitled, &enabled, code, &none)?.render(),
    "read"
  );
  for raw in ["read write", "admin", "write"] {
    let user = if raw == "write" { &none } else { &entitled };
    assert!(is_invalid_scope(ask(
      Some(raw),
      &registered,
      user,
      &enabled,
      code,
      &none
    )));
  }
  let open = names(&["openid"]);
  assert!(is_invalid_scope(ask(
    Some("openid"),
    &open,
    &open,
    &enabled,
    code,
    &none
  )));
  let enabled_open = names(&["openid", "read"]);
  assert_eq!(
    ask(Some("openid"), &open, &open, &enabled_open, code, &none)?.render(),
    "openid"
  );
  assert_eq!(
    ask(
      None,
      &registered,
      &entitled,
      &enabled,
      GrantKind::DeviceCode,
      &none
    )?
    .render(),
    "read"
  );
  let cc = GrantKind::ClientCredentials;
  let ex = GrantKind::TokenExchange;
  assert_eq!(
    ask(Some("read write"), &registered, &none, &enabled, cc, &none)?.render(),
    "read write"
  );
  assert_eq!(
    ask(Some("read"), &registered, &none, &enabled, ex, &allow)?.render(),
    "read"
  );
  assert!(is_invalid_scope(ask(
    Some("write"),
    &registered,
    &none,
    &enabled,
    ex,
    &allow
  )));
  assert!(is_invalid_scope(ask(
    Some("read"),
    &registered,
    &none,
    &enabled,
    ex,
    &none
  )));
  Ok(())
}

#[test]
fn scope_refresh_narrows_only_and_rechecks_catalog() -> TestResult {
  let enabled = names(&["read", "write"]);
  let previous = names(&["read", "write"]);
  assert_eq!(
    narrow_on_refresh(&previous, None, &enabled, &enabled, &enabled)?.render(),
    "read write"
  );
  assert_eq!(
    narrow_on_refresh(&previous, Some("read"), &enabled, &enabled, &enabled)?.render(),
    "read"
  );
  assert!(is_invalid_scope(narrow_on_refresh(
    &names(&["read"]),
    Some("read write"),
    &enabled,
    &enabled,
    &enabled
  )));
  assert!(is_invalid_scope(narrow_on_refresh(
    &previous,
    Some("admin"),
    &enabled,
    &enabled,
    &enabled
  )));
  assert_eq!(
    narrow_on_refresh(&previous, None, &names(&["read"]), &enabled, &enabled)?.render(),
    "read"
  );
  Ok(())
}

#[test]
fn refresh_scopes_retained_vs_access() -> TestResult {
  let full = names(&["read", "write"]);
  let read = names(&["read"]);
  // Explicit narrow: retained keeps the re-checked previous intersection,
  // access narrows to the candidate.
  let split = refresh_scopes(
    &names(&["read", "write"]),
    Some("read"),
    &full,
    &full,
    &full,
  )?;
  assert_eq!(split.retained.render(), "read write");
  assert_eq!(split.access.render(), "read");
  // Omitted scope: retained and access agree.
  let kept = refresh_scopes(&names(&["read", "write"]), None, &full, &full, &full)?;
  assert_eq!(kept.retained.render(), "read write");
  assert_eq!(kept.access.render(), "read write");
  assert_eq!(kept.retained, kept.access);
  // Revoked entries drop silently from retained (catalog, registration, and
  // entitlement terms each narrow); an explicit narrow of the survivor still
  // applies only to access.
  let catalog_revoked = refresh_scopes(&names(&["read", "write"]), None, &read, &full, &full)?;
  assert_eq!(catalog_revoked.retained.render(), "read");
  assert_eq!(catalog_revoked.access.render(), "read");
  let entitled_revoked = refresh_scopes(
    &names(&["read", "write"]),
    Some("read"),
    &full,
    &full,
    &read,
  )?;
  assert_eq!(entitled_revoked.retained.render(), "read");
  assert_eq!(entitled_revoked.access.render(), "read");
  // A fully revoked grant retains (and grants) nothing rather than failing.
  let emptied = refresh_scopes(
    &names(&["read", "write"]),
    None,
    &full,
    &full,
    &ScopeSet::empty(),
  )?;
  assert!(emptied.retained.is_empty());
  assert!(emptied.access.is_empty());
  // Widening via an explicit request is still `invalid_scope`.
  assert!(is_invalid_scope(refresh_scopes(
    &read,
    Some("read write"),
    &full,
    &full,
    &full
  )));
  Ok(())
}

#[test]
fn scope_refresh_enforces_current_entitlements() -> TestResult {
  let enabled = names(&["read", "write"]);
  let previous = names(&["read", "write"]);
  let entitled_both = names(&["read", "write"]);
  let entitled_read = names(&["read"]);
  let registered_both = names(&["read", "write"]);
  let registered_read = names(&["read"]);
  // Omitted scope silently narrows to the still-entitled, still-registered
  // intersection; a fully de-entitled grant narrows to empty.
  assert_eq!(
    narrow_on_refresh(&previous, None, &enabled, &registered_both, &entitled_read)?.render(),
    "read"
  );
  assert_eq!(
    narrow_on_refresh(&previous, None, &enabled, &registered_read, &entitled_both)?.render(),
    "read"
  );
  assert_eq!(
    narrow_on_refresh(&previous, None, &enabled, &registered_both, &entitled_both)?.render(),
    "read write"
  );
  assert!(
    narrow_on_refresh(
      &previous,
      None,
      &enabled,
      &registered_both,
      &ScopeSet::empty()
    )?
    .is_empty()
  );
  // An explicit request for a no-longer-entitled or de-registered scope is
  // `invalid_scope`; a still-entitled explicit narrow is kept.
  assert!(is_invalid_scope(narrow_on_refresh(
    &previous,
    Some("read write"),
    &enabled,
    &registered_both,
    &entitled_read
  )));
  assert!(is_invalid_scope(narrow_on_refresh(
    &previous,
    Some("read write"),
    &enabled,
    &registered_read,
    &entitled_both
  )));
  assert_eq!(
    narrow_on_refresh(
      &previous,
      Some("read"),
      &enabled,
      &registered_both,
      &entitled_both
    )?
    .render(),
    "read"
  );
  Ok(())
}

proptest! {
  #[test]
    fn scope_parse_render_roundtrip_is_idempotent(words in proptest::collection::vec("[a-z0-9:_.-]{1,12}", 0..8)) {
    match ScopeSet::parse(&words.join(" ")) {
      Ok(set) => match ScopeSet::parse(&set.render()) {
        Ok(again) => {
          prop_assert_eq!(set.render(), again.render());
          prop_assert!(again.is_subset_of(&set));
        }
        Err(_) => prop_assert!(false, "rendered form must re-parse"),
      },
      Err(_) => prop_assert!(words.is_empty(), "valid words must parse"),
    }
  }
}

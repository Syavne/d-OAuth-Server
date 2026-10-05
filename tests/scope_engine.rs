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
    effective_scope, narrow_on_refresh,
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
    narrow_on_refresh(&previous, None, &enabled)?.render(),
    "read write"
  );
  assert_eq!(
    narrow_on_refresh(&previous, Some("read"), &enabled)?.render(),
    "read"
  );
  assert!(is_invalid_scope(narrow_on_refresh(
    &names(&["read"]),
    Some("read write"),
    &enabled
  )));
  assert!(is_invalid_scope(narrow_on_refresh(
    &previous,
    Some("admin"),
    &enabled
  )));
  assert!(is_invalid_scope(narrow_on_refresh(
    &previous,
    None,
    &names(&["read"])
  )));
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

//! Acceptance tests for configuration loading and validation.
//!
//! Named so `cargo nextest run -E 'test(config)'` selects them. No test reads
//! the real process environment or a live database/Redis.

use std::{error::Error, time::Duration};

use serde_json::{Map, Value, json};

use super::{Config, ConfigError, DcrRedirectPolicy, RedisTopology};
use crate::keys::KeyRingError;

fn base() -> Map<String, Value> {
  match json!({
    "issuer": "https://auth.example.com",
    "environment": "production",
    "tls": {
      "cert_path": "/etc/d-oauth/tls.crt",
      "key_path": "/etc/d-oauth/tls.key",
      "client_ca_path": "/etc/d-oauth/client-ca.pem"
    },
    "database": {
      "url": "postgres://oauth:DB_PASSWORD_XYZ@db:5432/oauth?sslmode=verify-full",
      "root_cert_path": "/etc/d-oauth/pg-ca.pem"
    },
    "redis": {
      "url": "rediss://redis:6379",
      "durability": "waitaof",
      "root_cert_path": "/etc/d-oauth/redis-ca.pem"
    },
    "token_pepper": "SUPER_SECRET_PEPPER_VALUE-0123456789abcdef",
    "token_pepper_id": "v1",
    "totp_encryption_key": "SUPER_SECRET_TOTP_KEY-0123456789abcdef",
    "totp_key_id": "v1",
    "pii_encryption_key": "SUPER_SECRET_PII_KEY-0123456789abcdef",
    "pii_key_id": "v1",
    "cookie_secure": true,
    "allow_open_registration": false,
    "dcr_redirect_policy": "catalog",
    "cors_allowed_origins": [],
    "scope_registry": [],
    "allow_token_exchange": false
  }) {
    Value::Object(map) => map,
    _ => Map::new(),
  }
}

fn try_load(map: &Map<String, Value>) -> Result<Config, ConfigError> {
  let source = ::config::Config::try_from(map).map_err(ConfigError::from)?;
  Config::from_source(source)
}

fn without(key: &str) -> Map<String, Value> {
  let mut map = base();
  map.remove(key);
  map
}

fn with_database_field(key: &str, value: Value) -> Map<String, Value> {
  let mut map = base();
  if let Some(database) = map.get_mut("database").and_then(Value::as_object_mut) {
    database.insert(key.to_owned(), value);
  }
  map
}

fn without_redis_durability() -> Map<String, Value> {
  let mut map = base();
  if let Some(redis) = map.get_mut("redis").and_then(Value::as_object_mut) {
    redis.remove("durability");
  }
  map
}

fn with_ttl(access_secs: u64, refresh_secs: u64) -> Map<String, Value> {
  let mut map = base();
  map.insert(
    "ttl".to_owned(),
    json!({ "access_secs": access_secs, "refresh_secs": refresh_secs }),
  );
  map
}

#[test]
fn config_loads_with_empty_scope_registry() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  assert!(cfg.scope_registry.is_empty());
  assert_eq!(cfg.ttl.access, Duration::from_secs(300));
  assert_eq!(cfg.ttl.refresh, Duration::from_secs(2_592_000));
  assert_eq!(cfg.ttl.code, Duration::from_secs(60));
  assert_eq!(cfg.ttl.par, Duration::from_secs(90));
  assert_eq!(cfg.ttl.device, Duration::from_secs(600));
  assert_eq!(cfg.ttl.dcr_initial_access, Duration::from_secs(86_400));
  assert_eq!(cfg.ttl.session, Duration::from_secs(43_200));
  assert!(cfg.cookie_secure);
  assert_eq!(cfg.dcr_redirect_policy, DcrRedirectPolicy::Catalog);
  assert!(!cfg.allow_open_registration);
  assert!(cfg.cors_allowed_origins.is_empty());
  Ok(())
}

#[test]
fn config_defaults_bind_and_health_addresses() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  assert_eq!(cfg.bind_addr.to_string(), "0.0.0.0:8080");
  assert_eq!(cfg.health_addr.to_string(), "0.0.0.0:8081");
  Ok(())
}

#[test]
fn config_rejects_missing_issuer() {
  let result = try_load(&without("issuer"));
  assert!(matches!(result, Err(ConfigError::MissingIssuer)));
}

#[test]
fn config_rejects_insecure_http_issuer() {
  let mut map = base();
  map.insert("issuer".to_owned(), Value::String("http://x".to_owned()));
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::InsecureIssuer { .. })));
}

#[test]
fn config_rejects_issuer_with_trailing_slash() {
  let mut map = base();
  map.insert(
    "issuer".to_owned(),
    Value::String("https://auth.example.com/".to_owned()),
  );
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::InsecureIssuer { .. })));
}

#[test]
fn config_rejects_missing_token_pepper() {
  let result = try_load(&without("token_pepper"));
  assert!(matches!(
    result,
    Err(ConfigError::KeyRing(KeyRingError::MissingTokenPepper))
  ));
}

#[test]
fn config_rejects_redis_without_durability_contract() {
  let result = try_load(&without_redis_durability());
  assert!(matches!(result, Err(ConfigError::RedisDurabilityContract)));
}

#[test]
fn config_rejects_single_node_with_replicated_durability() {
  let mut map = base();
  if let Some(redis) = map.get_mut("redis").and_then(Value::as_object_mut) {
    redis.insert("durability".to_owned(), Value::String("wait".to_owned()));
  }
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::RedisDurabilityContract)));
}

#[test]
fn config_accepts_cluster_with_wait_durability() -> Result<(), Box<dyn Error>> {
  let mut map = base();
  if let Some(redis) = map.get_mut("redis").and_then(Value::as_object_mut) {
    redis.remove("url");
    redis.insert("seeds".to_owned(), json!(["redis-0:6379", "redis-1:6379"]));
    redis.insert("tls".to_owned(), Value::Bool(true));
    redis.insert("durability".to_owned(), Value::String("wait".to_owned()));
  }
  let cfg = try_load(&map)?;
  assert!(matches!(cfg.redis.topology, RedisTopology::Cluster { .. }));
  Ok(())
}

#[test]
fn config_rejects_production_postgres_without_verify_full() {
  let map = with_database_field(
    "url",
    Value::String("postgres://oauth:pw@db:5432/oauth".to_owned()),
  );
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::InsecureDatabaseTls)));
}

#[test]
fn config_allows_development_postgres_without_verify_full() -> Result<(), Box<dyn Error>> {
  let mut map = with_database_field(
    "url",
    Value::String("postgres://oauth:pw@127.0.0.1:5432/oauth".to_owned()),
  );
  map.insert(
    "environment".to_owned(),
    Value::String("development".to_owned()),
  );
  let cfg = try_load(&map)?;
  assert_eq!(cfg.environment, super::Environment::Development);
  Ok(())
}

#[test]
fn config_rejects_invalid_timeout_ladder() {
  let map = with_database_field("lock_timeout_secs", json!(5));
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::InvalidTimeoutLadder)));
}

#[test]
fn config_rejects_access_ttl_longer_than_refresh() {
  let map = with_ttl(2_592_001, 2_592_000);
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::InvalidTtlLadder)));
}

#[test]
fn config_accepts_access_ttl_equal_to_refresh() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&with_ttl(3_600, 3_600))?;
  assert_eq!(cfg.ttl.access, Duration::from_secs(3_600));
  Ok(())
}

#[test]
fn config_rejects_reserved_openid_scope() {
  let mut map = base();
  map.insert("scope_registry".to_owned(), json!([{ "name": "openid" }]));
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::ReservedScope { .. })));
}

#[test]
fn config_accepts_namespaced_scope_registry() -> Result<(), Box<dyn Error>> {
  let mut map = base();
  map.insert(
    "scope_registry".to_owned(),
    json!([
      { "name": "api:read", "description": "read the API" },
      {
        "name": "api:write",
        "allowed_grants": ["authorization_code"],
        "allowed_client_classes": ["confidential"]
      }
    ]),
  );
  let cfg = try_load(&map)?;
  assert_eq!(cfg.scope_registry.len(), 2);
  assert_eq!(cfg.scope_registry[0].name, "api:read");
  Ok(())
}

#[test]
fn config_redis_startup_assertions_are_callable() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  assert!(cfg.redis.assert_noeviction_policy("noeviction").is_ok());
  assert!(matches!(
    cfg.redis.assert_noeviction_policy("allkeys-lru"),
    Err(ConfigError::RedisEvictionPolicy { .. })
  ));
  assert!(cfg.redis.assert_aof_persistence(true).is_ok());
  assert!(matches!(
    cfg.redis.assert_aof_persistence(false),
    Err(ConfigError::RedisAofDisabled)
  ));
  assert!(cfg.redis.assert_topology_reachable(true).is_ok());
  assert!(matches!(
    cfg.redis.assert_topology_reachable(false),
    Err(ConfigError::RedisUnreachable)
  ));
  Ok(())
}

#[test]
fn config_debug_redacts_secret_values() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  let rendered = format!("{cfg:?}");
  assert!(!rendered.contains("SUPER_SECRET_PEPPER_VALUE-0123456789abcdef"));
  assert!(!rendered.contains("SUPER_SECRET_TOTP_KEY-0123456789abcdef"));
  assert!(!rendered.contains("SUPER_SECRET_PII_KEY-0123456789abcdef"));
  assert!(!rendered.contains("DB_PASSWORD_XYZ"));
  assert!(rendered.contains("REDACTED"));
  Ok(())
}

#[test]
fn config_env_double_underscore_maps_to_nested_snake_keys() -> Result<(), Box<dyn Error>> {
  let mut env = std::collections::HashMap::new();
  env.insert(
    "D_OAUTH_TLS__CERT_PATH".to_owned(),
    "/certs/tls.crt".to_owned(),
  );
  env.insert(
    "D_OAUTH_TLS__KEY_PATH".to_owned(),
    "/certs/tls.key".to_owned(),
  );
  env.insert(
    "D_OAUTH_TOKEN_PEPPER".to_owned(),
    "dev-only-pepper-ROTATE-IN-PROD-000000".to_owned(),
  );
  let built = ::config::Config::builder()
    .add_source(super::env_source().source(Some(env)))
    .build()?;
  let raw: super::raw::RawConfig = built.try_deserialize()?;
  assert_eq!(
    raw.tls.cert_path,
    Some(std::path::PathBuf::from("/certs/tls.crt"))
  );
  assert_eq!(
    raw.tls.key_path,
    Some(std::path::PathBuf::from("/certs/tls.key"))
  );
  assert_eq!(
    raw.token_pepper.as_deref(),
    Some("dev-only-pepper-ROTATE-IN-PROD-000000")
  );
  Ok(())
}

#[test]
fn config_rejects_missing_pii_key() {
  let result = try_load(&without("pii_encryption_key"));
  assert!(matches!(
    result,
    Err(ConfigError::KeyRing(KeyRingError::MissingPiiKey))
  ));
}

#[test]
fn config_rejects_empty_active_pii_key() {
  let mut map = base();
  map.insert(
    "pii_encryption_key".to_owned(),
    Value::String("   ".to_owned()),
  );
  let result = try_load(&map);
  assert!(matches!(
    result,
    Err(ConfigError::KeyRing(KeyRingError::MissingPiiKey))
  ));

  let path = std::env::temp_dir().join(format!("d-oauth-empty-pii-key-{}.txt", std::process::id()));
  if std::fs::write(&path, "").is_ok() {
    let mut file_map = base();
    file_map.remove("pii_encryption_key");
    file_map.insert(
      "pii_encryption_key_file".to_owned(),
      Value::String(path.to_string_lossy().into_owned()),
    );
    let result = try_load(&file_map);
    let _ = std::fs::remove_file(&path);
    assert!(matches!(
      result,
      Err(ConfigError::KeyRing(KeyRingError::MissingPiiKey))
    ));
  }
}

/// A resolved pepper/TOTP/PII key shorter than 32 bytes is rejected with the
/// offending key named; retained previous keys are checked too.
#[test]
fn config_rejects_weak_key_material() {
  for (key, value) in [
    ("token_pepper", "short-pepper-material"),
    ("totp_encryption_key", "short-totp-key-material"),
    ("pii_encryption_key", "short-pii-key-material"),
  ] {
    let mut map = base();
    map.insert(key.to_owned(), Value::String(value.to_owned()));
    assert!(
      matches!(
        try_load(&map),
        Err(ConfigError::WeakKeyMaterial { key: rejected }) if rejected == key
      ),
      "{key} shorter than 32 bytes must be rejected"
    );
  }
  for key in ["totp_previous_key", "pii_previous_key"] {
    let mut map = base();
    map.insert(
      key.to_owned(),
      Value::String("short-previous-key".to_owned()),
    );
    map.insert(format!("{key}_id"), Value::String("v0".to_owned()));
    assert!(
      matches!(
        try_load(&map),
        Err(ConfigError::WeakKeyMaterial { key: rejected }) if rejected == key
      ),
      "previous key {key} shorter than 32 bytes must be rejected"
    );
  }
}

/// The key-length boundary is exact: 31 bytes is rejected, 32 accepted.
#[test]
fn config_key_length_boundary_is_32_bytes() -> Result<(), Box<dyn Error>> {
  let mut exact = base();
  exact.insert("token_pepper".to_owned(), Value::String("p".repeat(32)));
  let cfg = try_load(&exact)?;
  assert!(cfg.keys.active_pepper().is_some());

  let mut short = base();
  short.insert("token_pepper".to_owned(), Value::String("p".repeat(31)));
  assert!(matches!(
    try_load(&short),
    Err(ConfigError::WeakKeyMaterial {
      key: "token_pepper"
    })
  ));
  Ok(())
}

#[test]
fn config_builds_pii_chain() -> Result<(), Box<dyn Error>> {
  let mut map = base();
  map.insert(
    "pii_previous_key".to_owned(),
    Value::String("SUPER_SECRET_PII_PREVIOUS-0123456789abcdef".to_owned()),
  );
  map.insert(
    "pii_previous_key_id".to_owned(),
    Value::String("v0".to_owned()),
  );
  map.insert("pii_dual_write".to_owned(), Value::Bool(true));
  let cfg = try_load(&map)?;
  let active = cfg.keys.active_pii_key().ok_or("missing active pii key")?;
  assert_eq!(active.0.as_str(), "v1");
  let retained = cfg
    .keys
    .pii_key_by_id("v0")
    .ok_or("missing retained pii key")?;
  assert!(!cfg.keys.pii_key_by_id("v9").is_some());
  let _ = retained;
  let ids: Vec<&str> = cfg
    .keys
    .pii_keys_newest_first()
    .map(|(id, _)| id.as_str())
    .collect();
  assert_eq!(ids, vec!["v1", "v0"]);
  assert!(cfg.pii_dual_write);

  let dual_default = try_load(&base())?;
  assert!(!dual_default.pii_dual_write);
  Ok(())
}

#[test]
fn config_rejects_previous_key_without_id() {
  let mut map = base();
  map.insert(
    "pii_previous_key".to_owned(),
    Value::String("SUPER_SECRET_PII_PREVIOUS-0123456789abcdef".to_owned()),
  );
  let result = try_load(&map);
  assert!(matches!(result, Err(ConfigError::MissingPreviousKeyId)));

  let mut same_id = base();
  same_id.insert(
    "pii_previous_key".to_owned(),
    Value::String("SUPER_SECRET_PII_PREVIOUS-0123456789abcdef".to_owned()),
  );
  same_id.insert(
    "pii_previous_key_id".to_owned(),
    Value::String("v1".to_owned()),
  );
  let result = try_load(&same_id);
  assert!(matches!(result, Err(ConfigError::MissingPreviousKeyId)));

  let mut totp = base();
  totp.insert(
    "totp_previous_key".to_owned(),
    Value::String("SUPER_SECRET_TOTP_PREVIOUS-0123456789abcdef".to_owned()),
  );
  let result = try_load(&totp);
  assert!(matches!(result, Err(ConfigError::MissingPreviousKeyId)));
}

#[test]
fn config_rejects_previous_key_without_active() {
  let mut pii = without("pii_encryption_key");
  pii.insert(
    "pii_previous_key".to_owned(),
    Value::String("SUPER_SECRET_PII_PREVIOUS-0123456789abcdef".to_owned()),
  );
  pii.insert(
    "pii_previous_key_id".to_owned(),
    Value::String("v0".to_owned()),
  );
  let result = try_load(&pii);
  assert!(matches!(
    result,
    Err(ConfigError::KeyRing(KeyRingError::MissingPiiKey))
  ));

  let mut totp = without("totp_encryption_key");
  totp.insert(
    "totp_previous_key".to_owned(),
    Value::String("SUPER_SECRET_TOTP_PREVIOUS-0123456789abcdef".to_owned()),
  );
  totp.insert(
    "totp_previous_key_id".to_owned(),
    Value::String("v0".to_owned()),
  );
  let result = try_load(&totp);
  assert!(matches!(
    result,
    Err(ConfigError::KeyRing(KeyRingError::MissingTotpKey))
  ));
}

#[test]
fn config_treats_empty_previous_key_as_absent() -> Result<(), Box<dyn Error>> {
  let mut map = base();
  map.insert(
    "pii_previous_key".to_owned(),
    Value::String("   ".to_owned()),
  );
  map.insert(
    "pii_previous_key_id".to_owned(),
    Value::String("v0".to_owned()),
  );
  let cfg = try_load(&map)?;
  let ids: Vec<&str> = cfg
    .keys
    .pii_keys_newest_first()
    .map(|(id, _)| id.as_str())
    .collect();
  assert_eq!(ids, vec!["v1"]);

  let path = std::env::temp_dir().join(format!(
    "d-oauth-empty-pii-previous-{}.txt",
    std::process::id()
  ));
  if std::fs::write(&path, "").is_ok() {
    let mut file_map = base();
    file_map.insert(
      "pii_previous_key_file".to_owned(),
      Value::String(path.to_string_lossy().into_owned()),
    );
    file_map.insert(
      "pii_previous_key_id".to_owned(),
      Value::String("v0".to_owned()),
    );
    let cfg = try_load(&file_map)?;
    let _ = std::fs::remove_file(&path);
    let ids: Vec<&str> = cfg
      .keys
      .pii_keys_newest_first()
      .map(|(id, _)| id.as_str())
      .collect();
    assert_eq!(ids, vec!["v1"]);
  }
  Ok(())
}

#[test]
fn config_rejects_dotted_key_id() {
  for key in ["token_pepper_id", "totp_key_id", "pii_key_id"] {
    let mut map = base();
    map.insert(key.to_owned(), Value::String("v1.evil".to_owned()));
    assert!(
      matches!(try_load(&map), Err(ConfigError::InvalidKeyId { .. })),
      "{key} must reject a dotted key id"
    );
  }
  let mut previous = base();
  previous.insert(
    "pii_previous_key".to_owned(),
    Value::String("SUPER_SECRET_PII_PREVIOUS-0123456789abcdef".to_owned()),
  );
  previous.insert(
    "pii_previous_key_id".to_owned(),
    Value::String("v0.evil".to_owned()),
  );
  assert!(matches!(
    try_load(&previous),
    Err(ConfigError::InvalidKeyId { .. })
  ));
}

#[test]
fn read_secret_file_preserves_surrounding_spaces() -> Result<(), Box<dyn Error>> {
  use secrecy::ExposeSecret as _;
  let path = std::env::temp_dir().join(format!(
    "d-oauth-read-secret-file-{}.txt",
    std::process::id()
  ));
  std::fs::write(&path, "  spaced-secret  \n")?;
  let secret = super::read_secret_file(Some(path.as_path()))?;
  let _ = std::fs::remove_file(&path);
  let secret = secret.ok_or("secret file returned None")?;
  assert_eq!(secret.expose_secret(), "  spaced-secret  ");
  Ok(())
}

/// The trusted-proxy allowlist defaults to empty: headers are never honored
/// unless the operator configures the proxy peers explicitly.
#[test]
fn config_trusted_proxies_default_empty() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  assert!(cfg.rate_limit.trusted_proxies.is_empty());
  Ok(())
}

/// Exact IPs and CIDRs load into the allowlist and match only their range.
#[test]
fn config_accepts_trusted_proxy_allowlist() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;
  let mut map = base();
  map.insert(
    "rate_limit".to_owned(),
    json!({ "trusted_proxies": ["10.0.0.1", "192.168.0.0/16", "2001:db8::/32"] }),
  );
  let cfg = try_load(&map)?;
  assert_eq!(cfg.rate_limit.trusted_proxies.len(), 3);
  let contains = |text: &str| {
    cfg
      .rate_limit
      .trusted_proxies
      .iter()
      .any(|net| net.contains(IpAddr::from_str(text).unwrap_or(IpAddr::from([0, 0, 0, 0]))))
  };
  assert!(contains("10.0.0.1"));
  assert!(!contains("10.0.0.2"));
  assert!(contains("192.168.34.7"));
  assert!(!contains("192.167.0.1"));
  assert!(contains("2001:db8::1"));
  assert!(!contains("2001:db9::1"));
  Ok(())
}

/// T3-D2: the server-side session lifetime is pinned at 12 h. The review
/// outcome is absolute expiry with no idle sliding: reads never re-arm the
/// TTL, so a live session always dies 12 h after its last write.
#[test]
fn config_session_ttl_pinned_to_12h() -> Result<(), Box<dyn Error>> {
  let cfg = try_load(&base())?;
  assert_eq!(cfg.ttl.session, Duration::from_secs(43_200));
  Ok(())
}

/// T3-D2: a zero session lifetime is rejected like every other zero TTL.
#[test]
fn config_rejects_zero_session_ttl() {
  let mut map = base();
  map.insert("ttl".to_owned(), json!({ "session_secs": 0 }));
  assert!(matches!(try_load(&map), Err(ConfigError::InvalidTtl)));
}

/// T3-D2: production without the `Secure` cookie attribute is rejected at
/// load; the `cookie_secure = false` gate is a development-only exception.
#[test]
fn config_rejects_production_cookie_without_secure() {
  let mut map = base();
  map.insert("cookie_secure".to_owned(), Value::Bool(false));
  assert!(matches!(
    try_load(&map),
    Err(ConfigError::InsecureSessionCookie)
  ));
}

/// T3-D2: development keeps the localhost exception (`Secure` off), and the
/// session cookie drops the `__Host-` prefix there (browsers reject `__Host-`
/// without `Secure`).
#[test]
fn config_allows_development_cookie_without_secure() -> Result<(), Box<dyn Error>> {
  let mut map = base();
  map.insert(
    "environment".to_owned(),
    Value::String("development".to_owned()),
  );
  map.insert("cookie_secure".to_owned(), Value::Bool(false));
  let cfg = try_load(&map)?;
  assert!(!cfg.cookie_secure);
  assert_eq!(
    crate::ui::login::session_cookie_name(&cfg),
    crate::ui::login::INSECURE_SESSION_COOKIE
  );
  Ok(())
}

/// T3-D2: a `cookie_domain` outside the issuer host is rejected at load.
#[test]
fn config_rejects_cookie_domain_mismatch() {
  let mut map = base();
  map.insert(
    "cookie_domain".to_owned(),
    Value::String("evil.example".to_owned()),
  );
  assert!(matches!(
    try_load(&map),
    Err(ConfigError::InvalidCookieDomain { .. })
  ));
}

/// T3-D2: even a matching `cookie_domain` is rejected: the `__Host-` session
/// cookie forbids `Domain`, so sessions stay host-only by design.
#[test]
fn config_rejects_cookie_domain_even_when_suffix_of_issuer_host() {
  for domain in ["auth.example.com", "example.com"] {
    let mut map = base();
    map.insert("cookie_domain".to_owned(), Value::String(domain.to_owned()));
    assert!(
      matches!(try_load(&map), Err(ConfigError::InvalidCookieDomain { .. })),
      "cookie_domain {domain:?} must be rejected under the __Host- prefix"
    );
  }
}

/// T3-D2: a blank `cookie_domain` is treated as absent, matching the other
/// optional keys — only a non-blank value is rejected.
#[test]
fn config_blank_cookie_domain_treated_as_absent() -> Result<(), Box<dyn Error>> {
  for domain in ["", "   ", ".", " . "] {
    let mut map = base();
    map.insert("cookie_domain".to_owned(), Value::String(domain.to_owned()));
    let cfg = try_load(&map)?;
    assert!(
      cfg.cookie_domain.is_none(),
      "blank cookie_domain {domain:?} must be treated as absent"
    );
  }
  Ok(())
}

/// The documented env form `D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES='["10.0.0.5"]'`
/// loads through `env_source()`: the JSON array string becomes one allowlist
/// entry (config-rs 0.15 leaves env values as strings without this handling).
#[test]
fn config_trusted_proxies_env_array_loads() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;
  let mut env = std::collections::HashMap::new();
  env.insert(
    "D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES".to_owned(),
    r#"["10.0.0.5"]"#.to_owned(),
  );
  let built = ::config::Config::builder()
    .add_source(super::env_source().source(Some(env)))
    .build()?;
  let raw: super::raw::RawConfig = built.try_deserialize()?;
  assert_eq!(raw.rate_limit.trusted_proxies, vec!["10.0.0.5"]);
  let validated = super::types::RateLimitConfig::from_raw(raw.rate_limit)?;
  assert_eq!(validated.trusted_proxies.len(), 1);
  let probe = IpAddr::from_str("10.0.0.5").map_err(|_| "bad test ip")?;
  assert!(
    validated
      .trusted_proxies
      .iter()
      .any(|net| net.contains(probe))
  );
  Ok(())
}

/// A malformed entry, an out-of-range prefix, or a trust-everything `/0`
/// fails the load: an unparseable allowlist must never silently mean "trust
/// nobody" or "trust everybody".
#[test]
fn config_rejects_invalid_trusted_proxy() {
  for entry in [
    "not-an-ip",
    "",
    "10.0.0.0/33",
    "2001:db8::/129",
    "10.0.0.1/-1",
    "10.0.0.0/0",
    "0.0.0.0/0",
    "::/0",
    "10.0.0.1/abc",
    "10.0.0.256",
  ] {
    let mut map = base();
    map.insert(
      "rate_limit".to_owned(),
      json!({ "trusted_proxies": [entry] }),
    );
    assert!(
      matches!(try_load(&map), Err(ConfigError::InvalidTrustedProxy { .. })),
      "entry {entry:?} must be rejected"
    );
  }
}

/// T3-C3: CIDR boundary prefixes match exactly their range. A `/32` (v4) or
/// `/128` (v6) host route matches only its own address; a `/1` splits the
/// address space in half.
#[test]
fn config_trusted_proxy_cidr_boundaries() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;

  use super::types::TrustedProxyNet;
  let host_v4 = TrustedProxyNet::from_str("10.0.0.5/32")?;
  assert!(host_v4.contains(IpAddr::from_str("10.0.0.5")?));
  assert!(!host_v4.contains(IpAddr::from_str("10.0.0.6")?));
  assert!(!host_v4.contains(IpAddr::from_str("10.0.0.4")?));
  let host_v6 = TrustedProxyNet::from_str("2001:db8::1/128")?;
  assert!(host_v6.contains(IpAddr::from_str("2001:db8::1")?));
  assert!(!host_v6.contains(IpAddr::from_str("2001:db8::2")?));
  let lower_half = TrustedProxyNet::from_str("0.0.0.0/1")?;
  assert!(lower_half.contains(IpAddr::from_str("10.0.0.1")?));
  assert!(lower_half.contains(IpAddr::from_str("127.0.0.1")?));
  assert!(!lower_half.contains(IpAddr::from_str("128.0.0.1")?));
  assert!(!lower_half.contains(IpAddr::from_str("200.0.0.1")?));
  let upper_half = TrustedProxyNet::from_str("128.0.0.0/1")?;
  assert!(upper_half.contains(IpAddr::from_str("200.0.0.1")?));
  assert!(!upper_half.contains(IpAddr::from_str("10.0.0.1")?));
  Ok(())
}

/// T3-C3: a CIDR base with host bits set is normalized to its network base,
/// so `192.168.1.5/24` behaves exactly like `192.168.1.0/24`.
#[test]
fn config_trusted_proxy_prefix_normalization() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;

  use super::types::TrustedProxyNet;
  let host_bits = TrustedProxyNet::from_str("192.168.1.5/24")?;
  let canonical = TrustedProxyNet::from_str("192.168.1.0/24")?;
  for address in ["192.168.1.1", "192.168.1.5", "192.168.1.254"] {
    let ip = IpAddr::from_str(address)?;
    assert!(
      host_bits.contains(ip),
      "{address} must be inside 192.168.1.5/24"
    );
    assert_eq!(host_bits.contains(ip), canonical.contains(ip));
  }
  for address in ["192.168.2.5", "192.168.0.5", "10.0.0.1"] {
    let ip = IpAddr::from_str(address)?;
    assert!(
      !host_bits.contains(ip),
      "{address} must be outside 192.168.1.5/24"
    );
  }
  let host_bits_v6 = TrustedProxyNet::from_str("2001:db8::1/32")?;
  assert!(host_bits_v6.contains(IpAddr::from_str("2001:db8::dead:beef")?));
  assert!(!host_bits_v6.contains(IpAddr::from_str("2001:db9::1")?));
  Ok(())
}

/// T3-C3: an entry never matches an address of the other family, so a v4
/// allowlist cannot be satisfied by a v6 peer and vice versa.
#[test]
fn config_trusted_proxy_family_mismatch_never_matches() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;

  use super::types::TrustedProxyNet;
  let v4_net = TrustedProxyNet::from_str("10.0.0.0/8")?;
  assert!(!v4_net.contains(IpAddr::from_str("::1")?));
  assert!(!v4_net.contains(IpAddr::from_str("::ffff:10.0.0.1")?));
  assert!(!v4_net.contains(IpAddr::from_str("2001:db8::1")?));
  let v6_net = TrustedProxyNet::from_str("2001:db8::/32")?;
  assert!(!v6_net.contains(IpAddr::from_str("127.0.0.1")?));
  assert!(!v6_net.contains(IpAddr::from_str("10.0.0.1")?));
  let v4_host = TrustedProxyNet::from_str("10.0.0.1")?;
  assert!(!v4_host.contains(IpAddr::from_str("::ffff:10.0.0.1")?));
  Ok(())
}

/// T3-C3: the allowlist cap admits exactly 64 entries; the 65th fails the
/// load instead of silently truncating the operator's intent.
#[test]
fn config_trusted_proxy_allowlist_cap_64_accepts_65_rejects() -> Result<(), Box<dyn Error>> {
  let entries: Vec<Value> = (0..64)
    .map(|index| Value::String(format!("10.0.{index}.1")))
    .collect();
  let mut map = base();
  map.insert(
    "rate_limit".to_owned(),
    json!({ "trusted_proxies": entries }),
  );
  let cfg = try_load(&map)?;
  assert_eq!(cfg.rate_limit.trusted_proxies.len(), 64);
  let entries: Vec<Value> = (0..65)
    .map(|index| Value::String(format!("10.0.{index}.1")))
    .collect();
  let mut map = base();
  map.insert(
    "rate_limit".to_owned(),
    json!({ "trusted_proxies": entries }),
  );
  assert!(
    matches!(try_load(&map), Err(ConfigError::InvalidTrustedProxy { .. })),
    "65 trusted-proxy entries must exceed the allowlist cap"
  );
  Ok(())
}

/// T3-C3: surrounding whitespace is trimmed and duplicate entries load as
/// written (no silent dedup, no silent drop).
#[test]
fn config_trusted_proxy_whitespace_and_duplicates() -> Result<(), Box<dyn Error>> {
  use std::net::IpAddr;
  use std::str::FromStr as _;

  let mut map = base();
  map.insert(
    "rate_limit".to_owned(),
    json!({ "trusted_proxies": ["  10.0.0.1  ", "10.0.0.1", "\t192.168.0.0/16\n"] }),
  );
  let cfg = try_load(&map)?;
  assert_eq!(cfg.rate_limit.trusted_proxies.len(), 3);
  let probe_v4 = IpAddr::from_str("10.0.0.1")?;
  assert!(
    cfg
      .rate_limit
      .trusted_proxies
      .iter()
      .any(|net| net.contains(probe_v4))
  );
  let probe_range = IpAddr::from_str("192.168.9.9")?;
  assert!(
    cfg
      .rate_limit
      .trusted_proxies
      .iter()
      .any(|net| net.contains(probe_range))
  );
  Ok(())
}

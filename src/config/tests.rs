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
    "token_pepper": "SUPER_SECRET_PEPPER_VALUE",
    "token_pepper_id": "v1",
    "totp_encryption_key": "SUPER_SECRET_TOTP_KEY",
    "totp_key_id": "v1",
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
  assert!(cfg.trusted_proxy.is_none());
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
  assert!(!rendered.contains("SUPER_SECRET_PEPPER_VALUE"));
  assert!(!rendered.contains("SUPER_SECRET_TOTP_KEY"));
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

# Configuration

The server is configured from `D_OAUTH_*` environment variables plus an optional
file named by `D_OAUTH_CONFIG`. Configuration is validated at load time and the
process refuses to start on an insecure or inconsistent setting.

## Purpose

This guide lists every configuration key, its default, and its validation rule,
so an operator can build a correct environment without reading the source. The
loader lives in `src/config.rs` and its submodules.

## How loading works

`Config::load` builds a layered source:

1. An environment source with prefix `D_OAUTH`, prefix separator `_`, and
   nesting separator `__`, lowercased and parsed with type coercion.
2. An optional file from `D_OAUTH_CONFIG` (YAML or TOML by extension). It is
   not required.
3. Two conventional secret-file overrides: `DATABASE_PASSWORD_FILE` sets
   `database.password_file`, and `REDIS_PASSWORD_FILE` sets
   `redis.password_file`.

The environment spelling of a nested key is `D_OAUTH_` followed by the path
with every `.` replaced by `__`, uppercased. For example:

| YAML path | Environment variable |
| --- | --- |
| `database.url` | `D_OAUTH_DATABASE__URL` |
| `redis.connect_timeout_secs` | `D_OAUTH_REDIS__CONNECT_TIMEOUT_SECS` |
| `ttl.access_secs` | `D_OAUTH_TTL__ACCESS_SECS` |
| `failure_policy.request_timeout_secs` | `D_OAUTH_FAILURE_POLICY__REQUEST_TIMEOUT_SECS` |
| `tls.cert_path` | `D_OAUTH_TLS__CERT_PATH` |

A secret may be given inline or as a mounted file. Inline wins when both are
set. Mounted files are read and trimmed of trailing newlines.

The key ring follows the same pattern: `token_pepper_file`,
`totp_encryption_key_file`, and `pii_encryption_key_file` (environment
spellings `D_OAUTH_TOKEN_PEPPER_FILE`, `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`, and
`D_OAUTH_PII_ENCRYPTION_KEY_FILE`) name mounted files. The cluster Deployment
uses those file forms so the material never enters the process environment;
mount them `0400` on a tmpfs (the shipped manifests project them at
`/run/secrets` with group `65532`). The inline forms are retained and win when
both are set, so an existing environment-based deployment still starts. Each
purpose also has an optional retained previous key (`*_previous_key` and its
`*_previous_key_file` form) so a rotation can keep old ciphertext readable.
Every resolved key — `token_pepper`, `totp_encryption_key`,
`pii_encryption_key`, and each retained `*_previous_key` — must be at least 32
bytes (256 bits). A shorter key is rejected at load with `WeakKeyMaterial`,
which names the offending key.

## Top-level keys

| Key | Default | Rule |
| --- | --- | --- |
| `issuer` | required | Absolute `https` URL with no trailing slash and no whitespace in the authority. |
| `bind_addr` | `0.0.0.0:8080` | A socket address. The TLS public listener. |
| `health_addr` | `0.0.0.0:8081` | A socket address. `serve` refuses a loopback address; `config check` does not. The plaintext health listener. |
| `environment` | `production` | `production` or `development`. Development relaxes the database TLS requirement. |
| `cookie_domain` | none (host-only) | Optional cookie domain. |
| `cookie_secure` | `true` | Adds the `Secure` attribute. Set `false` only for localhost testing. |
| `allow_open_registration` | `false` | When false, DCR requires a valid initial-access token. |
| `dcr_redirect_policy` | `catalog` | `catalog`, `catalog_loopback`, or `open`. See below. |
| `cors_allowed_origins` | empty | An explicit origin allowlist. Empty means no CORS layer. A lone `*` is silently dropped (no CORS layer, no error). |
| `allow_token_exchange` | `false` | Enables the token-exchange grant. |
| `token_exchange_allowlist` | empty | Rules of `{caller, subject, scopes[]}` for token exchange. |

## TLS keys

| Key | Default | Rule |
| --- | --- | --- |
| `tls.cert_path` | required | PEM certificate chain for the public listener. |
| `tls.key_path` | required | PEM private key matching the chain. |
| `tls.client_ca_path` | none | Optional client-CA bundle for in-process mTLS peer verification. |

## Database keys

Production requires `sslmode=verify-full` in `database.url` unless
`require_verify_full` is set to false.

| Key | Default |
| --- | --- |
| `database.url` | required |
| `database.password_file` | none |
| `database.root_cert_path` | none (`sslrootcert`) |
| `database.max_connections` | `15` |
| `database.min_connections` | `2` |
| `database.acquire_timeout_secs` | `3` |
| `database.idle_timeout_secs` | `300` |
| `database.max_lifetime_secs` | `1800` |
| `database.statement_timeout_secs` | `3` |
| `database.lock_timeout_secs` | `1` |
| `database.idle_in_transaction_timeout_secs` | `30` |
| `database.application_name` | `oauth21-server` |
| `database.require_verify_full` | `true` |

`max_connections` must be greater than zero and at least `min_connections`.
`database.root_cert_path` (or `sslrootcert` in the URL) is required in practice
for `sslmode=verify-full` unless the server certificate chains to a system root;
the cluster ConfigMap pins `/certs/db-ca.crt`.

## Redis keys

Exactly one topology is selected: `url` for single node, `nodes` plus
`master_name` for Sentinel, or `seeds` for Cluster. Setting more than one, or
none, is rejected as ambiguous.

| Key | Default | Notes |
| --- | --- | --- |
| `redis.url` | none | Single-node `redis://` or `rediss://` URL. |
| `redis.nodes` | `[]` | Sentinel `host:port` addresses. |
| `redis.master_name` | none | Required for Sentinel. |
| `redis.seeds` | `[]` | Cluster seed `host:port` addresses. |
| `redis.sentinel_auth` | none | Sentinel node password. |
| `redis.data_auth` | none | Sentinel data-node password. |
| `redis.auth` | none | Cluster password. |
| `redis.tls` | `false` | TLS for Sentinel and Cluster connections. |
| `redis.connect_timeout_secs` | `3` | Connection timeout. |
| `redis.response_timeout_secs` | `2` | Per-command response timeout. |
| `redis.retry_budget` | `6` | Reconnect attempts. |
| `redis.retry_min_delay_ms` | `100` | Minimum backoff. |
| `redis.retry_max_delay_ms` | `5000` | Maximum backoff. |
| `redis.durability` | required | `wait`, `waitaof`, or `appendfsync_always`. See [REDIS.md](REDIS.md). |
| `redis.noeviction_required` | `true` | Requires `maxmemory-policy noeviction` at startup. |
| `redis.aof_required` | `true` | Requires `appendonly yes` at startup. |
| `redis.token_key_prefix` | `oauth:{state}:` | Must contain the `{state}` hash tag. |
| `redis.ratelimit_key_prefix` | `oauth:{rl}:` | Must contain the `{rl}` hash tag and differ from the token prefix. |
| `redis.root_cert_path` | none | Root certificate for `rediss://` endpoints. |
| `redis.password_file` | none | Mounted password for the data node. |

Durability must match the topology. Single node requires `waitaof` or
`appendfsync_always`; replicated topologies require `wait`. A mismatch is
rejected. `redis.password_file` holds the raw password and is applied to the
connection directly, so it may contain any bytes (no URL encoding required).

## Key-ring keys

| Key | Default | Notes |
| --- | --- | --- |
| `token_pepper` | none | Inline token-pepper secret. Required unless `token_pepper_file` is set. |
| `token_pepper_file` | none | Mounted token-pepper secret. |
| `token_pepper_id` | `v1` | Version id stored with the hash so peppers can rotate. |
| `totp_encryption_key` | none | Inline AES-256-GCM key for TOTP secrets. Required to enroll TOTP. |
| `totp_encryption_key_file` | none | Mounted TOTP key. |
| `totp_key_id` | `v1` | Version id carried in the encrypted TOTP blob. |
| `totp_previous_key` | none | Optional retained previous TOTP key for rotation. |
| `totp_previous_key_file` | none | Mounted previous TOTP key. |
| `totp_previous_key_id` | none | Required when a previous TOTP key is set; must differ from `totp_key_id`. |
| `pii_encryption_key` | none | Inline AES-256-GCM master key for PII field encryption and blind indexes. Required unless `pii_encryption_key_file` is set. |
| `pii_encryption_key_file` | none | Mounted PII key. |
| `pii_key_id` | `v1` | Version id carried in every `_enc` blob and blind index. |
| `pii_previous_key` | none | Optional retained previous PII key for rotation. |
| `pii_previous_key_file` | none | Mounted previous PII key. |
| `pii_previous_key_id` | none | Required when a previous PII key is set; must differ from `pii_key_id`. |
| `pii_dual_write` | `false` | Rolling-upgrade switch. `true` also writes the plaintext column and emits v2 TOTP blobs so version N-1 replicas keep working; `false` is encrypt-only. |

The exact environment spellings:

| Key | Environment variable |
| --- | --- |
| `token_pepper` | `D_OAUTH_TOKEN_PEPPER` |
| `token_pepper_file` | `D_OAUTH_TOKEN_PEPPER_FILE` |
| `token_pepper_id` | `D_OAUTH_TOKEN_PEPPER_ID` |
| `totp_encryption_key` | `D_OAUTH_TOTP_ENCRYPTION_KEY` |
| `totp_encryption_key_file` | `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE` |
| `totp_key_id` | `D_OAUTH_TOTP_KEY_ID` |
| `totp_previous_key` | `D_OAUTH_TOTP_PREVIOUS_KEY` |
| `totp_previous_key_file` | `D_OAUTH_TOTP_PREVIOUS_KEY_FILE` |
| `totp_previous_key_id` | `D_OAUTH_TOTP_PREVIOUS_KEY_ID` |
| `pii_encryption_key` | `D_OAUTH_PII_ENCRYPTION_KEY` |
| `pii_encryption_key_file` | `D_OAUTH_PII_ENCRYPTION_KEY_FILE` |
| `pii_key_id` | `D_OAUTH_PII_KEY_ID` |
| `pii_previous_key` | `D_OAUTH_PII_PREVIOUS_KEY` |
| `pii_previous_key_file` | `D_OAUTH_PII_PREVIOUS_KEY_FILE` |
| `pii_previous_key_id` | `D_OAUTH_PII_PREVIOUS_KEY_ID` |
| `pii_dual_write` | `D_OAUTH_PII_DUAL_WRITE` |

The token pepper and the PII field-encryption key are required: without either
the key ring cannot be built and the server refuses to start with
`MissingPiiKey` (or `MissingPepper`). The shipped cluster manifests set
`D_OAUTH_TOKEN_PEPPER_FILE`, `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`, and
`D_OAUTH_PII_ENCRYPTION_KEY_FILE` rather than the inline keys; see
[DEPLOYMENT.md](DEPLOYMENT.md).

These three values are the server's master keys and are supplied entirely by
the deployment. There is a hard custody requirement that they never live in the
database or in the same backup as the database; a KMS/HSM or a secret manager
should hold them and inject them through a `*_FILE` path. The server has no
built-in KMS integration and never fetches a key itself. The full contract and
the forbidden locations are in
[SECURITY.md](SECURITY.md#master-key-custody); the operator procedure is in
[DEPLOYMENT.md](DEPLOYMENT.md#master-key-custody-and-kmshsm).

## Failure policy keys

Security endpoints are always fail-closed. Setting `open` on any of them is a
load-time error.

| Key | Default |
| --- | --- |
| `failure_policy.default_mode` | `closed` |
| `failure_policy.endpoints` | the seven security endpoints mapped to `closed` |
| `failure_policy.retryable` | `io`, `timeout`, `connection_reset`, `temporarily_unavailable`, `pool_timed_out` |
| `failure_policy.retry_budget` | `3` |
| `failure_policy.request_timeout_secs` | `10` |

The security endpoints are `authorize`, `token`, `introspect`, `revoke`, `par`,
`device_authorization`, and `register`.

## Lifetime and hashing keys

| Key | Default |
| --- | --- |
| `ttl.access_secs` | `300` |
| `ttl.refresh_secs` | `2592000` (30 days) |
| `ttl.code_secs` | `60` |
| `ttl.par_secs` | `90` |
| `ttl.device_secs` | `600` |
| `ttl.dcr_initial_access_secs` | `86400` (24 hours) |
| `ttl.session_secs` | `43200` (12 hours) |
| `argon2.memory_kib` | `19456` (19 MiB) |
| `argon2.iterations` | `2` |
| `argon2.parallelism` | `1` |

Every TTL must be non-zero, and the access-token TTL must not exceed the
refresh-token TTL. Argon2 memory must be at least 8192 KiB, with a non-zero
iteration count and parallelism.

## Rate-limit keys

| Key | Default |
| --- | --- |
| `rate_limit.enabled` | `true` |
| `rate_limit.window_secs` | `60` |
| `rate_limit.per_ip` | `120` |
| `rate_limit.per_client` | `300` |
| `rate_limit.login_per_ip` | `20` |
| `rate_limit.token_per_client` | `60` |

The window must be non-zero.

## Scope registry and token exchange

`scope_registry` is an optional declarative input applied only by `config sync`.
It is never required to be non-empty. Each entry is `{name, description?,
allowed_grants?, allowed_client_classes?}`. The name must match the RFC 6749
scope-token grammar, may not be `openid`, and may not exceed 128 characters.

`token_exchange_allowlist` entries are `{caller, subject, scopes[]}`; caller and
subject may not be empty.

## The timeout ladder

The four database and request timeouts must satisfy:

```
lock_timeout < statement_timeout <= acquire_timeout < request_timeout
```

With the defaults that is `1s < 3s <= 3s < 10s`. A violation is a load-time
error, which prevents a request from outliving a pool slot or a lock outliving
the statement.

## dcr_redirect_policy

- `catalog`: only redirect URIs present in the runtime catalog may be
  registered. This is the default.
- `catalog_loopback`: catalog URIs plus dynamic loopback URIs (RFC 8252).
- `open`: any absolute `https` redirect URI, or an RFC 8252 loopback URI, may
  be registered. This is an explicit opt-in and is not the default; other
  schemes and plaintext non-loopback URIs are still rejected.

## Security properties

- No secret is ever printed. `Config`'s `Debug` impl redacts the database URL,
  Redis URLs, and every password.
- A production database URL without `sslmode=verify-full` is refused.
- A Redis topology that does not satisfy the durability contract is refused at
  load and re-checked live at startup.
- A pepper/TOTP/PII key shorter than 32 bytes is refused at load
  (`WeakKeyMaterial`).
- Forwarded client-cert and client-IP headers are never trusted: the listener
  uses only the TLS peer address and the certificate chain it verified itself.
- CORS and open registration are off by default.
- File-backed pepper/TOTP/PII keys are read from a `0400` tmpfs file, never
  from the process environment.

## Edge cases

- `D_OAUTH_CONFIG` pointing at a missing file is not an error; the file is
  optional.
- An inline `token_pepper` of only whitespace is treated as absent.
- A blank `pii_previous_key` / `totp_previous_key` (including a zero-byte or
  whitespace-only `*_previous_key_file`) is treated as absent, so an empty mount
  never becomes a live key.
- A previous key with no `*_previous_key_id`, a blank id, or an id equal to the
  active id is a load-time error (`ConfigError::MissingPreviousKeyId`).
- A previous key set while its active key is absent is `MissingPiiKey` /
  `MissingTotpKey`, so a retained key can never silently become the active one.
- An unreadable `*_file` path is a load-time error (`ConfigError::SecretFile`),
  never a silent fallback to an absent key.
- `scope delete` and `redirect-uri delete` disable a referenced row instead of
  deleting it. See [OPERATIONS.md](OPERATIONS.md).
- A deliberate mismatch of `dcr_redirect_policy = open` and mTLS is a deployment
  error, not a load error: open registration lets a caller register any
  `https`/loopback redirect URI without pre-registration.

## Operational runbook

Validate any environment before starting the server:

```bash
D_OAUTH_ISSUER=https://auth.example.com cargo run --bin d-oauth-server -- config check
```

`config check` prints `config ok: issuer=...` and exits 0 on success, or prints
the first validation error and exits 1. It does not connect to Postgres or
Redis.

## File and directory references

- `src/config.rs` for the loader and `ConfigError`.
- `src/config/build.rs` for defaults and cross-field validation.
- `src/config/db.rs`, `src/config/redis.rs`, `src/config/types.rs`,
  `src/config/policy.rs`, `src/config/scope.rs` for the per-area keys.
- `src/config/tests.rs` for the asserted defaults.

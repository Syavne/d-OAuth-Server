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

String-list keys (`cors_allowed_origins`, `rate_limit.trusted_proxies`,
`protected_resource_ids`, `redis.nodes`, `redis.seeds`) accept a real array in
the file and either a JSON array string or a comma-separated string from the
environment, because config-rs 0.15 keeps env values as strings and never
coerces arrays. Both
`D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES='["10.0.0.5"]'` and
`D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES='10.0.0.5,10.0.1.0/24'` load; a blank
string loads as empty, and malformed JSON array text fails the load instead
of silently meaning empty.

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
| `cookie_domain` | none (host-only) | Reserved: any non-blank value is rejected at load (`InvalidCookieDomain`). The `__Host-` session cookie forbids `Domain`, so sessions stay host-only; blank values are treated as absent. |
| `cookie_secure` | `true` | Adds the `Secure` attribute and uses the `__Host-session_id` cookie name. `false` is a development-only localhost exception (production refuses to load without `Secure` with `InsecureSessionCookie`); it drops `Secure` and the cookie name falls back to plain `session_id`, because browsers reject a `__Host-` cookie without `Secure`. Both variants are host-only (`Path=/`, `HttpOnly`, `SameSite=Lax`, no `Domain`). In production the server reads **only** `__Host-session_id`; the plain `session_id` cookie is never honored there, so a cookie planted by a sibling subdomain cannot fixate a login onto an attacker presession. The development variant reads plain `session_id` first and may additionally fall back to `__Host-session_id` for a cookie left over from before a config flip. `POST /logout` clears every name the reader honors. The `false` gate checks only `environment = production`: a non-production environment (for example staging) running `cookie_secure = false` re-opens plain-cookie sibling-subdomain fixation, so staging must use the production environment or keep secure cookies. |
| `allow_open_registration` | `false` | When false, DCR requires a valid initial-access token. |
| `dcr_redirect_policy` | `catalog` | `catalog`, `catalog_loopback`, or `open`. See below. |
| `cors_allowed_origins` | empty | An explicit origin allowlist. Empty means no CORS layer. A lone `*` is silently dropped (no CORS layer, no error). |
| `allow_token_exchange` | `false` | Enables the token-exchange grant. |
| `token_exchange_allowlist` | empty | Rules of `{caller, subject, scopes[]}` for token exchange. |
| `resource_indicators_enabled` | `false` | Honors the RFC 8707 `resource` indicator on the authorization, PAR, token, device, and introspection endpoints. Off plus any `resource` is `invalid_target`, never a silent drop. |
| `cimd_enabled` | `false` | Enables Client ID Metadata Document lookup (an `https://` `client_id` is fetched and validated per request). When on, the AS metadata advertises `client_id_metadata_document_supported` and keeps `none` advertised. |
| `protected_resources_enabled` | `false` | Emits the RFC 9728 `protected_resources` metadata member. |
| `protected_resource_ids` | empty | Identifiers advertised in `protected_resources` when `protected_resources_enabled` is on. |
| `allow_localhost_redirect` | `false` | Accepts the RFC 8252 host `localhost` loopback redirect (`127.0.0.1`/`[::1]` stay loopback regardless). |
| `jwt_access_tokens_enabled` | `false` | Global kill-switch for JWT access tokens (`at+jwt`). Opaque tokens remain the only format while off. |
| `jwt_signing_key` (`_file`) | none | Active JWT signing key: exactly 32 bytes of raw material. Inline wins; a mounted file is trimmed of trailing newlines. |
| `jwt_signing_kid` | `v1` | Key id placed in the JOSE header; must match `[A-Za-z0-9_-]+`. |
| `jwt_signing_previous_keys` | empty | Rotated-out keys of `{kid, key}` for verification only; every `key` must be exactly 32 bytes and every `kid` distinct. |
| `jwt_access_token_signing_alg` | `ES256` | `ES256` or `EdDSA` only. Both take exactly-32-byte raw key material; RSA is not supported. |
| `cimd_fetch_timeout_secs` | `5` | CIMD document fetch timeout, 1-10 seconds. |
| `cimd_max_bytes` | `5120` | CIMD document size cap, 1-5120 bytes. |

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
| `token_pepper_previous_key` | none | Optional retained previous token-pepper secret for rotation. Required unless `token_pepper_previous_key_file` is set. |
| `token_pepper_previous_key_file` | none | Mounted previous token-pepper secret. |
| `token_pepper_previous_key_id` | none | Required when a previous pepper key is set; must differ from `token_pepper_id`. |
| `totp_encryption_key` | none | Inline AES-256-GCM key for TOTP secrets. Required; the server refuses to start without it (or `totp_encryption_key_file`). |
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
| `token_pepper_previous_key` | `D_OAUTH_TOKEN_PEPPER_PREVIOUS_KEY` |
| `token_pepper_previous_key_file` | `D_OAUTH_TOKEN_PEPPER_PREVIOUS_KEY_FILE` |
| `token_pepper_previous_key_id` | `D_OAUTH_TOKEN_PEPPER_PREVIOUS_KEY_ID` |
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

The token pepper, the TOTP encryption key, and the PII field-encryption key are
required: without any of them the key ring cannot be built and the server
refuses to start with `ConfigError::KeyRing(KeyRingError::MissingTokenPepper)`
for the token pepper, `ConfigError::KeyRing(KeyRingError::MissingTotpKey)` for
the TOTP key, or `ConfigError::KeyRing(KeyRingError::MissingPiiKey)` for the
PII key. Key ids (`token_pepper_id`,
`totp_key_id`, `pii_key_id`, and any `*_previous_key_id`) are stored verbatim:
token hashes as `<kid>.<digest>` (split on the first `.`) and PII blind
indexes as `<kid>:<digest>`, so an id must contain neither `.` (token split)
nor `:` (PII ambiguity); keep to `[A-Za-z0-9_-]+`. The shipped cluster manifests set
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
refresh-token TTL. The authorization-code lifetime is additionally capped at
60 s (`CODE_TTL_CAP` in `src/protocol/code.rs`), so a `ttl.code_secs` value
above 60 is effectively clamped. Argon2 memory must be at least 8192 KiB, with a non-zero
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
| `rate_limit.trusted_proxies` | empty |

The window must be non-zero.

`rate_limit.trusted_proxies` (environment spelling
`D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES`) is the L7 reverse-proxy allowlist for
rate-limit IP attribution only. Each entry is an exact IP (`10.0.0.1`) or a
CIDR (`10.0.0.0/8`, `2001:db8::/32`). From the environment use a JSON array
string (`D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES='["10.0.0.5"]'`) or a
comma-separated string (`D_OAUTH_RATE_LIMIT__TRUSTED_PROXIES='10.0.0.5'`); in
the file use a real array (`trusted_proxies = ["10.0.0.5"]`). Default empty means forwarded headers
are never honored: the limiter keys the IP bucket off the verified TCP peer.
When the peer belongs to the allowlist, the limiter attributes the
rightmost-untrusted `X-Forwarded-For` entry instead; a header from an
untrusted peer is ignored, and a malformed header falls back to the peer, so
spoofing cannot evade or shift the bucket. A malformed entry, an out-of-range
prefix, a trust-everything `/0`, or more than 64 entries fails the load with
`InvalidTrustedProxy`. Entries are not deduplicated, so duplicates count
toward the 64-entry cap. A value starting with `[` parses as a JSON array, so
a bracketed IPv6 literal (`[2001:db8::1]`) fails the load — always use bare
IPs, in entries and in arrays. This trust never authenticates a client and never
carries a client certificate: in-process mTLS still requires L4/TCP
passthrough (see [DEPLOYMENT.md](DEPLOYMENT.md#mtls-and-the-l7-constraint)).

## Scope registry and token exchange

`scope_registry` is an optional declarative input applied only by `config sync`.
It is never required to be non-empty. Each entry is `{name, description?,
allowed_grants?, allowed_client_classes?}`. The name must match the RFC 6749
scope-token grammar, may not be `openid`, and may not exceed 128 characters.

`token_exchange_allowlist` entries are `{caller, subject, scopes[]}`; caller and
subject may not be empty.

## JWT access tokens and optional-feature keys

Every optional feature is off by default and none of these keys changes
default-on behavior. The feature flags (`resource_indicators_enabled`,
`cimd_enabled`, `protected_resources_enabled`, `jwt_access_tokens_enabled`, and
`allow_localhost_redirect`) default to `false`; `protected_resource_ids` and
`jwt_signing_previous_keys` default to empty.

CIMD is the registration-free client path. Enabling it does not change the
`POST /register` gate: `allow_open_registration` and `dcr_redirect_policy` still
decide dynamically registered clients, and `allow_localhost_redirect` is the
single server-wide switch that makes the host `localhost` a loopback redirect
for both registered and CIMD clients. The operator runbook, including a
validating example document, is in
[OPERATIONS.md](OPERATIONS.md#mcp-client-registration).

| Key | Default | Rule |
| --- | --- | --- |
| `D_OAUTH_JWT_ACCESS_TOKENS_ENABLED` | `false` | Global kill-switch for JWT access tokens. Enabling it requires a signing key; a configured `jwt` client with the switch off gets `503`. |
| `D_OAUTH_JWT_SIGNING_KEY` | none | Active signing key: the literal UTF-8 bytes of the string, exactly 32 bytes. Shorter or longer material is `WeakKeyMaterial`; unusable EC/EdDSA material is `InvalidJwtSigningKey`. Inline values are whitespace-trimmed. |
| `D_OAUTH_JWT_SIGNING_KEY_FILE` | none | Mounted form of the active key. Read verbatim except that trailing CR/LF are stripped; the inline form wins when both are set. |
| `D_OAUTH_JWT_SIGNING_KID` | `v1` | Key id for the active key, `[A-Za-z0-9_-]+`. It is the JOSE `kid` and the JWKS entry id. |
| `D_OAUTH_JWT_SIGNING_PREVIOUS_KEYS` | empty | Rotated-out keys, a list of `{kid, key}` objects. Each key is validated exactly like the active key (32 bytes); kids must be distinct and different from the active kid (`DuplicateJwtSigningKid`); configuring any entry requires an active key. Supply as a YAML/TOML array in the `D_OAUTH_CONFIG` file, not as one environment string. |
| `D_OAUTH_JWT_ACCESS_TOKEN_SIGNING_ALG` | `ES256` | `ES256` or `EdDSA` only. Both use 32-byte raw key material, so there is no RSA/`RS256` branch. All retained keys share this algorithm. |

- `jwt_signing_key` is the active JOSE signing key. It must be **exactly** 32
  bytes of raw material: shorter or longer material is rejected at load with
  `WeakKeyMaterial` (this is stricter than the pepper/TOTP/PII chains, which
  enforce only a minimum). A `jwt_signing_key_file` mount works exactly like the
  other `*_file` keys and is trimmed of trailing newlines; the inline form wins
  when both are set. The key material is turned into a real JOSE signing key at
  load, so an all-zero EC scalar or EdDSA seed, or an out-of-range EC scalar,
  fails at boot with `InvalidJwtSigningKey`, not at the first mint. Enabling
  `jwt_access_tokens_enabled` without a signing key fails closed with
  `MissingJwtSigningKey`.
- `jwt_signing_previous_keys` retains rotated-out keys as a list of
  `{kid, key}` objects so a token signed under an old `kid` can still verify.
  Each `key` is validated exactly like the active key (exactly 32 bytes) and
  every `kid` must be distinct and different from the active `jwt_signing_kid`;
  a duplicate is rejected with `DuplicateJwtSigningKid`.
- `jwt_access_token_signing_alg` accepts only `ES256` or `EdDSA`. Both use
  exactly-32-byte raw key material, so there is no RSA / `RS256` branch.
- No JWT signing key material is ever printed: `Config`'s `Debug` impl and
  `JwtSigningKey`'s `Debug` impl emit the key id and algorithm only.
- `cimd_fetch_timeout_secs` must be between 1 and 10 seconds
  (`InvalidCimdFetchTimeout`) and `cimd_max_bytes` between 1 and 5120
  (`InvalidCimdMaxBytes`). A malformed value fails the load rather than
  silently meaning "no limit".
- `protected_resources_enabled` is validated at load
  (`InvalidProtectedResources`): it requires `resource_indicators_enabled=true`
  and a non-empty, duplicate-free `protected_resource_ids` list of absolute
  `https` URIs with a host and no wildcard, userinfo, fragment, or query. With
  the flag off the identifiers are inert.

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
  The host `localhost` counts as loopback here only when
  `allow_localhost_redirect` is on.
- `open`: any absolute `https` redirect URI, or an RFC 8252 loopback URI, may
  be registered. This is an explicit opt-in and is not the default; other
  schemes and plaintext non-loopback URIs are still rejected. As with
  `catalog_loopback`, `localhost` is loopback only when
  `allow_localhost_redirect` is on.

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
- File-backed pepper/TOTP/PII keys are read from a `0400` tmpfs file, so the
  material avoids the process environment; the inline forms are supported and
  win when both are set.

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

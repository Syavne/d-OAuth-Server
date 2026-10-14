# d-OAuth-Server

An OAuth 2.1-only authorization server written in Rust. It is deliberately not
backwards compatible with OAuth 2.0: PKCE is mandatory, the implicit and
resource-owner-password grants do not exist, bearer-in-query is rejected, and
redirect URIs match exactly.

It implements the authorization-code, refresh-token, client-credentials,
device-code, and token-exchange grants, with DPoP, mTLS, PAR, JAR, dynamic
client registration, introspection, and revocation. Tokens are opaque and
hashed at rest. All durable domain state is in PostgreSQL and all ephemeral
state is in Redis, so replicas are interchangeable.

- Protocol and deltas: [docs/OAUTH.md](docs/OAUTH.md)
- Threat model and token design: [docs/SECURITY.md](docs/SECURITY.md)
- Vulnerability reporting policy: [SECURITY.md](SECURITY.md)
- Module layout and request flow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Every configuration key: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- Schema and migrations: [docs/DATABASE.md](docs/DATABASE.md)
- Redis keys and durability: [docs/REDIS.md](docs/REDIS.md)
- Container and cluster: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- Admin CLI and runbooks: [docs/OPERATIONS.md](docs/OPERATIONS.md)
- Contributor guide: [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- Changelog: [docs/CHANGELOG.md](docs/CHANGELOG.md)
- Admin bootstrap procedure: [RUNBOOK.md](RUNBOOK.md)

## Prerequisites

- Rust stable, as pinned by `rust-toolchain.toml`.
- PostgreSQL 16 or newer with the `citext` extension available (the shipped
  `compose.yaml` pins `postgres:18-alpine`).
- Redis 8 or newer, with persistence enabled and eviction off.
- A TLS certificate and key for the public listener.
- Docker, for the container image, for the shared test Postgres and Redis in
  `compose.test.yaml`, and for the handful of suites that still use
  `testcontainers` because they need Redis nodes of their own (the keep-list is
  under [Tests](#tests)).
- `cargo-nextest` for the test suite:
  `cargo install cargo-nextest --locked`.

## Build

```bash
cargo build --locked
cargo build --locked --release
```

## Quick start

The server reads configuration from `D_OAUTH_*` environment variables. Export a
development configuration (values here are placeholders; see
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for every key). The ports below
are the local-dev defaults (Postgres `5432`, Redis `6379`); the shared test
services use `5433`/`6380` (see Tests).

```bash
export D_OAUTH_ISSUER=https://localhost:8080
export D_OAUTH_ENVIRONMENT=development
export D_OAUTH_BIND_ADDR=0.0.0.0:8080
export D_OAUTH_HEALTH_ADDR=0.0.0.0:8081
export D_OAUTH_TLS__CERT_PATH=/path/to/tls.crt
export D_OAUTH_TLS__KEY_PATH=/path/to/tls.key
export D_OAUTH_DATABASE__URL='postgres://oauth:password@127.0.0.1:5432/oauth?sslmode=disable'
export D_OAUTH_REDIS__URL=redis://127.0.0.1:6379
export D_OAUTH_REDIS__DURABILITY=waitaof
export D_OAUTH_TOKEN_PEPPER='replace-with-32-bytes-of-random-00'
export D_OAUTH_TOTP_ENCRYPTION_KEY='replace-with-32-bytes-of-random-00'
export D_OAUTH_PII_ENCRYPTION_KEY='replace-with-32-bytes-of-random-00'
```

Development relaxes the database TLS requirement. Production requires
`sslmode=verify-full` (unless `database.require_verify_full` is set false) and an
`issuer` on `https` (no trailing slash, non-empty authority, no whitespace).

Validate the configuration, then apply the schema once:

```bash
cargo run --bin d-oauth-server -- config check
cargo run --bin d-oauth-server -- migrate
```

Bootstrap the first administrator. It is created in a forced-change state and
must change its password and enroll TOTP before it gains authority:

```bash
cargo run --bin d-oauth-server -- admin bootstrap --email admin@example.com
```

Apply the scope catalog, redirect URIs, and entitlements from a JSON file
idempotently. The file format is in [docs/OPERATIONS.md](docs/OPERATIONS.md):

```bash
cargo run --bin d-oauth-server -- config sync --file ./oauth-config.json
```

Run the server. It serves TLS on `bind_addr` and plaintext health on
`health_addr`; it never migrates:

```bash
cargo run --bin d-oauth-server -- serve
```

Check it is alive and ready:

```bash
curl -s http://127.0.0.1:8081/health/live
curl -s http://127.0.0.1:8081/health/ready
curl -sk https://localhost:8080/.well-known/oauth-authorization-server | jq .
```

## Authorization-code and PKCE walkthrough

The flow is: start at `/authorize`, log in and consent, receive a code on the
redirect, then redeem it at `/token` with the PKCE verifier.

1. Generate a verifier and its `S256` challenge:

```bash
VERIFIER=$(openssl rand -base64 64 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
```

2. Visit the authorization endpoint in a browser. A confidential client must
   use PAR or a signed request object; a public client may use the query string:

```
https://localhost:8080/authorize?response_type=code&client_id=example-client&redirect_uri=https://app.example.com/callback&scope=orders:read&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256
```

3. Log in, approve consent, and read the `code` from the redirect.

4. Redeem the code at the token endpoint:

```bash
curl -sk https://localhost:8080/token \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri=https://app.example.com/callback \
  -d client_id=example-client \
  -d code_verifier="$VERIFIER"
```

5. A public client must present a DPoP proof with the token request; a
   confidential client authenticates with its secret or an mTLS certificate.

The `POST /token` dispatcher and the `/register*` DCR routes (RFC 7591/RFC
7592) are wired, so step 4 redeems a code end to end; a client can also be
created through `POST /register`. See [docs/OAUTH.md](docs/OAUTH.md) for the
full grant behavior.

## Tests

The authoritative suite. The integration and end-to-end tests connect to the
shared test Postgres and Redis from `compose.test.yaml` (test defaults:
Postgres on `127.0.0.1:5433`, Redis on `127.0.0.1:6380` — not the dev
`5432`/`6379`), so start the services first and
tear them down with `down -v`:

```bash
docker compose -f compose.test.yaml up -d
cargo nextest run --all-targets
cargo test --doc
docker compose -f compose.test.yaml down -v
```

Override the endpoints with `D_OAUTH_TEST_POSTGRES_URL` and
`D_OAUTH_TEST_REDIS_URL`. Each test gets its own freshly created database and
unique Redis key prefixes, so tests run in parallel and nothing flushes shared
state. Killing the suite mid-run no longer orphans containers: the lifecycle
tests still `rm` theirs on drop.

Only these suites use `testcontainers`; every other unit and integration suite
uses the shared `compose.test.yaml` services:

- `src/test_guard.rs` and `src/state/test_support.rs`: the shared container
  helpers the keep-list below is built on.
- `tests/resilience.rs`: stop and restart lifecycle.
- `src/state/tests_topology.rs`: Sentinel, Cluster, and `requirepass` topology.
- The `--appendfsync always` refresh-token suite:
  `src/protocol/token/grants/refresh_token/tests.rs` and
  `src/protocol/token/grants/refresh_token/tests/failover.rs`.
- The two Redis durability tests in `src/store/tests_store.rs`
  (`store_persistence_survives_restart` and `store_durability_barrier_modes`).
- `dcr_manage_token_survives_redis_flush` in
  `src/protocol/dcr/manage/tests_delete.rs`, which starts a private Redis for
  the flush.

`tests/topology.rs` is separate: it spawns in-process `redis-test`
Sentinel/Cluster fixtures that need a real `redis-server` binary. Docker must
be running. To iterate on one area, filter by name:

```bash
cargo nextest run -E 'test(refresh_rotation)'
cargo nextest run -E 'test(admin_bootstrap)'
```

Quality gates:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run --all-targets
cargo test --doc
cargo audit
cargo deny check
python3 scripts/check_doc_links.py
```

## Container

Build both architectures with the bake definition, then run the image. The
image is non-root, has no shell, and expects a read-only root filesystem:

```bash
# Both architectures (linux/amd64 + linux/arm64)
docker buildx bake image

# Single architecture (no arm64 QEMU emulation needed)
docker buildx bake image --set image.platform=linux/amd64

docker run --rm -p 8080:8080 --read-only \
  --env-file ./oauth.env \
  -v /path/to/tls:/certs:ro \
  d-oauth-server:latest
```

Building `linux/arm64` on an amd64 host needs QEMU binfmt
(`docker run --privileged --rm tonistiigi/binfmt --install arm64`); see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

The container `HEALTHCHECK` uses the `healthcheck` subcommand, which probes the
plaintext health listener without a shell or curl. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

For a local multi-replica proof, `compose.yaml` runs three app replicas
against one Postgres and one Redis. It is the local
analogue of the cluster manifests, and proves that a token issued by one replica
is introspectable via another; see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md):

```bash
docker compose -f compose.yaml up --scale app=3
```

Cluster deployment uses a separate migration Job, a PodDisruptionBudget, and
probes on the health listener. In-process mTLS requires L4/TCP passthrough at
the load balancer, because an L7 ingress that terminates TLS strips the client
certificate.

## Security caveats

- OAuth 2.1 only. Do not point an OAuth 2.0 client that needs implicit or
  password grant at this server.
- The server targets `draft-ietf-oauth-v2-1-16` (published 3 September 2026;
  an Internet-Draft, not an RFC):
  https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1. There are no
  open gaps against that draft; see [docs/OAUTH.md](docs/OAUTH.md).
- There is no default credential and no HTTP admin API. Provision through the
  CLI.
- The token pepper, TOTP encryption key, and PII field-encryption key are
  required; losing the pepper invalidates every live opaque token, and losing
  the PII key makes the sealed directory unreadable.
- Master keys (pepper, TOTP, and PII) must each be at least 32 bytes; shorter
  values are refused at load (`WeakKeyMaterial`).
- `user disable` purges the account's Redis sessions, tokens, grants, codes,
  device records, and lockout counters before flipping `users.disabled`; that
  user's live tokens then introspect inactive and refuse refresh
  (`invalid_grant`).
- Production requires `issuer` on `https` and, unless
  `database.require_verify_full` is set false, a database URL with
  `sslmode=verify-full`.
- Redis must run with `noeviction` and persistence. The server asserts this at
  startup and refuses to start otherwise, unless `redis.noeviction_required` or
  `redis.aof_required` is set false (both default `true`).
- When Postgres or Redis is unavailable, security endpoints return `503` rather
  than failing open.
- CORS is empty by default. Browser clients need an explicit origin allowlist.
- Never commit a secret, a token, or key material. See
  [docs/SECURITY.md](docs/SECURITY.md).

## CLI pointers

- Scope catalog: `scope create|list|enable|disable|delete`. Scopes are
  runtime-managed and start empty.
- Redirect URIs: `redirect-uri create|list|enable|disable|delete` and
  `client attach-redirect-uri|detach-redirect-uri|redirect-uris`.
  `redirect-uri create|enable|disable|delete` and
  `client attach-redirect-uri|detach-redirect-uri` accept
  `--kind authorize|post_logout` (default `authorize`); `post_logout` URIs are
  the return targets for `POST /logout` (`GET /logout` is read-only).
- Users and entitlements: `user create|enroll-totp|disable|unlock|grant-scope|revoke-scope|scopes`.
- Admin: `admin bootstrap` (see [RUNBOOK.md](RUNBOOK.md)).
- Declarative apply: `config sync --file` and `config check`.
- PII migration and rotation: `pii backfill`, `pii verify`, and `pii rotate`,
  plus `totp rewrap` for the TOTP key. See [docs/OPERATIONS.md](docs/OPERATIONS.md).
- DCR initial access:
  `initial-access-token issue --uses <n> --ttl <seconds> [--label <text>] [--show-secret]`.
- Utilities: `keygen` and `healthcheck`.

Full flags are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## License

ISC. See [LICENSE.md](LICENSE.md).

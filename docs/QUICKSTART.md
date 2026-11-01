# Quick start

Get a development instance running on `https://localhost:8080`, bootstrap the
first administrator, and mint a token through the authorization-code flow with
PKCE. The whole path takes one terminal, one Postgres, one Redis, and one TLS
certificate pair.

## Purpose

For a first-time operator or integrator: the shortest correct route from a
checkout to a working authorization server, and the one walkthrough that proves
the grant machinery end to end. It is deliberately a tutorial, not a reference:
every key, command, and endpoint is documented in the guides linked from
[the documentation index](README.md).

## Prerequisites

- Rust stable, as pinned by `rust-toolchain.toml`.
- PostgreSQL 16 or newer with the `citext` extension available (the shipped
  `compose.yaml` pins `postgres:18-alpine`).
- Redis 8 or newer, with persistence enabled and eviction off. The server
  asserts both at startup and refuses to start otherwise unless
  `redis.noeviction_required` or `redis.aof_required` is set false.
- A TLS certificate and key for the public listener. If you have none yet, build
  a throwaway pair with the private-CA steps in
  [DEPLOYMENT.md](DEPLOYMENT.md#generate-a-private-ca-and-a-server-certificate).
- Docker, only if you want the container image or the local multi-replica
  `compose.yaml` stack. Contributing (the test suite, the shared test services,
  `cargo-nextest`) is covered in [CONTRIBUTING.md](CONTRIBUTING.md).

## Build

```bash
cargo build --locked
cargo build --locked --release
```

The build is offline-safe for SQL: the `query!` macros compile against the
committed `.sqlx/` cache. Regenerate that cache when a query or a migration
changes; [CONTRIBUTING.md](CONTRIBUTING.md#build) has the commands.

## Development configuration

The server reads configuration from `D_OAUTH_*` environment variables plus an
optional file named by `D_OAUTH_CONFIG`. Export a development configuration
(values here are placeholders; [CONFIGURATION.md](CONFIGURATION.md) lists every
key, its default, and its validation rule).

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

The three master keys must each be at least 32 bytes, and each is a live
secret: losing the pepper invalidates every opaque token, and losing the PII key
makes the sealed directory unreadable. Use the output of `openssl rand -base64
32` for each placeholder; in a cluster, mount them as files through the
`*_FILE` variants instead of the environment
([DEPLOYMENT.md](DEPLOYMENT.md#secret-material-as-files)).

Development relaxes the database TLS requirement. Production requires
`sslmode=verify-full` (unless `database.require_verify_full` is set false) and an
`issuer` on `https` (no trailing slash, non-empty authority, no whitespace).

The ports above are the local-dev defaults (Postgres `5432`, Redis `6379`). The
shared test services use `5433`/`6380` and are documented in
[CONTRIBUTING.md](CONTRIBUTING.md#database-backed-tests).

## Apply the schema and bootstrap the first admin

Validate the configuration, then apply the schema once:

```bash
cargo run --bin d-oauth-server -- config check
cargo run --bin d-oauth-server -- migrate
```

`config check` prints `config ok: issuer=...` and exits 0 without touching
Postgres or Redis; it prints the first validation error and exits 1 otherwise.
`serve` never migrates, so `migrate` is a separate, once-per-deployment step.

Bootstrap the first administrator. It is created in a forced-change state and
must change its password and enroll TOTP before it gains authority:

```bash
cargo run --bin d-oauth-server -- admin bootstrap --email admin@example.com
```

The full replacement procedure (change the password, enroll TOTP, capture
recovery codes, create a named admin, disable the bootstrap account) is in
[RUNBOOK.md](RUNBOOK.md).

Apply the scope catalog, redirect URIs, resource servers, and entitlements from
a JSON file, idempotently:

```bash
cargo run --bin d-oauth-server -- config sync --file ./oauth-config.json
```

The file format is in
[OPERATIONS.md](OPERATIONS.md#config-sync-file-format). Scopes start empty, so an
authorization request naming a scope that `config sync` did not create is
rejected.

## Run and probe

```bash
cargo run --bin d-oauth-server -- serve
```

The process serves TLS on `bind_addr` and plaintext health on `health_addr`.
Check it is alive, ready, and advertising metadata:

```bash
curl -s http://127.0.0.1:8081/health/live
curl -s http://127.0.0.1:8081/health/ready
curl -sk https://localhost:8080/.well-known/oauth-authorization-server | jq .
```

Readiness is fail-closed: it reports ready only when Postgres, Redis, and the
schema version all agree with the binary. Any other outcome is
`503 {"status":"not_ready"}`.

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

5. A DPoP-bound public client (`dpop_bound_access_tokens: true`) must present
   a DPoP proof with the token request; an unbound public client (the
   default) mints `Bearer` tokens with no proof. A confidential client
   authenticates with its secret or an mTLS certificate.

The client in step 2 must exist. Create one through `POST /register` (RFC 7591;
see [OAUTH.md](OAUTH.md#dynamic-client-registration)) or use an
operator-registered client from [OPERATIONS.md](OPERATIONS.md). Both the
`POST /token` dispatcher and the `/register*` DCR routes are wired, so step 4
redeems a code end to end.

## Edge cases

- `serve` never applies migrations. A replica whose schema version is behind the
  binary reports not ready and is pulled from service; a second `migrate` is a
  no-op.
- Unbound public clients become bearer-capable on upgrade. Operators wanting
  DPoP-mandatory public clients register them with
  `dpop_bound_access_tokens: true`.
- The health listener is plaintext and separate from the TLS listener. It is
  probed inside the pod network only; never publish it.
- `config sync` is an upsert, not a delete: re-running the same file reports
  `config sync: no changes`, and an unchanged row does not bump `updated_at`
  ([OPERATIONS.md](OPERATIONS.md#declarative-config)).
- A missing `D_OAUTH_CONFIG` file is not an error; the file is optional.
- A generated bootstrap password prints only to a TTY. On a non-TTY stdout the
  command refuses rather than risking the secret in job logs; use
  `--password-file`.

## Operational runbook

- Validate an environment without starting the server:
  `d-oauth-server config check`.
- Liveness: `GET http://127.0.0.1:8081/health/live` returns `200 {"status":"live"}`
  without touching a dependency.
- Readiness: `GET http://127.0.0.1:8081/health/ready` returns `200 {"status":"ready"}`
  only with Postgres and Redis answering; otherwise `503`.
- The container `HEALTHCHECK` runs `d-oauth-server healthcheck`, which speaks raw
  HTTP/1.1 to the health listener, so an image with no shell works
  ([DEPLOYMENT.md](DEPLOYMENT.md#the-container-image)).
- Day-two administration (users, scopes, redirect URIs, key rotation, backup) is
  [OPERATIONS.md](OPERATIONS.md).

## File and directory references

- `src/main.rs` for the thin binary entry point; `src/cli.rs` for the command
  surface used above.
- `src/serve.rs` for listener bootstrap, `src/state/` for readiness.
- `compose.yaml` for the local multi-replica stack (one Postgres, one Redis,
  three replicas); `compose.test.yaml` for the shared test services.
- `.sqlx/` for the offline query cache the locked build uses.
- [CONFIGURATION.md](CONFIGURATION.md) for every key in the block above.
- [RUNBOOK.md](RUNBOOK.md) for admin bootstrap replacement and breach response.

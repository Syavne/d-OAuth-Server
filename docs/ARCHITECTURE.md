# Architecture

The d-OAuth authorization server is a single Rust process with two listeners:
a TLS public listener for OAuth traffic and a plaintext health-only listener
for probes. All durable domain state lives in PostgreSQL and all ephemeral
state lives in Redis. There is no in-process state that a second replica would
need, so replicas are interchangeable.

## Purpose

This guide explains how the code is laid out, what happens to a request from
socket to response, and where the Postgres/Redis boundary sits. Use it to find
the module that owns a behavior before you change it.

## Module layout

The crate is one library (`src/lib.rs`) plus a thin binary (`src/main.rs`). The
binary parses the CLI and maps the result to an exit code; all behavior lives in
the library.

| Module | Owns |
| --- | --- |
| `src/config.rs`, `src/config/` | Layered configuration load from `D_OAUTH_*` env vars and an optional file, then fail-fast validation. See [CONFIGURATION.md](CONFIGURATION.md). |
| `src/keys.rs` | The versioned `KeyRing`: token peppers and the TOTP encryption key, each under a key id. |
| `src/crypto/` | Constant-time comparison, PKCE, opaque token mint/hash, TOTP, and password/client-secret hashing. |
| `src/jose/` | DPoP proof verification, JAR request objects, `private_key_jwt` client assertions, and JWK parsing. |
| `src/db/` | Postgres repositories for the six domain tables. See [DATABASE.md](DATABASE.md). |
| `src/store/` | Redis ephemeral state and the durability barrier. See [REDIS.md](REDIS.md). |
| `src/protocol/` | OAuth endpoints and grants. See [OAUTH.md](OAUTH.md). |
| `src/ui/` | Server-rendered login, consent, and device pages (Askama templates) plus the embedded same-origin stylesheet served at `/assets/app.css`. |
| `src/middleware/` | Request id, tracing and redaction, rate limiting, security headers, and audit. |
| `src/resilience.rs` | Load-shed, concurrency-limit, and timeout guard between CORS and rate limiting. |
| `src/routes.rs` | Router assembly and the middleware order. |
| `src/serve.rs`, `src/tls.rs` | Listener bootstrap and the custom TLS accept loop. |
| `src/state.rs`, `src/state/` | `AppState`, the topology-aware Redis connection, health endpoints. |
| `src/cli.rs`, `src/cli/` | The operator command tree. See [OPERATIONS.md](OPERATIONS.md). |
| `src/error.rs` | `AppError`: the client-safe OAuth error type and its HTTP mapping. |

Every behavior belongs to exactly one module. When a change spans modules, the
new logic goes in the one that owns the behavior; the others call into it.

## Request lifecycle

A public request enters through the TLS listener and passes through one
`tower` stack before reaching a handler. The order, from outermost to innermost,
is fixed in `build_router_with_options` in `src/routes.rs`:

1. Request id: mints or propagates `X-Request-Id` and opens the redacted
   `http_request` tracing span. Tracing and redaction live here.
2. Proxy-header stripping: when no `trusted_proxy` is configured, forged
   `x-forwarded-tls-client-*` headers are removed before any handler can read
   them. Without a configured proxy, proxy evidence is never trusted.
3. CORS: answers preflights from the explicit allowlist. Absent when the
   allowlist is empty, which is the default.
4. Resilience: sheds excess load, caps concurrency, and times out slow
   handlers before they reach rate limiting.
5. Rate limit: enforces the per-IP and per-client budgets. Health and metadata
   have no rule and pass through; those handlers fail closed on their own.
6. Body limit: caps request bodies at 2 MiB.
7. Security headers: adds `Referrer-Policy`, `X-Content-Type-Options`, a CSP
   with `frame-ancestors 'none'`, HSTS on the TLS listener, and
   `Cache-Control: no-store` on every response except `/.well-known/…` metadata.

A handler that needs a dependency takes `AppState` and calls a repository or the
store. Errors are converted to `AppError`, which maps to an OAuth error body and
the correct HTTP status. A dependency outage on a security path maps to `503`
with `Retry-After`; it never fails open.

## The two listeners

- The public listener binds `bind_addr` (default `0.0.0.0:8080`) and speaks TLS
  only. It is driven by a custom `hyper-util` plus `tokio-rustls` accept loop
  in `src/tls.rs`, not `axum::serve`, because the loop must inject the verified
  client-certificate chain into request extensions for mTLS.
- The health listener binds `health_addr` (default `0.0.0.0:8081`) in
  plaintext and serves exactly two routes, `/health/live` and `/health/ready`.
  Every OAuth route returns 404 there by construction. It is not exposed
  through the `Service` or an ingress; only the pod network probes it.

The health address must not be loopback. Kubelet probes originate from the node
network namespace and cannot reach pod-loopback, so `serve` refuses a loopback
`health_addr` at startup.

## Postgres and Redis split

The split is strict and drives the whole design:

- PostgreSQL holds durable domain state only: `oauth_clients`, `users`,
  `scopes`, `user_scopes`, `redirect_uris`, `client_redirect_uris`, plus sqlx's
  `_sqlx_migrations`. Nothing is written to Postgres per request. A failed login
  does not touch Postgres; the counter lives in Redis.
- Redis holds every short-lived value: authorization codes, access and refresh
  tokens, grant chains, sessions, PAR request URIs, device codes, DCR
  initial-access tokens, DPoP and `private_key_jwt` replay markers, and
  rate-limit counters.

The consequence is that a Redis flush loses ephemeral state but not clients,
users, scopes, or redirect URIs. Registration access tokens are the one token
kind stored as a hash in Postgres, so client management survives a Redis loss.

## Topology layer

`AppState.redis` is the `RedisConn` enum (`src/state/redis.rs`), not a concrete
connection type. One enum lets single-node, Sentinel, and Cluster share every
call site:

- Single: one `redis::aio::ConnectionManager`.
- Sentinel: a hand-built master re-resolution loop, because the driver's
  Sentinel support does not follow a promoted master across a failover.
- Cluster: native slot refresh, so `MOVED` and `ASK` redirects recover without
  a restart.

Atomic multi-key operations use Lua scripts keyed under the `{state}` hash tag,
so they stay on a single slot. See [REDIS.md](REDIS.md).

## Security properties

- The public listener is TLS-only; `issuer` is validated as absolute `https`.
- Secrets stay in `secrecy`/`zeroize` types and never reach a `Debug` output,
  a log, or an error body.
- Dependency failure on a security path fails closed with `503`.
- Middleware order puts request identity and redaction before any handler, and
  strips untrusted proxy headers before they could be read.
- The health listener cannot reach OAuth handlers, so a probe port cannot
  become a second, unauthenticated API surface.

## Edge cases

- A mTLS client certificate terminates at an L7 ingress that strips it. In that
  case in-process verification fails; use L4/TCP passthrough or the explicit
  trusted-proxy mode. See [DEPLOYMENT.md](DEPLOYMENT.md).
- `/metadata` reads the enabled scope catalog from Postgres on every request, so
  a CLI catalog mutation is visible immediately on every replica; when Postgres
  is down it returns `503` rather than advertising an empty or unknown scope
  list.
- Migrations are applied out of band. A replica whose schema version is behind
  the binary reports not ready and is pulled from service.

## Operational runbook

- Liveness: `GET http://<pod-ip>:8081/health/live` returns `200 {"status":"live"}`
  without touching a dependency.
- Readiness: `GET http://<pod-ip>:8081/health/ready` returns `200 {"status":"ready"}`
  only when Postgres and Redis answer and the schema version matches the binary.
  Any other outcome is `503 {"status":"not_ready"}`.
- On `SIGTERM` the process flips readiness to `503` first, waits a one second
  propagation grace, drains in-flight requests under a 30 second deadline, then
  closes the pools and exits 0.
- Tracing is JSON to stdout. Use the `X-Request-Id` value to correlate a request
  with its logs.

## File and directory references

- `src/lib.rs` for the authoritative module list.
- `src/routes.rs` for endpoint inventory and middleware order.
- `src/serve.rs` for listener bootstrap and shutdown semantics.
- `src/state.rs`, `src/state/health.rs`, `src/state/redis.rs`,
  `src/state/sentinel.rs` for state, health, and topology.
- `src/tls.rs` for the TLS accept loop.

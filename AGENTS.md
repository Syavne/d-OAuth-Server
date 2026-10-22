# AGENTS.md

Guidance for AI assistants working in this repository. Read this first; the
guides under `docs/` carry the depth.

## What this is

An OAuth 2.1-only authorization server in Rust. Durable domain state is in
PostgreSQL; all ephemeral state is in Redis. The crate is one library
(`src/lib.rs`) plus a thin binary (`src/main.rs`). No HTTP admin API; the CLI is
the admin surface.

## Module map and where to add what

| Add a... | To this module | Notes |
| --- | --- | --- |
| Configuration key or validation rule | `src/config.rs`, `src/config/` | Add to the raw serde struct, then validate in the matching submodule. Update [docs/CONFIGURATION.md](docs/CONFIGURATION.md). |
| Key-ring behavior | `src/keys.rs` | Versioned ids only; never print key material. |
| Crypto primitive (hash, compare, PKCE, TOTP) | `src/crypto/` | Constant-time for secret compares. |
| PII field codec / blind index | `src/crypto/field.rs` | Versioned AES-256-GCM; never log plaintext or key material. |
| JOSE verification (DPoP, JAR, `private_key_jwt`) | `src/jose/` | Reject fail-closed with the exact error code. |
| Client ID metadata document (CIMD) fetch, validation, or cache | `src/protocol/cimd.rs` | One guarded `https` fetch (no redirects, byte and time caps); only `none`/`private_key_jwt`, inline `jwks` only, no wildcard redirects; cache under `{state}`. `resolve_client` is the seam: a registered row wins, else the document when `cimd_enabled`. Update [docs/OAUTH.md](docs/OAUTH.md), [docs/SECURITY.md](docs/SECURITY.md), and [docs/OPERATIONS.md](docs/OPERATIONS.md). |
| Postgres query or repository | `src/db/` | `query!`/`query_as!` macros; regenerate `.sqlx`. |
| Resource-server (RFC 8707) catalog query | `src/db/resource_repo.rs` | Exact-match only: no wildcard, prefix, or normalization. Update [docs/DATABASE.md](docs/DATABASE.md) and [docs/OAUTH.md](docs/OAUTH.md). |
| Repeated `resource` parsing or audience binding | `src/protocol/params.rs` | One wire-order capture for the five raw-parameter endpoints; validate fail-closed with `invalid_target`. Update [docs/OAUTH.md](docs/OAUTH.md). |
| Redis record or Lua script | `src/store/` | Domain keys under `{state}`, rate-limit counters under `{rl}` (must differ); update [docs/REDIS.md](docs/REDIS.md). |
| OAuth endpoint or grant | `src/protocol/` | Cite the RFC section in a comment. Update [docs/OAUTH.md](docs/OAUTH.md). A subject-scoped Redis purge lives at `src/protocol/purge.rs` (`purge_subject` for `user disable`, `purge_sibling_sessions` on credential change); domain keys under `{state}`, rate-limit counters under `{rl}` and update docs/REDIS.md. |
| Login, consent, or device page | `src/ui/` | Keep CSP and CSRF intact. |
| Cross-cutting HTTP concern | `src/middleware/` | Mind the layer order in `src/routes.rs`. |
| Endpoint or layer order | `src/routes.rs` | Update [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). |
| Listener or shutdown behavior | `src/serve.rs`, `src/tls.rs` | Update [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). |
| Health or topology behavior | `src/state/` | Readiness is fail-closed. |
| CLI command or flag | `src/cli.rs`, `src/cli/` | Match the flag exactly in [docs/OPERATIONS.md](docs/OPERATIONS.md). The RFC 8707 catalog lives in `src/cli/resource.rs` (`resource-server create|list|enable|disable|delete`). |
| Error code or HTTP mapping | `src/error.rs` | Add the variant and its status together. |

If a change spans modules, put the logic in the module that owns the behavior
and call into it from the others.

## Strict Rust rules

- Plain, idiomatic Rust. Edition 2024. 2-space indent (`rustfmt.toml`).
- `#![forbid(unsafe_code)]` is on the crate. Never add `unsafe`.
- No `unwrap`, `expect`, or `panic` in request paths. Clippy denies them.
- Typed errors with `thiserror`. Map a dependency failure to the right
  client-safe error, do not stringify it.
- Use `tokio` and `axum` idioms: `async` handlers, `tower` layers, no blocking
  work on the runtime thread.
- Secrets use `secrecy` and `zeroize`. A secret-holding type must not print the
  secret in `Debug`.
- Use constant-time comparison (`subtle`) for any secret or token compare.
- No business logic in `main.rs`.
- Keep files focused; split by responsibility rather than growing a module.
- Import grouping is `StdExternalCrate`.

## Security checklist

Before finishing any change, confirm:

- [ ] Secret and token comparisons are constant time.
- [ ] No secret, token, password, or OTP in a log, error body, metric label, or
      evidence file.
- [ ] Security endpoints fail closed: a dependency outage yields `503`, never a
      fail-open success and never a `500` or panic.
- [ ] A code, PAR handle, or device code is single-use and consumed atomically.
- [ ] DPoP and `private_key_jwt` `jti` replay markers are written with `SET NX`.
- [ ] Redirect URI match is exact, with the RFC 8252 loopback exception only.
- [ ] PKCE is `S256` only; `plain` is rejected; a missing verifier cannot
      downgrade.
- [ ] Scope is intersected, never widened on refresh.
- [ ] Only hashed or encrypted secrets are stored; no raw token at rest.
- [ ] A sender-constrained grant re-verifies a fresh proof on every use.
- [ ] `private_key_jwt` is treated as authentication only, never as a binding.
- [ ] Master keys (pepper, TOTP/PII keys, and retained previous keys) carry at least 32 bytes; shorter material is rejected at load (`WeakKeyMaterial`).
- [ ] A disabled subject is dead everywhere: introspection reports inactive, refresh rejects with `invalid_grant` before minting, and refresh re-checks current entitlements; `user disable` purges the subject's Redis state (sessions and their meta, codes, devices with their sidecars and `user_code` mappings, grants and their token sidecars, standalone tokens and their sidecars, lockout) before flipping `users.disabled`, failing closed on a Redis error.
- [ ] The change does not introduce a wildcard scope, redirect URI, or CORS
      origin.

## TDD workflow

Red, green, refactor. Write the failing test first and confirm it fails for the
right reason.

```bash
cargo nextest run -E 'test(<behavior_name>)'   # red, then green
```

Integration tests use the real shared Postgres and Redis from
`compose.test.yaml` (`docker compose -f compose.test.yaml up -d`: Postgres on
`127.0.0.1:5433`, Redis on `127.0.0.1:6380`; override with
`D_OAUTH_TEST_POSTGRES_URL` and `D_OAUTH_TEST_REDIS_URL`). They get per-test
isolation from a fresh database and unique Redis key prefixes. `testcontainers`
remains only for the suites that need Redis nodes of their own:
`src/test_guard.rs` and `src/state/test_support.rs` (the shared container
helpers), `tests/resilience.rs` (stop/start lifecycle),
`src/state/tests_topology.rs` (Sentinel/Cluster/`requirepass`), the
`--appendfsync always` refresh-token suite
(`src/protocol/token/grants/refresh_token/tests.rs` and its `tests/failover.rs`),
the two Redis durability tests in `src/store/tests_store.rs`, and
`dcr_manage_token_survives_redis_flush` in
`src/protocol/dcr/manage/tests_delete.rs`. Every other unit and integration
suite uses the shared services. `tests/topology.rs` uses in-process `redis-test`
fixtures that need a `redis-server` binary. Prefer a real object or an in-memory
fake over a mock. Assert the observable contract. Tear the services down with
`docker compose -f compose.test.yaml down -v`.

Quality gates for any change:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run --all-targets
cargo test --doc
cargo audit
cargo deny check
python3 scripts/check_doc_links.py
```

`fuzz/` is a standalone workspace, so no gate above compiles it, and a fuzz
target that builds a library type by hand goes stale the moment that struct
gains a field. When a change adds or reshapes a type or function a target
constructs or calls, build the targets too:

```bash
cd fuzz && cargo fuzz build --target x86_64-unknown-linux-gnu
```

When a query or migration is added or changed, regenerate and commit the
offline cache. CI runs `cargo sqlx prepare --check --workspace` and fails if
the committed cache is stale; regenerate it with the plain form:

```bash
cargo sqlx prepare --check --workspace   # CI gate
cargo sqlx prepare --workspace           # regenerate the cache
```

## File-scope discipline

- A delegated or subagent change runs only the narrowest name-filtered test for
  the touched code, for example `cargo nextest run -E 'test(admin_bootstrap)'`.
  Never the full suite, and never repo-wide setup.
- The primary agent runs the full authoritative suite after integration:
  `cargo nextest run --all-targets` followed by `cargo test --doc`.

## Documentation contract

Documentation is part of the change, not a follow-up. Any behavior change
updates the relevant guide in the same commit:

- OAuth flow, grants, error codes: `docs/OAUTH.md`.
- Threat model, attack surface, tokens, sender constraints, admin runbook:
  `docs/SECURITY.md`.
- Modules, lifecycle, topology: `docs/ARCHITECTURE.md`.
- Config keys and defaults: `docs/CONFIGURATION.md`.
- Schema and migrations, disabled-user re-check: `docs/DATABASE.md`.
- Redis keys, TTLs, durability, subject purge: `docs/REDIS.md`.
- Image, manifests, probes: `docs/DEPLOYMENT.md`.
- CLI and runbooks: `docs/OPERATIONS.md`, `RUNBOOK.md`.
- This file, when the module map or rules change.

A change to the deployment surface (a new listener, mount, dependency class, or
runtime setting) updates the attack-surface section in `docs/SECURITY.md`.

A command in a doc must match the real CLI. Then run the link check:

```bash
python3 scripts/check_doc_links.py
```

The `.github/workflows/docs.yml` `link-check` job (mirrored by the `doc-links`
job in `.github/workflows/ci.yml`) runs the same check, so a stale file or
heading reference fails the build.

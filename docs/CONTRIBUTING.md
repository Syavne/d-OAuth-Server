# Contributing

How to build, test, and change the d-OAuth-Server authorization server. The rules here
are enforced by CI, so a change that skips them will not merge.

## Purpose

This guide is for anyone editing the Rust source. It covers prerequisites, the
quality gates, module conventions, the test-driven workflow, commit style, and
the documentation contract. Operators looking to run the server should start
with the [README](../README.md) and [OPERATIONS.md](OPERATIONS.md).

## Prerequisites

- The Rust toolchain pinned in `rust-toolchain.toml` (stable, with `rustfmt`
  and `clippy`). `rustup` installs it automatically on first build.
- [`cargo-nextest`](https://nexte.st/) for the test suite:
  `cargo install cargo-nextest --locked`.
- Docker, to run the shared test Postgres and Redis from
  `compose.test.yaml` (`docker compose -f compose.test.yaml up -d`), and for
  the handful of suites that still use `testcontainers` (see
  [Database-backed tests](#database-backed-tests)).
- `sqlx-cli` only when you add or change a SQL query or a migration:
  `cargo install sqlx-cli --locked --features runtime-tokio,tls-rustls-ring`.

The crate uses edition 2024 and the rustfmt settings in `rustfmt.toml`
(2-space indent, `StdExternalCrate` import grouping).

## Build

```bash
cargo build --locked            # debug
cargo build --locked --release  # release (thin LTO, stripped)
```

The build is offline-safe for SQL: with `SQLX_OFFLINE=true` the `query!` macros
compile against the committed `.sqlx/` cache, so no database is needed at build
time. The Docker build relies on exactly this. When a query or a migration
changes, regenerate and commit the cache. CI runs the check form and fails if
the committed cache is stale:

```bash
cargo sqlx prepare --check --workspace   # CI gate
cargo sqlx prepare --workspace           # regenerate the cache
```

## Quality gates

Run all of these before opening a change. CI runs this set plus additional
gates: `cargo sqlx prepare --check --workspace`, the fuzz targets
(`cargo fuzz build`), coverage, `cargo mutants`, `miri`, and the separate
`.github/workflows/docs.yml` link check. Nothing in the set below compiles
`fuzz/`, so build the targets yourself when a change reshapes a type or
function one of them uses (see [Fuzzing](#fuzzing)).

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run --all-targets
cargo test --doc
cargo audit
cargo deny check
python3 scripts/check_doc_links.py
```

Start the shared test services before `cargo nextest run --all-targets`:
`docker compose -f compose.test.yaml up -d`, then tear them down with
`docker compose -f compose.test.yaml down -v`. `cargo nextest run` is the
authoritative test entry point. It runs unit, integration, and end-to-end tests;
they all use the shared services except the keep-list under
[Database-backed tests](#database-backed-tests), which needs `testcontainers`.
`cargo test --doc` runs the doc examples separately because nextest does not
cover doctests.

### Narrow scope while developing

While iterating on one area, filter to just that area:

```bash
cargo nextest run -E 'test(refresh_rotation)'
cargo nextest run -E 'test(admin_bootstrap)'
```

A delegated or subagent change runs only the narrowest filter that covers the
touched code. The full suite runs once, at integration time.

### Database-backed tests

Integration tests connect to the shared Postgres and Redis started from
`compose.test.yaml`:

```bash
docker compose -f compose.test.yaml up -d
cargo nextest run --all-targets
docker compose -f compose.test.yaml down -v
```

The defaults are Postgres on `127.0.0.1:5433` and Redis on `127.0.0.1:6380`,
overridable through `D_OAUTH_TEST_POSTGRES_URL` and `D_OAUTH_TEST_REDIS_URL`.
Each test isolates itself with a freshly created database and unique Redis key
prefixes, so parallel tests never share state and nothing is flushed.
Migrations are never run by the test process against the shared `postgres`
database; a test that asserts on a migration applies it to its own fresh
database.

The suites that need their own Redis nodes are the exception. Only these use
`testcontainers`:

- `src/test_guard.rs` and `src/state/test_support.rs`: the shared container
  helpers the rest of this list is built on.
- `tests/resilience.rs`: stops and restarts containers; the guards synchronously
  `rm` them on drop, so killing the suite mid-run no longer orphans containers.
- `src/state/tests_topology.rs`: Sentinel, Cluster, and `requirepass` topology.
- The `--appendfsync always` refresh-token suite:
  `src/protocol/token/grants/refresh_token/tests.rs` and its `tests/failover.rs`.
- The two Redis durability tests in `src/store/tests_store.rs`.
- `dcr_manage_token_survives_redis_flush` in
  `src/protocol/dcr/manage/tests_delete.rs`.

Every other unit and integration suite uses the shared services.
`tests/topology.rs` is separate: it spawns in-process `redis-test`
Sentinel/Cluster fixtures, which need a real `redis-server` binary. Docker must
be running, and the in-process topology fixtures additionally need that binary.

### Fuzzing

Fuzz targets live in `fuzz/fuzz_targets/` (a standalone workspace under
`fuzz/`, built only by the nightly leg — the root stable pin is untouched):

| Target | Real entry point fuzzed |
| --- | --- |
| `token_form` | `crypto::tokens::TokenHash::parse_storage_string` |
| `dcr_json` | `protocol::dcr::RegisterRequest` deserialization |
| `jar_claims` | JWT-claims envelope shape + `jose::jar::require_par_or_jar` |
| `dpop_proof` | `jose::jwk::{decoding_key, thumbprint}` (embedded-JWK gate) |
| `jar_verify` | `protocol::client_auth::assertion::{unverified_iss, validate_assertion}` |
| `redirect_uri` | `protocol::redirect_repo::match_redirect_uri` |
| `scope_parse` | `protocol::scope::ScopeSet::{parse, render}` |

Every target is small and hermetic (no network, Postgres, or Redis):
signature verification that needs keys and replay claims that need the store
stay under unit/proptest cover. Targets contain no `unwrap`/`expect`/`panic`/
`unsafe`, so arbitrary input can only surface a genuine parser panic.

```bash
cd fuzz
cargo fuzz build                       # every target must compile
cargo fuzz run <target> -- -max_total_time=60 -rss_limit_mb=2048
```

The containerized (ClusterFuzzLite/OSS-Fuzz) build runs inside the Rust base
image, which prepends `-fsanitize=address …` to `CFLAGS`/`CXXFLAGS` and exports
`CXX=clang++` with a `CXXFLAGS` selecting libc++. `.clusterfuzzlite/build.sh`
drops `CFLAGS`/`CXXFLAGS`/`RUSTFLAGS` for the build:

- The sanitizer C flags instrument the `cc`-compiled C/asm in a dependency
  (`ring`, pulled by sqlx's `tls-rustls-ring-webpki` feature). Those objects
  reach the host proc-macro `sqlx-macros` through its dependency graph, and
  rustc does not link the ASan runtime into a proc-macro cdylib, so that `.so`
  fails at `dlopen` with undefined `__asan_*`/`__sancov_lowest_stack`.
- Dropping `CXXFLAGS` also removes `-stdlib=libc++`; libfuzzer-sys compiles
  libFuzzer's C++ runtime with `$CXX` while rustc/`cc` links `-lstdc++`, so the
  runtime's libc++ (`std::__1::`) symbols would otherwise go undefined. clang++
  then defaults to libstdc++.

The Rust code keeps full ASan + libFuzzer coverage: `cargo fuzz` supplies those
Rust flags itself (the same scoped flags as the `ci.yml fuzz-build` leg, which
runs with no sanitizer env). The image pins `cargo-fuzz` so the tool cannot
drift.

Corpora persist across runs: `cargo fuzz run` reads and writes
`fuzz/corpus/<target>/` (gitignored, but cached across CI runs by the
`fuzz-run` leg), and crashes land in `fuzz/artifacts/<target>/`. To grow a
local seed, drop an input in `fuzz/corpus/<target>/` and confirm the
target still passes; keep seeds tiny and non-secret (never a real token, key,
or password). Seeds stay local: `fuzz/.gitignore` excludes `corpus/`, so a
seed is only shared by committing it with `git add -f` deliberately.

Continuous coverage is ClusterFuzzLite (`.clusterfuzzlite/` plus
`.github/workflows/cflite_pr.yml` for PRs and `cflite_batch.yml` for the
daily batch run). One-time owner setup for Efren:

1. Merge the `cflite_*.yml` workflows (PR fuzzing needs only the default
   `GITHUB_TOKEN`).
2. For batch fuzzing, follow the ClusterFuzzLite batch setup (Cloud Project +
   filestore) at <https://google.github.io/clusterfuzzlite/> and point it at
   this repository; no code change is needed — `.clusterfuzzlite/build.sh`
   already builds every target.
3. OSS-Fuzz enrollment (optional, stronger): propose the project at
   <https://github.com/google/oss-fuzz> reusing the same `Dockerfile` and
   `build.sh` layout.

## Module conventions

The crate is one library (`src/lib.rs`) plus a thin binary (`src/main.rs`).
Every module has a single responsibility:

| Area | Path | Owns |
| --- | --- | --- |
| Configuration | `src/config.rs`, `src/config/` | Layered env/file load and fail-fast validation. |
| Keys | `src/keys.rs` | Versioned `KeyRing` for the token pepper, TOTP encryption key, and PII field-encryption key. |
| Crypto primitives | `src/crypto/` | Constant-time compare, PKCE, token mint/hash, TOTP, secret hashing. |
| Field encryption | `src/crypto/field.rs` | AES-256-GCM PII field codec and keyed-HMAC blind index. |
| JOSE | `src/jose/` | DPoP, JAR, `private_key_jwt` verification, JWK parsing. |
| Postgres repositories | `src/db/` | The seven domain tables. |
| Redis store | `src/store/` | Ephemeral state: codes, tokens, grants, sessions, PAR, device, DCR, rate limits. |
| Protocol handlers | `src/protocol/` | OAuth endpoints and grants. |
| Server-rendered UI | `src/ui/` | Login, consent, and device pages. |
| Middleware | `src/middleware/` | Request id, tracing/redaction, rate limit, security headers, audit. |
| Resilience | `src/resilience.rs` | Load-shed, timeout, and concurrency-limit guard. |
| Routing and serving | `src/routes.rs`, `src/serve.rs`, `src/tls.rs` | Router assembly and the two listeners. |
| Application state | `src/state.rs`, `src/state/` | `AppState`, the topology-aware Redis connection, health endpoints (health/pg/redis/sentinel). |
| Operator CLI | `src/cli.rs`, `src/cli/` | Every administrative command. |
| Errors | `src/error.rs` | `AppError`: the client-safe OAuth error type and its HTTP mapping. |

Rules that apply everywhere:

- Plain, idiomatic Rust. `#![forbid(unsafe_code)]` is on the crate.
- No `unwrap`, `expect`, or `panic` in request paths. They are denied by the
  clippy lints in `Cargo.toml`.
- Errors are typed with `thiserror`; map dependency failures to the correct
  client-safe error rather than stringifying them.
- Secrets use `secrecy` and `zeroize`. A type that holds a secret must not have
  a `Debug` impl that prints it.
- Constant-time comparison (`subtle`) for any secret or token comparison.
- Keep `main.rs` free of business logic.
- No file grows past roughly 250 pure lines without a good reason; split by
  responsibility instead.

## Test-driven workflow

Every behavior change follows red, green, refactor:

1. Red: write a failing test that names the behavior and run it. Confirm it
   fails for the reason you expect, not because of a typo or a missing import.
2. Green: write the smallest change that makes the test pass.
3. Refactor: restructure with the test green as the safety net.

Write the test against the shared Postgres and Redis from
`compose.test.yaml` (defaults `127.0.0.1:5433` and `127.0.0.1:6380`, override
with `D_OAUTH_TEST_POSTGRES_URL` / `D_OAUTH_TEST_REDIS_URL`), with a fresh
database and unique Redis prefixes per test. Reach for `testcontainers` only
when the test needs Redis nodes of its own (the keep-list under
[Database-backed tests](#database-backed-tests)); stop/start lifecycle cases are
the common reason. Prefer a real object or an in-memory fake over a mock. Assert
the observable contract, not an implementation dump.

## Commit style

One commit per logical change, in conventional-commit form:

```
feat(token): add token-exchange grant
fix(store): fail closed when the durability barrier is missed
docs(agents): document the module map
test(resilience): cover Redis restart recovery
```

The subject is imperative and lowercase after the type. The body explains why,
and links the evidence file when the task process requires one. Never commit a
secret, a real token, or key material.

## Documentation contract

The docs are part of the code, not an afterthought. Any behavior change updates
the relevant guide in the same commit:

- OAuth flow, grants, or error codes: `docs/OAUTH.md`.
- Threat model, tokens, sender constraints, or the admin runbook:
  `docs/SECURITY.md`.
- Module layout or request lifecycle: `docs/ARCHITECTURE.md`.
- A config key or default: `docs/CONFIGURATION.md`.
- Schema or migration behavior: `docs/DATABASE.md`.
- Redis keys, TTLs, or topology: `docs/REDIS.md`.
- Image, manifests, or probes: `docs/DEPLOYMENT.md`.
- A CLI command or runbook step: `docs/OPERATIONS.md`.
- Anything at all: the module map in [AGENTS.md](../AGENTS.md).

Then run the link checker, which CI also runs:

```bash
python3 scripts/check_doc_links.py
```

A command in a doc must match the real CLI. If you change a flag, change the doc
in the same commit.

# Test Coverage

## Baseline

Authoritative all-targets baseline (orchestrator run, 1050/1050 tests,
elapsed 767.6 s = 12.79 min):

- Global line coverage: 90.5% (22026/24335), floor 89.0.
- Security aggregate (the ten core modules: crypto, jose, protocol, db,
  store, state, middleware, keys, error, routes): 92.2% (17230/18695),
  floor 91.0.

Per-module baselines and floors (floor = truncate(baseline) - 1.0,
enforced by `scripts/coverage_floors.json`):

| Module     | Baseline | Hit / Found | Floor |
|------------|----------|-------------|-------|
| crypto     | 95.6%    | 1066/1115   | 94.0  |
| jose       | 92.7%    | 1107/1194   | 91.0  |
| protocol   | 93.3%    | 8312/8911   | 92.0  |
| db         | 91.7%    | 1602/1747   | 90.0  |
| store      | 88.6%    | 2091/2360   | 87.0  |
| state      | 76.0%    | 355/467     | 75.0  |
| middleware | 95.7%    | 986/1030    | 94.0  |
| ui         | 88.7%    | 1362/1535   | 87.0  |
| config     | 93.5%    | 907/970     | 92.0  |
| keys       | 88.5%    | 184/208     | 87.0  |
| error      | 89.7%    | 425/474     | 88.0  |
| routes     | 92.7%    | 1102/1189   | 91.0  |
| tls        | 96.1%    | 49/51       | 95.0  |

The `ui`, `config`, and `tls` modules carry per-module floors only and are
excluded from the security aggregate.

Floors file: `scripts/coverage_floors.json`.

Reproduce:

```bash
docker compose -f compose.test.yaml up -d
cargo llvm-cov nextest --all-targets --lcov --output-path lcov.info --ignore-filename-regex '(^|/)tests/|(^|/)tests\.rs$|(^|/)tests_[^/]*\.rs$|test_support\.rs$|test_guard\.rs$'
python3 scripts/check_coverage.py lcov.info --floors scripts/coverage_floors.json
docker compose -f compose.test.yaml down -v
```

Note: the authoritative run used `--test-threads=1 --retries=3
--no-fail-fast` because WAITAOF barriers flaked under high local parallelism
(host-specific; 1050/1050 passed).

## Flow matrix

Every row is one OAuth flow. The level columns read `covered` or `gap`; a
covered cell names the suite or target that delivers it. The evidence column
names the canonical capture under `.omo/evidence/test-coverage-audit/` (local
run evidence, not shipped in the repository). Each `NN-*.txt` name in that
column is shorthand for `.omo/evidence/test-coverage-audit/NN-*.txt`.

Levels:

- `unit`: white-box module tests, either inline in `src/` or in a pure
  `tests/*.rs` suite that never starts the router.
- `proptest`: a `proptest!` property suite over the flow's core parser or
  invariant.
- `e2e`: the real router or TLS handshake over the shared Postgres and Redis.
- `fuzz`: a hermetic target under `fuzz/fuzz_targets/`.

| Flow | unit | proptest | e2e | fuzz | Evidence |
| --- | --- | --- | --- | --- | --- |
| Authorization code | covered (`authorization_code.rs`, `code/tests.rs`) | gap | covered (`e2e_flow`, `e2e_conformance`, `e2e_grants`, `e2e_stale_catalog`) | gap | `03-baseline.txt`, `18-login-negatives.txt`, `17-stale-catalog.txt` |
| Refresh | covered (`refresh_token/tests/*`, 34 tests) | covered (`proptest_rotation`) | covered (`e2e_grants`, `e2e_stale_catalog`, `e2e_admin`) | gap | `03-baseline.txt`, `17-stale-catalog.txt`, `11-admin.txt` |
| Client credentials | covered (`client_credentials/tests.rs`, 14 tests) | gap | covered (`e2e_grants`, `e2e_mtls_grant`) | gap | `03-baseline.txt`, `14-mtls.txt` |
| Device | covered (`device_code/*`, `device/tests.rs`) | gap | covered (`e2e_device`, `e2e_edge_matrix`, `e2e_stale_catalog`) | gap | `09-device.txt`, `16-edge-matrix.txt`, `17-stale-catalog.txt` |
| Exchange | covered (`token_exchange/tests/*`, 7 tests) | gap | covered (`e2e_token_exchange`, `e2e_edge_matrix`, `e2e_grants`) | gap | `10-token-exchange.txt`, `16-edge-matrix.txt` |
| DPoP | covered (`jose/dpop/tests.rs`, 21 tests) | gap | covered (`e2e_grants`, `e2e_flow`) | covered (`dpop_proof`) | `03-baseline.txt`, `20-fuzz-build.txt` |
| mTLS | covered (`tests/mtls.rs` vectors and selection) | gap | covered (`e2e_mtls_grant`, `tests/mtls.rs` handshake) | covered (`mtls_cert`) | `14-mtls.txt`, `20-fuzz-build.txt` |
| PAR | covered (`par/tests/*`, 29 tests) | covered (`proptest_inputs` wire-form properties) | covered (`e2e_conformance`, `e2e_grants`, `e2e_cimd`) | covered (`params_form`) | `03-baseline.txt`, `15-cimd.txt`, `19-proptest.txt`, `21-fuzz-smoke.txt` |
| JAR | covered (`jose/jar/*` inline tests, 7 tests) | gap | covered (`tests/jar.rs`, `e2e_cimd`) | covered (`jar_claims`, `jar_verify`) | `03-baseline.txt`, `15-cimd.txt`, `20-fuzz-build.txt` |
| DCR | covered (`dcr/tests.rs`, 50 tests) | gap | covered (`e2e_dcr`, `e2e_edge_matrix`) | covered (`dcr_json`) | `08-dcr.txt`, `16-edge-matrix.txt`, `20-fuzz-build.txt` |
| Introspection | covered (`introspect/tests.rs`, 23 tests) | gap | covered (`e2e_conformance`, `e2e_abuse`, `e2e_device`, `e2e_admin`, `e2e_token_exchange`, `e2e_mtls_grant`) | gap | `03-baseline.txt`, `11-admin.txt` |
| Revocation | covered (`revoke/tests/*`, 20 tests) | gap | covered (`e2e_abuse`, `e2e_conformance`) | gap | `03-baseline.txt` |
| Logout | covered (`src/ui/login/tests/auth.rs`) | gap | covered (`e2e_logout`) | gap | `13-logout.txt` |
| CIMD | covered (`cimd/tests*.rs`, `ssrf/tests.rs`) | gap | covered (`e2e_cimd`) | covered (`cimd_document`, `ssrf_url`) | `15-cimd.txt`, `20-fuzz-build.txt`, `21-fuzz-smoke.txt` |
| Resource indicators | covered (`params/tests.rs`, token audience tests) | covered (`proptest_inputs` repeated `resource` fields) | covered (`e2e_grants`, `e2e_stale_catalog`) | covered (`params_form`) | `03-baseline.txt`, `17-stale-catalog.txt`, `19-proptest.txt`, `21-fuzz-smoke.txt` |
| Scope catalog | covered (`tests/scope_engine.rs`, 5 pure tests) | covered (`proptest_scope`, `scope_engine` round trip) | covered (`e2e_stale_catalog`, `e2e_abuse`) | covered (`scope_parse`) | `03-baseline.txt`, `17-stale-catalog.txt`, `21-fuzz-smoke.txt` |
| PKCE | covered (`crypto/pkce.rs`, 9 tests) | covered (`proptest_pkce`) | covered (`e2e_conformance`, `e2e_grants`, `e2e_flow`) | covered (`pkce`) | `03-baseline.txt`, `18-login-negatives.txt`, `21-fuzz-smoke.txt` |

Reading the gaps: `proptest` gaps are flows whose invariant is carried by
example-based unit and e2e tests instead of a generated strategy (device,
exchange, DCR, introspection, revocation, logout, CIMD, JAR, DPoP, mTLS,
client credentials, authorization code). The `fuzz` gaps are grants with no
hermetic parser to fuzz; the five form endpoints share the `params_form`
target, and opaque token storage strings share `token_form`, but neither
target exercises grant-specific state. A gap is a statement about this
matrix, not an unbounded hole.

## Closed gaps (waves 3-5)

Each row names the suite or target that closed the gap and the capture that
proves it.

| Closed gap | Delivering suite or target | Evidence |
| --- | --- | --- |
| DCR registration lifecycle: register, use, read, update, delete | `tests/e2e_dcr.rs` | `08-dcr.txt` |
| Device grant approve, poll, deny, user-code normalization, guess limit | `tests/e2e_device.rs` | `09-device.txt` |
| Token exchange allowlisted mint, scope widening, multi-hop | `tests/e2e_token_exchange.rs` | `10-token-exchange.txt` |
| Disabled-user cascade: introspection, refresh, code, device, session | `tests/e2e_admin.rs` | `11-admin.txt` |
| CLI `user disable` purge-then-flag ordering | `tests/cli_user_disable.rs` | `12-cli-disable.txt` |
| Logout POST, GET read-only, CSRF mismatch | `tests/e2e_logout.rs` | `13-logout.txt` |
| mTLS `tls_client_auth` token mint with `cnf` binding | `tests/e2e_mtls_grant.rs` | `14-mtls.txt` |
| CIMD authorize, login, consent, token, cache, invalid documents, dead row | `tests/e2e_cimd.rs` | `15-cimd.txt` |
| DCR, device, and exchange HTTP edge matrix | `tests/e2e_edge_matrix.rs` | `16-edge-matrix.txt` |
| Stale resource and scope catalog on refresh, device, auth code, authorize | `tests/e2e_stale_catalog.rs` | `17-stale-catalog.txt` |
| Login TOTP and CSRF negatives | `tests/e2e_flow.rs` | `18-login-negatives.txt` |
| Input properties: params wire order, TOTP window, at+jwt no panic | `tests/proptest_inputs.rs` | `19-proptest.txt` |
| Fuzz targets: `jwt_access_verify`, `cimd_document`, `mtls_cert`, `params_form`, `ssrf_url`, `totp_input`, `pkce` | `fuzz/fuzz_targets/` | `20-fuzz-build.txt`, `21-fuzz-smoke.txt` |
| Local seeds and CI fuzz matrix | `fuzz/corpus/`, `.github/workflows/ci.yml` | `22-ci-matrix.txt` |

## Reproduce a run

Coverage, with the shared services up:

```bash
docker compose -f compose.test.yaml up -d
cargo llvm-cov nextest --all-targets --lcov --output-path lcov.info --ignore-filename-regex '(^|/)tests/|(^|/)tests\.rs$|(^|/)tests_[^/]*\.rs$|test_support\.rs$|test_guard\.rs$'
python3 scripts/check_coverage.py lcov.info --floors scripts/coverage_floors.json
docker compose -f compose.test.yaml down -v
```

The floor checker's own fixtures:

```bash
python3 scripts/test_check_coverage.py
```

One suite at a time:

```bash
cargo nextest run -E 'binary(e2e_dcr)'
cargo nextest run -E 'binary(e2e_device)'
cargo nextest run -E 'binary(e2e_token_exchange)'
cargo nextest run -E 'binary(e2e_admin)'
cargo nextest run -E 'binary(cli_user_disable)'
cargo nextest run -E 'binary(e2e_logout)'
cargo nextest run -E 'binary(e2e_mtls_grant)'
cargo nextest run -E 'binary(e2e_cimd)'
cargo nextest run -E 'binary(e2e_edge_matrix)'
cargo nextest run -E 'binary(e2e_stale_catalog)'
cargo nextest run -E 'binary(e2e_flow)'
cargo nextest run -E 'binary(proptest_inputs)'
```

The property suites that predate the audit:

```bash
cargo nextest run -E 'binary(proptest_pkce)'
cargo nextest run -E 'binary(proptest_redirect)'
cargo nextest run -E 'binary(proptest_scope)'
cargo nextest run -E 'binary(proptest_rotation)'
```

Fuzz targets and seeds (standalone workspace, nightly pin):

```bash
cd fuzz
cargo fuzz build --target x86_64-unknown-linux-gnu
cargo fuzz run <target> -- -max_total_time=60 -rss_limit_mb=2048
cargo fuzz run token_form corpus/token_form/valid-zero-digest corpus/token_form/malformed -- -runs=1
cargo fuzz run dcr_json corpus/dcr_json/minimal corpus/dcr_json/malformed -- -runs=1
cargo fuzz run jar_claims corpus/jar_claims/envelope corpus/jar_claims/malformed -- -runs=1
```

The documentation link check:

```bash
python3 scripts/check_doc_links.py
```

## Final gate run

The closing run on the final tree passed every authoritative gate with exit
code 0. The full nextest suite passed 1050/1050 tests in 59.1 s; the coverage
run passed the same 1050/1050 tests in 761.2 s, and the full coverage command
took 784 s. These are the final numbers; the baseline above stays as the
historical first measurement.

Final coverage (`scripts/check_coverage.py` exit 0):

- Global: 90.5% (22022/24335), floor 89.0.
- Security aggregate: 92.1% (17226/18695), floor 91.0.

| Module     | Final    | Hit / Found | Floor |
|------------|----------|-------------|-------|
| crypto     | 95.6%    | 1066/1115   | 94.0  |
| jose       | 92.6%    | 1106/1194   | 91.0  |
| protocol   | 93.3%    | 8313/8911   | 92.0  |
| db         | 91.7%    | 1602/1747   | 90.0  |
| store      | 88.6%    | 2090/2360   | 87.0  |
| state      | 76.0%    | 355/467     | 75.0  |
| middleware | 95.7%    | 986/1030    | 94.0  |
| ui         | 88.7%    | 1362/1535   | 87.0  |
| config     | 93.5%    | 907/970     | 92.0  |
| keys       | 88.5%    | 184/208     | 87.0  |
| error      | 89.0%    | 422/474     | 88.0  |
| routes     | 92.7%    | 1102/1189   | 91.0  |
| tls        | 96.1%    | 49/51       | 95.0  |

The gates, all exit 0: `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`,
`cargo nextest run --all-targets --retries=3 --no-fail-fast`,
`cargo test --doc`, the `cargo llvm-cov nextest` command from
[Reproduce a run](#reproduce-a-run), `scripts/check_coverage.py`,
`cd fuzz && cargo fuzz build --target x86_64-unknown-linux-gnu`,
`cd fuzz && cargo fmt --check`,
`cd fuzz && cargo clippy --all-targets -- -D warnings`,
`python3 scripts/check_doc_links.py`, `cargo audit`, and
`cargo deny check`. `cargo audit` reports one allowed unmaintained warning
(`basic-toml`, RUSTSEC-2026-0374); `cargo deny check` reports advisories, bans,
licenses, and sources all ok.

The run used the shared Postgres and Redis from `compose.test.yaml` with
`--test-threads=1 --retries=3 --no-fail-fast`. Local WAITAOF barriers flake
under high parallelism on this host; CI uses its own settings.

An interim `cargo clippy` on the fuzz workspace failed with
`clippy::collapsible-if` in `fuzz/fuzz_targets/ssrf_url.rs`. The nested
`if let` blocks were collapsed into an edition-2024 let-chain with the
assertions unchanged, and the final fuzz clippy, fmt, build, and `ssrf_url`
smoke runs all pass.

## Coverage caveats

Known untested network path: `ssrf::fetch_guarded_bytes_with` is covered only
by its unit tests and by the URL-policy fuzz target (`ssrf_url`). No test opens
a real outbound connection through it: CIMD tests inject a `CimdFetcher`, so
the socket connect, the redirect refusal on a live response, and the byte and
time caps over a real body stay unexercised. The unit tests pin the address
policy and the failure mapping; `validate_fetch_url` and `is_blocked_ip` are
the fuzzed surface. Treat a change to the connection loop as unverified by the
suite and review it by hand.

Inline `#[cfg(test)]` modules inside production files cannot be excluded by
filename, so `--all-targets` coverage counts their lines and modestly inflates
the score. The per-module table shows that effect rather than hiding it.

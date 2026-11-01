# d-OAuth-Server

An OAuth 2.1-only authorization server written in Rust. It is deliberately not
backwards compatible with OAuth 2.0: PKCE is mandatory, the implicit and
resource-owner-password grants do not exist, bearer-in-query is rejected, and
redirect URIs match exactly (with the RFC 8252 §7.3 loopback exception, which
includes the host `localhost` only when `allow_localhost_redirect` is set).

It implements the authorization-code, refresh-token, client-credentials,
device-code, and token-exchange grants, with DPoP, mTLS, PAR, JAR, dynamic
client registration, client ID metadata documents, introspection, and
revocation. Tokens are opaque and hashed at rest by default; a global enable
switch plus a per-client `jwt` access-token format mints RFC 9068 `at+jwt`
tokens verified against the AS JWKS. All durable domain state is in PostgreSQL
and all ephemeral state is in Redis, so replicas are interchangeable.
Administration is CLI plus declarative configuration: there is no HTTP admin
API and no default credential.

## Run it

A self-contained local stack, from the repository root. `compose.yaml`
generates a throwaway TLS certificate and dev-only key files, applies
migrations exactly once, and starts one replica against its own Postgres and
Redis:

```bash
docker compose -f compose.yaml up --build
docker compose -f compose.yaml port app 8080   # host port of the TLS listener
```

The listener uses that self-signed certificate, so probe it with `-k`. The
discovery document advertises the configured issuer (`https://localhost:8080`),
independent of the random host port:

```bash
curl -sk https://127.0.0.1:<host-port>/.well-known/oauth-authorization-server | jq .
```

From a checkout, against a Postgres and a Redis of your own, with the
development environment exported as in
[QUICKSTART.md](docs/QUICKSTART.md#development-configuration):

```bash
cargo build --locked
cargo run --bin d-oauth-server -- config check
cargo run --bin d-oauth-server -- migrate
cargo run --bin d-oauth-server -- admin bootstrap --email admin@example.com
cargo run --bin d-oauth-server -- serve
```

```bash
curl -s http://127.0.0.1:8081/health/live
curl -s http://127.0.0.1:8081/health/ready
```

That is the short version. The full first-run path, including creating a
client and minting an access token with PKCE, is
[QUICKSTART.md](docs/QUICKSTART.md).

## Documentation

Comprehensive guides live in [`docs/`](docs/README.md), whose index maps every
guide by audience and reading order.

| I want to... | Start with |
| --- | --- |
| Run it, end to end, with a token | [QUICKSTART.md](docs/QUICKSTART.md) |
| Look up a configuration key | [CONFIGURATION.md](docs/CONFIGURATION.md) |
| Administer a live install | [OPERATIONS.md](docs/OPERATIONS.md), [RUNBOOK.md](docs/RUNBOOK.md) |
| Deploy it to a cluster | [DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Integrate an OAuth client | [OAUTH.md](docs/OAUTH.md) |
| Protect an API (resource server) | [RS-CONTRACT.md](docs/RS-CONTRACT.md) |
| Understand or change the code | [ARCHITECTURE.md](docs/ARCHITECTURE.md), [CONTRIBUTING.md](docs/CONTRIBUTING.md) |
| Review the security properties | [SECURITY.md](docs/SECURITY.md) |
| Inspect the schema or the Redis keys | [DATABASE.md](docs/DATABASE.md), [REDIS.md](docs/REDIS.md) |
| See what changed in a release | [CHANGELOG.md](docs/CHANGELOG.md) |

To report a vulnerability, use the [reporting policy](SECURITY.md), not a guide.

## Before production

- There is no default credential and no HTTP admin API. Provision through the
  CLI or a migration Job ([RUNBOOK.md](docs/RUNBOOK.md)).
- The token pepper, TOTP encryption key, and PII field-encryption key are
  required, must each be at least 32 bytes (`WeakKeyMaterial` otherwise), and
  are live secrets: losing the pepper invalidates every opaque token, and losing
  the PII key makes the sealed directory unreadable. Mount them as files, not
  environment values ([DEPLOYMENT.md](docs/DEPLOYMENT.md#secret-material-as-files)).
- Production requires an `https` issuer and, unless
  `database.require_verify_full` is set false, a database URL with
  `sslmode=verify-full`.
- Redis must run with `noeviction` and persistence; the server asserts both at
  startup and refuses to start otherwise
  ([REDIS.md](docs/REDIS.md#the-durability-barrier)).
- Security endpoints fail closed: when Postgres or Redis is unavailable they
  return `503` rather than failing open. CORS is empty by default, so browser
  clients need an explicit origin allowlist.

The threat model and the full invariant list are in
[SECURITY.md](docs/SECURITY.md).

## Tests

`cargo nextest run --all-targets` is the authoritative suite, backed by the
shared Postgres and Redis from `compose.test.yaml`; `cargo test --doc` covers
the doctests. The quality gates, the coverage floors, the fuzzing targets, and
the exact commands are in [CONTRIBUTING.md](docs/CONTRIBUTING.md#quality-gates),
with the measured baseline in
[TEST-COVERAGE.md](docs/TEST-COVERAGE.md).

## License

ISC. See [LICENSE.md](LICENSE.md).

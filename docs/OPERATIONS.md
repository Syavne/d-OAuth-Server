# Operations

Administration is CLI plus declarative configuration only. There is no HTTP
admin API, no default credential, and nothing is auto-created at startup. This
is the de-facto admin interface and the runbook for its day-two tasks.

## Purpose

For an operator: the full command surface, the declarative `config sync` file,
the audit stream, key and certificate rotation, and backup and restore.

## The admin model

- The `migrate` subcommand owns the schema and is the only writer of it.
- The `serve` subcommand serves OAuth and never migrates and never provisions.
- Every mutation (scopes, users, entitlements, redirect URIs, client
  attachments) is audited on the `audit` tracing target.
- Secrets are read from stdin, a file, or the environment, never from argv. A
  secret is printed only when the operator asked for a one-time value.

## Command reference

The binary is `d-oauth-server` (`cargo run --bin d-oauth-server -- <command>`).
Exit codes: `0` success, `1` command failure, `2` usage error.

### serve and migrate

```bash
d-oauth-server serve
d-oauth-server migrate
d-oauth-server config check
```

- `serve` loads config, connects Postgres and Redis, asserts the Redis
  durability contract, and runs the TLS public listener plus the plaintext
  health listener. It never migrates. It drains on `SIGTERM`.
- `migrate` applies forward-only migrations under sqlx's advisory lock and
  prints `applied N migration(s)`.
- `config check` validates configuration and prints `config ok: issuer=...`.

### Users

```bash
d-oauth-server user create --email <email> [--admin] [--password-stdin] [--password-file <path>]
d-oauth-server user enroll-totp --email <email>
d-oauth-server user disable --email <email>
d-oauth-server user grant-scope --email <email> --scope <scope>
d-oauth-server user revoke-scope --email <email> --scope <scope>
d-oauth-server user scopes --email <email>
```

- `create` reads the password from stdin by default or from `--password-file`.
  The two sources are mutually exclusive. `--admin` sets `is_admin`. A created
  user always starts with `must_change_password = true`.
- `enroll-totp` generates an encrypted TOTP secret and prints the secret and the
  `otpauth://` URI exactly once. Register the secret in an authenticator now.
- `grant-scope` requires the scope to exist in the catalog.
- `revoke-scope` is idempotent.

### Scopes

```bash
d-oauth-server scope create <name> [--description <text>]
d-oauth-server scope list
d-oauth-server scope enable <name>
d-oauth-server scope disable <name>
d-oauth-server scope delete <name>
```

`create` upserts: it creates a scope or updates its description. `delete`
deletes a scope that nothing references, and disables it when `user_scopes`
references it, so entitlements are not silently destroyed. The enabled scope
catalog is what `/metadata` advertises as `scopes_supported`.

### Redirect URIs and client attachments

```bash
d-oauth-server redirect-uri create <uri> [--kind authorize|post_logout] [--description <text>]
d-oauth-server redirect-uri list
d-oauth-server redirect-uri enable <uri> [--kind authorize|post_logout]
d-oauth-server redirect-uri disable <uri> [--kind authorize|post_logout]
d-oauth-server redirect-uri delete <uri> [--kind authorize|post_logout]
d-oauth-server client attach-redirect-uri --client-id <id> --uri <uri> [--kind authorize|post_logout]
d-oauth-server client detach-redirect-uri --client-id <id> --uri <uri> [--kind authorize|post_logout]
d-oauth-server client redirect-uris --client-id <id>
```

A redirect URI is a global catalog entry; a client attaches to it. `/authorize`
matches only the client's attached and enabled `authorize` set. Detaching or
disabling a URI stops future redirects to it; already issued tokens are
unaffected. Deleting a referenced URI disables it instead.

`kind` selects the URI's role. `authorize` (the default) is an
authorization-response callback. `post_logout` is a bare return target used only
by `GET /logout` to send the browser back to the client after the session ends.
A client may register at most one enabled `post_logout` URI; `GET /logout`
redirects only to it, and only while the URI is enabled and the client active.

### Declarative config

```bash
d-oauth-server config sync --file <path>
d-oauth-server config check
```

`config sync` applies a JSON file idempotently. A second identical run reports
`config sync: no changes`. See the format below.

### Admin bootstrap

```bash
d-oauth-server admin bootstrap --email <email> [--password-file <path>] [--force]
```

Creates the first admin under an advisory lock in one transaction. It refuses
while any enabled admin exists unless `--force` is given (a loud warning and an
audit event). The full replacement procedure is in `RUNBOOK.md`.

### Initial access tokens (DCR)

```bash
d-oauth-server initial-access-token issue --uses <n> --ttl <seconds> [--label <text>]
```

Mints a one-time-use DCR initial-access token. The raw token is printed once;
only its keyed hash and remaining-use budget are stored. The token is required
when `allow_open_registration` is false.

### Key generation and health

```bash
d-oauth-server keygen --alg es256
d-oauth-server healthcheck --url http://127.0.0.1:8081/health/live
```

`keygen` emits an ES256 keypair for test fixtures and client-side DPoP keys. It
is never an authorization-server signing key; the server publishes no
`jwks_uri`. `healthcheck` probes the health listener over raw HTTP and exits 0
or 1; it is the container `HEALTHCHECK`.

## config sync file format

The file is JSON. Every section is optional and defaults to empty.

```json
{
  "scopes": [
    { "name": "orders:read", "description": "Read orders", "enabled": true }
  ],
  "redirect_uris": [
    { "uri": "https://app.example.com/callback", "enabled": true },
    { "uri": "https://app.example.com/signed-out", "kind": "post_logout", "enabled": true }
  ],
  "user_scopes": [
    { "email": "operator@example.com", "scope": "orders:read" }
  ],
  "client_redirect_uris": [
    { "client_id": "example-client", "uri": "https://app.example.com/callback" },
    { "client_id": "example-client", "uri": "https://app.example.com/signed-out", "kind": "post_logout" }
  ]
}
```

Scope names must match the RFC 6749 scope-token grammar. `openid` is reserved.
Redirect URIs must be absolute and are matched exactly at `/authorize` (or, for
`kind: post_logout`, at `GET /logout`). `kind` defaults to `authorize`.

Apply and re-apply:

```bash
d-oauth-server config sync --file ./oauth-config.json
d-oauth-server config sync --file ./oauth-config.json
```

The first reports the counts of what it created; the second reports no changes.
Upserts use `IS DISTINCT FROM`, so an unchanged row does not bump `updated_at`.

## Audit events

CLI mutations go to the `audit` target with `event = "cli.mutation"`, an
`operation`, and a `subject`. The operations are `migrate`, `config.sync`,
`user.create`, `user.enroll_totp`, `user.disable`, `user.grant_scope`,
`user.revoke_scope`, `scope.create`, `scope.enable`, `scope.disable`,
`scope.delete`, `redirect_uri.create`, `redirect_uri.enable`,
`redirect_uri.disable`, `redirect_uri.delete`, `client.attach_redirect_uri`,
`client.detach_redirect_uri`, `initial_access_token.issue`, and the
`admin.bootstrap.*` family.

HTTP events on the same target include `login.success`, `login.failure`,
`consent`, `token.issue`, `token.revoke`, `token.refresh_reuse_detected`, and
`dcr.register`. No event carries a token, password, OTP, or secret.

Tracing is JSON. Route it to your log pipeline and alert on
`token.refresh_reuse_detected` and repeated `login.failure`.

## Key and certificate rotation

### Token pepper

Opaque token hashes are stored under a version id, default `v1`, set by
`token_pepper_id`. The key ring resolves a stored id newest-first across a
retained chain, so verification keeps working while an old pepper is retained.
The current loader supplies one active pepper; to rotate without invalidating
live tokens, retain the previous key id for at least the refresh lifetime
(`ttl.refresh_secs`, default 30 days) before removing it. New tokens are always
minted under the active pepper.

### TOTP encryption key

The encrypted TOTP blob carries its key id, and the ring can resolve a retained
TOTP key by id. Rotate by making the new key active and retaining the old key
until every user has re-enrolled or until existing secrets are re-encrypted.

### TLS certificate

`serve` loads the certificate chain and key once at startup. Rotate by
replacing the mounted material and performing a rolling restart; there is no
hot reload, by design.

## Backup and restore

Postgres holds all durable state, so a normal backup covers it:

```bash
pg_dump --format=custom "$DATABASE_URL" > oauth.dump
pg_restore --clean --if-exists --dbname "$DATABASE_URL" oauth.dump
```

Restore into a migrated database, then run `migrate` to confirm the schema
version matches the binary. Redis is ephemeral and need not be backed up: codes,
tokens, sessions, and replay markers are re-created as clients re-authenticate,
and a Redis loss does not lose clients, users, scopes, or redirect URIs.
Registration access token hashes are in Postgres, so DCR client management also
survives a Redis loss.

## Security properties

- No HTTP admin surface and no default credential.
- Every mutation is audited.
- Bootstrap refuses a second admin without `--force`, which is loud and
  audited.
- A restricted session (forced password change or missing TOTP) cannot reach
  `/authorize`, the OAuth endpoints, or admin-gated actions.
- Secrets stay out of argv, logs, and audit events.

## Edge cases

- Deleting a referenced scope or redirect URI disables it rather than leaving a
  dangling foreign key.
- A second `config sync` is a no-op; a changed field is an update, not a new
  row.
- Rotating the token pepper without retaining the old key invalidates every
  live opaque token. Plan the overlap.
- `admin bootstrap` with a non-TTY stdout and no password source refuses rather
  than print a generated password into job logs.

## Operational runbook

- First install: `migrate`, then `admin bootstrap`, then complete the forced
  password change and TOTP enrollment, then create a named admin. See
  `RUNBOOK.md`.
- Routine provisioning: `config sync` for scopes, redirect URIs, and
  entitlements; `user create` for users.
- Key rotation: overlap the pepper for at least the refresh lifetime.
- Backup: `pg_dump` Postgres; Redis is not backed up.
- Health: liveness `GET /health/live`, readiness `GET /health/ready` on the
  plaintext health listener.

## File and directory references

- `src/cli.rs` for the command tree and flags.
- `src/cli/ops.rs`, `src/cli/user.rs`, `src/cli/scope.rs`,
  `src/cli/redirect.rs`, `src/cli/sync.rs`, `src/cli/admin.rs`,
  `src/cli/secret.rs` for implementations.
- `src/middleware/audit.rs` for the HTTP audit events.
- `RUNBOOK.md` for the bootstrap and replacement procedure.

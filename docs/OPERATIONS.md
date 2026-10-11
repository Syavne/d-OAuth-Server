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
  prints `schema current: N known migration(s)` (`N` is the embedded count,
  not the delta just applied).
- `config check` validates configuration and prints `config ok: issuer=...`.

### Users

```bash
d-oauth-server user create --email <email> [--admin] [--password-stdin] [--password-file <path>]
d-oauth-server user enroll-totp --email <email>
d-oauth-server user disable --email <email>
d-oauth-server user unlock --email <email>
d-oauth-server user grant-scope --email <email> --scope <scope>
d-oauth-server user revoke-scope --email <email> --scope <scope>
d-oauth-server user scopes --email <email>
```

- `create` reads the password from stdin by default or from `--password-file`.
  The two sources are mutually exclusive. `--admin` sets `is_admin`. A created
  user always starts with `must_change_password = true`. A `--password-file`
  must not be world-readable (use mode `0600`); a world-readable file is
  rejected before it is read. Passwords are held in wiped-on-drop memory and
  never appear in logs, errors, or audit events.
- `enroll-totp` generates an encrypted TOTP secret and prints the secret and the
  `otpauth://` URI exactly once. The secret prints only to an interactive
  terminal; a redirected stdout (pipe, file, or job log) refuses unless
  `--show-secret` is passed to acknowledge the disclosure. Register the secret
  in an authenticator now.
- `disable` first purges all of the user's Redis ephemeral state (login
  sessions and their `:meta` sidecars, access/refresh tokens and their grants,
  authorization codes, device records with their `:cnf`/`:poll` sidecars and
  `user_code` mappings, and the lockout counters (account plus per-IP)), then flips the Postgres
  `disabled` flag. If Redis is unavailable the command fails and the user
  stays enabled (fail closed). Disabling alone does not touch PAR records,
  replay markers, or rate-limit counters, which carry no subject.
- `unlock` clears the user's login lockout counters (the per-account counter
  and every per-IP composite bucket) without touching the account. The user
  must exist; a Redis outage fails closed and clears nothing. Unknown-label
  buckets carry no account label and are never touched. The per-IP sweep uses
  `SCAN`, so on Cluster topologies it covers the contacted node only and
  buckets on other nodes may survive; re-run against each node or wait out
  the window.
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
by `POST /logout` to send the browser back to the client after the session ends
(`GET /logout` is read-only and issues no redirect).
A client may register at most one enabled `post_logout` URI; `POST /logout`
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
audit event). The password comes from `--password-file`, from stdin, or — when
neither yields a value — a generated 256-bit password that prints exactly once
and only to a TTY (a non-TTY stdout with a generated password is an error, so
the secret can never leak into job logs). A `--password-file` must not be
world-readable (use mode `0600`). The full replacement procedure is in
`RUNBOOK.md`.

### Initial access tokens (DCR)

```bash
d-oauth-server initial-access-token issue --uses <n> --ttl <seconds> [--label <text>] [--show-secret]
```

Mints a one-time-use DCR initial-access token. The raw token is printed once;
only its keyed hash and remaining-use budget are stored. The token prints only
to an interactive terminal; a redirected stdout refuses unless `--show-secret`
is passed to acknowledge the disclosure. The token is required
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

### PII and TOTP migration commands

```bash
d-oauth-server pii backfill
d-oauth-server pii verify
d-oauth-server pii rotate
d-oauth-server totp rewrap
```

All four take no options and read the key ring from configuration. `pii
backfill`, `pii verify`, and `pii rotate` require a migration-role DSN
(`D_OAUTH_DATABASE__URL`); they scan every row and print counts only, never a
value.

- `pii backfill` seals every remaining plaintext PII value, blanks the plaintext
  columns, and upgrades every TOTP blob to v3. It refuses while
  `pii_dual_write=true`, and must run with the app tier scaled to zero.
- `pii verify` reports the four cutover checks: no plaintext remains, every
  `_enc` opens under a retained key, every TOTP blob is v3, and every stored
  blind index matches. It exits non-zero when any check is dirty.
- `pii rotate` re-encrypts every `_enc` value and recomputes every blind index
  under the active PII key. Run it under a write freeze with the previous key
  retained. It is idempotent: a re-run re-encrypts only stale blobs.
- `totp rewrap` re-wraps every v3 per-row DEK under the active TOTP key without
  touching the data ciphertext. It is idempotent.

### PII encryption rollout and cutover

The expansion is additive. The backfill blanks the plaintext columns but this
release does **not** drop them; dropping the now-inert columns is a later
release. Follow this order exactly:

0. Apply the expansion migration with the PII key configured:
   `d-oauth-server migrate`. The migration drops `NOT NULL` on the plaintext
   columns and builds the new indexes, so run it in a maintenance window. See
   [DATABASE.md](DATABASE.md#expand-and-contract).
1. Set `pii_dual_write=true` (`D_OAUTH_PII_DUAL_WRITE=true`).
2. Roll every replica so all of them dual-write and emit v2 TOTP blobs.
3. Set `pii_dual_write=false` and scale the app tier to zero, so no writer runs
   during the backfill.
4. Run `d-oauth-server pii backfill`.
5. Run `d-oauth-server pii verify`; it must exit 0.
6. Scale the app tier back up. Startup readiness is fail-closed: if
   `pii_dual_write=false` and any blanked plaintext column still holds a value,
   `GET /health/ready` returns `503` and the replica stays out of service.

While the rollout window is open, CLI `d-oauth-server user enroll-totp` and
login-driven TOTP enrollment MUST run with `D_OAUTH_PII_DUAL_WRITE=true`. With
it `false` they write v3 TOTP blobs, which a version N-1 replica cannot read, so
the user's next TOTP check fails on an old replica. Keep dual-write on for the
whole window; turn it off only at the scale-to-zero step above.

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
`client.detach_redirect_uri`, `initial_access_token.issue`,
`pii.backfill`, `pii.rotate`, `totp.rewrap`, and the `admin.bootstrap.*`
family. `pii verify` is read-only and emits no mutation event.

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

### TLS certificate

`serve` loads the certificate chain and key once at startup. Rotate by
replacing the mounted material and performing a rolling restart; there is no
hot reload, by design.

## PII and TOTP key rotation

Both the PII field-encryption key and the TOTP encryption key are versioned in
the ring, and each has an optional retained previous key. Keep the previous key
id configured until every value has been migrated, then retire it. A previous
key without a distinct `*_previous_key_id`, or without its active key, is a
load-time error.

### TOTP encryption key

The TOTP blob carries its key id, and the ring resolves a retained TOTP key by
id. To rotate:

1. Put the old key in `totp_previous_key` / `totp_previous_key_file` with a
   distinct `totp_previous_key_id`, and set the new `totp_encryption_key` /
   `totp_encryption_key_file` as active.
2. Roll the replicas so the ring loads both keys.
3. Run `d-oauth-server totp rewrap`. Every v3 blob is re-wrapped under the new
   key. Version 1 and 2 blobs have no DEK and still decrypt through the legacy
   path, so re-enroll those users with `d-oauth-server user enroll-totp` before
   the old key is dropped.
4. Remove the previous key once no blob names it.

### PII field-encryption key

The blind index is key-dependent, so equality and uniqueness only hold within
one key generation. Rotate under a write freeze:

1. Put the old key in `pii_previous_key` / `pii_previous_key_file` with a
   distinct `pii_previous_key_id`, and set the new `pii_encryption_key` /
   `pii_encryption_key_file` as active.
2. Roll the replicas, then scale the app tier to zero (the write freeze). No
   writer may run while the indexes are recomputed.
3. Run `d-oauth-server pii rotate`. It re-encrypts every `_enc` value and
   recomputes every blind index under the new key in bounded transactions; a
   duplicate across key generations aborts that batch instead of overwriting a
   row. It is idempotent and resumable because the previous key is retained.
4. Run `d-oauth-server pii verify`; it must exit 0.
5. Remove the previous key and scale the app tier back up.

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
- The container is non-root with a read-only rootfs and no shell, and every
  secret is a mounted file, so `kubectl exec` / `docker exec` reads no
  credential from the environment. Exec still bypasses the application's own
  authorization — the binary *is* the admin CLI — so it must be restricted.
- Grant `pods/exec` only to a break-glass role and enable Kubernetes audit
  logging for the `pods/exec` subresource.

## Edge cases

- Deleting a referenced scope or redirect URI disables it rather than leaving a
  dangling foreign key.
- A second `config sync` is a no-op; a changed field is an update, not a new
  row.
- Rotating the token pepper without retaining the old key invalidates every
  live opaque token. Plan the overlap.
- `admin bootstrap` with a non-TTY stdout and no password source refuses rather
  than print a generated password into job logs. `user enroll-totp` and
  `initial-access-token issue` refuse a redirected stdout the same way unless
  `--show-secret` is passed.
- A `--password-file` must use mode `0600` (or any mode without the
  world-readable bit); a world-readable password file is rejected before it is
  read.

## Operational runbook

- First install: `migrate`, then `admin bootstrap`, then complete the forced
  password change and TOTP enrollment, then create a named admin. See
  `RUNBOOK.md`.
- Routine provisioning: `config sync` for scopes, redirect URIs, and
  entitlements; `user create` for users.
- Key rotation: overlap the pepper for at least the refresh lifetime. Rotate the
  TOTP key with `totp rewrap`, and the PII key with a write freeze plus
  `pii rotate` then `pii verify`; see
  [PII and TOTP key rotation](#pii-and-totp-key-rotation).
- Backup: `pg_dump` Postgres; Redis is not backed up.
- Access: prefer running admin commands as a one-shot Job (or the local CLI
  against the database) over `exec` into a running replica. If `exec` is
  needed, restrict `pods/exec` to a break-glass role and audit the subresource.
- Health: liveness `GET /health/live`, readiness `GET /health/ready` on the
  plaintext health listener.
- Durability barrier: a `RotatedUnbarriered` refresh response means the
  originating rotation applied but the barrier failed after the write, so the
  returned pair is the live one; every other barrier failure stays
  fail-closed (`503`).

## File and directory references

- `src/cli.rs` for the command tree and flags.
- `src/cli/ops.rs`, `src/cli/user.rs`, `src/cli/scope.rs`,
  `src/cli/redirect.rs`, `src/cli/sync.rs`, `src/cli/admin.rs`,
  `src/cli/secret.rs` for implementations.
- `src/cli/pii/` for `pii backfill|verify|rotate` and `src/cli/totp.rs` for
  `totp rewrap`.
- `src/crypto/field.rs` for the PII field codec and blind index.
- `src/middleware/audit.rs` for the HTTP audit events.
- `RUNBOOK.md` for the bootstrap and replacement procedure.

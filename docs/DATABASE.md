# Database

PostgreSQL holds durable domain state only. Every ephemeral value lives in
Redis, so no request writes a per-request row to Postgres.

## Purpose

This guide describes the schema, the indexes and constraints, the migration
lifecycle, and the operational rules for applying migrations. It is the
reference for anyone changing a table or a query.

## The six tables

Migrations create exactly six domain tables plus sqlx's `_sqlx_migrations`
bookkeeping table. They create schema only and seed zero rows, so a fresh
install starts empty by design.

### oauth_clients

One row per registered client (RFC 7591 / RFC 7592).

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `uuid` | Primary key. |
| `client_id` | `text` | Unique table constraint, and the FK target for `client_redirect_uris`. |
| `client_secret_hash` | `text` | Argon2id hash, never a raw secret. |
| `client_secret_expires_at` | `timestamptz` | Optional expiry. |
| `client_id_issued_at` | `timestamptz` | Issue time. |
| `client_name` | `text` | Display name. |
| `grant_types` | `text[]` | Registered grant types. |
| `response_types` | `text[]` | Registered response types. |
| `scope` | `text` | Registered scope string. |
| `token_endpoint_auth_method` | `text` | One of the supported methods. |
| `jwks` | `jsonb` | Optional inline JWKS. |
| `jwks_uri` | `text` | Optional JWKS URL (fetched with the SSRF guard). |
| `tls_client_auth_subject_dn` | `text` | RFC 8705 subject DN binding. |
| `tls_client_auth_cert_thumbprint` | `text` | RFC 8705 `x5t#S256` binding. |
| `request_uris` | `jsonb` | Pre-registered JAR request URIs. |
| `contacts` | `jsonb` | Metadata only. |
| `software_id` | `text` | Metadata only. |
| `active` | `bool` | Soft disable, default true. |
| `registration_access_token_hash` | `text` | Keyed hash of the RFC 7592 management token. |
| `dpop_bound_access_tokens` | `bool` | Whether this client's tokens require DPoP proof (`migrations/1791244800_client_dpop_bound.sql`). |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

Two partial unique indexes enforce that a client certificate authenticates at
most one client:

- `ux_oauth_clients_tls_subject_dn` on `tls_client_auth_subject_dn` where it is
  not null.
- `ux_oauth_clients_tls_cert_thumbprint` on `tls_client_auth_cert_thumbprint`
  where it is not null.

The `UNIQUE (client_id)` is a table constraint, not merely an index, because
Postgres accepts only a unique constraint as a foreign-key target.

### users

One row per resource owner.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `uuid` | Primary key. |
| `email` | `citext` | Case-insensitive email-as-username, unique. |
| `password_hash` | `text` | Argon2id PHC string. |
| `totp_secret_enc` | `bytea` | AES-256-GCM encrypted TOTP secret, never plaintext. |
| `totp_enabled` | `bool` | Default false. |
| `totp_recovery_code_hashes` | `jsonb` | Hashes of recovery codes. |
| `is_admin` | `bool` | Default false. Gates privileged actions. |
| `must_change_password` | `bool` | Default false; true for a bootstrapped admin. |
| `password_changed_at` | `timestamptz` | Stamped on password change. |
| `disabled` | `bool` | Default false. |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

There are deliberately no failed-login or lockout columns. Those counters are
security-ephemeral and live in Redis.

### scopes

The runtime-managed scope catalog.

| Column | Type | Notes |
| --- | --- | --- |
| `name` | `text` | Primary key. |
| `description` | `text` | Default empty. |
| `enabled` | `bool` | Default true. |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

The enabled rows are the single source of truth for `scopes_supported` in the
RFC 8414 metadata document, read on each discovery request.

### user_scopes

Per-user scope entitlements. New users start with none.

| Column | Type | Notes |
| --- | --- | --- |
| `user_id` | `uuid` | FK to `users(id)`, cascade delete. |
| `scope_name` | `text` | FK to `scopes(name)`. |
| `granted_at` | `timestamptz` | Grant time. |
| `granted_by` | `uuid` | Optional granting admin. |

Composite primary key `(user_id, scope_name)`.

### redirect_uris

The runtime-managed redirect-URI catalog. `uri` is stored normalized-exact and
is unique per `(uri, kind)`.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `uuid` | Primary key. |
| `uri` | `text` | Unique per `kind`. |
| `kind` | `text` | `authorize` (default) or `post_logout`. |
| `enabled` | `bool` | Default true. |
| `description` | `text` | Default empty. |
| `created_by` | `uuid` | Optional creator. |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

`kind` separates the two browser landings: `authorize` URIs are valid
authorization-response callbacks (they carry `code`/`state`); `post_logout` URIs
are bare navigation targets used only by `GET /logout`. Both kinds are matched
with the same exact-string + RFC 8252 loopback rule.

### client_redirect_uris

The join between a client and a catalog redirect URI.

| Column | Type | Notes |
| --- | --- | --- |
| `client_id` | `text` | FK to `oauth_clients(client_id)`, cascade delete. |
| `redirect_uri_id` | `uuid` | FK to `redirect_uris(id)`, cascade delete. |
| `attached_at` | `timestamptz` | Attachment time. |
| `attached_by` | `uuid` | Optional attacher. |

Composite primary key `(client_id, redirect_uri_id)`.

## The citext extension

The `users` migration runs `CREATE EXTENSION IF NOT EXISTS citext`. This makes
email comparison case-insensitive, so `A@x.com` and `a@x.com` collide and there
is one account per email regardless of case. Installing `citext` requires
superuser or trusted-extension privileges, so the migration role must have
them, or an operator must install the extension out of band before migrating.

## Migration lifecycle

- Migrations are versioned, forward-only sqlx migrations compiled into the
  binary by `sqlx::migrate!("./migrations")`. They are tracked in
  `_sqlx_migrations`.
- They are applied by the `migrate` subcommand, which runs
  `sqlx::Migrator::run` under sqlx's Postgres advisory lock. Concurrent
  migration runs serialize on that lock, so a cluster Job cannot double-apply.
- `serve` never migrates. Startup only reads the schema. Readiness returns 503
  until every embedded migration version is present in `_sqlx_migrations`.
- A checksum mismatch or a dirty migration fails fast rather than guessing.
- Each file is deterministic with no down path. There is no `DROP` and no
  rollback.

In a cluster, run migrations from a dedicated Job, never from every replica.

## Expand and contract

Rolling upgrades keep version N-1 and N replicas serving at once. A migration
must be backward compatible:

1. Expand: add the new column or table in a way the old code ignores.
2. Deploy: roll out the new code that uses it.
3. Contract: remove the old column or table only after no old replica remains.

A migration that drops or renames a column in one step breaks the old replicas
during the rollout. Do not do it.

## Security properties

- Only hashed or encrypted secrets are stored: client secrets in
  `oauth_clients`, passwords in `users`, TOTP secrets encrypted in `users`.
  Raw tokens are never rows here.
- The `registration_access_token_hash` column is the one token hash in
  Postgres, so RFC 7592 client management survives a Redis loss.
- Foreign keys with `ON DELETE CASCADE` keep the join tables consistent, and a
  scope referenced by `user_scopes` is disabled rather than deleted.

## Access hardening

This section records the controls an operator can put around the database. The
server does not create, ship, or enforce any of them; each is a deployment
choice. What the server does do is connect with one role and store secrets
hashed or encrypted, as described in [Security properties](#security-properties).

### Risk baseline: no application audit trail

The schema tables above are domain state. None is an audit log, and the server
writes no per-access row outside them, so a reader of the schema can run a
`SELECT` or a `COPY ... TO` and leave nothing behind in the database. A dump is
silent by construction. Tamper-evidence has to come from PostgreSQL and the
operator's logging, not from an application table.

### Least privilege

`database.url` (`src/config/db.rs`) carries a single DSN, so by default the
server connects with one role for both migrations and runtime. Two separate
roles reduce the blast radius:

| Role | Privileges | Used by |
| --- | --- | --- |
| Migration role | Owns the schema and holds the `citext` privilege. `CREATE EXTENSION IF NOT EXISTS citext` needs superuser or trusted-extension rights, so this role must have them (see [The citext extension](#the-citext-extension)). | `migrate` |
| Runtime role | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the six domain tables, plus read access to `_sqlx_migrations`. No DDL and no superuser. | `serve` |

The migration role runs once per release; the runtime role is the only one the
long-lived replicas hold. The server neither creates nor enforces roles. An
operator grants them and points each subcommand's DSN at the right one.

### Connection and transport

- Production requires `sslmode=verify-full` with a pinned CA
  (`database.root_cert_path`, `/certs/db-ca.crt`); validation fails closed at
  startup if it is missing.
- Prefer a private network or a unix socket and keep the Postgres listener off
  the public internet. The shipped manifest uses the in-cluster Service DNS
  name, not an external endpoint.
- Passwords are file-mounted rather than embedded in the DSN
  (`deploy/k8s/secret.yaml`).

### Audit and tamper-evidence

- `pgaudit` with, for example, `pgaudit.log = 'write,ddl,role'` records the
  statements that matter here: data changes, schema changes, and role changes.
- `log_connections` and `log_disconnections`, plus `log_statement = 'ddl'`,
  capture who connected and when.
- Ship Postgres logs to a separate append-only or central store, so a dump
  cannot also erase its own record.
- Alert on `pg_dump`, `COPY ... TO`, and any role or permission change.
- WAL archiving (`archive_mode`) gives a durable, append-only record of every
  change and lets a restore reach a point in time.

The server contributes no audit rows of its own, so coverage depends entirely on
the Postgres configuration and the operator's log pipeline.

### Encrypted backups

- `pg_dump`, `pg_basebackup`, and pgBackRest output must be encrypted at rest.
- Custody the backup key separately from the database, and never co-locate it
  with the master keys ([SECURITY.md](SECURITY.md#master-key-custody)).
- Store backups off-site and test restores.
- A backup is a full copy of the plaintext PII columns exactly as a live dump
  is, so it carries the same disclosure risk and needs the same handling.

### Postgres-level encryption

Three layers, complementary rather than substitutes:

| Layer | Scope | Protects against | State here |
| --- | --- | --- | --- |
| Disk/volume encryption | Cloud EBS/PD or filesystem | Stolen or mislaid media | Operator choice, not shipped |
| TDE (`pg_tde`) | Whole database files | Stolen data files at rest | Where the engine supports it, not shipped |
| `pgcrypto` | Selected columns | A dump of those columns | An alternative, not the current implementation |

The application already does its own crypto before a row is written: passwords
and client secrets are Argon2id PHC, and TOTP secrets are AES-256-GCM under
HKDF-SHA256 (`src/crypto/totp.rs`). `pgcrypto` is an alternative for the
plaintext PII columns, but it moves key custody into the SQL path and is not
used today.

### See also

- [DEPLOYMENT.md](DEPLOYMENT.md#database-access-and-backups) for the connection,
  TLS, and backup runbook.
- [SECURITY.md](SECURITY.md#master-key-custody) for key custody.

## Edge cases

- Deleting a scope or redirect URI that is still referenced does not cascade
  away the reference. The CLI disables the catalog row instead, and
  `scope delete` falls back to disable when `user_scopes` references it.
- A client with a `tls_client_auth_subject_dn` or a thumbprint that another
  client already uses is rejected by the partial unique index.
- `citext` must exist before the `users` migration runs.

## Operational runbook

Apply migrations once, before rolling out replicas:

```bash
D_OAUTH_DATABASE__URL='postgres://oauth@db.example.com/oauth?sslmode=verify-full' \
  cargo run --bin d-oauth-server -- migrate
```

The command prints `schema current: N known migration(s)`. Run it as a cluster Job and let
readiness gate the Deployment. To confirm a fresh install, check that the six
tables exist and are empty:

```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public' ORDER BY table_name;
SELECT version, success FROM _sqlx_migrations ORDER BY version;
```

## File and directory references

- `migrations/1791072000_oauth_clients.sql` for `oauth_clients`.
- `migrations/1791158400_users.sql` for the other five tables and `citext`.
- `migrations/1791244800_client_dpop_bound.sql` for `oauth_clients.dpop_bound_access_tokens`.
- `migrations/1791331200_redirect_uri_kind.sql` for `redirect_uris.kind`.
- `src/db/` for the repositories.
- `src/state.rs` for `MIGRATOR`.
- `src/cli/ops.rs` for the `migrate` command.
- `src/state/health.rs` for the readiness schema check.

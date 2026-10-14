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
| `client_name` | `text` | Display name. Nullable after the PII expansion migration; the backfill blanks it to NULL. |
| `client_name_enc` | `bytea` | Sealed display name (versioned AES-256-GCM). |
| `grant_types` | `text[]` | Registered grant types. |
| `response_types` | `text[]` | Registered response types. |
| `scope` | `text` | Registered scope string. |
| `token_endpoint_auth_method` | `text` | One of the supported methods. |
| `jwks` | `jsonb` | Optional inline JWKS. Public by design; never sealed. |
| `jwks_uri` | `text` | Optional JWKS URL (fetched with the SSRF guard). |
| `jwks_uri_enc` | `bytea` | Sealed JWKS URL. |
| `tls_client_auth_subject_dn` | `text` | RFC 8705 subject DN binding. Nullable in the base table. |
| `tls_client_auth_subject_dn_enc` | `bytea` | Sealed subject DN. |
| `tls_client_auth_subject_dn_index` | `text` | Keyed blind index over the subject DN. |
| `tls_client_auth_cert_thumbprint` | `text` | RFC 8705 `x5t#S256` binding. Nullable in the base table. |
| `tls_client_auth_cert_thumbprint_enc` | `bytea` | Sealed certificate thumbprint. |
| `tls_client_auth_cert_thumbprint_index` | `text` | Keyed blind index over the thumbprint. |
| `request_uris` | `jsonb` | Pre-registered JAR request URIs. |
| `request_uris_enc` | `bytea` | Sealed request URIs (JSON ciphertext). |
| `contacts` | `jsonb` | Metadata only. |
| `contacts_enc` | `bytea` | Sealed contacts (JSON ciphertext). |
| `software_id` | `text` | Metadata only. |
| `software_id_enc` | `bytea` | Sealed software id. |
| `active` | `bool` | Soft disable, default true. |
| `registration_access_token_hash` | `text` | Keyed hash of the RFC 7592 management token. |
| `dpop_bound_access_tokens` | `bool` | Whether this client's tokens require DPoP proof (`migrations/1791244800_client_dpop_bound.sql`). |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

Four partial unique indexes enforce client-identity uniqueness. Two are on the
legacy plaintext columns, kept inert once the backfill blanks them; two are on
the new blind-index columns:

- `ux_oauth_clients_tls_subject_dn` on `tls_client_auth_subject_dn` where it is
  not null.
- `ux_oauth_clients_tls_cert_thumbprint` on `tls_client_auth_cert_thumbprint`
  where it is not null.
- `ux_oauth_clients_tls_subject_dn_index` on `tls_client_auth_subject_dn_index`
  where it is not null.
- `ux_oauth_clients_tls_cert_thumbprint_index` on
  `tls_client_auth_cert_thumbprint_index` where it is not null.

The `UNIQUE (client_id)` is a table constraint, not merely an index, because
Postgres accepts only a unique constraint as a foreign-key target.

### users

One row per resource owner.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `uuid` | Primary key. |
| `email` | `citext` | Case-insensitive email-as-username, unique. Nullable after the PII expansion migration; the backfill blanks it to NULL. |
| `email_enc` | `bytea` | Sealed email (versioned AES-256-GCM). |
| `email_index` | `text` | Keyed blind index over the normalized email. |
| `password_hash` | `text` | Argon2id PHC string. |
| `totp_secret_enc` | `bytea` | AES-256-GCM encrypted TOTP secret, never plaintext. |
| `totp_enabled` | `bool` | Default false. |
| `totp_recovery_code_hashes` | `jsonb` | Hashes of recovery codes. |
| `is_admin` | `bool` | Default false. Gates privileged actions. |
| `must_change_password` | `bool` | Default false; true for a bootstrapped admin. |
| `password_changed_at` | `timestamptz` | Stamped on password change. |
| `disabled` | `bool` | Default false. Introspection and refresh re-check this flag on every use via the subject account-status lookup: a disabled subject is inactive / `invalid_grant`, while an empty or unknown subject stays live; a datastore failure propagates and never reports active. |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

`ux_users_email_index` is a partial unique index on `email_index` where it is
not null; the legacy `ux_users_email UNIQUE (email)` constraint is kept and goes
inert once every `email` is NULL.

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
| `uri` | `text` | Unique per `kind`. Nullable after the PII expansion migration; the backfill blanks it to NULL. |
| `uri_enc` | `bytea` | Sealed URI (versioned AES-256-GCM). |
| `uri_index` | `text` | Keyed blind index over the URI, per `kind`. |
| `kind` | `text` | `authorize` (default) or `post_logout`. |
| `enabled` | `bool` | Default true. |
| `description` | `text` | Default empty. |
| `created_by` | `uuid` | Optional creator. |
| `created_at`, `updated_at` | `timestamptz` | Audit timestamps. |

`ux_redirect_uris_uri_index_kind` is a partial unique index on
`(uri_index, kind)` where `uri_index` is not null; the legacy
`ux_redirect_uris_uri_kind UNIQUE (uri, kind)` constraint is kept and goes inert
once every `uri` is NULL. `ck_redirect_uris_kind` is a
`CHECK (kind IN ('authorize', 'post_logout'))` constraint that keeps the column
to those two values.

`kind` separates the two browser landings: `authorize` URIs are valid
authorization-response callbacks (they carry `code`/`state`); `post_logout` URIs
are bare navigation targets used only by `POST /logout` (`GET /logout` is
read-only and issues no redirect). Both kinds are matched
with the same exact-string + RFC 8252 loopback rule, plus the draft-16 §2.3.1
private-use dot rule (`com.example.app:/` is accepted, `myapp:/` is rejected).

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

## PII encryption at rest

The plaintext identifier columns stay in the schema. The PII migration only adds
the `_enc`/`_index` columns and drops `NOT NULL`; it blanks nothing. The
plaintext is nulled later by the `pii backfill` cutover (`pii_dual_write=false`,
app tier scaled to zero), and only then are the columns inert: NULL for every
row, kept only so version N-1 replicas can still read them during the rollout.
While `pii_dual_write=true`, writers still store the plaintext alongside the
sealed value. The live values move into two parallel columns per field:

- **`_enc` (`bytea`)** holds a versioned AES-256-GCM blob with the framing
  `version(1)=1 || kid_len(1) || kid || nonce(12) || ciphertext+tag`: the format
  version byte, a one-byte key-id length, the key id (`kid`) of the PII key that
  wrote it, a random 96-bit nonce, then the ciphertext and tag. The key is
  derived from the master PII key with HKDF-SHA256 (info `pii-field-gcm-v1`), so
  the ciphertext is not key-stable: rotating the master key re-encrypts every
  blob.
- **`_index` (`text`)** holds a keyed-HMAC blind index in the form
  `{kid}:{hex}`. Encrypted bytes cannot be compared or made unique directly, so
  the columns that are looked up or must stay unique (`email_index`, the two
  mTLS indexes, `uri_index`) carry this deterministic tag under a separate HMAC
  key (HKDF info `pii-blind-index-v1`). A read computes candidates across every
  retained key id, newest first, so lookups work while an old key is retained.

The TOTP secret uses a different envelope. `users.totp_secret_enc` blob version
3 holds a random per-row data-encryption key (DEK), wrapped by a key-encryption
key derived from the TOTP master key (HKDF info `totp-kek-v1`). The data AAD
excludes the `kid`, so `totp rewrap` can re-wrap a DEK under a new TOTP key
without re-encrypting the secret. Versions 1 and 2 still decrypt.

The blind index is key-dependent, so uniqueness only holds within one key
generation. Rotating the PII key requires a write freeze (app tier scaled to
zero) while `pii rotate` re-encrypts and recomputes every index; see
[OPERATIONS.md](OPERATIONS.md#pii-and-totp-key-rotation).

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
- Each file is deterministic with no down path. There is no rollback and no
  `DROP TABLE` or `DROP COLUMN`; the release only adds columns, apart from
  dropping the legacy `ux_redirect_uris_uri` constraint and the `NOT NULL`s on
  the plaintext columns the backfill blanks.

In a cluster, run migrations from a dedicated Job, never from every replica.

## Expand and contract

Rolling upgrades keep version N-1 and N replicas serving at once. A migration
must be backward compatible:

1. Expand: add the new column or table in a way the old code ignores.
2. Deploy: roll out the new code that uses it.
3. Contract: remove the old column or table only after no old replica remains.

A migration that drops or renames a column in one step breaks the old replicas
during the rollout. Do not do it.

The PII encryption rollout follows this lifecycle exactly:

1. **Expand.** Apply `migrations/1791417600_pii_encryption.sql` with the PII key
   configured. It adds the `_enc`/`_index` columns and their partial unique
   indexes and drops `NOT NULL` on the plaintext columns the backfill blanks.
2. **Dual-write.** Set `pii_dual_write=true` and roll every replica. New writes
   seal the value and also write the legacy plaintext, so old replicas keep
   working.
3. **Scale-to-zero backfill.** Set `pii_dual_write=false` and scale the app tier
   to zero, so no write can interleave with the one-shot backfill.
4. **Backfill.** Run `pii backfill` to seal every remaining plaintext value,
   blank the plaintext columns, and upgrade TOTP blobs to v3.
5. **Cutover.** Run `pii verify`, then scale the app tier back up. The startup
   guard fails closed (readiness `503`) if `pii_dual_write=false` and any
   blanked plaintext PII column still holds a value.
6. **Contract (later release).** Dropping the now-inert plaintext columns and
   legacy constraints is a deliberate follow-up release, not part of this
   change. This release renames no column and drops no table or column, though
   it does drop the legacy `ux_redirect_uris_uri` constraint and the `NOT NULL`s
   on the plaintext columns the backfill blanks.

**Maintenance window.** `ALTER TABLE ... DROP NOT NULL` takes `ACCESS EXCLUSIVE`
on `users`, `redirect_uris`, and `oauth_clients`, blocking reads and writes for
its duration; each non-concurrent `CREATE INDEX` takes `SHARE`, blocking writes.
sqlx runs every migration inside one transaction, so a non-transactional
`CREATE INDEX CONCURRENTLY` is not used (PostgreSQL rejects it in a
transaction). Apply the expansion migration from the dedicated migration Job
during a maintenance window with the app tier quiesced.

## Security properties

- Only hashed or encrypted secrets are stored: client secrets in
  `oauth_clients`, passwords in `users`, TOTP secrets encrypted in `users`, and
  the PII identifiers sealed in the `_enc` columns with their blind indexes in
  `_index`. Raw tokens are never rows here.
- The `registration_access_token_hash` column is the one token hash in
  Postgres, so RFC 7592 client management survives a Redis loss.
- Foreign keys with `ON DELETE CASCADE` keep the join tables consistent, and a
  scope referenced by `user_scopes` is disabled rather than deleted.
- `user disable` purges the subject's Redis state before the
  `UPDATE users SET disabled` runs; a Redis failure aborts before the flag
  flips.

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
- A backup is a point-in-time copy of the `_enc` ciphertext and the blind
  indexes, plus the inert NULL plaintext columns. It still needs the same
  handling as a live dump: after the PII key is rotated, an old backup is
  readable only with the retained old PII key, so custody of the key store
  still governs backup disclosure.

### Postgres-level encryption

Three layers, complementary rather than substitutes:

| Layer | Scope | Protects against | State here |
| --- | --- | --- | --- |
| Disk/volume encryption | Cloud EBS/PD or filesystem | Stolen or mislaid media | Operator choice, not shipped |
| TDE (`pg_tde`) | Whole database files | Stolen data files at rest | Where the engine supports it, not shipped |
| `pgcrypto` | Selected columns | A dump of those columns | An alternative, not the current implementation |

The application already does its own crypto before a row is written: passwords
and client secrets are Argon2id PHC, TOTP secrets are AES-256-GCM under
HKDF-SHA256 (`src/crypto/totp.rs`), and the PII identifiers are sealed with the
field codec in `src/crypto/field.rs`. `pgcrypto` would move key custody into the
SQL path and is not used today.

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
- `migrations/1791417600_pii_encryption.sql` for the `_enc`/`_index` PII
  columns, their partial unique indexes, and the dropped `NOT NULL`s.
- `src/db/` for the repositories.
- `src/crypto/field.rs` for the field codec and blind index.
- `src/cli/pii/` for `pii backfill|verify|rotate`.
- `src/state.rs` for `MIGRATOR`.
- `src/cli/ops.rs` for the `migrate` command.
- `src/state/health.rs` for the readiness schema check.

-- PII envelope encryption, expansion step (plan todo 8).
--
-- Forward-only: deterministic, additive expansion only. This migration adds the
-- encrypted (`_enc`) and keyed blind-index (`_index`) columns the PII backfill
-- fills, and drops NOT NULL on the plaintext columns that backfill blanks to
-- NULL. Nothing is dropped or renamed: the old plaintext columns, the `citext`
-- extension, and the legacy unique constraints all remain, so version N-1
-- replicas keep working through the rolling upgrade (docs/DATABASE.md,
-- "Expand and contract").
--
-- Maintenance window: `ALTER TABLE ... DROP NOT NULL` takes ACCESS EXCLUSIVE on
-- users / redirect_uris / oauth_clients, blocking both reads and writes for the
-- duration; each non-concurrent `CREATE INDEX` takes SHARE, blocking writes.
-- sqlx runs every migration inside ONE transaction, so a non-transactional
-- `CREATE INDEX CONCURRENTLY` is NOT used (PostgreSQL rejects it in a
-- transaction). Apply this migration from the dedicated migration Job during a
-- maintenance window with the app tier quiesced; see RUNBOOK.md.
--
-- The legacy `ux_users_email UNIQUE (email)` and
-- `ux_redirect_uris_uri_kind UNIQUE (uri, kind)` constraints are deliberately
-- NOT dropped. PostgreSQL treats NULLs as distinct, so once the backfill blanks
-- the plaintext each constraint goes inert (any number of NULL rows allowed)
-- while still serving old replicas.

-- (a) Plaintext columns the backfill blanks become nullable.
ALTER TABLE users         ALTER COLUMN email       DROP NOT NULL;
ALTER TABLE redirect_uris ALTER COLUMN uri         DROP NOT NULL;
ALTER TABLE oauth_clients ALTER COLUMN client_name DROP NOT NULL;

-- (b) users: encrypted email ciphertext + keyed blind index.
ALTER TABLE users
  ADD COLUMN email_enc   bytea NULL,
  ADD COLUMN email_index text  NULL;

CREATE UNIQUE INDEX ux_users_email_index
  ON users (email_index)
  WHERE email_index IS NOT NULL;

-- (c) oauth_clients: encrypted PII metadata and blind-indexed mTLS identities.
ALTER TABLE oauth_clients
  ADD COLUMN client_name_enc                     bytea NULL,
  ADD COLUMN contacts_enc                        bytea NULL,
  ADD COLUMN request_uris_enc                    bytea NULL,
  ADD COLUMN jwks_uri_enc                        bytea NULL,
  ADD COLUMN software_id_enc                     bytea NULL,
  ADD COLUMN tls_client_auth_subject_dn_enc      bytea NULL,
  ADD COLUMN tls_client_auth_cert_thumbprint_enc bytea NULL,
  ADD COLUMN tls_client_auth_subject_dn_index    text  NULL,
  ADD COLUMN tls_client_auth_cert_thumbprint_index text NULL;

-- Mirrors ux_oauth_clients_tls_subject_dn / ux_oauth_clients_tls_cert_thumbprint
-- on the blind-index columns; the legacy plaintext indexes stay in place.
CREATE UNIQUE INDEX ux_oauth_clients_tls_subject_dn_index
  ON oauth_clients (tls_client_auth_subject_dn_index)
  WHERE tls_client_auth_subject_dn_index IS NOT NULL;

CREATE UNIQUE INDEX ux_oauth_clients_tls_cert_thumbprint_index
  ON oauth_clients (tls_client_auth_cert_thumbprint_index)
  WHERE tls_client_auth_cert_thumbprint_index IS NOT NULL;

-- (d) redirect_uris: encrypted URI ciphertext + keyed blind index per kind.
ALTER TABLE redirect_uris
  ADD COLUMN uri_enc   bytea NULL,
  ADD COLUMN uri_index text  NULL;

CREATE UNIQUE INDEX ux_redirect_uris_uri_index_kind
  ON redirect_uris (uri_index, kind)
  WHERE uri_index IS NOT NULL;

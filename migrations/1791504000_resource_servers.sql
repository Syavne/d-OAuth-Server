-- RFC 8707 resource indicators and the per-client JWT access-token selector.
--
-- Forward-only: deterministic, no DROP / down path. This migration creates
-- schema ONLY (the `resource_servers` catalog is created EMPTY and populated at
-- runtime) and adds one additive column to `oauth_clients`.
--
-- There is deliberately NO grants/audience column here: grant, access-token,
-- and refresh-token audience is security-ephemeral and lives in Redis, never in
-- a Postgres row.

-- Runtime-managed resource-server (resource indicator) catalog. `identifier`
-- is the RFC 8707 resource identifier (`resource` parameter / `aud` target) and
-- is globally unique, mirroring the `scopes` / `redirect_uris` catalogs.
CREATE TABLE resource_servers (
  id          uuid        NOT NULL,
  identifier  text        NOT NULL,
  description text        NOT NULL DEFAULT '',
  enabled     bool        NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL,
  CONSTRAINT resource_servers_pkey PRIMARY KEY (id),
  CONSTRAINT ux_resource_servers_identifier UNIQUE (identifier)
);

-- Per-client access-token format. `opaque` is the OAuth 2.1 baseline and the
-- default, so every existing client backfills to it (the CHECK applied after
-- the ADD COLUMN validates the defaulted rows); `jwt` is honored only while JWT
-- access tokens are enabled by configuration. Additive, so old replicas ignore
-- the column during the expand/contract rollout.
ALTER TABLE oauth_clients
  ADD COLUMN access_token_format text NOT NULL DEFAULT 'opaque';

ALTER TABLE oauth_clients
  ADD CONSTRAINT ck_oauth_clients_access_token_format
  CHECK (access_token_format IN ('opaque', 'jwt'));

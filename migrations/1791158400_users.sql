-- Users, scope catalog, per-user entitlements, redirect-URI catalog, and
-- per-client URI attachments (plan Scope line 31 / line 33).
--
-- Forward-only: deterministic, no DROP / down path. This migration creates
-- schema ONLY and seeds ZERO rows: the scope catalog, users, and redirect URIs
-- are all created at runtime via CLI / `config sync` / `admin bootstrap` /
-- DCR. Two deliberate omissions:
--   * no failed-login/lockout columns: those counters are security-ephemeral
--     and live in Redis (todo 11), never Postgres;
--   * the TOTP secret is stored ENCRYPTED as `bytea` (todo: TOTP encryption
--     key from the KeyRing), never as a plaintext column.
--
-- `users.id` PK and `oauth_clients.client_id` (task 8) are the FK targets for
-- the join tables below, so this migration's version is later than 1791072000.

-- Case-insensitive email-as-username requires the `citext` type. The extension
-- is created here (idempotently) because this is the first migration that needs
-- it; PostgreSQL requires superuser/trusted-extension privileges to install it.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id                        uuid        NOT NULL,
  email                     citext      NOT NULL,
  password_hash             text        NOT NULL,
  totp_secret_enc           bytea       NULL,
  totp_enabled              bool        NOT NULL DEFAULT false,
  totp_recovery_code_hashes jsonb       NULL,
  is_admin                  bool        NOT NULL DEFAULT false,
  must_change_password      bool        NOT NULL DEFAULT false,
  password_changed_at       timestamptz NULL,
  disabled                  bool        NOT NULL DEFAULT false,
  created_at                timestamptz NOT NULL,
  updated_at                timestamptz NOT NULL,
  CONSTRAINT users_pkey PRIMARY KEY (id),
  -- citext comparison makes this case-insensitive: `A@x.com` and `a@x.com`
  -- collide, so one account per email regardless of case.
  CONSTRAINT ux_users_email UNIQUE (email)
);

-- Runtime-managed scope catalog, created EMPTY (todo 9 has no seed rows).
-- The enabled rows are the single source of truth for `scopes_supported`.
CREATE TABLE scopes (
  name        text        NOT NULL,
  description text        NOT NULL DEFAULT '',
  enabled     bool        NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  CONSTRAINT scopes_pkey PRIMARY KEY (name)
);

-- Per-user entitlements. New users start with none (explicit grants only).
CREATE TABLE user_scopes (
  user_id    uuid        NOT NULL,
  scope_name text        NOT NULL,
  granted_at timestamptz NOT NULL,
  granted_by uuid        NULL,
  CONSTRAINT user_scopes_pkey PRIMARY KEY (user_id, scope_name),
  CONSTRAINT fk_user_scopes_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_user_scopes_scope FOREIGN KEY (scope_name)
    REFERENCES scopes(name)
);

-- Runtime-managed redirect-URI catalog. `uri` is stored normalized-exact and
-- is globally unique; clients attach to entries via `client_redirect_uris`.
-- Redirect URIs attach to clients, never to users.
CREATE TABLE redirect_uris (
  id          uuid        NOT NULL,
  uri         text        NOT NULL,
  enabled     bool        NOT NULL DEFAULT true,
  description text        NOT NULL DEFAULT '',
  created_by  uuid        NULL,
  created_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  CONSTRAINT redirect_uris_pkey PRIMARY KEY (id),
  CONSTRAINT ux_redirect_uris_uri UNIQUE (uri)
);

-- Join between a client and a catalog redirect URI. Composite PK makes an
-- attachment unique; the client FK needs a unique CONSTRAINT (task 8 provides
-- `ux_oauth_clients_client_id`, not merely a unique index).
CREATE TABLE client_redirect_uris (
  client_id       text        NOT NULL,
  redirect_uri_id uuid        NOT NULL,
  attached_at     timestamptz NOT NULL,
  attached_by     uuid        NULL,
  CONSTRAINT client_redirect_uris_pkey PRIMARY KEY (client_id, redirect_uri_id),
  CONSTRAINT fk_client_redirect_uris_client FOREIGN KEY (client_id)
    REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  CONSTRAINT fk_client_redirect_uris_uri FOREIGN KEY (redirect_uri_id)
    REFERENCES redirect_uris(id) ON DELETE CASCADE
);

-- RFC 7591 dynamic client registration / RFC 7592 client management.
--
-- Forward-only: deterministic, no DROP / down path. Redirect URIs are
-- deliberately NOT stored on this row; they live in the `redirect_uris`
-- catalog plus the `client_redirect_uris` join (todo 9).
--
-- The `UNIQUE (client_id)` table constraint (not merely a unique index) is
-- required because `client_redirect_uris.client_id` references this column,
-- and PostgreSQL only accepts a unique *constraint* as a foreign-key target.

CREATE TABLE oauth_clients (
  id                              uuid        NOT NULL,
  client_id                       text        NOT NULL,
  client_secret_hash              text        NULL,
  client_secret_expires_at        timestamptz NULL,
  client_id_issued_at             timestamptz NOT NULL,
  client_name                     text        NOT NULL,
  grant_types                     text[]      NOT NULL,
  response_types                  text[]      NOT NULL,
  scope                           text        NOT NULL,
  token_endpoint_auth_method      text        NOT NULL,
  jwks                            jsonb       NULL,
  jwks_uri                        text        NULL,
  tls_client_auth_subject_dn      text        NULL,
  tls_client_auth_cert_thumbprint text        NULL,
  request_uris                    jsonb       NULL,
  contacts                        jsonb       NULL,
  software_id                     text        NULL,
  active                          bool        NOT NULL DEFAULT true,
  registration_access_token_hash  text        NULL,
  created_at                      timestamptz NOT NULL,
  updated_at                      timestamptz NOT NULL,
  CONSTRAINT oauth_clients_pkey PRIMARY KEY (id),
  CONSTRAINT ux_oauth_clients_client_id UNIQUE (client_id)
);

-- A client certificate (subject DN or SHA-256 thumbprint) authenticates at
-- most one client; NULL means "not enrolled" and is unconstrained, so a
-- partial unique index is required (todo 21 relies on the ambiguity being
-- rejected at write time).
CREATE UNIQUE INDEX ux_oauth_clients_tls_subject_dn
  ON oauth_clients (tls_client_auth_subject_dn)
  WHERE tls_client_auth_subject_dn IS NOT NULL;

CREATE UNIQUE INDEX ux_oauth_clients_tls_cert_thumbprint
  ON oauth_clients (tls_client_auth_cert_thumbprint)
  WHERE tls_client_auth_cert_thumbprint IS NOT NULL;

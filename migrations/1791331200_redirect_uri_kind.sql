-- Distinguish authorization-response redirect URIs from post-logout return
-- URIs in the shared catalog. Both kinds use the same exact-match + RFC 8252
-- loopback validation, so they live in one table rather than a parallel one.
--
-- Existing rows predate post-logout support and are all authorization-response
-- URIs, so they backfill to 'authorize' via the column default.
ALTER TABLE redirect_uris
  ADD COLUMN kind text NOT NULL DEFAULT 'authorize';

ALTER TABLE redirect_uris
  DROP CONSTRAINT ux_redirect_uris_uri,
  ADD CONSTRAINT ux_redirect_uris_uri_kind UNIQUE (uri, kind),
  ADD CONSTRAINT ck_redirect_uris_kind CHECK (kind IN ('authorize', 'post_logout'));

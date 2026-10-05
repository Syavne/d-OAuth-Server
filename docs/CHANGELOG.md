# Changelog

All notable changes to the d-OAuth authorization server are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version stays below `1.0.0`, a minor bump may carry a breaking change.

## [Unreleased]

### Added

- `GET /logout` (a server-specific session endpoint, not an OAuth 2.1 or OIDC
  feature) ends the browser session so a different user can sign in. It destroys
  the session and expires the cookie, then renders a neutral page or redirects to
  the flow's registered `post_logout` URI. It accepts no query parameters: the
  redirect target is frozen in session meta when the authorization flow is bound
  and used only while the owning client is active and still registers that exact
  URI (exact-string match, with the RFC 8252 loopback exception). There is no
  `post_logout_redirect_uri` parameter, no `id_token_hint`, and no
  `end_session_endpoint` in metadata.
- The `redirect_uris` catalog gains a `kind` column (`authorize` | `post_logout`);
  existing rows backfill to `authorize`. `redirect-uri create|enable|disable|delete`
  and `client attach|detach-redirect-uri` accept `--kind`, and `config sync` file
  entries accept a `kind` field. A client may register at most one enabled
  `post_logout` URI.

### Fixed

- `GET /.well-known/oauth-authorization-server` reads the enabled scope catalog
  from Postgres on every request. A scope added, enabled, or disabled via the
  CLI now appears in `scopes_supported` immediately on every replica, instead of
  only after a restart; the previous in-process cache was never invalidated by
  the out-of-process CLI mutation.
- Responses on the OAuth surface are now `Cache-Control: no-store`
  (+ `Pragma: no-cache`) except `/.well-known/…` metadata, so authorization and
  consent pages, token bodies, request handles, and errors are never cached by
  a browser, the back/forward cache, or an intermediary. Token-endpoint error
  responses now carry `no-store`, closing a documented gap against
  draft-ietf-oauth-v2-1-16 §3.2.3.
- `GET /login?request_id=…` rebinds an already-authenticated session to the
  fresh authorization request instead of redirecting on the session's stale
  pending binding.

## [0.1.0] - 2026-10-03

The first release. This is an OAuth 2.1-only authorization server, not a
backwards-compatible OAuth 2.0 server. The deltas are deliberate: see
[OAUTH.md](OAUTH.md) for the exact differences.

### Added

- Authorization-code grant with mandatory PKCE `S256`; `plain` and missing
  challenges are rejected. Implicit and resource-owner-password grants do not
  exist.
- Refresh-token grant with rotation, tombstones, and reuse detection. Rotation
  is idempotent under a deterministic `rotation_request_id`, so a retried
  request returns the same tokens instead of double-rotating.
- `client_credentials`, device-code (RFC 8628, with the user-facing `/device`
  page), and policy-gated token-exchange (RFC 8693) grants.
- Opaque access and refresh tokens: 256 bits of CSPRNG output, base64url
  encoded, stored only as a keyed HMAC-SHA256 hash under a versioned pepper.
  No raw token ever reaches Postgres, Redis, a log, or an error body.
- Dynamic client registration (RFC 7591) and management (RFC 7592), protected
  by a one-time initial-access token; open registration is off by default.
  Registration access tokens are hashed in Postgres so client management
  survives a Redis loss.
- Sender-constrained tokens: DPoP (RFC 9449) and mTLS (RFC 8705), plus PAR
  (RFC 9126) and JAR (RFC 9101). `private_key_jwt` is client authentication
  only and is never treated as a sender constraint.
- Introspection (RFC 7662) and revocation (RFC 7009), including grant-chain
  cascade revocation.
- RFC 8414 authorization-server metadata with `scopes_supported` served from
  the enabled `scopes` table. The document carries no `jwks_uri`: the server
  signs no artifact of its own.
- Resource-owner login with Argon2id, TOTP (RFC 6238, plus recovery codes and
  a used-code replay cache), server-side Redis sessions, and server-rendered
  login/consent pages with CSP and CSRF protection.
- Runtime-managed scope catalog and redirect-URI catalog. Scope reduction is
  enforced as `requested ∩ client-registered ∩ user-entitled ∩ enabled`.
- Operator CLI for every administrative action: `migrate`, `serve`, `user`,
  `scope`, `redirect-uri`, `client`, `config sync`, `config check`,
  `admin bootstrap`, `initial-access-token issue`, `keygen`, and `healthcheck`.
  There is no HTTP admin API and no default credential.
- Admin bootstrap that creates exactly one admin under an advisory lock in a
  single transaction, with a forced password change and TOTP enrollment before
  the account gains authority.
- Fail-closed dependency handling: a Postgres or Redis outage returns
  `503 temporarily_unavailable` with `Retry-After` on security paths, never a
  fail-open success and never a `500` or panic.
- A minimal multi-arch container image (static musl, non-root UID 65532, no
  shell) and a `healthcheck` subcommand that probes the plaintext health
  listener without a shell or curl.
- Redis topologies from day one: single node, Sentinel (with hand-built master
  re-resolution), and Cluster (with native slot refresh). Multi-key atomic
  operations stay on one hash slot through the `{state}` hash tag.

### Security

- `#![forbid(unsafe_code)]` across the crate; `unwrap`, `expect`, and `panic`
  are denied by lint in request paths.
- Opaque hash-at-rest token storage with a versioned key ring for the token
  pepper and the TOTP encryption key.
- Rate limiting per IP and per client, with counters in a keyspace separated
  from token state so counters can never evict tokens.
- Security headers: CSP with `frame-ancestors 'none'`, `X-Content-Type-Options`,
  `Referrer-Policy`, and HSTS on the TLS listener.
- No wildcard CORS. Browser public clients require an explicit origin
  allowlist.

[Unreleased]: https://example.invalid/d-oauth/compare/v0.1.0...HEAD
[0.1.0]: https://example.invalid/d-oauth/releases/tag/v0.1.0

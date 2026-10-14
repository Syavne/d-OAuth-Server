# Changelog

All notable changes to the d-OAuth-Server authorization server are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version stays below `1.0.0`, a minor bump may carry a breaking change.

## [Unreleased]

### Added

- Container release publishing on GHCR. A `v*` git tag builds and pushes the
  signed multi-arch image under semver tags (`X.Y.Z`, `X.Y`, `X`, `latest`; a
  pre-release gets only `X.Y.Z`) and creates a GitHub Release. The image path is
  `ghcr.io/syavne/d-oauth-server`.
- Application-level envelope encryption for the PII directory: emails, client
  names, contacts, redirect URIs, JAR request URIs, JWKS URLs, software ids, and
  mTLS subject DNs/thumbprints are sealed with versioned AES-256-GCM under a new
  mandatory `pii_encryption_key`, and the looked-up or unique values carry a
  keyed-HMAC blind index. TOTP secrets move to a per-row envelope (blob version
  3) so a DEK can be re-wrapped without re-encrypting the secret. New
  `pii backfill`, `pii verify`, and `pii rotate` commands run the one-shot
  migration and PII key rotation, and `totp rewrap` re-wraps the TOTP DEKs. The
  expansion adds `_enc`/`_index` columns; the backfill blanks the plaintext
  columns but this release does **not** drop them (the contract drop is a later
  release).
- Documentation for the encryption model, the new keys, the
  expand/dual-write/scale-to-zero-backfill/cutover rollout, and the PII/TOTP
  rotation runbooks across `docs/DATABASE.md`, `docs/SECURITY.md`,
  `docs/CONFIGURATION.md`, and `docs/OPERATIONS.md`.
- `GET /logout` and `POST /logout` (a server-specific session endpoint, not
  an OAuth 2.1 or OIDC feature) end the browser session so a different user
  can sign in. `GET /logout` is read-only: it renders a confirm page (live
  session) or a neutral signed-out page (anonymous) and never destroys the
  session or writes cookies. Only `POST /logout`, carrying the session-bound
  CSRF `form_token`, destroys the session and expires the cookie, then renders
  a neutral page or redirects to
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
- The server-rendered pages (login, consent, device, TOTP) now share an embedded
  same-origin stylesheet served at `GET /assets/app.css` (`src/ui/app.css`). It
  adds no JavaScript and needs no CSP change: the page policy's existing
  `style-src 'self'` covers it, so `script-src 'none'` still holds.
- TOTP enrollment now renders the `otpauth://` URI as a server-side inline SVG
  QR code beside the text secret and URI, so users can scan instead of
  hand-typing. The new `qrcode` dependency is pinned SVG-only (no `image`
  codecs); the text secret, URI, and one-time recovery codes are unchanged.
- A full-database-disclosure response procedure: `docs/SECURITY.md` gains the
  dump blast-radius table and the ordered rotation (token pepper, TOTP key,
  PII field-encryption key, client secrets, DCR registration tokens), and `RUNBOOK.md` gains the
  matching operator checklist with concrete commands.
- Cluster hardening in `deploy/k8s`: the token pepper and TOTP key mount as
  `0400` tmpfs files under `/run/secrets` (read through
  `D_OAUTH_TOKEN_PEPPER_FILE` / `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`, mirrored
  in `compose.yaml`), the image reference defaults to the mutable `:latest`
  tag (a digest pin is available but not the default; see
  `docs/DEPLOYMENT.md`), a NetworkPolicy
  default-denies pod egress except DNS plus Postgres/Redis scoped to their
  namespace (no internet-wide `0.0.0.0/0` peer; `scripts/check_manifests.py`
  rejects one), and `automountServiceAccountToken` is `false`. Remote JAR
  `request_uri` is documented as unsupported under the default-deny, with the
  Cilium FQDN opt-in path in `docs/DEPLOYMENT.md`.
- `user disable` now purges all subject-scoped Redis state for the subject (sessions and their
  meta, codes, devices with their sidecars and mappings, grants via cascade
  revoke, standalone tokens, and the lockout counter) before flipping
  `users.disabled`; records without a subject (PAR, pending, DPoP and
  `private_key_jwt` replay markers, rotation map, TOTP replay, rate-limit
  counters) are untouched. A Redis failure aborts before the flag changes, so the
  command fails closed.
- `POST /revoke` authenticates mTLS-registered clients (RFC 8705 §2) with the
  verified peer chain injected by the TLS accept loop, exactly as the token and
  introspection endpoints do; a missing or unregistered chain fails closed as
  `invalid_client`. Client certificates are expected to be short-lived, so
  expiry bounds exposure without a revocation list.
- The token-pepper key ring can retain a previous pepper, matching TOTP and
  PII: `token_pepper_previous_key` / `token_pepper_previous_key_file` with an
  explicit `token_pepper_previous_key_id` lets a rotated pepper keep verifying
  hashes issued under the old one, so rotation no longer invalidates live
  opaque tokens.

### Changed

- The key ring now holds three independent chains (token pepper, TOTP
  encryption key, and PII field-encryption key), each with an optional retained
  previous key. `pii_dual_write` (default `false`, encrypt-only) turns on
  dual-write for the rolling-upgrade window; readiness fails closed while the
  switch is off and any blanked plaintext PII column still holds a value.
- TOTP secrets now use a per-row envelope (blob version 3): a random DEK
  wrapped by AES-256-GCM under HKDF-SHA256 (info `totp-kek-v1`), so
  `totp rewrap` re-wraps the DEK without re-encrypting the secret. Versions 1
  (bare `SHA256(totp_key)`) and 2 (HKDF info `totp-gcm-v2`) keep decrypting
  through a legacy fallback, so no re-enrollment is needed.

- `GET /.well-known/oauth-authorization-server` now carries an explicit
  `Cache-Control: public, max-age=3600` instead of relying on browser
  heuristic freshness, so metadata caching is intentional and tunable. The
  plaintext health listener (which does not mount the public router's
  security-header layer) now sets `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff` on its own probe responses, with a
  regression test pinning both.
- Forwarded client-cert and IP headers are never trusted; the dead
  proxy-header fallback is removed.
- The login lockout now also covers TOTP enrollment confirmation, and the rate
  limiter classifies requests by their full path.
- Key ids are `String`-backed and preserved verbatim end to end: a `vN` id
  mixes the 4-byte big-endian generation into the token HMAC message
  (byte-identical to the pre-change scheme) and any other id mixes its UTF-8
  bytes, stored as `<kid>.<digest>`, so non-`vN` labels hash distinctly and
  every `trim/parse::<u32>` collapse site is gone. Back-compat is scoped to
  `vN` ids: hashes issued under an old `vN` id keep verifying through the
  retained-key chain (newest-first, capped at 8 generations), so rotation
  needs no re-issuance.

### Security

- A PII or TOTP ciphertext that fails to open (tamper, truncation, or a missing
  key id) is fail-closed: the request returns `503 temporarily_unavailable` and
  emits a `pii.decrypt_failure` audit event carrying only the request id, never
  a value. Full-blob substitution by an attacker with database write access
  remains out of the threat model and is documented in `docs/SECURITY.md`.
- Introspection and refresh re-check `users.disabled`, and refresh re-checks
  the subject's current entitlements; a disabled subject introspects inactive
  and refresh rejects with `invalid_grant` before any token is minted.
- Master keys (the token pepper, TOTP key, PII key, and any retained previous
  key) shorter than 32 bytes are rejected at load with `WeakKeyMaterial`.
- `private_key_jwt` assertion lifetime is capped and its `jti` replay marker
  now tracks the remaining validity; `PS256` is added to the assertion
  algorithm allowlist.
- DCR `open` redirect policy now accepts only `https` or RFC 8252 loopback
  URIs, and the SSRF guard pins the fetch to the addresses it pre-validated.
- Secret-holding token types keep a locked `Debug`: the pepper,
  `TokenService`, and minted pairs print ids/lengths plus a `[REDACTED]`
  marker, never raw pepper bytes or token strings, and the located-token
  wrappers stay transitive through identifier-only records. Positive
  `[REDACTED]` assertions pin the markers.
- Regression tests pin the hardening headers (`no-store`, `nosniff`) on
  every short-circuit path: limiter 429/503, CORS preflights, body-limit
  413, and resilience 503.
- The TOTP replay fingerprint is an HMAC under the token pepper instead of
  unkeyed SHA-256, so a Redis dump no longer exposes the 6-digit code space.
- JAR request objects are verified against an explicit asymmetric allowlist
  (`RS256`/`PS256`/`ES256`/`EdDSA`, kept in sync with the `private_key_jwt`
  assertion allowlist); anything else is rejected before key selection.
- Token lookup validates the 43-char base64url shape before HMAC and Redis
  work, so junk tokens are rejected fast. This is a cost guard only:
  well-formed lookups still retry retained peppers newest-first.
- `POST /logout` verifies the session-bound CSRF `form_token` and rejects a
  missing or forged token with `invalid_request` leaving the session intact,
  so a cross-site POST cannot sign the user out; `GET /logout` is read-only
  (confirm page, no `Set-Cookie`) and the clearing cookie mirrors every
  attribute of the session cookie.

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
- Permanent Redis infrastructure failures (`OOM`, `READONLY`, `CROSSSLOT`,
  auth, and connection-type errors) fail closed as `503
  temporarily_unavailable` instead of `500`, while programming-error classes
  stay masked as `server_error` so 500-alerts still fire on real bugs.
- Dead audit-misleading code is removed: the `client_assertion` JOSE stub
  (the real logic lives in `protocol::client_auth::assertion`) and the
  caller-less `store::grants::add_token` helper.
- Auditor-facing comments corrected: the `jose` module TODO no longer lists
  the deleted stub, the token shape-gate comment no longer claims to mask
  generation probing, and the two algorithm allowlists carry keep-in-sync
  pointers.
- Device `decide` runs a single conditional-`HSET` Lua script instead of
  `EXISTS`-then-`HSET`, so a concurrent consume cannot leave a zombie record;
  the device poll marker is a Lua compare-and-set admitting exactly one poller
  (the rest get `slow_down`).
- PAR/code consume binds the ownership check into the consume Lua
  (`consume_bound` over `client_id`, plus `redirect_uri`/PKCE challenge for
  codes): a foreign-client or wrong-verifier presentation leaves the single-use
  record intact instead of burning the victim's value.
- The token endpoint accepts a missing or empty `redirect_uri` on
  `grant_type=authorization_code` and skips the binding check
  (draft-ietf-oauth-v2-1-16 §4.1.3, §10.2); a supplied value must still match
  exactly or redemption fails `invalid_grant`.
- A private-use redirect-URI scheme must contain reverse-DNS dot notation
  (draft-ietf-oauth-v2-1-16 §2.3.1): `com.example.app:/` is accepted and
  `myapp:/` is rejected with `invalid_redirect_uri` on DCR and `invalid input`
  on the CLI; `https` and the RFC 8252 loopback exception are unchanged.
- Refresh rotation splits the scope (draft-ietf-oauth-v2-1-16 §4.3.1 +
  §4.3.3): the replacement refresh token retains the presented scope re-checked
  against the current `enabled` catalog, client registration, and user
  entitlements (revoked entries drop silently), while an explicit narrower
  `scope` narrows only the access token and the response `scope`.
- Grant cascade `revoke` drains in a bounded loop until the member set reads
  empty, and the rotation script carries a grant-record fence (`NOGRANT`
  before any write), so a token minted mid-cascade is deleted by a later pass
  or refused outright.
- A durability-barrier failure after the originating write returns the minted
  pair (`RotatedUnbarriered` on rotation) or deletes the won DPoP marker so the
  originating `jti` can re-claim, instead of locking the client out; other
  callers stay fail-closed (a `Replay` hit discards its orphan pre-mint and
  rejects with `invalid_grant`).

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

# Security

This guide states the threat model, the token and key design, the sender
constraint model, the fail-closed policy, and the admin replacement procedure.
The implementation is the authority; the citations point at it.

## Purpose

For a security reviewer and an operator: what the server protects, how, and what
to do when something goes wrong. The standards behind the design are RFC 9700
(BCP 240) and `draft-ietf-oauth-v2-1-16` (published 3 September 2026; an
Internet-Draft, not an RFC, at
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1).

## Threat model

### Assets

- Opaque access and refresh tokens, and the authorization codes and device codes
  that yield them.
- Client secrets, user passwords, TOTP secrets, and DCR initial-access tokens.
- The token pepper and TOTP encryption keys.
- The integrity of the authorization decision: which client may act for which
  user with which scopes.

### Adversaries

- A network attacker who can read and modify traffic. TLS and sender
  constraints address this.
- A malicious or compromised client that tries to escalate scope, replay a
  code, or replay a token.
- A stolen token used from another key or certificate.
- An operator or job that could leak a secret through logs, argv, or an error
  body.
- A forged reverse-proxy header claiming a client certificate.

### Trust boundaries

- The TLS public listener is the only route to OAuth handlers.
- The plaintext health listener carries no OAuth routes.
- Postgres holds durable domain state; Redis holds ephemeral state.
- Forwarded client-cert and client-IP headers are trusted only from the
  configured `trusted_proxy`; otherwise they are stripped before any handler
  reads them.

## Attack surface

This section records the container and host attack surface: how an attacker could
reach the container or the host through the image, the controls already in place,
and the residual risk. It is durable threat-model material, not a backlog; update
it whenever the deployment surface changes (a new listener, mount, dependency
class, or runtime setting).

| Vector | Existing controls | Residual risk |
| --- | --- | --- |
| Application-level RCE in a parser (form bodies, DPoP/JAR/`private_key_jwt` JWTs, DCR JSON, `jwks_uri`/`request_uri` fetches) | `#![forbid(unsafe_code)]`, no `unwrap`/`panic` in request paths, rustls/ring (no OpenSSL), fuzz targets for token-form/DCR-JSON/JAR-claims | Fuzzing is not exhaustive. |
| Dependency / supply-chain compromise | Committed `Cargo.lock`, `cargo deny`/`cargo audit` in CI, SBOM + provenance + keyless cosign, digest-pinned bases | A zero-day in a trusted crate. |
| Container escape via kernel or runtime bug | Non-root UID 65532, read-only root filesystem, all capabilities dropped, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault` | A kernel LPE or runc bug, mitigated but not eliminated. |
| Secret exfiltration from the process environment | Secrets are injected at runtime, not baked into image layers; the pepper/TOTP key live outside the database | An attacker with code execution reads env vars directly (see `docs/TODO.md` item 7). |
| Exposed management surface | The plaintext health listener (8081) is unauthenticated but not published in the Service (only 8080 is) | A misconfigured Service/Ingress could expose it; it must never be internet-facing. |
| Host access via mounted volumes | `/certs` is mounted read-only at mode `0400`; no Docker socket is mounted | Operator misconfiguration. |
| Image/registry compromise | Digest pinning and cosign verification in CI | The base manifest still uses a mutable `:latest` tag that CI rewrites to a digest before rollout (see `docs/TODO.md` item 8). |

Last reviewed: 2026-10-04. The mitigations to close the residual risks are
tracked in `docs/TODO.md`.

## Toplevel rules

- `#![forbid(unsafe_code)]` across the crate.
- `unwrap`, `expect`, and `panic` are denied by lint in request paths.
- A raw token, secret, password, OTP, or client secret never appears in
  Postgres, Redis, logs, an error body, or an evidence file.
- Secret comparisons are constant time.

## Browser and intermediary caching

- Every response except `/.well-known/…` metadata carries
  `Cache-Control: no-store` (+ `Pragma: no-cache` for legacy clients). An
  authorization page, consent page, token body, request handle, or error is
  therefore never reused by a browser, the back/forward cache, or a shared
  intermediary.
- This covers the `GET /login` and `GET /consent` pages (which carry a
  session-bound CSRF token and the bound `request_id`), the `/authorize`
  redirects and error responses, the token endpoint (success and error), PAR,
  device authorization, DCR, introspection, and revocation.
- OAuth metadata discovery is intentionally left cacheable; a metadata handler
  that fails closed returns a `503` error, which is itself `no-store`.

## Opaque tokens, hashed at rest

- A token is at least 256 bits from a CSPRNG, base64url encoded.
- Only a keyed HMAC-SHA256 hash is persisted, under a versioned pepper key id.
- The newest pepper mints; verification retries across retained key ids,
  newest-first and bounded.
- A raw token is never a storage key or a stored value.
- A storage dump therefore yields no usable token.

## Rotation, tombstones, and replay

- Refresh rotation is a Lua compare-and-set, keyed by a deterministic
  `rotation_request_id` derived from the old refresh token hash and the pepper.
- The old record becomes a tombstone with `used` and `rotated_to`, kept for the
  refresh lifetime.
- Reuse of a rotated token is detected, revokes the whole grant family, and
  emits `token.refresh_reuse_detected`.
- A lost post-write reply is resolved by re-reading the rotation mapping, so a
  retry returns the same tokens and never double-rotates.
- The write is followed by a topology-appropriate durability barrier before any
  token is returned. A barrier below the required level fails closed.

See [REDIS.md](REDIS.md) for the barrier modes.

## Sender constraints

Reference: RFC 9449 (DPoP), RFC 8705 (mTLS).

Every sender-constrained grant requires a freshly verified proof on every use.

| Client class | Required binding |
| --- | --- |
| Public | DPoP only. A missing proof fails with `invalid_grant`. |
| Confidential | mTLS and/or DPoP. The confirmation records each proven component. |

- `cnf` propagates to every newly minted token.
- A stored `cnf` alone never mints: the proof is re-verified per use.
- For token exchange, the proof must match the subject token's confirmation,
  not merely the caller's.
- `private_key_jwt` is client authentication only. It produces no confirmation
  and never satisfies sender constraint. This is deliberate.
- mTLS identity is a client certificate subject DN (`tls_client_auth`) or a
  certificate thumbprint (`self_signed_tls_client_auth`), each unique per the
  partial indexes in the schema.
- A DPoP proof is rejected if it is malformed, oversized, uses an unsupported
  algorithm, has the wrong `typ`, or has a bad or replayed `jti`, `htm`, `htu`,
  `iat`, or `ath`.

## PAR and JAR

Reference: RFC 9126, RFC 9101.

- A confidential client at `/authorize` must use a PAR `request_uri` or a signed
  `request` object. This is mandatory, not optional.
- A JAR request object must be signed; `none` and symmetric algorithms are
  rejected. `iss` must equal `client_id`, `aud` must be the issuer, and conflicts
  with the query string are rejected.
- A `request_uri` is one-time and client-bound, or exactly pre-registered, and
  is fetched only through the SSRF guard (https only, no redirects, global IPs
  only, size and time capped).
- PAR credentials are read from the header and body only, never the query.

## Key ring and rotation

- One versioned `KeyRing` holds the token-pepper chain and the TOTP-encryption
  chain, newest first.
- Opaque token hashes carry the pepper key id; the TOTP blob carries its key id.
- Rotating the pepper requires retaining the old key for at least the refresh
  lifetime so live tokens still verify.
- `Debug` prints key ids only, never key material.
- There is no authorization-server JWT-signing key and no `jwks_uri`. The
  `keygen` command emits keys for test fixtures and client-side DPoP only.

## Fail-closed policy

The seven security endpoints (`authorize`, `token`, `introspect`, `revoke`,
`par`, `device_authorization`, `register`) are always fail-closed. An attempt to
configure one as fail-open is a load-time error.

- A Postgres or Redis outage returns `503 temporarily_unavailable` with
  `Retry-After: 1`, never a fail-open success.
- Only idempotent operations are retried, under a bounded budget. A
  non-idempotent token operation is never blindly replayed.
- Readiness reports `503` while a dependency is down; liveness stays `200`
  because it touches no dependency.
- A cold scope cache with Postgres down returns `503` rather than an empty list.

## Replay and single-use

- An authorization code is consumed atomically, exactly once.
- A PAR `request_uri` is consumed atomically.
- A device code is consumed atomically on approval.
- DPoP and `private_key_jwt` `jti` values are recorded with `SET NX`, so a
  replayed proof or assertion is rejected.
- A TOTP code is recorded in a replay cache for its time-step window.

## Input and output safety

- Redirect URI matching is exact, with the RFC 8252 loopback exception only.
  There are no wildcards and no prefix matches.
- PKCE is `S256` only. A verifier cannot be omitted to downgrade.
- Scope is intersected: `requested ∩ client-registered ∩ user-entitled ∩
  enabled`, and refresh can only narrow.
- The login, consent, and device pages set a strict CSP with
  `frame-ancestors 'none'`. They use server-side sessions, CSRF protection, and
  no open redirect.
- `GET /logout` is a server-specific session endpoint (not OAuth 2.1/OIDC
  defined). It destroys the session and clears the cookie, then renders a
  neutral page or redirects to a `post_logout` URI. It accepts **no query
  parameters**: the target is read only from session meta, frozen when the
  authorization flow was bound, and used only if the owning client is still
  active and still registers that exact URI (exact-string match + RFC 8252
  loopback). A forced navigation to `/logout` can therefore only end a session
  and, at most, send the browser to that client's own pre-registered URI — never
  to an attacker target. There is no `post_logout_redirect_uri` parameter and no
  `id_token_hint`.
- Failed-login and lockout counters live in Redis, not Postgres, so a login
  flood does not write rows.
- Rate limiting is per IP and per client. Counters live in a Redis keyspace
  separated from token state.
- CORS is empty by default and never a wildcard.
- DCR is protected by a one-time initial-access token; open registration is off
  by default.
- Secrets are read from stdin, a file, or the environment, never argv, and are
  printed only for an explicit one-time value.

## Admin bootstrap and replace immediately

No default admin credential ships. `migrate` seeds zero users and `serve` never
creates one. The first admin is created by `admin bootstrap`, which runs inside a
single transaction under an advisory lock, so two concurrent bootstraps cannot
both create an admin. Once any enabled admin exists, a second bootstrap refuses
unless `--force` is given, which prints a loud warning and emits
`admin.bootstrap.force`.

The bootstrap admin starts with `must_change_password = true` and
`totp_enabled = false`. Its first login yields a restricted session that can only
change the password and enroll TOTP; `/authorize`, the OAuth endpoints, and
admin-gated actions deny it until both complete.

Replace it immediately:

- [ ] Log in as the bootstrap admin and change the password (minimum 12
      characters). This clears `must_change_password` and stamps
      `password_changed_at`.
- [ ] Enroll TOTP and confirm with an authenticator code; the session is
      re-issued with full authority only now.
- [ ] Capture the recovery codes shown once and store them offline.
- [ ] Create a named second admin:
      `d-oauth-server user create --admin --email <name>@example.com`.
- [ ] Verify the named admin has full access.
- [ ] Disable the bootstrap account:
      `d-oauth-server user disable --email <bootstrap>@example.com`.
- [ ] Rotate or expire the bootstrap secret: delete the mounted password file
      and revoke any generated one-time password.

The step-by-step command runbook lives in `RUNBOOK.md`. The split is deliberate:
`RUNBOOK.md` is the task-47 operator procedure, and this section is the task-48
security rationale and checklist.

## Detecting an incident

- `token.refresh_reuse_detected` means a rotated refresh token was replayed.
  Treat the grant family as compromised.
- Repeated `login.failure` for one subject means a credential-stuffing attempt.
- `admin.bootstrap.force` means an admin was created despite an existing one.
- A spike in `503` on security endpoints means a dependency is down; the server
  is failing closed, not open.

## Operational runbook

1. Rotate the suspect credential: disable the user, revoke the client, or
   rotate the client secret.
2. Revoke the affected tokens. Reuse detection already cascades the family.
3. If the token pepper may be compromised, rotate it and accept that tokens
   minted under the old pepper stop verifying once it is removed.
4. If a TLS key is compromised, replace the mounted material and roll the
   replicas (there is no hot reload).
5. Preserve logs. The `X-Request-Id` header correlates a request to its logs;
   audit events never contain a secret.

## Edge cases

- A Redis flush loses ephemeral tokens but not clients, users, scopes, or
  redirect URIs. DCR client management survives because its token hash is in
  Postgres.
- An L7 ingress that terminates TLS strips the client certificate; in-process
  mTLS then fails. Use L4 passthrough or trusted-proxy mode.
- A trusted proxy that is misconfigured to a broad address trusts forged
  headers. Keep `trusted_proxy` as narrow as possible.
- A public client that loses its DPoP key cannot use its tokens; there is no
  bearer fallback for a sender-constrained grant.

## File and directory references

- `src/crypto/` for token minting, hashing, TOTP, and constant-time compare.
- `src/keys.rs` for the key ring.
- `src/protocol/token/types.rs` for the sender-constraint matrix.
- `src/jose/dpop.rs`, `src/jose/jar.rs`,
  `src/protocol/client_auth/assertion.rs` for proof verification.
- `src/protocol/mtls.rs` for mTLS matching.
- `src/store/mod.rs`, `src/store/tokens.rs` for rotation and tombstones.
- `src/config/policy.rs` for the fail-closed policy.
- `src/middleware/` for redaction, rate limiting, and security headers.
- `src/cli/admin.rs` for bootstrap.
- `RUNBOOK.md` for the operator bootstrap procedure.

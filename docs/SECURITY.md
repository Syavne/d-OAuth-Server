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
| Secret exfiltration from the process environment | Secrets are injected at runtime, not baked into image layers; the pepper/TOTP key live outside the database; the Deployment mounts every secret — pepper, TOTP key, and the database/Redis passwords — as `0400` tmpfs files under `/run/secrets` (read through their `*_FILE` variables), and the passwordless DSNs come from the ConfigMap, so no secret enters the environment | An attacker with code execution can still read the mounted secret files under `/run/secrets`; that is the same capability the server has. |
| Exposed management surface | The plaintext health listener (8081) is unauthenticated but not published in the Service (only 8080 is) | A misconfigured Service/Ingress could expose it; it must never be internet-facing. |
| Host access via mounted volumes | `/certs` is mounted read-only at mode `0400`; no Docker socket is mounted | Operator misconfiguration. |
| Unrestricted pod egress (SSRF to metadata, exfiltration) | `networkpolicy.yaml` default-denies egress except DNS (53 to `kube-system`) and Postgres/Redis (5432/6379), with link-local `169.254.0.0/16` excluded; ingress is limited to pod ports 8080/8081 | Enforcement depends on a NetworkPolicy-capable CNI; a cluster that ignores NetworkPolicy gets no benefit. The default-deny also blocks the JAR `request_uri` HTTPS fetch — a deployment that needs it must allow the specific host on 443 (see `docs/DEPLOYMENT.md`). |
| Operator `exec` into a running pod | No shell and a non-root, read-only-rootfs container limit what runs; every secret is a file the container user already reads, and no secret is in the environment | `pods/exec` (and `docker exec`) bypass the application's own authorization; restrict it with RBAC and audit it (`docs/OPERATIONS.md`). |
| Kubernetes API access from the pod | `automountServiceAccountToken: false`; the binary never calls the API | A future feature that needs the API would have to re-enable it deliberately. |
| Image/registry compromise | Digest pinning, cosign verification, and a committed digest reference with no shippable `:latest`; CI writes the signed build digest into `kustomization.yaml` | A registry compromise before the digest is recorded still ships; the pin step must run. |

Last reviewed: 2026-10-04. File-mounted DB/Redis passwords, digest pinning,
NetworkPolicy, `automountServiceAccountToken: false`, and scheduled fuzzing are
implemented in the shipped manifests and workflows; the remaining mitigations
are tracked in `docs/TODO.md`.

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
- The plaintext health listener does not mount the security-header layer, so
  the health router inserts `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff` on each probe response itself. A regression
  test pins both headers so a route added to that listener cannot silently drop
  the policy.
- OAuth metadata discovery is cacheable by design and carries an explicit
  positive `Cache-Control: public, max-age=3600` (not browser heuristic
  freshness). A metadata handler that fails closed returns a `503` error, which
  is itself `no-store`.

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

## Master key custody

- The token pepper and the TOTP-encryption key are the server's master keys.
  They live in the versioned `KeyRing` (`src/keys.rs`), loaded once at startup
  from configuration. Nothing re-reads or fetches them later.
- **Hard requirement.** A master key must never be stored in Postgres, captured
  in the same backup or restore as Postgres, baked into an image layer, placed
  in a ConfigMap, or injected into the process environment by the shipped
  manifests. A database dump plus its backup must not yield either key.
- Losing the token pepper invalidates every live opaque access and refresh
  token, because only keyed HMAC hashes are persisted and the pepper is the
  HMAC key.
- The real config surface is small: inline `token_pepper` /
  `totp_encryption_key`, or the mounted-file forms `token_pepper_file` /
  `totp_encryption_key_file`. When both are set the inline value wins
  (`resolve_secret` in `src/config/build.rs`). The key ids default to `v1`
  through `token_pepper_id` / `totp_key_id` (`src/config/raw.rs`).
- The shipped cluster manifests never use the inline or environment forms: the
  Secret file-mounts the keys `0400` on a tmpfs volume at `/run/secrets`, and
  the loader reads them through `D_OAUTH_TOKEN_PEPPER_FILE` /
  `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE` (`deploy/k8s/secret.yaml`,
  `deploy/k8s/configmap.yaml`). The ConfigMap carries only non-secret settings.
- **The server does not talk to a KMS or an HSM.** It has no cloud SDK and no
  key-fetch code path. Sourcing a key from a KMS/HSM or a secret manager is the
  deployment's responsibility; this section is a documented contract, not an
  implemented feature.

Custody, in order of preference:

- **Preferred.** The key is held in a KMS/HSM or a secret manager that never
  co-locates the key with the database backup: cloud KMS, Vault Transit, or a
  PKCS#11 HSM.
- **Acceptable.** A secret manager writes a `0400` tmpfs file that the server
  reads through its `*_FILE` key. This is what the shipped manifests expect.
- **Forbidden.** The key is in the database, in a database backup, in an image
  layer, in the ConfigMap, or in the process environment of the shipped
  manifests.

Custody and rotation interact. Retain the old pepper key id for at least the
refresh lifetime, or live tokens stop verifying; retain the old TOTP key id
only long enough to re-enroll users, then drop it. The full order is above; a
rotation that removes an id early is a deliberate invalidation of what that key
protects.

The operator procedure for custody and KMS/HSM sourcing lives in
[DEPLOYMENT.md](DEPLOYMENT.md#master-key-custody-and-kmshsm).

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

### Full-database-disclosure blast radius

A full dump is worse than one leaked token: it exposes the whole directory and
every hash or ciphertext at once. The token pepper and the TOTP encryption key
are supplied outside the database (environment variable or mounted file), so a
pure dump does not carry them; treat them as compromised anyway unless the key
store can be shown untouched.

| Dumped class | Protection at rest | What the dump yields |
| --- | --- | --- |
| User passwords | Argon2id PHC, salted | Offline cracking only. |
| Client secrets | Argon2id PHC | Offline cracking only. |
| TOTP secrets | AES-256-GCM under HKDF-SHA256 (info `totp-gcm-v2`; pre-migration v1 blobs under bare `SHA256(totp_key)` still decrypt) | Readable only if the TOTP key also leaks. |
| TOTP recovery codes | Argon2id PHC | Offline cracking only. |
| DCR registration access tokens | Keyed HMAC (`registration_access_token_hash`) | Opaque while the pepper stays outside the dump. |
| Emails, client names, contacts, redirect URIs, scopes, entitlements | Plaintext | Full disclosure. |
| Client public keys (`jwks`) | Plaintext | Public by design. |
| `tls_client_auth_subject_dn` and certificate thumbprints | Plaintext | Identifier disclosure. |
| `is_admin`, `disabled`, `must_change_password`, timestamps | Plaintext | Metadata disclosure. |

If the key store leaked too, the dump is a full compromise: TOTP secrets
decrypt, the Argon2id hashes are the only barrier left on passwords and client
secrets, and registration-access-token hashes can be recomputed. Respond in the
order below.

### Full-database-disclosure rotation order

Rotate in this order. Each step retires a class of credential the dump already
exposed; do not skip ahead because a later step looks cheaper.

1. **Token pepper first.** Make a new pepper active and remove the old key id.
   Removing the old id kills every live opaque access and refresh token, so
   every grant is forced back through authentication. This is the only step
   that retires tokens the dump cannot reconstruct. Retain the old id only to
   keep live tokens verifying, which is the opposite of what a breach response
   wants; a full disclosure drops it.
2. **TOTP encryption key second.** Make a new key active. Existing TOTP blobs
   stay readable only while the old key is retained; once it is removed every
   user must re-enroll. Re-enroll with `user enroll-totp` before the old key is
   dropped, or the user cannot complete TOTP.
3. **Client secrets third.** Rotate every confidential client secret through
   RFC 7592 `PUT /register/{client_id}`, which mints a fresh secret when the
   method is secret-based and returns it once.
4. **DCR registration tokens last.** The same `PUT /register/{client_id}` call
   rotates the registration access token on every update, and the response
   carries the only copy. Do not re-issue DCR tokens by replaying an
   initial-access token; it is single-use and consumed at registration.

The seven security endpoints stay fail-closed throughout. A Postgres or Redis
outage while responding returns `503 temporarily_unavailable` with
`Retry-After: 1`, never a fail-open success; do not relax the policy to keep
service up mid-rotation. The operator checklist with concrete commands is in
[RUNBOOK.md](../RUNBOOK.md).

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
- `RUNBOOK.md` for the operator runbook (admin bootstrap, full-database-disclosure response).

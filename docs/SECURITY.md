# Security

This guide states the threat model, the token and key design, the sender
constraint model, the fail-closed policy, and the admin replacement procedure.
The implementation is the authority; the citations point at it. To report a
vulnerability, see the separate [reporting policy](../SECURITY.md), not this
guide.

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
- The token pepper, the TOTP encryption key, and the PII field-encryption key.
- The directory itself: emails, client names, contacts, redirect URIs, JAR
  request URIs, JWKS URLs, software ids, and mTLS identities.
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

### Trust boundaries

- The TLS public listener is the only route to OAuth handlers.
- The plaintext health listener carries no OAuth routes.
- Postgres holds durable domain state; Redis holds ephemeral state.
- Forwarded client-cert headers are never trusted: the listener uses only
  the certificate chain it verified itself. Forwarded client-IP headers are
  never trusted either, except for the single narrow purpose of rate-limit
  bucket selection, and then only when the TCP peer is a configured
  `rate_limit.trusted_proxies` entry (rightmost-untrusted `X-Forwarded-For`
  over bare-IP entries only, rightmost 32 entries capped, unparseable entries
  skipped, fail-closed onto the peer).

## Attack surface

This section records the container and host attack surface: how an attacker could
reach the container or the host through the image, the controls already in place,
and the residual risk. It is durable threat-model material, not a backlog; update
it whenever the deployment surface changes (a new listener, mount, dependency
class, or runtime setting).

| Vector | Existing controls | Residual risk |
| --- | --- | --- |
| Application-level RCE in a parser (form bodies, DPoP/JAR/`private_key_jwt` JWTs, DCR JSON, CIMD documents, `jwks_uri`/`request_uri` fetches) | `#![forbid(unsafe_code)]`, no `unwrap`/`panic` in request paths, rustls/ring (no OpenSSL), fuzz targets for token-form/DCR-JSON/JAR-claims plus DPoP-JWK/assertion-verify/redirect-URI/scope-parse, with continuous ClusterFuzzLite coverage (`.clusterfuzzlite/`, `cflite_*.yml`) | Fuzzing is not exhaustive. |
| Dependency / supply-chain compromise | Committed `Cargo.lock`, `cargo deny`/`cargo audit` in CI, SBOM + provenance + keyless cosign, digest-pinned bases | A zero-day in a trusted crate. |
| Container escape via kernel or runtime bug | Non-root UID 65532, read-only root filesystem, all capabilities dropped, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault` | A kernel LPE or runc bug, mitigated but not eliminated. |
| Secret exfiltration from the process environment | Secrets are injected at runtime, not baked into image layers; the pepper/TOTP/PII keys live outside the database; the Deployment mounts every secret — pepper, TOTP key, PII key, and the database/Redis passwords — as `0400` tmpfs files under `/run/secrets` (read through their `*_FILE` variables), and the passwordless DSNs come from the ConfigMap, so no secret enters the environment | An attacker with code execution can still read the mounted secret files under `/run/secrets`; that is the same capability the server has. |
| Exposed management surface | The plaintext health listener (8081) is unauthenticated but not published in the Service (only 8080 is) | A misconfigured Service/Ingress could expose it; it must never be internet-facing. |
| Host access via mounted volumes | `/certs` is mounted read-only at mode `0400`; no Docker socket is mounted | Operator misconfiguration. |
| Unrestricted pod egress (SSRF to metadata, exfiltration) | `networkpolicy.yaml` default-denies egress except DNS (53 to `kube-system`) and Postgres/Redis (5432/6379) scoped to the namespace hosting them — no internet-wide `0.0.0.0/0` peer; any `ipBlock` peer excludes `169.254.0.0/16`; ingress is limited to pod ports 8080/8081 | Enforcement depends on a NetworkPolicy-capable CNI; a cluster that ignores NetworkPolicy gets no benefit. A managed database outside the cluster needs a specific CIDR or a CNI FQDN policy. The default-deny also blocks the JAR `request_uri` HTTPS fetch and the CIMD `client_id` document fetch, so remote request objects and CIMD are unsupported unless the deployment adds a scoped allowance (see `docs/DEPLOYMENT.md`). |
| Operator `exec` into a running pod | No shell and a non-root, read-only-rootfs container limit what runs; every secret is a file the container user already reads, and no secret is in the environment | `pods/exec` (and `docker exec`) bypass the application's own authorization; restrict it with RBAC and audit it (`docs/OPERATIONS.md`). |
| Kubernetes API access from the pod | `automountServiceAccountToken: false`; the binary never calls the API | A future feature that needs the API would have to re-enable it deliberately. |
| Image/registry compromise | Keyless cosign v3 signing (OCI 1.1 referrer bundles) in the `supply-chain.yml` `merge` job (`Keyless sign (cosign, OIDC)`), verify-before-rollout with `cosign verify` on `ghcr.io/syavne/d-oauth-server:latest` (see `docs/DEPLOYMENT.md`), a mutable `:latest` reference that trades immutability for a simple admin flow, and a local-build fallback that still signs (`cosign sign`) and verifies (`cosign verify`) before loading; each rollout records the digest the tag resolved to in `RUNBOOK.md` | A registry compromise of the mutable `:latest` tag ships if the operator skips the verify step, and the tag can move between verify and pull (TOCTOU), so the verified digest may not be the one a node pulls; an unsigned `docker save \\| docker load` tarball bypasses every control, so it is forbidden except through the documented local sign/verify fallback. |
| Rate-limit evasion via spoofed `X-Forwarded-For` behind an L7 proxy | Default-empty   `rate_limit.trusted_proxies` (headers ignored unless the TCP peer is an allowlisted proxy IP/CIDR); rightmost-untrusted selection; malformed headers fall back to the verified peer; attribution is bucket selection only, never authentication | An allowlist entry that is too broad (or a compromised proxy) attributes attacker-chosen IPs; keep entries to the proxy peers and never a `/0` (rejected at load). Proxies must emit bare IPs (no port/brackets/`unknown`); anything else is skipped, and only the rightmost 32 entries are considered. |

`GET /jwks.json` is the only public endpoint the JWT access-token feature adds.
The AS metadata document advertises it as `jwks_uri`, together with the exact
configured signing algorithm, only while `jwt_access_tokens_enabled` is on, so a
disabled deployment exposes neither a key set nor an algorithm claim.
Its body is public verification material by construction: a JWK Set carrying
`kid`, `kty`, `crv`, `x` (and `y` for EC), `use: "sig"`, and `alg` for the
current and retained signing keys, with no private member (`d`, CRT parameters,
or `k`) ever rendered. Endpoint enumeration therefore reveals no client, token,
or subject existence; with `jwt_access_tokens_enabled` off it is an empty
`{"keys":[]}`, and the short cache window bounds how long a rotated-out key
stays reachable through an intermediary.

CIMD adds a client class fetched from the internet, so it is a deployment-surface
change, not just an endpoint change. With `cimd_enabled` on, the authorization
server makes outbound HTTPS requests to a host chosen by the caller (the
`client_id` URL). The shipped NetworkPolicy default-denies that egress; a
deployment that enables CIMD must add a scoped allowance for the document hosts
it intends to trust. The guard blocks internal targets, but it cannot make an
untrusted origin trustworthy: the document decides the redirect set, scope
bound, grant allowlist, and DPoP flag within the validation rules described in
[Client ID metadata documents (CIMD)](#client-id-metadata-documents-cimd). Do not
enable CIMD in a deployment that cannot enforce egress policy.

This server is the authorization server and hosts no resource server: it adds
no `/.well-known/oauth-protected-resource` route and no RS route to
`src/routes.rs`, and its AS metadata document never carries a `resource_metadata`
member. The resource-server side of discovery, the
`WWW-Authenticate: Bearer resource_metadata="..."` challenge, and the audience
and scope checks that stop a token minted for one resource from being replayed
at another (RFC 9728 §7.4) are a separate deployable's responsibility. That
contract is in [RS-CONTRACT.md](RS-CONTRACT.md); a resource server that skips the
audience check re-opens the cross-resource replay this server's audience binding
is meant to close.

Disabling or deleting a `resource_servers` row is a kill switch for that
audience: refresh and device mints re-validate the stored audience against the
current enabled catalog, so a disabled/deleted member (or
`resource_indicators_enabled` turned off) fails `invalid_target` instead of
minting. A refresh token stays live; a device code is already consumed by the
poll; an authorization code is not consumed because catalog validation now runs
before the redemption. The client must re-authorize (or retry the live refresh
token) once the identifier is enabled again.

Last reviewed: 2026-10-22. File-mounted DB/Redis passwords, a mutable `:latest`
image reference, NetworkPolicy, `automountServiceAccountToken: false`, scheduled
fuzzing, and the CIMD outbound fetch surface are implemented in the shipped
manifests and workflows.
Deploy provenance is a documented verify-before-rollout path
(`docs/DEPLOYMENT.md`, `RUNBOOK.md`): the signed `ghcr.io` image verified with
`cosign verify` and a recorded digest, with local builds kept only as a signed
fallback.

## Toplevel rules

- `#![forbid(unsafe_code)]` across the crate.
- `unwrap`, `expect`, and `panic` are denied by lint in request paths.
- A raw token, secret, password, OTP, or client secret never appears in
  Postgres, Redis, logs, an error body, or an evidence file.
- Log redaction masks `authorization`, `cookie`, `dpop`, `code`, `token`,
  `client_secret`, `code_verifier`, `password`, `user_code`, `device_code`, and
  `request_uri`, plus any key whose name contains `secret`, and any
  `*_token`/`*_secret`/`*_password`/`*_code` key, in headers, JSON, form bodies,
  and query strings; `code_challenge` and `request_id` stay visible.
- Secret comparisons are constant time.

## Browser and intermediary caching

- Every response except `/.well-known/…` metadata and `GET /jwks.json` carries
  `Cache-Control: no-store` (+ `Pragma: no-cache` for legacy clients). An
  authorization page, consent page, token body, request handle, or error is
  therefore never reused by a browser, the back/forward cache, or a shared
  intermediary.
- `GET /jwks.json` is deliberately cacheable with `public, max-age=300`: the
  advertised members (`kid`, `kty`, `crv`, `x`, and `y` for EC, `use: "sig"`,
  `alg`) are public verification coordinates, never private key material. The
  five-minute window is a revocation trade-off: a rotated-out key stays
  available for resource servers still checking old tokens, but caches drop it
  ten times faster than the one-hour metadata document.
- `/jwks.json` is a new public, unauthenticated path: it returns only public
  key coordinates, and it is the only addition to the routing table for the
  JWT feature. It does not reveal whether any client or token exists.
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

## JWT access-token signing and revocation

Reference: RFC 9068 §2.1, §2.2, §4; RFC 7517 §5.

The signer is off by default and is separate from the pepper/TOTP/PII master
chains. When `jwt_access_tokens_enabled` is on, exactly 32 bytes of raw key
material (`jwt_signing_key` or its `*_file` mount) become a PKCS#8 signing key
for `ES256` (P-256 scalar) or `EdDSA` (Ed25519 seed), chosen by
`jwt_access_token_signing_alg`. There is no RSA path and no PEM handling. A
probe signature is produced at load, so an all-zero or out-of-range scalar fails
at boot rather than at the first mint, and enabling the feature without a key is
a load-time error.

Threat model for the signer:

- The algorithm is pinned by configuration, never taken from the token. A JWT
  whose header names any other `alg` is rejected, including `none` and HS
  variants, so there is no algorithm-confusion path and no symmetric key to
  confuse with a public one.
- The header `typ` must be exactly `at+jwt`, and `kid` must name the current or
  a retained previous key. An unknown `kid` fails with no fallback.
- `iss` and `exp` are enforced with zero clock-skew leeway. `aud` containment is
  applied when the caller supplies an expected audience.
- Key material never appears in `Debug`, an error, a metric label, or a log.
  `Config` and `JwtSigningKey` print only the key id and algorithm; `/jwks.json`
  carries public coordinates only (`kid`, `kty`, `crv`, `x`, and `y` for EC).
  `JwtClaims`'s `Debug` redacts the PII `sub` and the raw `jti`; only public
  claim members print.
- Rotation is verify-only for the old key: the current key signs, every
  `jwt_signing_previous_keys` entry verifies. Kids must be distinct, and a
  previous key cannot be configured without a current key. Retain the old key at
  least until every token it signed has reached `exp` (`ttl.access_secs`, 300 s
  by default). The JWKS route advertises current first, then retained keys, and
  intermediaries may cache that document for 300 s, so a removed key can remain
  visible for up to that window.

Revocation is an allowlist, not a denylist. Every minted JWT writes a
`jwt:<jti-hash>` marker (fields `grant_id`, `client_id`, `subject`; TTL equal to
the access TTL) in the same atomic script as its grant membership. A token is
live only while its marker exists and, for introspection, while the marker's own
grant set still contains it. `POST /introspect` also re-checks the current
account status, so a disabled subject reports inactive. The server fails closed
(`503`) if Redis or Postgres cannot answer that liveness question.

The marker is torn down by every revocation path:

- A grant cascade deletes `jwt:<hash>` markers as its third ARGV, alongside the
  access records and grant set members.
- `user disable` sweeps `jwt:` keys by their `subject` field before flipping
  `users.disabled`.
- `POST /revoke` accepts a JWT-shaped token directly: it verifies signature and
  `iss`, requires both the signed `client_id` and the marker's `client_id` to
  match the caller, then deletes marker, record, and grant membership with a
  durability barrier. A failed ownership check is a uniform no-op (`200`).
- DCR `DELETE` (`/register/{client_id}`) sweeps the client's access records; a
  `jwt:<hash>` access record also deletes its allowlist marker, covering a
  client-credentials token that has no refresh record to trigger the grant
  cascade.

A resource server that verifies locally against `/jwks.json` cannot observe any
of this: it sees the signature, `iss`, `exp`, and its own audience binding, so it
accepts a revoked or disabled user's token until `exp`. That is the exp-bounded
trade-off of a self-contained token. A resource server that needs immediate
revocation must use `POST /introspect`; one that verifies locally must keep the
access TTL short. The same trade-off is stated from the protocol side in
[OAUTH.md](OAUTH.md#the-resource-server-trade-off).

## Sender constraints

Reference: RFC 9449 (DPoP), RFC 8705 (mTLS).

Every sender-constrained grant requires a freshly verified proof on every use.

| Client class | Required binding |
| --- | --- |
| Public, DPoP-bound (`dpop_bound_access_tokens: true`) | DPoP only. A missing proof fails with `invalid_grant`. |
| Public, unbound (default) | None: the client mints `Bearer` tokens. A presented DPoP proof is still verified and recorded. |
| Confidential | mTLS and/or DPoP. The confirmation records each proven component. |

Rollout note: `dpop_bound_access_tokens` defaults to false, so upgrading
makes an existing public client bearer-capable; a client that must stay
DPoP-mandatory has to be registered (or updated via RFC 7592) with
`dpop_bound_access_tokens: true`. A presented bad proof is still rejected for
both classes, and scope and disabled-subject rules are unchanged.

- `cnf` propagates to every newly minted token.
- A stored `cnf` alone never mints: the proof is re-verified per use.
- For token exchange, the proof must match the subject token's confirmation,
  not merely the caller's.
- `private_key_jwt` is client authentication only. It produces no confirmation
  and never satisfies sender constraint. This is deliberate. Its `exp` may lie
  at most 300 s past `now` (plus clock skew), and the `jti` replay marker is
  held for the assertion's full remaining validity, so a long-lived assertion
  cannot be replayed once its marker expires. `RS256`, `PS256`, `ES256`, and
  `EdDSA` are accepted; `none` and HMAC are rejected.
- mTLS identity is a client certificate subject DN (`tls_client_auth`) or a
  certificate thumbprint (`self_signed_tls_client_auth`), each unique per the
  partial indexes in the schema.
- A client certificate is matched only against the identity registered for the
  requesting `client_id`, and only while inside its validity window. A
  cross-wired or expired certificate is `invalid_client` and never binds a
  `cnf`.
- A DPoP proof is rejected if it is malformed, oversized, uses an unsupported
  algorithm, has the wrong `typ`, or has a bad or replayed `jti`, `htm`, `htu`,
  `iat`, or `ath`.

## PAR and JAR

Reference: RFC 9126, RFC 9101.

- A confidential client at `/authorize` must use a PAR `request_uri` or a signed
  `request` object. This is mandatory, not optional.
- A JAR request object must be signed with `RS256`, `PS256`, `ES256`, or `EdDSA`;
  `none` and everything else are rejected before key selection. `iss` must equal `client_id`, `aud` must be the issuer, and conflicts
  with the query string are rejected.
- A `request_uri` is one-time and client-bound, or exactly pre-registered, and
  is fetched only through the SSRF guard (https only, no redirects, global IPs
  only, size and time capped). The connection is pinned to the addresses
  validated before the fetch, so a rebinding hostname cannot redirect it to a
  blocked address.
- PAR credentials are read from the header and body only, never the query.

## Client ID metadata documents (CIMD)

Reference: `draft-ietf-oauth-client-id-metadata-document-02` §3 through §5,
§8.6, §8.7.

CIMD is a registration-free client class: an `https://` URL used as the
`client_id` is fetched and validated, and the result is used as client metadata
for that request. The trust model is remote-document trust with strict
validation. The server does fetch, and it does not treat the client as trusted
because "it registered"; there is no row and no initial-access token. The
feature is off by default (`cimd_enabled`); with it off, an `https://`
`client_id` with no registered row is still an unknown client.

Fetch boundary:

- One guarded fetch, the same fetcher used for `request_uri` and `jwks_uri`:
  `https` only, redirects disabled (a 3xx fails closed), DNS pinned to the
  validated addresses, proxy disabled, and special-use, private, and loopback
  targets rejected before any connection.
- The body is capped by `cimd_max_bytes` (default `5120`, allowed `1`-`5120`)
  and the whole request by `cimd_fetch_timeout_secs` (default `5`, allowed
  `1`-`10`). A non-2xx status or a non-JSON body fails closed.
- A fetch or document-validation failure is a client error
  (`invalid_client_metadata`, or `invalid_redirect_uri` for the redirect set),
  never a fail-open success. A Redis or Postgres outage on the same path is a
  fail-closed `503`.

Threat notes:

- **Document substitution.** The document must echo the fetched URL in
  `client_id` byte for byte, so a document hosted at one URL cannot claim to be
  another. The remaining trust is the origin itself: whoever controls the URL
  controls the redirect set, scope bound, grant allowlist, and DPoP flag,
  within the server's validation rules and the enabled scope catalog. Use only
  URLs whose origin you control; the consent page shows the client and its
  redirect target before approval.
- **Cache poisoning window.** A validated document is cached for 15 minutes as
  `cimd:<sha256(url)>` under the `{state}` keyspace. Only the raw document is
  cached, and it is revalidated on every read, so a disabled scope or removed
  catalog entry takes effect on the next request. A malformed cache entry is
  deleted and treated as a miss. A document changed at its origin can still be
  served from cache for up to the TTL, because a cache hit performs no fetch.
  Redis write access is therefore equivalent to control of client metadata for
  that window; treat Redis as trusted infrastructure exactly as for every other
  security record.
- **Inline-only `jwks`.** A CIMD `private_key_jwt` client must carry its key set
  inline, and any `jwks_uri` member is rejected even alongside an inline
  `jwks`. Client authentication therefore never triggers a second network
  fetch on the token or assertion path, which removes a second SSRF surface and
  a key-substitution race between the fetched document and a separately fetched
  key set.
- **No shared secret or mTLS.** Only `none` and `private_key_jwt` are accepted.
  A remote document cannot hold a shared secret or attest a client certificate,
  and CIMD §4.1 defines these clients as unable to do so. `private_key_jwt` is
  authentication only and never a sender constraint.
- **DPoP and Bearer.** `dpop_bound_access_tokens` absent or `false` produces
  Bearer tokens; `true` requires a fresh DPoP proof at every gate. A CIMD
  `none` client is therefore bearer-capable by default, the same as an unbound
  registered public client, and a stolen Bearer token is usable until it
  expires or is revoked. The document author chooses the flag, not the
  operator. PKCE `S256` and exact redirect matching still bound the code path.
- **No row, no operator controls.** A CIMD client has no `oauth_clients` row,
  so it cannot be given JWT access tokens (`access_token_format` stays
  `opaque`), attached to the redirect catalog, or edited through RFC 7592. A
  CIMD `none` client can revoke its own token but cannot introspect; a CIMD
  `private_key_jwt` client can do both.
- **The DCR gate is unchanged.** CIMD adds a resolution fallback only when no
  registered row exists. `POST /register` still requires a one-time
  initial-access token unless `allow_open_registration` is set, and that gate
  has no CIMD branch.

## Key ring and rotation

- One versioned `KeyRing` holds three independent chains, newest first: the
  token-pepper chain, the TOTP-encryption chain, and the PII field-encryption
  chain. Each purpose also has an optional retained previous key.
- Opaque token hashes carry the pepper key id; the TOTP blob and every `_enc`
  PII blob carry their own key id, and the blind index carries its key id.
- Rotating the pepper requires retaining the old key for at least the refresh
  lifetime so live tokens still verify.
- Rotating the PII key re-encrypts every `_enc` value and recomputes every blind
  index (`pii rotate`); rotating the TOTP key re-wraps the per-row DEKs
  (`totp rewrap`). See
  [OPERATIONS.md](OPERATIONS.md#pii-and-totp-key-rotation).
- `Debug` prints key ids only, never key material.
- There is a separate, opt-in JWT access-token signer (`jwt_signing_key` plus
  `jwt_signing_previous_keys`), not part of the three master chains. The
  `keygen` command still emits ES256 keys only for test fixtures and
  client-side DPoP; it does not manage the server's JWT signing key.

## PII field encryption

Reference: AES-256-GCM (`ring`), HKDF-SHA256, HMAC-SHA256.

- The directory columns listed under [Assets](#assets) are sealed in the
  application with a versioned AES-256-GCM field codec
  (`src/crypto/field.rs`). The key is derived from the PII master key with
  HKDF-SHA256 (info `pii-field-gcm-v1`), never from the TOTP key.
- A keyed-HMAC blind index (`{kid}:{hex}`, info `pii-blind-index-v1`) is stored
  for the columns that are looked up or must stay unique: `email_index`, the
  two mTLS indexes, and `uri_index`. Encrypted bytes cannot be compared or made
  unique directly, so the index is what enforces uniqueness and equality.
- A read accepts candidates across every retained key id, newest first, so a
  lookup keeps working while an old key is retained. A create or register path
  runs an explicit dual-predicate uniqueness pre-check because a partial unique
  index cannot span a sealed row and a not-yet-backfilled plaintext row.
- TOTP secrets use a per-row envelope (blob version 3): a random DEK wrapped by
  a key derived from the TOTP key (info `totp-kek-v1`). The data AAD excludes
  the key id, so a DEK can be re-wrapped under a new key without re-encrypting
  the secret. Versions 1 and 2 still decrypt.
- Decryption of a stored ciphertext is fail-closed: a tampered, truncated,
  unknown-key, or undecodable blob maps to `AppError::PiiDecrypt`
  (`temporarily_unavailable`, `503`) and emits the `pii.decrypt_failure` audit
  event with the request id. No value or plaintext is written to the event.
- **Out of scope.** An attacker who already has database write access can move
  an entire encrypted body between rows (full-blob substitution) or replay a
  sealed value. Field encryption binds ciphertext to a key, not to a row
  identity, and defending against a write-capable adversary would require row
  binding or a MAC over the row that this release does not add. This is a
  documented threat-model boundary, not a defect.

## Master key custody

- The token pepper, the TOTP-encryption key, and the PII field-encryption key
  are the server's master keys. They live in the versioned `KeyRing`
  (`src/keys.rs`), loaded once at startup from configuration. Nothing re-reads
  or fetches them later.
- **Hard requirement.** A master key must never be stored in Postgres, captured
  in the same backup or restore as Postgres, baked into an image layer, placed
  in a ConfigMap, or injected into the process environment by the shipped
  manifests. A database dump plus its backup must not yield any of the three
  keys.
- Losing the token pepper invalidates every live opaque access and refresh
  token, because only keyed HMAC hashes are persisted and the pepper is the
  HMAC key. Losing the PII key makes every sealed directory value unreadable.
- The real config surface is small: inline `token_pepper`, `totp_encryption_key`,
  and `pii_encryption_key`, or the mounted-file forms `token_pepper_file`,
  `totp_encryption_key_file`, and `pii_encryption_key_file`. When both are set
  the inline value wins (`resolve_secret` in `src/config/build.rs`). The key ids
  default to `v1` through `token_pepper_id` / `totp_key_id` / `pii_key_id`
  (`src/config/raw.rs`). Each purpose may retain one previous key
  (  `*_previous_key` / `*_previous_key_file`) with an explicit, distinct
  `*_previous_key_id`; a previous key without its active key is a config error.
- **Minimum length.** Every resolved master-key value — `token_pepper`,
  `totp_encryption_key`, `pii_encryption_key`, and each retained
  `*_previous_key`, inline or `*_FILE` — must be at least 32 bytes (256 bits).
  Shorter material is rejected at load with `ConfigError::WeakKeyMaterial`,
  which names the offending key.
- The shipped cluster manifests never use the inline or environment forms: the
  Secret file-mounts the keys `0400` on a tmpfs volume at `/run/secrets`, and
  the loader reads them through `D_OAUTH_TOKEN_PEPPER_FILE`,
  `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`, and `D_OAUTH_PII_ENCRYPTION_KEY_FILE`
  (`deploy/k8s/secret.yaml`, `deploy/k8s/configmap.yaml`). The ConfigMap carries
  only non-secret settings; the previous keys stay optional and are never
  required in a workload.
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
only long enough to re-enroll users or re-wrap blobs, then drop it; retain the
old PII key id until `pii rotate` has re-encrypted every value and recomputed
every blind index, then drop it. A rotation that removes an id early is a
deliberate invalidation of what that key protects.

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
  replayed proof or assertion is rejected. A `private_key_jwt` marker lives for
  the assertion's full remaining validity, bounded by the 360 s bound (a 300 s
  maximum assertion lifetime plus 2×30 s clock skew).
- A TOTP code is recorded in a replay cache for its time-step window.

## Input and output safety

- Redirect URI matching is exact, with the RFC 8252 loopback exception only.
  There are no wildcards and no prefix matches. A private-use scheme must
  contain reverse-DNS dot notation (draft-16 §2.3.1): `com.example.app:/` is
  accepted, `myapp:/` is rejected; `https` and loopback are unaffected.
- The loopback exception covers the literal hosts `127.0.0.1` and `[::1]`
  unconditionally. The host `localhost` is covered only when
  `allow_localhost_redirect` is set (default off). RFC 8252 §8.3 warns that a
  hostname such as `localhost` is resolution-dependent: `/etc/hosts`, DNS, or
  a search suffix can point it away from the loopback interface, so enabling
  the flag widens the exception to whatever `localhost` resolves to on the
  user agent. It is an explicit operator opt-in, never a default, and it does
  not change the literal-IP behavior. OAuth clients such as MCP servers that
  use `http://localhost:{port}/…` redirects rely on this flag; the consent
  page shows the client and its redirect target, so a user can see where the
  authorization code will be delivered before approving.
- PKCE is `S256` only. A verifier cannot be omitted to downgrade.
- Scope is intersected: `requested ∩ client-registered ∩ user-entitled ∩
  enabled`. Refresh re-checks the current `enabled` catalog, the client's
  current registration, and the user's current entitlements (fresh Postgres
  reads) and splits the result (draft-16 §4.3.1 + §4.3.3): the replacement
  refresh token retains the presented scope minus revoked entries (dropped
  silently, possibly to empty), while an explicit narrower `scope` narrows only
  the access token and the response `scope` — the next rotation from the
  retained refresh token can still use the full retained scope.
- The login, consent, and device pages set a strict CSP with
  `frame-ancestors 'none'`. They use server-side sessions, CSRF protection, and
  no open redirect.
- The session cookie is `__Host-session_id` (RFC 6265bis): `HttpOnly`,
  `Path=/`, `SameSite=Lax`, host-only with no `Domain` ever emitted, and
  `Secure` in every environment except a localhost development exception
  (`cookie_secure = false`, which production rejects at load with
  `InsecureSessionCookie`). The exception also drops the `__Host-` prefix
  (the cookie is then plain `session_id` with the same `Path`/`HttpOnly`/
  `SameSite`/no-`Domain` attributes), because browsers reject a `__Host-`
   cookie without `Secure` and the session would otherwise never persist. Any non-blank `cookie_domain` is rejected at load
   (`InvalidCookieDomain`) as incompatible with the `__Host-` prefix; blank
   values are treated as absent. The
  server-side session lives 12 h absolute (`ttl.session_secs`, pinned by test);
  reads never re-arm the TTL, so there is no idle sliding — a live session
   always dies 12 h after its last write. In production the session reader
  honors `__Host-session_id` **alone**: a plain `session_id` cookie is never
  read there, so a sibling subdomain cannot plant a session id and fixate a
  victim's login onto the attacker's pending presession. The development
  variant reads plain `session_id` and only additionally falls back to
  `__Host-session_id` for a cookie left over from before a config flip. Only
  `POST /logout` clears the session, emitting a clearing cookie for **every**
  name the reader honors (the `__Host-` name in production; both names in
  development), each mirroring the session-cookie name and every attribute.
- `GET /logout` is a server-specific session endpoint (not OAuth 2.1/OIDC
  defined). It is read-only: it renders a confirm page and never destroys the
  session or writes cookies, so a forced navigation cannot log a victim out.
  Only `POST /logout` with the session-bound CSRF `form_token` destroys the
  session and clears the cookie. It accepts **no query
  parameters**: the target is read only from session meta, frozen when the
  authorization flow was bound, and used only if the owning client is still
  active and still registers that exact URI (exact-string match + RFC 8252
  loopback). `GET /logout` issues no redirect; only `POST /logout` redirects,
  and only to that bound URI. A forced navigation to `/logout` therefore only
  renders the confirm page — it never ends the session and never leaves the
  page, so it cannot log a victim out nor send the browser
  to an attacker target. There is no `post_logout_redirect_uri` parameter and no
  `id_token_hint`.
- Failed-login and lockout counters live in Redis, not Postgres, so a login
  flood does not write rows. Lockout is composite: 5 failures from one IP for
  one account (`ui::login::LOCKOUT_THRESHOLD`) lock that IP's bucket only, so
  a burst from an attacker IP never locks the victim from another IP; 20
  failures from any IPs (`ui::login::ACCOUNT_LOCKOUT_THRESHOLD`) lock the
  account globally as the distributed-burst cap. Attempts for absent labels
  never mint per-label keys — they share the source IP's single
  `loginfail:unknown` bucket — so label enumeration cannot spray the keyspace.
   `user unlock --email` clears the account counter and every per-IP bucket
   for the user instead of waiting out the 15-minute window. Lockout buckets
   use the TCP peer address, never the rate-limit `trusted_proxies`
   attribution: behind an L7 proxy every login shares the proxy's peer IP,
   so the per-IP composites collapse into one bucket and the 20-failure
   account cap becomes the effective control. Keep L4/TCP passthrough (see
   `docs/DEPLOYMENT.md`) where per-IP lockout isolation matters.
- Rate limiting classifies by full request path: `/token`,
  `/authorize`/`/consent`/`/device*`/`/introspect`/`/revoke`/`/par`,
   `/login*`/`/logout`, and `/register*`; `/health`, `/.well-known`, and
   `/assets` are unrated. The per-client bucket is keyed by the
   `(peer_ip, client_id)` composite, not by the raw `client_id`: the id is
   read before client authentication, so a global per-id bucket would let an
   attacker exhaust a victim client's budget or rotate fake ids to evade the
    limit; the per-IP bucket remains the primary control. Counters live in a Redis keyspace separated from token
    state. A breach is `429` + `Retry-After`; a store outage or a missing peer
    address fails closed `503`. Behind an L7 proxy the IP bucket is attributed
    from `X-Forwarded-For` only when the TCP peer is a configured
    `rate_limit.trusted_proxies` entry (exact IP/CIDR, default empty): the
    rightmost-untrusted chain entry is used over the rightmost 32 bare-IP
    entries, a header from an untrusted peer
    is ignored, and a header with no parseable bare-IP entry falls back to the verified peer, so a
    spoofed header can neither evade the limit nor shift a victim's bucket.
    This attribution never authenticates a client and never carries a client
    certificate.
- TOTP enrollment confirmation (`confirm_totp`) shares the login lockout counter
  and policy: a failed code increments it, success clears it, and a locked
  account rejects even a correct code — indistinguishably — until the window
  expires.
- A disabled subject is dead everywhere: introspection reports it inactive and
  refresh rejects it with `invalid_grant` before minting; `user disable` first
  purges every Redis record whose subject is the user (sessions + `:meta`, the
  `loginfail` account counter plus every per-IP composite bucket, authorization codes, device records + `:cnf`/`:poll` +
  `user_code` mappings, grants via cascade revoke plus member `:act`, and
  standalone access/refresh records), then flips Postgres `disabled`. A Redis
  outage fails closed and leaves the user enabled. Records with no subject
  (`par:`, `pending:`, `dpop_jti:`, `client_assertion_jti:`, `rotation:`,
   `totp_replay:`, rate-limit counters) are untouched.
- A password change (`change_password`) or TOTP re-enrollment
  (`confirm_totp`) ends the subject's other login sessions (records plus
  `:meta` sidecars) via the same session sweep, scoped to the subject minus
  the session in hand, which survives and is re-issued full. The sweep runs
  before the credential write, so a Redis outage fails the call with `503`
  with the password unchanged (the caller retries); a later database failure
  costs only re-authentication. OAuth tokens, codes, and grants are
  untouched: ending the sessions forces re-authentication, while live tokens
  keep working until they expire or the account is disabled.
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
- `pii.decrypt_failure` means a stored PII or TOTP ciphertext failed to open
  (tamper, truncation, or a missing key id). Treat it as possible data
  corruption or key-store drift; it carries only the request id, never a value.
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
| TOTP secrets | Per-row DEK wrapped by AES-256-GCM under HKDF-SHA256 (info `totp-kek-v1`; a re-wrap keeps the data ciphertext unchanged); v1/v2 blobs still decrypt | Readable only if the TOTP key also leaks. |
| TOTP recovery codes | Argon2id PHC | Offline cracking only. |
| DCR registration access tokens | Keyed HMAC (`registration_access_token_hash`) | Opaque while the pepper stays outside the dump. |
| Emails, client names, contacts, redirect URIs, JAR `request_uris`, `jwks_uri`, software ids, mTLS subject DNs and certificate thumbprints | Sealed AES-256-GCM under HKDF-SHA256 (info `pii-field-gcm-v1`), with keyed-HMAC blind indexes in `_index` | Opaque without the PII key. The blind indexes are deterministic tags, not plaintext, but they do reveal equality within one key generation. |
| Scopes, entitlements, timestamps, actor ids | Plaintext | Metadata disclosure. |
| Client public keys (`jwks`) | Plaintext | Public by design. |
| `is_admin`, `disabled`, `must_change_password`, `totp_enabled`, timestamps | Plaintext | Metadata disclosure. |
| Client registration metadata (`grant_types`, `response_types`, `token_endpoint_auth_method`, `software_id`, `active`, `dpop_bound_access_tokens`, `client_id_issued_at`, `client_secret_expires_at`) and catalog metadata (scope/redirect `description`, `enabled`, `kind`, actor ids `granted_by`/`created_by`/`attached_by`) | Plaintext | Metadata disclosure. |

If the key store leaked too, the dump is a full compromise: TOTP secrets and
the sealed directory decrypt, the Argon2id hashes are the only barrier left on
passwords and client secrets, and registration-access-token hashes can be
recomputed. Respond in the order below.

### Full-database-disclosure rotation order

Rotate in this order. Each step retires a class of credential the dump already
exposed; do not skip ahead because a later step looks cheaper.

1. **Token pepper first.** Make a new pepper active and remove the old key id.
   Removing the old id kills every live opaque access and refresh token, so
   every grant is forced back through authentication. This is the only step
   that retires tokens the dump cannot reconstruct. Retain the old id only to
   keep live tokens verifying, which is the opposite of what a breach response
   wants; a full disclosure drops it.
2. **TOTP encryption key second.** Make a new key active with the old key
   retained. Existing TOTP blobs stay readable while the old key is retained;
   run `totp rewrap` to re-wrap every v3 per-row DEK under the new key (the data
   ciphertext is untouched), or re-enroll with `user enroll-totp` before the old
   key is dropped. Once the old key is removed, a blob still naming it cannot
   decrypt.
3. **PII field-encryption key third.** Make a new PII key active with the old
   key retained, then run `pii rotate` under a write freeze (the app tier scaled
   to zero). Rotation re-encrypts every `_enc` value and recomputes every blind
   index under the new key, in bounded transactions under an advisory lock. The
   blind index is key-dependent, so uniqueness is only enforced within one key
   generation during the window; the freeze is what keeps a duplicate from
   slipping between generations. Run `pii verify` and only then retire the old
   key. See
   [OPERATIONS.md](OPERATIONS.md#pii-and-totp-key-rotation).
4. **Client secrets fourth.** Rotate every confidential client secret through
   RFC 7592 `PUT /register/{client_id}`, which mints a fresh secret when the
   method is secret-based and returns it once.
5. **DCR registration tokens last.** The same `PUT /register/{client_id}` call
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
  mTLS then fails. Use L4 passthrough.
- A public client that loses its DPoP key cannot use its tokens; there is no
  bearer fallback for a sender-constrained grant.

## File and directory references

- `src/crypto/` for token minting, hashing, TOTP, and constant-time compare.
- `src/crypto/field.rs` for the PII field codec and keyed blind index.
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

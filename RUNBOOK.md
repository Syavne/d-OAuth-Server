# Operator Runbook

How to create the first administrator of a fresh `d-oauth-server` install, how to
replace that bootstrap account immediately, and how to respond to a full
database disclosure. There is no HTTP bootstrap endpoint: provisioning is
CLI/Job only.

> Task 48 owns `SECURITY.md`; this file is the task-47 operator runbook.
> The threat model and the replace-immediately rationale live there.

## Prerequisites

- Migrations applied exactly once via the migration Job (never per replica):
  `d-oauth-server migrate`
- Zero enabled admins exist (a migrated database seeds zero users).

## Migrations and the maintenance window

Apply the PII envelope-encryption expansion
(`migrations/1791417600_pii_encryption.sql`) during a maintenance window with
the app tier quiesced, from the dedicated migration Job:

```sh
d-oauth-server migrate
```

`ALTER TABLE ... DROP NOT NULL` takes `ACCESS EXCLUSIVE` on `users`,
`redirect_uris`, and `oauth_clients`, blocking reads and writes on each table for
the duration. Each non-concurrent `CREATE INDEX` in the file takes `SHARE` on its
table, blocking writes. A non-transactional `CREATE INDEX CONCURRENTLY` is not
used because sqlx applies every migration inside one transaction, and
PostgreSQL rejects `CONCURRENTLY` in a transaction. The migration is additive:
no column is dropped or renamed and the legacy unique constraints are kept, so
version N-1 replicas keep working through the rollout.

## 1. Bootstrap the first admin

Interactive (password read from stdin, never argv, never logged):

```sh
d-oauth-server admin bootstrap --email ops@example.com
```

Non-interactive / cluster Job (mounted secret file):

```sh
d-oauth-server admin bootstrap --email ops@example.com \
  --password-file /run/secrets/bootstrap-password
```

When neither a file nor stdin yields a password, the command generates a
256-bit password and prints it exactly once, and only to a TTY. If stdout is
not a TTY the command refuses instead of risking the secret in Job logs:
re-run attached to a terminal or supply `--password-file`.

A second `admin bootstrap` refuses while any enabled admin exists:

```sh
d-oauth-server admin bootstrap --email second@example.com
# error: already exists: an administrator already exists (1); ...
```

The override requires explicit `--force`, prints a loud warning to stderr,
and emits an audited `admin.bootstrap.force` event. Prefer routine
provisioning instead:

```sh
d-oauth-server admin bootstrap --email second@example.com --force
d-oauth-server user create --admin --email named-admin@example.com
```

## 2. Replace the bootstrap admin immediately

The bootstrap account starts with `must_change_password=true` and
`totp_enabled=false`. Its first login yields a restricted session that can
only change the password and enroll TOTP — `/authorize`, `/oauth/*`, and
admin-gated actions deny it until both steps complete.

- [ ] Log in as the bootstrap admin; you land on `/login/change-password`.
- [ ] Change the password (minimum 12 characters). This clears
      `must_change_password` and stamps `password_changed_at`.
- [ ] Enroll TOTP at `/login/totp/setup` and confirm with an authenticator
      code. The session is re-issued with full authority only now.
- [ ] Capture the recovery codes shown once at enrollment; store them offline.
- [ ] Create a named second admin:
      `d-oauth-server user create --admin --email <name>@example.com`
- [ ] Log in as the named admin and verify full access.
- [ ] Disable the bootstrap account: `d-oauth-server user disable --email ops@example.com`. `user disable` purges the account's Redis sessions, tokens, grants, codes, device records, and lockout counter before flipping the Postgres `disabled` flag, and fails closed (leaving the user enabled) if Redis is unavailable. Records with no subject (PAR, pending, replay markers, rotation map, TOTP replay, rate-limit counters) are untouched. See docs/OPERATIONS.md.
- [ ] Rotate/expire the bootstrap secret: delete the mounted
      `/run/secrets/bootstrap-password` material and revoke any copy of a
      generated one-time password.

## 3. Audit events

On the `audit` target (never carrying secrets): `admin.bootstrap.created`
and `admin.count.changed` on success, `admin.bootstrap.refused` on refusal,
`admin.bootstrap.force` on a forced override. First-login, password-changed,
and TOTP-enrolled outcomes are emitted by the login flow itself.

## 4. What never happens

- No default or hardcoded admin credential ships; `migrate` seeds zero users
  and `serve` never creates one.
- The bootstrap password is never accepted via argv, never logged, and never
  stored (only its Argon2id hash reaches Postgres).
- Bootstrap is CLI/Job only; no HTTP endpoint can create an admin.

## 5. Full-database-disclosure response

Use this when a PostgreSQL dump, backup, or read replica has left your control
on unknown terms. The blast radius and the rationale for the order below are in
[docs/SECURITY.md](docs/SECURITY.md); this is the operator checklist. Preserve
evidence first: capture the audit stream and keep the `X-Request-Id`
correlation. No step below writes a secret to a log.

### Rotation order and commands

- [ ] Confirm whether the key store leaked with the dump. The token pepper, the
      TOTP encryption key, and the PII field-encryption key live outside the database
      (`D_OAUTH_TOKEN_PEPPER` / `D_OAUTH_TOKEN_PEPPER_FILE`,
      `D_OAUTH_TOTP_ENCRYPTION_KEY` / `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`,
      `D_OAUTH_PII_ENCRYPTION_KEY` / `D_OAUTH_PII_ENCRYPTION_KEY_FILE`); if it
      is not provably untouched, assume it leaked and continue.
- [ ] **1. Rotate the token pepper.** Point `D_OAUTH_TOKEN_PEPPER` (or
      `D_OAUTH_TOKEN_PEPPER_FILE`) at a new value, bump
      `D_OAUTH_TOKEN_PEPPER_ID`, and perform a rolling restart. Dropping the old
      id invalidates every live opaque access and refresh token, so clients
      re-authenticate.
- [ ] Confirm opaque tokens are dead by re-authenticating a test client. Expect
      `invalid_grant` for a token minted before the rotation.
- [ ] **2. Rotate the TOTP encryption key.** Point
      `D_OAUTH_TOTP_ENCRYPTION_KEY` (or `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE`) at a
      new value, bump `D_OAUTH_TOTP_KEY_ID`, and roll the replicas. Retain the
      old key only until every user has re-enrolled.
- [ ] Re-enroll every TOTP user before dropping the old key:
      `d-oauth-server user enroll-totp --email <email>`
      (prints the secret and `otpauth://` URI exactly once).
- [ ] **3. Rotate the PII field-encryption key.** Point
      `D_OAUTH_PII_ENCRYPTION_KEY` (or `D_OAUTH_PII_ENCRYPTION_KEY_FILE`) at a
      new value, bump `D_OAUTH_PII_KEY_ID`, and roll the replicas with the old
      key retained. Then, under a write freeze (app tier scaled to zero), run
      `d-oauth-server pii rotate` to re-encrypt every `_enc` value and recompute
      every blind index, verify with `d-oauth-server pii verify`, and only then
      retire the old key. See
      [docs/OPERATIONS.md](docs/OPERATIONS.md#pii-and-totp-key-rotation).
- [ ] **4. Rotate every confidential client secret.** Read the current metadata,
      then re-submit it through RFC 7592 `PUT /register/{client_id}` to mint a
      new secret and a new registration token:

      ```sh
      curl -sS https://<issuer>/register/<client_id> \
        -H "Authorization: Bearer <current-registration-access-token>"

      curl -sS -X PUT https://<issuer>/register/<client_id> \
        -H "Authorization: Bearer <current-registration-access-token>" \
        -H 'Content-Type: application/json' \
        --data @client-metadata.json
      ```

      The `PUT` response carries `client_secret` and
      `registration_access_token` exactly once. Store both before the process
      exits; the previous registration token immediately answers `403`.
- [ ] **5. Rotate every DCR registration token.** Every successful `PUT` above
      already rotated the registration token. If you also need new
      registrations after the breach, issue a fresh single-use initial-access
      token:
      `d-oauth-server initial-access-token issue --uses <n> --ttl <seconds>`
      (the raw token is printed once).
- [ ] **6. Verify fail-closed behavior.** Readiness must report ready only with
      both dependencies up:
      `d-oauth-server healthcheck [--url http://127.0.0.1:8081/health/ready]`
      (readiness; liveness is `/health/live` as in
      [docs/OPERATIONS.md](docs/OPERATIONS.md)).
      A dependency outage during recovery must yield `503`, never a fail-open
      success.

### What not to do

- Do not rotate the TOTP key before the pepper: the pepper step is the only one
  that retires live opaque tokens the dump cannot reconstruct.
- Do not remove the old TOTP key before every user has re-enrolled.
- Do not relax the fail-closed policy to keep the security endpoints up.
- Do not paste the leaked registration tokens, client secrets, or the pepper
  into a ticket, chat, or log.

## 6. Deploy provenance (signed `ghcr.io` image)

Every rollout ships the signed `ghcr.io/syavne/d-oauth-server` image the
`supply-chain.yml` `merge` job signed (step `Keyless sign (cosign, OIDC)`).
Nothing ships from an unverified local tarball. The full path is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#deploy-path-use-the-ghcrio-image).

- [ ] Verify the signature before applying (the `latest` tag resolves to the
  current digest at verify time; signatures are cosign v3 OCI 1.1 referrers, so
  use a cosign v3+ client):

  ```sh
  cosign verify \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp 'supply-chain' \
    'ghcr.io/syavne/d-oauth-server:latest'
  kustomize build deploy/k8s
  python3 scripts/check_manifests.py
  kubectl apply --dry-run=server -k deploy/k8s
  kubectl apply -k deploy/k8s
  ```

- [ ] Record the rollout: the digest the `latest` tag resolved to (from the
  `cosign verify` output), the `build` run that produced the `sbom.spdx.json`
  artifact and `trivy.sarif`, and the `cosign verify` result. A rollout with no
  matching record is unverified: stop and re-verify.
- [ ] Local-build fallback only (registry unreachable): build with
  `docker buildx bake image --set image.platform=linux/amd64`, sign and verify
  the image with `cosign sign --key <local-key-ref> 'd-oauth-server:latest'`
  and `cosign verify --key <local-pub-ref> 'd-oauth-server:latest'`, then load
  the verified image and record the deploy as explicitly local, non-`ghcr.io`.
  Never `docker save | docker load` an unsigned image onto a live host.

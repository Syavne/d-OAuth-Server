# Admin Bootstrap Operator Runbook

How to create the first administrator of a fresh `d-oauth` install, and how
to replace that bootstrap account immediately. There is no HTTP bootstrap
endpoint: provisioning is CLI/Job only.

> Task 48 owns `SECURITY.md`; this file is the task-47 operator runbook.
> The threat model and the replace-immediately rationale live there.

## Prerequisites

- Migrations applied exactly once via the migration Job (never per replica):
  `d-oauth-server migrate`
- Zero enabled admins exist (a migrated database seeds zero users).

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
- [ ] Disable the bootstrap account: `d-oauth-server user disable --email ops@example.com`
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

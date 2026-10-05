# TODO

This is a backlog of deferred hardening work. Each item is a candidate to be
planned and implemented later; none of them is a current defect that makes the
server unusable. The items came out of a threat-model review that asked one
question: if an attacker walks off with a full dump of the PostgreSQL database,
what can they still read or crack, and what should we do about it?

This document only records the gaps. It does not describe anything that is
already implemented, and it does not propose code changes here.

## What a database dump exposes today

The baseline is better than a naive server's, because secrets are stored hashed
or encrypted, and the key material lives outside the database. The table below
is the full accounting.

| Data | Protection at rest | If the dump leaks |
| --- | --- | --- |
| User passwords | Argon2id PHC, salted (`src/db/user_repo.rs`) | Offline cracking only. |
| Client secrets | Argon2id PHC (`src/db/client_repo.rs`) | Offline cracking only. |
| TOTP secrets | AES-256-GCM under `SHA256(totp_key)` (`src/crypto/totp.rs`) | Safe only if the key is not in the dump. |
| TOTP recovery codes | Argon2id PHC (`src/db/user_repo/totp.rs`) | Offline cracking only. |
| DCR registration access tokens | Keyed HMAC hash (`src/db/client_repo.rs`) | Safe; the pepper is not in the database. |
| Emails, client names, contacts, redirect URIs, scopes, entitlements | Plaintext | Full disclosure. |
| `jwks` (client public keys) | Plaintext | Public by design. |
| `tls_client_auth_subject_dn` and cert thumbprints | Plaintext | Identifier disclosure. |
| `is_admin`, `disabled`, `must_change_password`, timestamps | Plaintext | Metadata disclosure. |

The critical dependency is outside the database. The token pepper and the TOTP
encryption key are supplied through environment variables or mounted files
(`src/config/raw.rs`, `src/config/build.rs`), never through a table. A pure
database dump therefore does not yield them, and every hashed or encrypted
column above stays opaque. This separation is the single most important
protection the server has today, and the gaps below are mostly about not
depending on it alone.

## Gaps to plan and implement

Each item names the risk, the change to plan, and the files it would touch. The
list is deliberately short and ordered by value.

### 1. Application-level encryption of PII columns

- **Risk.** Emails, client names, contacts, and redirect URIs are plaintext. A
  dump leaks the full user and client directory, which enables phishing,
  credential stuffing against other services, and mapping of who talks to whom.
- **Proposed change.** Encrypt these columns with AES-256-GCM under a KeyRing
  key. Add a blind index (a keyed HMAC of the normalized value) for the `email`
  lookup so case-insensitive uniqueness still works.
- **Files.** `src/db/user_repo.rs`, `src/db/client_repo.rs`,
  `src/db/redirect_repo.rs`, `src/keys.rs`, `migrations/`.

### 2. Strengthen TOTP key derivation

- **Risk.** The TOTP encryption key is derived with a bare `SHA256(totp_key)`
  (`src/crypto/totp.rs`) and no KDF stretching. If the key file leaks alongside
  the dump, every TOTP secret falls immediately. A low-entropy passphrase is
  cheap to brute-force when a single hash is all that stands in the way.
- **Proposed change.** Derive the AES key with Argon2id or HKDF from a
  high-entropy key, so a leaked passphrase costs an attacker real work.
- **Files.** `src/crypto/totp.rs`, `src/cli/secret.rs`.

### 3. Envelope encryption with per-row DEKs

- **Risk.** One static key encrypts every TOTP secret. There is no per-row data
  key, so there is no way to rotate the master key without re-encrypting the
  entire table in one pass, and a single key compromise exposes all rows.
- **Proposed change.** Give each row a data encryption key wrapped by the master
  key, which makes rotation incremental and limits a single leak's blast radius.
- **Files.** `src/crypto/totp.rs`, `src/keys.rs`.

### 4. KMS/HSM-backed master key

- **Risk.** The master keys are plain environment variables or files. Where they
  are stored, who can read them, and whether they ever end up in the same backup
  as the database is undocumented and unenforced.
- **Proposed change.** Document, and optionally support, a master key held in a
  KMS or HSM. At a minimum, document the hard requirement that the key never
  lives with the database backup.
- **Files.** `src/config/`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md`.

### 5. Breach-response runbook

- **Risk.** There is no documented procedure for what to rotate after a dump, or
  in what order. The [SECURITY.md](SECURITY.md) operational runbook covers an
  incident in general terms but not a full database disclosure.
- **Proposed change.** Document the blast radius and the rotation order: rotate
  the token pepper first so all opaque tokens die, then rotate the TOTP key so
  users re-enroll, then rotate client secrets, then rotate DCR registration
  tokens.
- **Files.** `docs/SECURITY.md`, `RUNBOOK.md`.

### 6. Database access hardening

- **Risk.** There is no tamper-evidence or audit trail for database access, and
  no guidance on encrypted backups or Postgres-level encryption such as TDE or
  `pgcrypto`. A dump could be taken by a read-only job and leave no trace.
- **Proposed change.** Document the controls and, where they fit, implement them.
- **Files.** `docs/DATABASE.md`, `docs/DEPLOYMENT.md`.

## Container and host hardening

The attack surface and the existing controls are documented in
[SECURITY.md](SECURITY.md); this section lists only the mitigations to close the
residual risks.

This section covers a second threat-model question: if an attacker is already
inside the image's trust boundary, how could they reach the container or the
host, and how should we reduce that risk? The image is already hardened: it runs
as non-root UID 65532, uses a read-only root filesystem, drops all capabilities,
sets `allowPrivilegeEscalation: false` and `seccompProfile: RuntimeDefault`,
ships no shell, builds a static musl binary from digest-pinned bases, and
produces an SBOM, provenance, and a cosign signature in CI. The remaining vectors
are therefore narrow, and none of them is a current defect. This section lists
the mitigations to implement.

### Mitigations to plan and implement

### 7. Move secrets from environment variables to files

- **Risk.** Environment variables are readable by the process
  (`/proc/self/environ`), appear in `docker inspect`, are inherited by children,
  and leak into logs and crash dumps; an attacker with code execution reads the
  token pepper and TOTP key directly.
- **Proposed change.** Mount the pepper and TOTP key as files (tmpfs, mode
  `0400`, owned by 65532) and use the already-supported
  `D_OAUTH_TOKEN_PEPPER_FILE` / `D_OAUTH_TOTP_ENCRYPTION_KEY_FILE` variables
  (`src/config/raw.rs`, `src/config/build.rs`).
- **Files.** `deploy/k8s/deployment.yaml`, `deploy/k8s/secret.yaml`,
  `compose.yaml`, `docs/DEPLOYMENT.md`, `docs/CONFIGURATION.md`.

### 8. Pin the image by digest in the committed manifest

- **Risk.** The base manifest uses a mutable `:latest` tag with
  `imagePullPolicy: IfNotPresent`; a compromised registry tag could be pulled if
  the CI digest-rewrite step does not run.
- **Proposed change.** Commit the digest-pinned image reference.
- **Files.** `deploy/k8s/deployment.yaml`, `deploy/k8s/kustomization.yaml`.

### 9. Add a NetworkPolicy

- **Risk.** Unrestricted pod egress allows SSRF-to-metadata and data
  exfiltration.
- **Proposed change.** Restrict egress to Postgres and Redis only, and ingress
  to the Service.
- **Files.** `deploy/k8s/` (new `networkpolicy.yaml`), `docs/DEPLOYMENT.md`.

### 10. Disable the service-account token

- **Risk.** The app never calls the Kubernetes API, so the auto-mounted service
  account token is pure attack surface.
- **Proposed change.** Set `automountServiceAccountToken: false` on the pod.
- **Files.** `deploy/k8s/deployment.yaml`.

### 11. Strengthen runtime isolation

- **Risk.** A kernel or runtime escape is possible after code execution.
- **Proposed change.** Consider a sandboxed runtime class (gVisor/Kata) and a
  custom seccomp allowlist instead of `RuntimeDefault`.
- **Files.** `deploy/k8s/deployment.yaml`, `docs/DEPLOYMENT.md`.

### 12. Continuous fuzzing and dependency review

- **Risk.** CI-only fuzzing and `cargo deny` do not catch a zero-day in a
  trusted crate.
- **Proposed change.** Run the fuzz targets continuously and add
  `cargo vet`/`cargo crev` review.
- **Files.** `.github/workflows/`, `fuzz/`, `deny.toml`.

### 13. Restrict and audit container exec

- **Risk.** `docker exec` / `kubectl exec` into the running container bypasses
  every image control.
- **Proposed change.** Restrict who may exec and audit it.
- **Files.** `docs/OPERATIONS.md`, `docs/DEPLOYMENT.md`.

## Priority

Ranked by value against effort:

- **High value, low effort:** items 1, 2, 5.
- **Medium:** items 3, 4.
- **Lower, mostly operational:** item 6.
- **Container/host hardening:** items 7, 8, 9, 10 are high value and low effort;
  items 11, 12, 13 are medium/operational.

Recommendation: implement 1, 2, 5, 7, 8, 9, and 10 first. Item 1 closes the
largest plaintext disclosure, item 2 removes an easy offline win if the key file
leaks, item 5 is mostly writing down a procedure the team already needs, and
items 7 through 10 are high-value, low-effort container and host controls.

## Open questions

- Is the token pepper and TOTP key supplied through environment variables,
  mounted files, or a secrets manager in the target deployment? This decides
  whether envelope encryption (item 3) is worth building at all.
- Should PII encryption (item 1) be mandatory or gated behind configuration?
- Should the pepper and TOTP key move to file-based secrets now, or wait for the
  envelope-encryption work (item 3)?
- Is a sandboxed runtime class (gVisor/Kata) available in the target cluster?

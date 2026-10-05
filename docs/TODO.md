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
| TOTP secrets | AES-256-GCM under HKDF-SHA256 (`src/crypto/totp.rs`, info `totp-gcm-v2`; pre-migration v1 blobs under bare `SHA256(totp_key)` still decrypt) | Safe only if the key is not in the dump. |
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

### 2. Envelope encryption with per-row DEKs

- **Risk.** One static key encrypts every TOTP secret. There is no per-row data
  key, so there is no way to rotate the master key without re-encrypting the
  entire table in one pass, and a single key compromise exposes all rows.
- **Proposed change.** Give each row a data encryption key wrapped by the master
  key, which makes rotation incremental and limits a single leak's blast radius.
- **Files.** `src/crypto/totp.rs`, `src/keys.rs`.

### 3. KMS/HSM-backed master key

- **Risk.** The master keys live in environment variables, files, or a
  secrets manager, but nothing enforces where they are stored or keeps them
  out of the same backup as the database.
- **Proposed change.** Document, and optionally support, a master key held in a
  KMS or HSM. At a minimum, document the hard requirement that the key never
  lives with the database backup.
- **Files.** `src/config/`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md`.

### 4. Database access hardening

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

### 5. Strengthen runtime isolation

- **Risk.** A kernel or runtime escape is possible after code execution.
- **Proposed change.** Consider a sandboxed runtime class (gVisor/Kata) and a
  custom seccomp allowlist instead of `RuntimeDefault`.
- **Files.** `deploy/k8s/deployment.yaml`, `docs/DEPLOYMENT.md`.

### 6. Continuous fuzzing and dependency review

- **Risk.** CI-only fuzzing and `cargo deny` do not catch a zero-day in a
  trusted crate.
- **Proposed change.** Run the fuzz targets continuously and add
  `cargo vet`/`cargo crev` review.
- **Files.** `.github/workflows/`, `fuzz/`, `deny.toml`.

### 7. Restrict and audit container exec

- **Risk.** `docker exec` / `kubectl exec` into the running container bypasses
  every image control.
- **Proposed change.** Restrict who may exec and audit it.
- **Files.** `docs/OPERATIONS.md`, `docs/DEPLOYMENT.md`.

## Priority

Ranked by value against effort:

- **Medium:** items 1, 2, 3. Item 1 is medium/high effort because it needs a
  migration plus a blind index with uniqueness and rotation handling.
- **Lower, mostly operational:** item 4.
- **Container/host hardening:** items 5, 6, 7 are medium/operational.

Recommendation: implement item 1 next. It closes the largest plaintext
disclosure; items 2 and 3 then reduce the cost of a future key compromise.

## Open questions

- Should PII encryption (item 1) be mandatory or gated behind configuration?
- Is the token pepper and TOTP key held in mounted files or a secrets manager
  in the target deployment? This decides whether envelope encryption (item 2)
  is worth building at all.
- Is a sandboxed runtime class (gVisor/Kata) available in the target cluster?

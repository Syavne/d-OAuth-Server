# TODO

This is a backlog of deferred hardening work. Each item is a candidate to be
planned and implemented later; none of them is a current defect that makes the
server unusable. The items came out of a threat-model review that asked two
questions: what an attacker can still read or crack from a full dump of the
PostgreSQL database, and what an attacker already inside the image's trust
boundary can reach.

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

## Container and host hardening

The attack surface and the controls already in place are documented in
[SECURITY.md](SECURITY.md); this section lists only the mitigations that remain.
It answers a second threat-model question: if an attacker is already inside the
image's trust boundary, how could they reach the container or the host, and how
should we reduce that risk? The remaining vectors are narrow.

### 3. NetworkPolicy versus remote `request_uri`

- **Risk.** The default-deny egress blocks outbound HTTPS, so the JAR
  `request_uri` fetch (`src/jose/jar/fetch.rs`) cannot reach a publicly routable
  request-object host. A deployment either relies on a feature that silently
  fails, or loosens egress further than intended.
- **Proposed change.** Decide per deployment: allow the specific request-object
  host on 443 with a scoped rule, or document that remote `request_uri` is
  unavailable under the shipped policy. A blanket 443 allowance is not an
  option because it restores arbitrary exfiltration.
- **Files.** `deploy/k8s/networkpolicy.yaml`, `docs/DEPLOYMENT.md`.

### 4. Narrow Postgres/Redis egress to their destination

- **Risk.** `networkpolicy.yaml` allows egress to *any* address on ports 5432 and
  6379 (link-local excluded), so those ports are an exfiltration channel to an
  arbitrary internet host, not only the database and cache.
- **Proposed change.** Where Postgres and Redis run in-cluster, replace the
  `ipBlock: 0.0.0.0/0` peer with their `namespaceSelector`/`podSelector` so only
  the real endpoints are reachable; keep a port-scoped rule only for an external
  managed database.
- **Files.** `deploy/k8s/networkpolicy.yaml`, `docs/DEPLOYMENT.md`.

## Priority

Ranked by value against effort:

- **Medium:** items 1 and 2. Item 1 is medium/high effort because it needs a
  migration plus a blind index with uniqueness and rotation handling.
- **Container/host hardening:** item 3 is the concrete correctness risk; item 4
  is the egress-narrowing follow-up.

Recommendation: implement item 1 next. It closes the largest plaintext
disclosure; item 2 then reduces the cost of a future key compromise.

## Open questions

- Should PII encryption (item 1) be mandatory or gated behind configuration?
- Is the token pepper and TOTP key held in mounted files or a secrets manager
  in the target deployment? This decides whether envelope encryption (item 2)
  is worth building at all.
- Which target environments rely on remote JAR `request_uri` objects? This
  decides whether item 3 needs a scoped egress rule or only documentation.
- Do Postgres and Redis run in-cluster? This decides whether item 4 can narrow
  egress to their namespace/selector.

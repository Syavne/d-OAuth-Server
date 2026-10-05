# TODO

This is a backlog of deferred hardening work. Each item is a candidate to be
planned and implemented later; none of them is a current defect that makes the
server unusable. The items came out of a threat-model review of what an attacker
can still read or crack from a full dump of the PostgreSQL database; the
image-trust-boundary items that review surfaced have since been closed (see
[SECURITY.md](SECURITY.md) and [DEPLOYMENT.md](DEPLOYMENT.md)).

This document only records the gaps. It does not describe anything that is
already implemented, and it does not propose code changes here.

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

## Priority

Ranked by value against effort:

- **Medium:** items 1 and 2. Item 1 is medium/high effort because it needs a
  migration plus a blind index with uniqueness and rotation handling.

Recommendation: implement item 1 next. It closes the largest plaintext
disclosure; item 2 then reduces the cost of a future key compromise.

## Open questions

- Should PII encryption (item 1) be mandatory or gated behind configuration?
- Is the token pepper and TOTP key held in mounted files or a secrets manager
  in the target deployment? This decides whether envelope encryption (item 2)
  is worth building at all.

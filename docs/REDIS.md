# Redis

Redis holds every short-lived value: authorization codes, access and refresh
tokens, grant chains, sessions, PAR request URIs, device codes, DCR
initial-access tokens, replay markers, and rate-limit counters. No raw token is
ever a Redis key or value; token keys are keyed hashes and values hold only
derived state. The JWT marker and CIMD cache use an unkeyed SHA-256 over a
random `jti` or a public document URL respectively, neither of which is secret.

## Purpose

This guide covers the key namespaces and their TTLs, the hash-tag scheme that
keeps atomic operations on one Cluster slot, the tombstone and durability
model, and the three supported topologies.

## Key namespaces

The token prefix defaults to `oauth:{state}:` and the rate-limit prefix to
`oauth:{rl}:`. Both are configurable but must keep their hash tags and must
differ.

| Key | Contents | TTL |
| --- | --- | --- |
| `oauth:{state}:code:<hash>` | Single-use authorization code, PKCE-bound. | `ttl.code` (60s), clamped to 60 s (`CODE_TTL_CAP`) |
| `oauth:{state}:access:<hash>` | Access-token record. | `ttl.access_secs` (default 300s) |
| `oauth:{state}:access:<hash>:act` | Token-exchange `act` claim sidecar. | Lives with the access record |
| `oauth:{state}:refresh:<hash>` | Refresh-token record or tombstone. | `ttl.refresh` (30d) |
| `oauth:{state}:grant:<id>` | Grant-chain record. | Refresh lifetime |
| `oauth:{state}:grant:<id>:tokens` | Set of member token hashes for cascade revoke. | Lives with the grant |
| `oauth:{state}:session:<id>` | Server-side login session. | `ttl.session` (12h) |
| `oauth:{state}:session:<id>:meta` | Session sidecar: `auth_time`, CSRF secret, bound `request_id`, and the bound post-logout client/URI. | `ttl.session` |
| `oauth:{state}:par:<id>` | PAR `request_uri` record. | `ttl.par` (90s) |
| `oauth:{state}:pending:<id>` | Validated pending-auth record. | `routes::PENDING_TTL` (300s) |
| `oauth:{state}:device:<hash>` | Device-code record. | `ttl.device` (600s) |
| `oauth:{state}:device:<hash>:cnf` | Device sender-binding sidecar. | Lives with the device record |
| `oauth:{state}:device:<hash>:poll` | Device poll-throttle marker. | Lives with the device record |
| `oauth:{state}:user_code:<code-hash>` | User code to device-hash mapping. | `ttl.device` |
| `oauth:{state}:dcr_iat:<hash>` | DCR initial-access token budget. | CLI `--ttl` |
| `oauth:{state}:dpop_jti:<hash>` | DPoP `jti` replay marker. | 300 s (`DPOP_JTI_TTL`; fixed, independent of proof `iat`) |
| `oauth:{state}:client_assertion_jti:<hash>` | `private_key_jwt` `jti` replay marker. | Remaining assertion validity (`exp + 30s skew - now`), clamped `[1s, 360s]` (300s max lifetime + 2×30s skew) |
| `oauth:{state}:rotation:<request-id>` | Rotation idempotency mapping. | `min(900s, refresh TTL)` |
| `oauth:{state}:loginfail:<sha256>` | Failed-login counter (hashed label; the global per-account cap). | `ui::login::LOCKOUT_WINDOW` (15 min) |
| `oauth:{state}:loginfail:ip:<sha256>:<sha256>` | Composite failed-login counter for one source IP and one account (both halves hashed; locks that IP only). | `ui::login::LOCKOUT_WINDOW` (15 min) |
| `oauth:{state}:loginfail:unknown:<sha256>` | Unknown-label bucket for one source IP (hashed IP only; no per-label keys, so label enumeration cannot spray the keyspace). | `ui::login::LOCKOUT_WINDOW` (15 min) |
| `oauth:{state}:totp_replay:<fingerprint>` | TOTP used-code replay marker. The fingerprint is an HMAC under the token pepper (never the code itself), so a dump does not reveal the code. | 180 s (`USED_CODE_TTL`; fixed, 6× the 30 s step) |
| `oauth:{state}:jwt:<jti-hash>` | JWT access-token kill marker (allowlist: a signed token is valid only while this hash is live). Carries `grant_id`, `client_id`, and the raw `subject` (email/user-id; empty for client-credentials), matching the `purge_subject` `subject` decoder. | `ttl.access_secs` (default 300s) |
| `oauth:{state}:cimd:<sha256>` | Cached client-id-metadata document (keyed by a hash of the URL, never the raw URL). | 15 minutes |
| `oauth:{state}:cimd:neg:<sha256>` | Negative cache for an origin-level CIMD fetch failure (network/TLS/non-2xx, timeout, non-JSON). | 30 seconds |
| `oauth:{state}:cimd:invalid:<sha256>` | Short completion marker for a fresh-fetch CIMD validation failure, so waiters do not re-fetch a deterministically invalid document. | 2 seconds |
| `oauth:{state}:cimd:lock:<sha256>` | Single-flight fetcher election for one uncached CIMD URL; a random token is released with a compare-and-delete Lua script. | `cimd_fetch_timeout_secs` + 1 s (2–11 s) |
| `oauth:{rl}:ratelimit:<bucket-hash>` | Fixed-window rate-limit counter. | `rate_limit.window` (60s) |

`<hash>` is a keyed hash for token lookups: tokens are opaque, so the server can
look a record up by re-hashing the presented value but cannot recover the raw
value from storage. The `<jti-hash>` of a JWT marker and the CIMD `<sha256>` are
unkeyed because their inputs are already a random token id and a public URL.

Resource audiences (`aud`, RFC 8707) ride on seven record families as a field
named `aud`: `code:`, `access:`, `refresh:`, `grant:`, `par:`, `device:`, and
`pending:` (the last is a JSON blob, not a hash). The value is a JSON array of
strings, so a URI that itself contains a comma can never collide with a
delimiter join. In the hash-backed records it is stored as a JSON string field,
so the rotation Lua script's `cjson.decode` sees a string rather than a Lua
table. A record written by a replica that predates audiences carries no `aud`
field and decodes back to an empty audience, so in-flight records survive a
rolling deploy; a present-but-malformed field fails closed as `InvalidData`.

The audience is `{state}`-keyspace metadata only. Resource indicators add no key
family and no `{rl}` counter; the durable catalog of allowed identifiers lives in
Postgres, not Redis.

JWT access tokens use an allowlist, not a denylist. Each mint writes a
`jwt:<jti-hash>` marker (`grant_id`, `client_id`, `subject`, TTL
`ttl.access_secs`) in the same atomic script as the grant membership, and a token is
live only while that hash exists. Because the marker rides the `{state}` tag, it
is single-slot with the access record and the grant set. Three paths delete it:

- A grant cascade deletes `jwt:<hash>` markers through the third ARGV of the
  revoke script, together with the member access records and the grant set.
- `user disable` sweeps `jwt:` keys by their `subject` field. Grant-bound
  markers are also covered by the cascade; markers for client-credentials
  tokens (empty subject) and any marker left outside a live grant rely on this
  sweep.
- `POST /revoke` with a JWT-shaped token deletes the marker, the
  `access:jwt:<hash>` record, and the grant membership after verifying the
  signature, `iss`, and ownership, then runs a durability barrier.

A resource server that verifies locally against `/jwks.json` never reads this
keyspace, so it cannot observe a deletion. See
[OAUTH.md](OAUTH.md#the-resource-server-trade-off) for that exp-bounded
trade-off.

## Hash tags and single-slot atomicity

Every token-state key carries the `{state}` hash tag, so one Lua operation that
touches several keys lands on a single Cluster slot. Rate-limit counters carry
`{rl}`, which puts them in a different slot group and a different shard from
token state. This is what keeps two promises:

- A multi-key token operation never fails with `CROSSSLOT`.
- Counters can never evict tokens, because the two keyspaces are separate and
  Redis eviction is off by default (`noeviction`, required unless
  `redis.noeviction_required` is set false).

The server asserts both properties at startup and refuses a prefix that lacks
its tag.

## Record writes

Every hash record is written through one atomic Lua script (`hset_record` →
`HSET_TTL`): the fields and the `PEXPIRE` happen in a single script, so no
record can ever be observed — or survive a crash — without its TTL. Replay
markers are `SET NX PX` plus a durability barrier.

## Rotation, tombstones, and idempotency

Refresh rotation is a Lua compare-and-set keyed by a deterministic
`rotation_request_id`, derived as an HMAC of the pepper over the old refresh
token hash. The script returns one of:

- `ROTATED`: the refresh was valid and new tokens were written.
- `REPLAY`: the same request id already completed, so the same minted tokens
  are returned. A lost reply does not cause a double rotation.
- `REUSE`: the presented token was already rotated. Its tombstone records the
  member it rotated to. Reuse also cascades revocation of the whole grant
  family.
- `ABSENT`: unknown token.
- `MISMATCH`: issued to a different client.
- `NOGRANT`: the grant record is gone (a mint racing a cascade is fenced
  before any write, so nothing is stored and no cascade runs).

The old refresh record is not deleted. It becomes a tombstone with a `used`
flag and a `rotated_to` member, kept for the refresh lifetime so reuse stays
detectable. The new tokens are minted before the script runs, so a crash during
the write cannot mint a token that was never stored.

Grant cascade `revoke` drains in a bounded loop: one script pass is atomic but
blind to a mint racing the cascade, so the pass repeats until the member set
reads empty and a token minted mid-cascade is deleted by a later pass (or
refused outright by the rotation `NOGRANT` fence) instead of surviving.

## The durability barrier

A rotation, tombstone, or replay-marker write is followed by a durability
barrier issued as a separate command after the write returns and before any
token is returned to the client. It is never run inside a Lua script or
`MULTI`/`EXEC`, where `WAIT` and `WAITAOF` do not block.

| Mode | Topology | Barrier |
| --- | --- | --- |
| `wait` | Sentinel or Cluster | `WAIT 1 <timeout>`; the write must be acknowledged by at least one replica. |
| `waitaof` | Single node | `WAITAOF 1 0 <timeout>`; the local AOF must be flushed. Falls back to the `appendfsync always` assertion on servers older than Redis 7.2. |
| `appendfsync_always` | Single node | Assert `CONFIG GET appendfsync` is `always`. This is instance-wide, not per-write-path. |

A barrier below the required level fails closed with `503`, mapped from
`StoreError::Durability`. Exception: a refresh rotation whose originating
write already applied returns the minted pair as `RotatedUnbarriered` instead
of `503` (any other caller, including a `Replay` hit, stays fail-closed).
The server-side wait leaves 500 ms of headroom under
the client response timeout so an expired barrier surfaces as a clean failure
rather than an ambiguous timeout.

The start of a claim: with the barrier active, a failover cannot resurrect a
rotated token or lose a replay marker. Any residual window only exists where
neither barrier nor `appendfsync always` is active, which the configuration
refuses for a single node.

## Topologies

Exactly one topology is selected at load time.

### Single

One node from `redis.url`, using the driver's `ConnectionManager`. Durability
must be `waitaof` or `appendfsync_always`; `wait` is rejected because there are
no replicas.

### Sentinel

A set of `host:port` nodes plus `master_name`. The driver's built-in Sentinel
support does not reliably follow a promoted master after a failover, so the
server hand-builds master re-resolution: when the current master fails, it asks
the Sentinels for the new master and reconnects. Durability is `wait`.

### Cluster

A set of seed nodes. The server uses native slot refresh, so `MOVED` and `ASK`
redirects recover without a restart. Multi-key token operations stay single-slot
through the `{state}` tag. Durability is `wait`.

## Error classification and retries

Errors are classified as `Transient` or `Permanent`.

- Transient: I/O errors, timeouts, dropped connections, and `LOADING`,
  `TRYAGAIN`, `MASTERDOWN`, `CLUSTERDOWN`, `MOVED`, `ASK`, `NOSCRIPT`.
- Permanent: `OOM` under noeviction, `READONLY`, auth failures, `CROSSSLOT`,
  type errors, and anything unrecognized.

Only idempotent reads and `SET NX` or idempotent Lua compare-and-set are
retried, and only on transient errors, under a bounded budget with jittered
backoff. Non-idempotent operations such as single-use consumes and `INCR` are
never retried. On an indeterminate post-`EXEC` result the caller re-reads the
rotation mapping or the record instead of replaying the write.

## Security properties

- Token keys are keyed hashes; the JWT marker and CIMD cache use an unkeyed
  SHA-256 over a random `jti` or a public URL. A Redis dump does not reveal a
  usable token.
- `noeviction` and AOF are required by default and asserted at startup unless
  the matching opt-out flag (`redis.noeviction_required` or `redis.aof_required`)
  is set false.
- Token state and rate-limit counters are separated, so a counter cannot evict
  a token.
- Replay markers are written atomically with `SET NX`, so a replayed `jti` is
  rejected.
- A failed durability barrier fails the request closed rather than returning a
  weakly durable token.

## Edge cases

- A Redis flush loses every ephemeral value but not clients, users, scopes, or
  redirect URIs. Clients registered through DCR can still be managed, because
  the registration access token hash is in Postgres.
- A rotation after a failover does not double-rotate: the mapping key resolves
  the retry to the original minted tokens.
- A `CROSSSLOT` error fails closed. It is never worked around by splitting an
  atomic operation across slots.

## Subject purge (`user disable`)

`d-oauth-server user disable --email <email>` revokes the user's ephemeral
state before the Postgres `disabled` flag flips (fail closed: a Redis outage
leaves the user enabled). The purge deletes every record whose `subject`
field is the canonical email or the user-id string:

- `session:<id>` records plus their `:meta` sidecars.
- The `loginfail:<sha256>` account counter plus every `loginfail:ip:*:<sha256>`
  composite bucket for the normalized email. The `loginfail:unknown:<sha256>`
  buckets carry no account label and are never touched.
- `code:<hash>` authorization-code records.
- `device:<hash>` records plus their `:cnf`/`:poll` sidecars and the
  `user_code:<code-hash>` mappings that point at them.
- `grant:<id>` families via the grant cascade (member token keys, the
  `:tokens` set, the record, and member `:act` sidecars), plus standalone
  `access:<hash>` (with `:act`) and `refresh:<hash>` records.
- `jwt:<jti-hash>` allowlist markers whose `subject` field matches. The grant
  cascade already removes markers for grant-bound tokens; this sweep covers a
  marker whose grant set is already gone. Client-credentials markers carry an
  empty subject, so the subject decoder never matches them; they expire with
  `ttl.access_secs`.

Records without a `subject` field are never touched: `par:`, `pending:`,
`dpop_jti:`, `client_assertion_jti:`, `rotation:`, `totp_replay:`, and the
`{rl}` rate-limit counters.

Like the DCR `DELETE` revocation, the purge scans with `SCAN MATCH <prefix>*
COUNT 100` and filters on the raw hash field. On Cluster topologies a scan
covers the contacted node only (Single and Sentinel scan fully).

`user unlock --email` sweeps the same `loginfail` keyspace the same way
(direct `DEL` of the account counter plus `SCAN MATCH` over the per-IP
composite buckets), so the same Cluster caveat applies: buckets living on
other nodes survive the sweep.

A password change or TOTP re-enrollment reuses the same session sweep scoped
to the subject minus the session in hand (`purge_sibling_sessions` in the
same file): sibling `session:<id>` records plus their `:meta` sidecars are
deleted, everything else is untouched, and no new key layout is introduced.

## Operational runbook

Configure Redis with persistence and eviction off. A minimal single-node
configuration looks like:

```conf
appendonly yes
appendfsync everysec
maxmemory-policy noeviction
min-replicas-to-write 1
min-replicas-max-lag 10
```

For a single node without replicas, use `appendfsync always` or Redis 7.2+ so
`WAITAOF` is available, and set `redis.durability = waitaof`.

On startup the server runs `PING`, checks `maxmemory-policy`, and checks
`appendonly`. A violation is a startup failure, not a warning, unless the
matching opt-out flag (`redis.noeviction_required` or `redis.aof_required`) is
set false. To inspect a key family, use `SCAN` with the prefix; never use `KEYS`
in a request path.

## File and directory references

- `src/store/mod.rs` for the key layout, Lua scripts, and the barrier.
- `src/store/tokens.rs`, `src/store/grants.rs`, `src/store/codes.rs`,
  `src/store/sessions.rs`, `src/store/par.rs`, `src/store/device.rs`,
  `src/store/dcr.rs`, `src/store/ratelimit.rs` for the per-family records.
- `src/protocol/purge.rs` for the `user disable` subject purge.
- `src/config/redis.rs` for topology, durability, and prefix validation.
- `src/state/redis.rs`, `src/state/sentinel.rs` for connection management.

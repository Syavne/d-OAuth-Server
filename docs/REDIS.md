# Redis

Redis holds every short-lived value: authorization codes, access and refresh
tokens, grant chains, sessions, PAR request URIs, device codes, DCR
initial-access tokens, replay markers, and rate-limit counters. No raw token is
ever a Redis key or value; keys are keyed hashes and values hold only derived
state.

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
| `oauth:{state}:code:<hash>` | Single-use authorization code, PKCE-bound. | `ttl.code` (60s) |
| `oauth:{state}:access:<hash>` | Access-token record. | `ttl.access` (300s) |
| `oauth:{state}:refresh:<hash>` | Refresh-token record or tombstone. | `ttl.refresh` (30d) |
| `oauth:{state}:grant:<id>` | Grant-chain record. | Refresh lifetime |
| `oauth:{state}:grant:<id>:tokens` | Set of member token hashes for cascade revoke. | Lives with the grant |
| `oauth:{state}:session:<id>` | Server-side login session. | `ttl.session` (12h) |
| `oauth:{state}:session:<id>:meta` | Session sidecar: `auth_time`, CSRF secret, bound `request_id`, and the bound post-logout client/URI. | `ttl.session` |
| `oauth:{state}:par:<id>` | PAR `request_uri` record. | `ttl.par` (90s) |
| `oauth:{state}:pending:<id>` | Validated pending-auth record. | Short, request-scoped |
| `oauth:{state}:device:<hash>` | Device-code record. | `ttl.device` (600s) |
| `oauth:{state}:user_code:<code-hash>` | User code to device-hash mapping. | `ttl.device` |
| `oauth:{state}:dcr_iat:<hash>` | DCR initial-access token budget. | CLI `--ttl` |
| `oauth:{state}:dpop_jti:<hash>` | DPoP `jti` replay marker. | Proof freshness window |
| `oauth:{state}:client_assertion_jti:<hash>` | `private_key_jwt` `jti` replay marker. | Assertion window |
| `oauth:{state}:rotation:<request-id>` | Rotation idempotency mapping. | `min(900s, refresh TTL)` |
| `oauth:{state}:loginfail:<sha256>` | Failed-login counter (hashed label). | Rate-limit window |
| `oauth:{state}:totp_replay:<fingerprint>` | TOTP used-code replay marker. | Time step window |
| `oauth:{rl}:ratelimit:<bucket-hash>` | Fixed-window rate-limit counter. | `rate_limit.window` (60s) |

`<hash>` is always a keyed hash. Tokens are opaque, so the server can look a
record up by re-hashing the presented value but cannot recover the raw value
from storage.

## Hash tags and single-slot atomicity

Every token-state key carries the `{state}` hash tag, so one Lua operation that
touches several keys lands on a single Cluster slot. Rate-limit counters carry
`{rl}`, which puts them in a different slot group and a different shard from
token state. This is what keeps two promises:

- A multi-key token operation never fails with `CROSSSLOT`.
- Counters can never evict tokens, because the two keyspaces are separate and
  Redis eviction is off entirely (`noeviction`).

The server asserts both properties at startup and refuses a prefix that lacks
its tag.

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

The old refresh record is not deleted. It becomes a tombstone with a `used`
flag and a `rotated_to` member, kept for the refresh lifetime so reuse stays
detectable. The new tokens are minted before the script runs, so a crash during
the write cannot mint a token that was never stored.

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
`StoreError::Durability`. The server-side wait leaves 500 ms of headroom under
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

- Only keyed hashes are stored. A Redis dump does not reveal a usable token.
- `noeviction` and AOF are required and asserted at startup.
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
`appendonly`. A violation is a startup failure, not a warning. To inspect a key
family, use `SCAN` with the prefix; never use `KEYS` in a request path.

## File and directory references

- `src/store/mod.rs` for the key layout, Lua scripts, and the barrier.
- `src/store/tokens.rs`, `src/store/grants.rs`, `src/store/codes.rs`,
  `src/store/sessions.rs`, `src/store/par.rs`, `src/store/device.rs`,
  `src/store/dcr.rs`, `src/store/ratelimit.rs` for the per-family records.
- `src/config/redis.rs` for topology, durability, and prefix validation.
- `src/state/redis.rs`, `src/state/sentinel.rs` for connection management.

# OAuth

This is an OAuth 2.1-only authorization server. It deliberately does not
implement the OAuth 2.0 behaviors that 2.1 removes. The server core is the
grant machinery under `src/protocol/`.

## Specification reference

This server targets **`draft-ietf-oauth-v2-1-16`**, "The OAuth 2.1
Authorization Framework".

- **Published:** 3 September 2026.
- **URL:** https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
- **Versioned text:**
  https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt

This is an Internet-Draft (work in progress), not a published RFC. It may be
updated, replaced, or obsoleted by other documents at any time, and citing it
here does not imply endorsement. The version above is the one this
implementation was reviewed against.

The draft consolidates RFC 6749 (OAuth 2.0), RFC 6750 (Bearer Token Usage),
RFC 8252 (OAuth 2.0 for Native Apps), RFC 9700 (Security Best Current
Practice), and the Browser-Based Apps draft.

## Purpose

For a protocol implementer or an integrator: the exact deltas from OAuth 2.0 and
the section citation behind each, the endpoints, the five grants and their
parameters, PKCE, redirect matching, and the error codes.

## Mandatory OAuth 2.1 deltas from 2.0

The 2.1 draft consolidates the OAuth 2.0 core with the security best current
practice in RFC 9700. This server enforces every one of these:

| Delta | Behavior here | Reference |
| --- | --- | --- |
| PKCE is mandatory for every authorization-code flow | A request without `code_challenge` is rejected; only `S256` is accepted. | draft-ietf-oauth-v2-1-16, RFC 9700 §2.1.1 |
| The `plain` PKCE method is removed | `code_challenge_method=plain` is rejected. | RFC 7636 §4.3, RFC 9700 §2.1.1 |
| The implicit grant is removed | Only `response_type=code` exists; there is no token response. | draft-ietf-oauth-v2-1-16, RFC 9700 |
| The resource-owner-password grant is removed | There is no `grant_type=password` code path. | draft-ietf-oauth-v2-1-16 |
| Bearer credentials in the URI query are rejected | Access tokens are presented in the `Authorization` header. | draft-ietf-oauth-v2-1-16 §5.1 |
| Redirect URIs are matched exactly | No prefix or wildcard match; one RFC 8252 loopback exception (`localhost` only under `allow_localhost_redirect`). | RFC 9700 §2.1, RFC 3986 §6.2.1 |
| All refresh tokens rotate on every use | Rotation with tombstone reuse detection applies to every refresh grant. | RFC 9700 §2.2.2, §4.14 |
| Authorization codes are single-use and short-lived | A code is consumed atomically and capped at 60 seconds. | RFC 9700 §4.5.3 |
| `state` is supported and echoed | The value is returned on the success and error redirects. | RFC 6749 §4.1.2.1 |
| No open redirect | The redirect URI must be registered, attached, and enabled. | RFC 9700 §4.1.3 |

## Endpoints

All endpoints are on the TLS public listener. The plaintext health listener
mounts only `/health/live` and `/health/ready`.

| Method | Path | Reference | Status |
| --- | --- | --- | --- |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 | Wired |
| GET | `/authorize` | RFC 6749 §4.1.2.1, RFC 9700 §4.1.3 | Wired |
| POST | `/par` | RFC 9126 §2.1 | Wired |
| POST | `/token` | RFC 6749 §4.1.3, RFC 8628 §3.4, RFC 8693 §2 | Wired |
| POST | `/device_authorization` | RFC 8628 §3.1 | Wired |
| GET, POST | `/device` | RFC 8628 §3.3 | Wired |
| GET, POST | `/login` | RFC 9700 §4.7.1 | Wired |
| GET | `/login/success` | server-specific | Wired |
| GET, POST | `/login/change-password` | server-specific | Wired |
| GET | `/login/totp/setup` | server-specific | Wired |
| GET, POST | `/login/totp/confirm` | server-specific | Wired |
| GET, POST | `/logout` | server-specific | Wired |
| GET, POST | `/consent` | RFC 9700 §4.7.1 | Wired |
| POST | `/introspect` | RFC 7662 §2.1 | Wired |
| POST | `/revoke` | RFC 7009 §2.1 | Wired |
| POST | `/register` | RFC 7591 §2 | Wired |
| GET, PUT, DELETE | `/register/{client_id}` | RFC 7592 §2 | Wired |
| GET | `/assets/app.css` | server-specific | Wired |
| GET | `/health/live`, `/health/ready` | server-specific (canonical: ARCHITECTURE.md) | Wired |

`GET /logout` and `POST /logout` are a server-specific session endpoint, not a
feature defined by OAuth 2.1 or OIDC. `GET /logout` is read-only: it renders
a confirm page (live session) or a neutral signed-out page (anonymous) and
never destroys the session or writes cookies. Only `POST /logout`, carrying
the session-bound CSRF `form_token`, destroys the authorization-server
session and expires the session cookie (`__Host-session_id`, or plain
`session_id` when `cookie_secure = false`; the clearing cookie mirrors the
session cookie's name and its `Path`/`HttpOnly`/`SameSite`/`Secure`; no `Domain` is ever
emitted, so the cookie stays host-only in both variants). In production the
session reader honors **only** `__Host-session_id`: a plain `session_id` cookie
is never read, so a cookie planted by a sibling subdomain cannot fixate a
victim's login onto an attacker presession. The development variant reads plain
`session_id` and may additionally fall back to `__Host-session_id`; `POST
/logout` clears every name the reader honors. `GET /logout` takes **no query
parameters** and issues no redirect at all, so a forced navigation
cannot cause an open redirect; only `POST /logout` may redirect, and only to a
`post_logout` URI that was **registered for the client and frozen in session
meta when the authorization flow was bound**. It redirects there only when the
owning client is still active and still registers that exact URI (exact-string
match, with the RFC 8252 loopback exception); otherwise it renders a neutral
signed-out page. A `POST /logout` with a live session but no bound redirect
target renders the neutral signed-out page instead of redirecting.
This is what lets a client end the browser SSO session so a different user can
sign in. There is no `post_logout_redirect_uri` parameter, no `id_token_hint`,
and no `end_session_endpoint` in metadata.

The `POST /token` handler parses the form once, authenticates the client
through the shared `client_auth` dispatch, verifies the fresh sender proof,
dispatches on `grant_type` to the matching grant, and shapes the RFC 6749 §5.1
JSON response; an unknown `grant_type` is `unsupported_grant_type`. The DCR
routes map onto `protocol::dcr::register_handler` and
`protocol::dcr::manage::{read,update,delete}_handler` (RFC 7591 / RFC 7592).

### Dynamic client registration

Dynamic registration redirect policy (`dcr_redirect_policy`): `catalog` attaches
only catalog-registered URIs; `catalog_loopback` additionally upserts RFC 8252
loopback URIs; `open` additionally upserts any absolute `https` URI with a
non-empty host and no userinfo, fragment, or whitespace. Loopback URIs are
always allowed. Under `catalog_loopback` and `open`, the RFC 8252 loopback
forms include `http://localhost:{port}` only when `allow_localhost_redirect` is
set; with it off, `http://localhost` is not loopback and is rejected.
Anything else is `invalid_redirect_uri`.

A dynamically registered client always stores `opaque` access tokens. JWT
access tokens are an operator-only opt-in (`client set-access-token-format`),
so a `POST /register` body carrying `access_token_format` is rejected with
`invalid_client_metadata` rather than silently ignored.

### Client ID metadata documents (CIMD)

Reference: `draft-ietf-oauth-client-id-metadata-document-02` §3, §4.1, §5.

CIMD removes registration for clients that can publish an `https://` document.
The client uses that absolute URL as its `client_id`; the authorization server
fetches the URL, validates the JSON document, and uses the result as the client
metadata for the request. This is remote-document trust with strict validation,
not "no fetch" and not "trusted because it registered". `cimd_enabled` (default
off) is the only switch: with it off an `https://` `client_id` with no
registered row keeps the existing unknown-client behavior.

A document is accepted only when all of these hold:

- The fetch is one guarded request: `https` only, redirects disabled, DNS
  pinned to the addresses checked before the request, special-use, private,
  and loopback targets rejected, no proxy, and both a total timeout
  (`cimd_fetch_timeout_secs`, default `5`, allowed `1`-`10`) and a body cap
  (`cimd_max_bytes`, default `5120`, allowed `1`-`5120`). A non-2xx response is
  a failure. The body must be a JSON object.
- The document's `client_id` must equal the fetched URL byte for byte. No
  normalization is performed.
- `token_endpoint_auth_method` must be absent, `none`, or `private_key_jwt`.
  Every shared-secret and mTLS method is rejected.
- Any `jwks_uri` member is rejected. For `private_key_jwt`, an inline `jwks`
  with a non-empty `keys` array is required. This is inline-only by decision,
  so client authentication never starts a second network fetch. An inline
  `jwks` on a `none` document is ignored: that client does not authenticate
  with a key.
- `redirect_uris` must be a non-empty array. Each entry is an absolute
  `http`/`https` URI with a non-empty host and no userinfo, query, or fragment,
  and no entry may contain `*`. Plaintext `http` is accepted only for an RFC
  8252 §7.3 loopback host: `127.0.0.1` and `[::1]` always, `localhost` only
  while `allow_localhost_redirect` is on. The check reuses the registered-client
  redirect matcher, so the two paths cannot disagree.
- `grant_types`, when present, must be a non-empty subset of
  `{authorization_code, refresh_token}`; when absent it defaults to
  `authorization_code`. Device, client-credentials, and token-exchange grants
  are not available to a CIMD client.
- `scope`, when present, must be a subset of the enabled scope catalog. An
  absent or empty `scope` means an empty client scope.
- `dpop_bound_access_tokens` omitted or `false` means Bearer tokens. `true`
  means DPoP is required at every gate, exactly like a registered client with
  that flag.

A bad redirect URI maps to `invalid_redirect_uri`. Every other document or
fetch failure maps to `invalid_client_metadata`. Only a Redis or Postgres
outage is a fail-closed `503`.

Resolution and the synthetic principal:

- A registered row always wins. A row whose `client_id` happens to be an
  `https://` URL is resolved from Postgres with no document fetch. An existing
  inactive row also blocks the document fetch (it resolved to "client is no
  longer active"), so deactivation cannot be bypassed; only a truly missing row
  can fall back to CIMD.
- The validated document is materialized as an in-memory `client_repo::Client`
  for the request. No `/register` row is written and no initial-access token
  is consumed.
- The client is active with the document's grant allowlist, scope bound, DPoP
  flag, and inline `jwks`. Secret fields, mTLS pins, `jwks_uri`,
  `request_uris`, contacts, and PII are empty. `access_token_format` is always
  `opaque`: a document can never opt into JWT access tokens, and the
  operator-only `client set-access-token-format` command has no CIMD target
  because there is no row.
- PKCE (`S256` only), exact redirect matching, PAR/JAR, and error delivery are
  unchanged. A `private_key_jwt` document authenticates with the inline key
  set; `private_key_jwt` is authentication only and never a sender constraint.
  The DPoP/Bearer outcome comes solely from `dpop_bound_access_tokens`.
- A CIMD `none` client can revoke its own token but cannot introspect: public
  clients do not introspect. A CIMD `private_key_jwt` client can revoke and
  introspect.
- Enabling CIMD does not change the `POST /register` gate. The one-time
  initial-access token requirement, and the `allow_open_registration` opt-out,
  are exactly the same as before.

The validated document is cached for 15 minutes under the `{state}` keyspace as
`cimd:<sha256(url)>` (the hash of the URL, never the raw URL). The parsed
document (unknown members dropped) is cached, and it is revalidated on every
read, so a scope disabled or a catalog row removed during the TTL takes effect
on the next request. A
malformed cache entry is deleted and treated as a miss. A cache hit does not
fetch; a document changed at its origin may therefore be served from cache for
up to the 15-minute TTL. An origin-level fetch failure (network/TLS/non-2xx,
timeout, or non-JSON body) is negatively cached for 30 seconds under
`cimd:neg:<sha256(url)>`. A fresh-fetch validation failure is short-cached for
2 seconds under `cimd:invalid:<sha256(url)>` (a single-flight completion
marker), so a corrected document is seen within 2 seconds and waiters do not
re-fetch a deterministically invalid one; a validation failure on an
already-cached document writes no marker. If the cache write after a successful
validation fails, the validated document is still served, uncached. Concurrent
misses for the same URL elect one fetcher through a `cimd:lock:<sha256(url)>`
Redis lock (TTL = the fetch timeout plus 1 s); the other requests wait for the
positive or negative result for the fetch budget plus 1.5 s, then try once more
to acquire the lock and otherwise fail closed. The lock is released with a
compare-and-delete, so a holder whose TTL expired cannot release a successor's
lock. Redis is not a second source of truth; a Redis read or lock failure on
this path is a fail-closed `503`.

## The five grants

The advertised set is `authorization_code`, `refresh_token`,
`client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`, and
`urn:ietf:params:oauth:grant-type:token-exchange`. DCR may register only
`authorization_code`, `refresh_token`, and `device_code`; `client_credentials`
is never registered for a dynamically created client.

### authorization_code

Reference: RFC 6749 §4.1.3, RFC 9700 §4.5.3, RFC 7636, RFC 9449 §6.

Parameters: `code`, `code_verifier`, `client_id`, optional `redirect_uri`,
`client_secret` or `client_assertion_type` with `client_assertion`, and a DPoP
proof when the client is DPoP-bound (`dpop_bound_access_tokens: true`). An
unbound public client redeems proof-free and receives a `Bearer` token; a
bound public client without a proof fails closed.

Behavior: the code is consumed exactly once. `redirect_uri` is accept-but-ignore
(draft-16 §4.1.3, §10.2): a missing or empty value skips the binding check; a
supplied value must still match exactly or redemption fails `invalid_grant`.
The client, PKCE verifier, and sender proof are all checked before minting. The
token is minted
under the code's grant chain. A refresh token is issued only if the client is
registered for the refresh grant.

### refresh_token

Reference: RFC 6749 §6, RFC 9700 §2.2.2 and §4.14, RFC 9449 §5.

Parameters: `client_id`, `refresh_token`, optional `requested_scope` (which may
narrow but never widen), and a freshly verified sender proof when the binding
requires one. An unbound public client whose stored binding is empty rotates
proof-free and stays `Bearer`; a bound grant still requires its matching proof
on every rotation. The replacement
refresh token keeps the presented scope re-checked against the current
`enabled` catalog and the client's current registration and the user's current
entitlements (fresh Postgres reads), so a revoked scope or entitlement drops
from the retained refresh scope on refresh; an explicit narrower `scope`
(§4.3.1) narrows only the access token and the response `scope`, and the next
rotation from the retained refresh token can still use the full scope.

Behavior: rotation on every use. The presented token is tombstoned with a
`rotated_to` member. Presenting a rotated token again is reuse: the whole grant
family is revoked and the request fails with `invalid_grant`. A lost reply does
not double-rotate, because the rotation is keyed by a deterministic request id
and a retry returns the same tokens. If the refresh token's non-empty subject
resolves to a disabled user, the request fails `invalid_grant` before minting or
rotating.

### client_credentials

Reference: RFC 6749 §4.4, RFC 9449 §6, RFC 8705 §3.

Parameters: `client_id` (confidential clients only), optional `requested_scope`,
and a sender proof when the client is sender-constrained.

Behavior: no user and no subject. The granted scope is the requested scope
intersected with the client's registered scope. No refresh token is issued.

### device_code

Reference: RFC 8628 §3.1 through §3.5.

Authorization: `POST /device_authorization` returns a device code, a user code,
a verification URI, an expiry, and a polling interval. A DPoP-bound public
client must present a proof to start the flow; an unbound public client starts
proof-free. The user completes
`GET /device` and `POST /device` and approves or denies.

Polling: `grant_type=urn:ietf:params:oauth:grant-type:device_code` with
`device_code`. Before approval the response is `authorization_pending`; polling
faster than the interval returns `slow_down`; denial returns `access_denied`;
expiry returns `expired_token`. On approval the token is minted with the scope
recomputed against the approving user's entitlements.

### token_exchange

Reference: RFC 8693 §2 through §4.1.

Parameters: `subject_token`, `subject_token_type` (an access-token type),
optional `actor_token` and `actor_token_type`, optional
`requested_token_type`, optional `requested_scope`, and a sender proof that
matches the subject token's confirmation, not merely the caller's.

Behavior: disabled by default and enabled with `allow_token_exchange`. The
exchange must be on the explicit `(caller, subject, scopes)` allowlist. The
granted scope is the subject's scope intersected with the caller's registered
scope, the subject's entitlements, the enabled catalog, and the allowlist, and
it can only narrow. Chained exchange is rejected.

## Resource indicators (RFC 8707)

Reference: RFC 8707 §2, §2.2, §3, §5.1, §5.2.

The `resource` parameter is honored only when `resource_indicators_enabled` is
set (default off). With the flag off, any request that carries `resource` fails
closed with `invalid_target`; the server never silently drops the parameter and
mints a broader token. The catalog is the enabled `resource_servers` table, an
exact-match allowlist. It is managed with the `resource-server` subcommands
(`create` with an optional `--description`, `list`, `enable`, `disable`,
`delete`) or a `resource_servers` array in `config sync --file`; see
[OPERATIONS.md](OPERATIONS.md#resource-server-onboarding-rfc-9728).

This server's validation is **stricter than RFC 8707 §2**, which only
SHOULD-NOTs a query component and leaves the identifier semantics to the
authorization server:

- Every value must be an absolute `https` URI with a host and no userinfo,
  query, or fragment.
- It must exactly match an enabled catalog row. There is no prefix, suffix,
  sub-path, case folding, or wildcard match; `*` cannot be registered.
- The RFC 8252 §7.3 loopback exception applies only to redirect URIs. It does
  **not** apply to audiences, so a loopback identifier is valid only when it is
  literally registered in the catalog.
- Values are never delimiter-joined. A URI containing a comma is stored as its
  own array element, so it cannot collide with a joined string.
- At most 32 raw `resource` values are accepted per request; more is
  `invalid_target`. Values containing an ASCII control character (at minimum
  NUL) are `invalid_target` before any catalog lookup.
- Duplicates are deduplicated before catalog validation so each distinct
  value costs one lookup. The validated set is sorted and deduplicated
  before it is pinned.

`resource` is a repeated parameter. On `GET /authorize` it is read from the
query string; on `POST /par`, `POST /token`, `POST /device_authorization`, and
`POST /introspect` it is read from the form body. A JAR request object may carry
`resource` as a JSON array or a single string. A `resource` in both the query
string and the request object is `invalid_request_object`, because the merged
single-valued map cannot represent repeats.

### Pinning and binding

| Entry point | Where the audience is pinned | Redemption rule |
| --- | --- | --- |
| `GET /authorize` | `PendingAuth.aud`, then the authorization-code record | The token request's set must equal the code's set; any subset, superset, different member, or an unbound request against a pinned code is `invalid_grant` (RFC 8707 §2). |
| `POST /par` | The PAR record's `aud`; the pushed request is re-validated at authorize | The code carries the same set; the token request must match it exactly. |
| `POST /device_authorization` | The device record's `aud` | An omitted `resource` at poll time inherits the pinned set; a presented set must equal it, else `invalid_grant`. The inherited set is re-validated against the current catalog at poll time; a disabled/deleted member or the flag turned off is `invalid_target` (the device code is consumed, so the client re-authorizes). |
| `POST /token` with `client_credentials` | The access-token record | No refresh token is issued. |
| `POST /token` with `refresh_token` | The rotated access and refresh records | See [Refresh audience narrowing](#refresh-audience-narrowing). The stored full set is re-validated against the current catalog before rotation. |

At `/authorize` the catalog check runs after the redirect URI is validated, so a
bad audience is delivered as an error redirect (`302`) with `invalid_target`
rather than an HTML error page. At the other endpoints it is the usual JSON error
response (`400`). On `/token`, `/introspect`, and `/device_authorization` the
client is authenticated before the catalog lookup, so an unauthenticated caller
observes `invalid_client` rather than a catalog error.

### Refresh audience narrowing

Reference: RFC 8707 §2.2.

A refresh token stays bound to the full audience set the grant was originally
issued with. On rotation:

- An omitted `resource` keeps that full set on both the access and the
  replacement refresh token.
- A present `resource` must be a **subset** of the grant's original set. A
  superset, a different member, or any member against an unbound grant is
  `invalid_target`, rejected before anything is minted or rotated, so the
  presented refresh token stays live.
- A valid subset narrows only the access token. The replacement refresh token
  keeps the full original set, so a later rotation can use the full audience
  again. Scope still intersects and is never widened.
- Before anything is minted or rotated, the stored full set is re-validated
  against the current enabled catalog. A member disabled or deleted since
  issuance, or `resource_indicators_enabled` turned off, is `invalid_target`;
  the presented refresh token stays live for a retry once the identifier is
  enabled again.

### Token exchange is excluded

RFC 8707 `resource` does not apply to the RFC 8693 token-exchange grant. A
`resource` on a
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` request is
`invalid_request`, checked before the catalog lookup, so a bogus value cannot
surface `invalid_target` from a grant whose RFC 8693 semantics are otherwise
untouched. The exchange mints no audience.

### Introspection

`POST /introspect` reports the token's audience in `aud` as a JSON array of
strings, including when there is exactly one audience. The member is omitted
when the record has no audience, and an inactive response never carries it.
This is a documented deviation from RFC 7662 §2.2, which describes `aud` as a
string; the array shape follows RFC 9068 §2.2. Both access-token and
refresh-token records report the audience they carry.

`/introspect` also accepts an **optional repeated `resource`** parameter. This
is a documented local extension to RFC 7662, which defines no such request
parameter. When present, the token is reported active only if its `aud` includes
every requested value; otherwise the response is the ordinary inactive body
(`{"active": false}`) and the token's metadata is not leaked. Inclusion is the
test, so a token pinned to a superset stays active. Without `resource`,
introspection remains audience-agnostic. The caller is authenticated before the
`resource` values are validated against the catalog.

`token_type` is `DPoP` for an access token bound with `cnf.jkt` (RFC 9449
§6.2), `Bearer` for an unbound or mTLS-only access token, and omitted for a
refresh token.

### `invalid_target` and `invalid_grant`

| Situation | Error |
| --- | --- |
| Flag off and any `resource` present | `invalid_target` |
| Relative, non-`https`, or hostless value | `invalid_target` |
| Unknown or disabled catalog row | `invalid_target` |
| Token request set differs from the pinned code or device set | `invalid_grant` |
| Device poll presents a set that differs from the pinned set | `invalid_grant` |
| Refresh or device mint where the stored audience contains a disabled/deleted member, or the indicator flag is off | `invalid_target` (refresh stays live; device code is consumed) |
| Refresh presents a superset, a different member, or a member against an unbound grant | `invalid_target` |
| Introspect presents `resource` the token is not bound to | Inactive body (`200`) |
| `resource` on token exchange | `invalid_request` |
| Postgres unavailable during catalog lookup | `temporarily_unavailable` (`503`, or `302` on the `/authorize` error redirect) |

Metadata advertises the capability as the local extension
`resource_indicators_supported`; see
[`resource_indicators_supported`](#resource_indicators_supported-local-extension).

## PKCE

Reference: RFC 7636, RFC 9700 §2.1.1.

- `S256` is the only accepted `code_challenge_method`. `plain` is never
  advertised and never accepted.
- The verifier is 43 to 128 characters from `ALPHA / DIGIT / - . _ ~`.
- The challenge is exactly 43 base64url characters without padding.
- The verifier is checked against the challenge at redemption with a
  constant-time comparison.
- A challenge without a verifier, a verifier without a challenge, and neither
  are all rejected. The verifier cannot be omitted to downgrade the request.
- RFC 7636 Appendix B test vector is covered by a unit test.

## Redirect URI matching

Reference: RFC 3986 §6.2.1, RFC 8252 §7.3, RFC 9700 §2.1.

- Matching is exact Simple String Comparison: scheme, host, port, path, and
  query must match byte for byte. There is no decoding, no case folding, and no
  prefix or wildcard match.
- The one exception is a native-app loopback URI. A registered
  `http://127.0.0.1` or `http://[::1]` matches the same scheme, host, and path
  on any port, and the request must carry no userinfo, query, or fragment.
- `localhost` is a loopback host only when `allow_localhost_redirect` is set
  (default off). With the flag on, a registered `http://localhost:{port}/path`
  matches the same scheme, host, and path on any port, exactly like the
  literal-IP loopback forms; with it off, `http://localhost` is not a loopback
  host and is rejected as a registration and as a request.
- A private-use URI scheme must contain reverse-DNS dot notation (draft-16
  §2.3.1): `com.example.app:/cb` is accepted, `myapp:/cb` is rejected.
  `https` and the loopback `http` exception are unaffected.
- A registered URI with userinfo, query, or fragment is never eligible for the
  loopback exception.

### Error-delivery matrix

Before a redirect URI is validated, the server must not redirect anywhere. It
returns an HTML page with no `Location` header for: absent or unknown
`client_id`, a JAR/PAR resolution failure, a `client_id` binding mismatch, and a
missing or unregistered `redirect_uri`. The page carries the error's HTTP
status: client errors render `400`, a fail-closed Postgres/PII outage
(`temporarily_unavailable`) renders `503` with `Retry-After: 1`, and a masked
internal failure renders `500`.

After the redirect URI is validated, errors are delivered on the redirect as
`302` with `error`, `error_description`, the echoed `state`, and the RFC 9207
`iss`. This covers
a missing or unsupported `response_type` (`invalid_request` when absent,
`unsupported_response_type` otherwise), `invalid_scope`, `invalid_target` for a
rejected `resource` indicator, the PKCE failures, and a `post_logout` catalog
outage (`temporarily_unavailable`/`server_error`).

## Error codes

Errors use the RFC 6749 §5.2 body `{error, error_description}`.

| Code | HTTP | Typical causes |
| --- | --- | --- |
| `invalid_request` | 400, or 302 on the `/authorize` error redirect once `client_id` and `redirect_uri` are validated | Missing or duplicated parameter; PAR misuse; JAR misuse. |
| `invalid_client` | 401 with `WWW-Authenticate` for Basic or Bearer, else 400 | Bad client authentication; ambiguous mTLS certificate. |
| `invalid_grant` | 400 | Unknown, consumed, or foreign code; rotation reuse; PKCE mismatch; proof against the wrong grant; the token request's resource set differing from the code/device set. |
| `invalid_scope` | 400 | Unknown, disabled, over-registered, or non-entitled scope; refresh widening. |
| `invalid_target` | 400, or 302 on the `/authorize` error redirect once `redirect_uri` is validated | Resource indicator rejected: flag off, non-`https` or relative value, unknown or disabled catalog row, or a refresh audience that exceeds the grant. |
| `unsupported_grant_type` | 400 | A `grant_type` outside the five. |
| `unsupported_response_type` | 302 error redirect | A `response_type` other than `code`. |
| `unauthorized_client` | 400 | A client that may not use the requested grant. |
| `invalid_request_object` | 400 | Malformed, unsigned, mis-bound, or conflicting JAR request object. |
| `invalid_dpop_proof` | 400 | Missing or invalid DPoP proof; replayed `jti`. |
| `invalid_redirect_uri` | 400 | DCR redirect URI not in the catalog or otherwise ineligible. |
| `invalid_client_metadata` | 400 | DCR metadata that violates the rules. |
| `access_denied` | 400 (403 on DCR manage token mismatch) | Resource-owner denial; RFC 7592 token mismatch. |
| `authorization_pending` | 400 | Device flow before approval. |
| `slow_down` | 400 | Device polling faster than the interval. |
| `expired_token` | 400 | Device code or code expired. |
| `temporarily_unavailable` | 503 with `Retry-After: 1` | Postgres or Redis is unavailable on a security path. |
| `server_error` | 500 | A masked internal failure. |

The device polling codes `authorization_pending`, `slow_down`, and
`expired_token` live in `src/protocol/token/grants/device_code/error.rs`
(`DevicePollError`) and have no `AppError` counterpart.

The server never fails open on a security path: a dependency outage yields
`503`, never a silent success.

## Sender constraints

Every sender-constrained grant requires a freshly verified proof of possession
on every use.

| Client class | Binding |
| --- | --- |
| Public | Bearer by default. `dpop_bound_access_tokens: true` makes DPoP mandatory, and a missing proof is a hard `invalid_grant`. |
| Confidential | mTLS and/or DPoP; the confirmation reports both when both are proven. |

`private_key_jwt` is client authentication only. It produces no confirmation and
never satisfies sender constraint. For token exchange, the proof must match the
subject token's confirmation. See [SECURITY.md](SECURITY.md) for the full matrix
and the confirmation propagation rule. `private_key_jwt` accepts `RS256`, `PS256`, `ES256`, and
`EdDSA` only (`none` and HMAC are rejected); DPoP proofs accept `ES256`, `EdDSA`, and `RS256` only (no `PS256`).
The `exp` acceptance bound is 330 s: `exp` may lie at most 300 s past `now` plus
30 s clock-skew leeway. The single-use `jti` marker lives for the assertion's
remaining validity, clamped to `[1 s, 360 s]`.

## JWT access tokens (RFC 9068 profile)

Reference: RFC 9068 §2.1, §2.2, §4; RFC 7517 §5; RFC 8707 §2.

JWT access tokens are opt-in twice. The deployment switch
`jwt_access_tokens_enabled` (default off) must be on, and the individual client
must carry `access_token_format = jwt`, set by the operator with
`client set-access-token-format --client-id <id> --format opaque|jwt`. Dynamic
registration always stores `opaque`, so a client can never opt itself in. A
`jwt` client whose deployment switch is off fails closed with `503`
`temporarily_unavailable` rather than falling back to an opaque token.

Only the access token changes shape. The refresh token, the grant chain, and
every other grant artifact stay opaque and hashed at rest, so refresh rotation,
tombstones, and reuse detection are identical for both formats. Token exchange
is opaque-only: a `jwt`-format caller of the exchange grant is refused with
`503`.

A JWT access token always carries a **non-empty** audience. A `jwt` client must
request at least one `resource` at `/authorize`, `/device_authorization`, or
`client_credentials`; an unbound grant (or a token request whose bound set is
empty) fails closed with `invalid_target`, never `aud: []`. The authorization-
code and device records are consumed before that mint-time check, so a `jwt`
client that authorized without a resource must re-run the flow with one. A
refresh of an unbound grant fails `invalid_target` before rotation, leaving the
refresh token live.

The JOSE header carries `typ: at+jwt`, the configured `kid`, and the configured
algorithm (`ES256` or `EdDSA`; there is no RSA branch because the key material
is a 32-byte P-256 scalar or Ed25519 seed). The claim set is the RFC 9068 §2.2
profile subset this server emits:

| Claim | Content |
| --- | --- |
| `iss` | The configured issuer. |
| `sub` | The resource owner (email or user id); empty for client credentials. |
| `aud` | The RFC 8707 audience as a JSON array, never the string form. A refresh that narrows the audience narrows this claim, not the refresh record. |
| `scope` | The granted scope, space-joined. |
| `exp`, `iat` | Seconds since the Unix epoch; `exp - iat` equals `ttl.access_secs`. |
| `jti` | A random token id. Only its hash is stored, as the allowlist marker. |
| `client_id` | The client the token was issued to (required by §2.2). |
| `cnf` | Present only when the grant is sender-constrained (DPoP or mTLS). |
| `act` | Reserved for a delegated token exchange (RFC 8693 §4.1). Exchange is opaque-only today, so no minted JWT carries it. |

In the authorization-server metadata document, a deployment with the switch on
advertises `jwks_uri` at `<issuer>/jwks.json` and
`access_token_signing_alg_values_supported` with exactly the configured
algorithm. Both members are absent when the switch is off, and the algorithm
list never contains an algorithm the signer cannot produce. `GET /jwks.json`
serves an RFC 7517 §5 JWK Set containing the current key first and every
retained verify-only key. The route is public, returns `200 {"keys":[]}` while
the feature is off, and is served with `Cache-Control: public, max-age=300`, so
resource servers may cache it for five minutes.

### The resource-server trade-off

A resource server that verifies a JWT locally against `/jwks.json` checks the
signature, `iss`, `exp`, and its own audience binding. It cannot see this
server's revocation state. Revoking a JWT removes its `jwt:<jti-hash>` allowlist
marker, but a local verifier does not consult that marker, so it keeps accepting
the token until `exp`. The same holds after `user disable` and after a grant
cascade. This is the deliberate exp-bounded trade-off of self-contained tokens,
not a bug:

- A resource server that needs immediate revocation **MUST** call
  `POST /introspect`, which applies the marker, the grant membership, and the
  current account status on every call.
- A resource server that verifies locally **MUST** keep `ttl.access_secs` short
  (the default is 300 s), because `exp` is the only bound on how long a revoked
  token remains usable there.

## Metadata

`GET /.well-known/oauth-authorization-server` returns the RFC 8414 document.
The only per-request state-dependent member is `scopes_supported`, read from the
enabled `scopes` table on every request. The catalog is mutated out of process
by the CLI, so a per-request read makes a change visible immediately on every
replica with no restart. When Postgres is unavailable the endpoint returns `503`
rather than advertising an unknown list.

`client_id_metadata_document_supported` (CIMD draft §6) is emitted as `true`
only while `cimd_enabled` is on. With the switch off it is absent, not `false`.
Clients that select CIMD check it together with `none` in
`token_endpoint_auth_methods_supported`; `none` is always advertised because it
is a normal public-client method, independent of the CIMD switch. See
[Client ID metadata documents (CIMD)](#client-id-metadata-documents-cimd).

`jwks_uri` (RFC 8414 §2) and `access_token_signing_alg_values_supported`
(RFC 9068 §2.1) are emitted only while `jwt_access_tokens_enabled` is on. When
on, `jwks_uri` is `<issuer>/jwks.json` and the algorithm list contains exactly
the configured `jwt_access_token_signing_alg`, `ES256` or `EdDSA`, never `RS256`
or any other algorithm the signer cannot produce. With the switch off both
members are absent; see [JWT access tokens (RFC 9068
profile)](#jwt-access-tokens-rfc-9068-profile). `code_challenge_methods_supported`
advertises only `S256`.
`authorization_response_iss_parameter_supported` is true, so the authorization
response carries `iss` (RFC 9207). The document advertises
`token_endpoint_auth_signing_alg_values_supported = [ES256, EdDSA, RS256,
PS256]`; `dpop_signing_alg_values_supported` stays `[ES256, EdDSA, RS256]`.

The document carries no `resource_metadata` member: RFC 9728 defines that member
as a `WWW-Authenticate` parameter owned by the resource server, not as
authorization-server metadata (RFC 9728 §4, §5.1). The one RFC 9728 AS-side
member, `protected_resources`, is emitted only when `protected_resources_enabled`
is set (default off). The resource-server side of discovery, the challenge, and
the audience and scope checks are described in [RS-CONTRACT.md](RS-CONTRACT.md).

### `resource_indicators_supported` (local extension)

RFC 8707 registers the `resource` request parameter (§5.1) and the
`invalid_target` error (§5.2), but defines no authorization-server metadata
member. `resource_indicators_supported` is therefore this server's vetted local
extension, not a registered RFC 8414 member: a client must treat it as
advisory and fall back to attempting `resource` when it is absent.

It is emitted as `true` only when `resource_indicators_enabled` is set (default
off). With the flag off the member is absent, not `false`, so the document never
advertises a capability the server would reject with `invalid_target`. When the
flag is on, the endpoints in
[Resource indicators (RFC 8707)](#resource-indicators-rfc-8707) accept the
parameter subject to the enabled resource-server catalog; token exchange is
excluded.

## JAR and PAR

Reference: RFC 9101 §4.1 and §5.2, RFC 9126 §2 and §3.

- At `/authorize`, a confidential client must use either a PAR-issued
  `request_uri` or a signed `request` object. A public client may use the query
  string.
- A signed request object must be signed, must have `iss` equal to `client_id`,
  must target the issuer as `aud`, and must use `RS256`, `PS256`, `ES256`, or
  `EdDSA` (`none` and everything else are rejected before key selection).
  Conflicts between the object and the query string are rejected.
- A `request_uri` is a one-time, client-bound PAR handle or an exactly
  pre-registered URI. It is fetched only with the SSRF guard: https only, no
  redirects, global IPs only, size and time capped. The connection is pinned to
  the addresses validated before the fetch, so a rebinding hostname cannot steer
  it to a blocked address.
- A remote (pre-registered, non-PAR) `request_uri` is fetched over outbound
  HTTPS, which the shipped cluster network policy default-denies. It is
  available only when the deployment adds a scoped egress allowance for the
  specific host; see [DEPLOYMENT.md](DEPLOYMENT.md#network-policy).

## Security properties

- A code or device code is single-use and consumed atomically.
- A rotation is idempotent and reuse is tombstoned and detected.
- A redirect is matched exactly, and errors before redirect validation do not
  redirect.
- The confirmation claim propagates to every newly minted token.
- A dependency outage fails closed.

## Edge cases

- A refresh request that omits `scope` keeps the prior grant on both new tokens
  after re-checking against the current `enabled` catalog, client registration,
  and user entitlements (fresh Postgres reads), with revoked entries dropped
  silently from the retained scope (possibly to empty); an explicit `scope`
  must be a subset of the prior grant and all three current sets, and narrows
  only the access token and the response `scope` — the replacement refresh
  token retains the full re-checked scope (draft-16 §4.3.1 + §4.3.3), so a
  later rotation with an omitted `scope` restores the full retained scope.
- A second authorization code made from the same request is a distinct code;
  each is single-use.
- A DPoP proof outside the `iat` freshness window, or with a replayed `jti`, is
  rejected.
- A pre-7.2 Redis has no `WAITAOF`; the server then requires instance-wide
  `appendfsync always`, or fails closed.

## Operational runbook

- Confirm the advertised capabilities:

```bash
curl -s https://auth.example.com/.well-known/oauth-authorization-server | jq .
```

- A code flow starts with `GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256`.
- Introspect a token: `POST /introspect` with `token` and client authentication.
  A token whose subject is a disabled user returns `{"active": false}` like an
  unknown token.
- Revoke a token: `POST /revoke` with `token` and an optional `token_type_hint`.
- If every security endpoint returns `503`, check `/health/ready` and the
  Postgres and Redis connections.

## File and directory references

- `src/protocol/authorize.rs` for authorization validation and the error matrix.
- `src/protocol/code.rs` for code issuance and the success redirect.
- `src/protocol/token/` for the grants and `TokenService`.
- `src/protocol/par.rs`, `src/protocol/device.rs`, `src/protocol/introspect.rs`,
  `src/protocol/revoke.rs` for the other endpoints.
- `src/protocol/dcr.rs`, `src/protocol/dcr/manage.rs` for registration.
- `src/protocol/metadata.rs` for the RFC 8414 document.
- `src/crypto/pkce.rs` for PKCE.
- `src/protocol/redirect_repo.rs` for redirect matching.
- `src/protocol/params.rs` for repeated-parameter parsing and RFC 8707
  audience validation.
- `src/db/resource_repo.rs` for the resource-server catalog.
- `src/jose/` for DPoP, JAR, and `private_key_jwt`.
- `src/error.rs` for the error-to-HTTP mapping.

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
| Bearer credentials in the URI query are rejected | Access tokens are presented in the `Authorization` header. | RFC 6750 §2 |
| Redirect URIs are matched exactly | No prefix or wildcard match; one loopback exception. | RFC 9700 §2.1, RFC 3986 §6.2.1 |
| Public-client refresh tokens rotate | Rotation on every use, with tombstone reuse detection. | RFC 9700 §2.2.2, §4.14 |
| Authorization codes are single-use and short-lived | A code is consumed atomically and capped at 60 seconds. | RFC 9700 §4.5.3 |
| `state` is supported and echoed | The value is returned on the success and error redirects. | RFC 6749 §4.1.2.1 |
| No open redirect | The redirect URI must be registered, attached, and enabled. | RFC 9700 §4.1.3 |

## Known gaps against draft-ietf-oauth-v2-1-16

An internal audit found the gaps below against the draft cited above. They are
listed as work "to revise", not as defects that make the server unusable. Each
entry names the draft section, what the implementation does today, and the
change to make.

1. **Token endpoint requires `redirect_uri`**: draft-16 §4.1.3 removed
   `redirect_uri` from the token request, and §10.2 says the back-compat mode
   must allow it, not require it. The implementation rejects a token request
   with an empty `redirect_uri` (`invalid_request`), which can break pure-2.1
   clients. To revise: accept-but-ignore it (or make it a per-client opt-in),
   never require it.

2. **Authorization error redirects omit `iss`**: draft-16 §4.1.2.1 and
   §7.15.1 make `iss` required on the authorization response, including errors.
   The success redirect includes `iss`, but the error redirect (`error`,
   `error_description`, `state`) does not. To revise: add `iss` to the error
   redirect.

3. **Missing `response_type` returns a direct error page instead of a redirect**:
   once `client_id` and `redirect_uri` are validated, draft-16 §4.1.1 and
   §4.1.2.1 require the error to be delivered via redirect. To revise: move the
   absent-`response_type` case to the redirect path.

4. **Rotated refresh-token scope narrows instead of staying identical**:
   draft-16 §4.3.3 requires the new refresh token's scope to be identical to the
   presented one, while §4.3.1 permits requesting a narrower scope. To revise:
   keep the new refresh token's scope identical and narrow only the access
   token, or document the deviation explicitly.

5. **No pinned TLS 1.2 minimum**: draft-16 §1.5 and §7.14 require TLS 1.2 or
   above. The server relies on rustls defaults rather than asserting a minimum
   protocol version. To revise: assert the minimum version explicitly and test
   it.

Two lower-priority SHOULD-level notes:

- The consent success redirect uses `302` where the draft prefers `303`
  (draft-16 §7.5.4).
- There is no reverse-DNS `.` check for a private-use URI scheme
  (draft-16 §2.3.1).

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
| GET, POST | `/logout` | server-specific | Wired |
| GET, POST | `/consent` | RFC 9700 §4.7.1 | Wired |
| POST | `/introspect` | RFC 7662 §2.1 | Wired |
| POST | `/revoke` | RFC 7009 §2.1 | Wired |
| POST | `/register` | RFC 7591 §2 | Wired |
| GET, PUT, DELETE | `/register/{client_id}` | RFC 7592 §2 | Wired |

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
always allowed. Anything else is `invalid_redirect_uri`.

## The five grants

The advertised set is `authorization_code`, `refresh_token`,
`client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`, and
`urn:ietf:params:oauth:grant-type:token-exchange`. DCR may register only
`authorization_code`, `refresh_token`, and `device_code`; `client_credentials`
is never registered for a dynamically created client.

### authorization_code

Reference: RFC 6749 §4.1.3, RFC 9700 §4.5.3, RFC 7636, RFC 9449 §6.

Parameters: `code`, `redirect_uri`, `code_verifier`, `client_id`,
`client_secret` or `client_assertion_type` with `client_assertion`, and a DPoP
proof when the code is DPoP-bound.

Behavior: the code is consumed exactly once. The client, redirect URI, PKCE
verifier, and sender proof are all checked before minting. The token is minted
under the code's grant chain. A refresh token is issued only if the client is
registered for the refresh grant.

### refresh_token

Reference: RFC 6749 §6, RFC 9700 §2.2.2 and §4.14, RFC 9449 §5.

Parameters: `client_id`, `refresh_token`, optional `requested_scope` (which may
narrow but never widen), and a freshly verified sender proof. The effective
scope is re-checked against the current `enabled` catalog and the client's
current registration and the user's current entitlements (fresh Postgres
reads), so a revoked scope or entitlement drops on refresh.

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
a verification URI, an expiry, and a polling interval. The user completes
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
- `localhost` is never treated as a loopback host.
- A registered URI with userinfo, query, or fragment is never eligible for the
  loopback exception.

### Error-delivery matrix

Before a redirect URI is validated, the server must not redirect anywhere. It
returns a `400` HTML page with no `Location` header for: absent or unknown
`client_id`, a JAR/PAR resolution failure, a `client_id` binding mismatch, and a
missing or unregistered `redirect_uri`.

After the redirect URI is validated, errors are delivered on the redirect as
`302` with `error`, `error_description`, and the echoed `state`. This covers
`unsupported_response_type`, `invalid_scope`, and the PKCE failures.

## Error codes

Errors use the RFC 6749 §5.2 body `{error, error_description}`.

| Code | HTTP | Typical causes |
| --- | --- | --- |
| `invalid_request` | 400 | Missing or duplicated parameter; PAR misuse; JAR misuse. |
| `invalid_client` | 401 with `WWW-Authenticate` for Basic or Bearer, else 400 | Bad client authentication; ambiguous mTLS certificate. |
| `invalid_grant` | 400 | Unknown, consumed, or foreign code; rotation reuse; PKCE mismatch; proof against the wrong grant. |
| `invalid_scope` | 400 | Unknown, disabled, over-registered, or non-entitled scope; refresh widening. |
| `unsupported_grant_type` | 400 | A `grant_type` outside the five. |
| `unsupported_response_type` | 302 error redirect | A `response_type` other than `code`. |
| `unauthorized_client` | 400 | A client that may not use the requested grant. |
| `invalid_request_object` | 400 | Malformed, unsigned, mis-bound, or conflicting JAR request object. |
| `invalid_dpop_proof` | 400 | Missing or invalid DPoP proof; replayed `jti`. |
| `invalid_redirect_uri` | 400 | DCR redirect URI not in the catalog or otherwise ineligible. |
| `invalid_client_metadata` | 400 | DCR metadata that violates the rules. |
| `access_denied` | 400 | Resource-owner denial; RFC 7592 token mismatch. |
| `authorization_pending` | 400 | Device flow before approval. |
| `slow_down` | 400 | Device polling faster than the interval. |
| `expired_token` | 400 | Device code or code expired. |
| `temporarily_unavailable` | 503 with `Retry-After: 1` | Postgres or Redis is unavailable on a security path. |
| `server_error` | 500 | A masked internal failure. |

The server never fails open on a security path: a dependency outage yields
`503`, never a silent success.

## Sender constraints

Every sender-constrained grant requires a freshly verified proof of possession
on every use.

| Client class | Binding |
| --- | --- |
| Public | DPoP mandatory. A missing proof is a hard `invalid_grant`. |
| Confidential | mTLS and/or DPoP; the confirmation reports both when both are proven. |

`private_key_jwt` is client authentication only. It produces no confirmation and
never satisfies sender constraint. For token exchange, the proof must match the
subject token's confirmation. See [SECURITY.md](SECURITY.md) for the full matrix
and the confirmation propagation rule. It accepts `RS256`, `PS256`, `ES256`, and
`EdDSA` only (`none` and HMAC are rejected); `exp` may lie at most 300 s past
`now` plus 30 s clock skew, and the single-use `jti` marker lives for the
assertion's remaining validity, clamped to `[1 s, 360 s]`.

## Metadata

`GET /.well-known/oauth-authorization-server` returns the RFC 8414 document.
The only state-dependent member is `scopes_supported`, read from the enabled
`scopes` table on every request. The catalog is mutated out of process by the
CLI, so a per-request read makes a change visible immediately on every replica
with no restart. When Postgres is unavailable the endpoint returns `503` rather
than advertising an unknown list.

The document carries no `jwks_uri`: the server signs no artifact of its own.
`code_challenge_methods_supported` advertises only `S256`.
`authorization_response_iss_parameter_supported` is true, so the authorization
response carries `iss` (RFC 9207). The document advertises
`token_endpoint_auth_signing_alg_values_supported = [ES256, EdDSA, RS256,
PS256]`; `dpop_signing_alg_values_supported` stays `[ES256, EdDSA, RS256]`.

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

- A refresh request that omits `scope` keeps the prior grant only while still
  enabled, then narrows to the still-registered ∩ still-entitled intersection
  (possibly empty, from fresh Postgres reads of the client registration, the
  user entitlements, and the `enabled` catalog); an explicit `scope` must be a
  subset of the prior grant and all three current sets.
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
- `src/jose/` for DPoP, JAR, and `private_key_jwt`.
- `src/error.rs` for the error-to-HTTP mapping.

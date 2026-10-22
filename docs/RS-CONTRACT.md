# Resource-server contract (RFC 9728)

This is the contract for the **resource server** (RS) that sits in front of a
protected API and accepts access tokens minted by this authorization server
(AS). The RS is a separate service. This repository is the AS only: it hosts no
resource server and adds no RS route.

The contract is written so an independent RS team can implement discovery,
challenge, token enforcement, and caching from this document alone, following
RFC 9728.

- Discovery entry point: `GET /.well-known/oauth-protected-resource` on the RS.
- Challenge: `WWW-Authenticate: Bearer resource_metadata="..."` (RFC 9728 §5.1).
- Token enforcement: audience match plus scope check (RFC 9728 §7.4, §7.2).
- Validation of the metadata document: the returned `resource` must be byte-for-byte
  identical to the resource identifier the client used (RFC 9728 §3.3).
- Caching: AS metadata and JWKS are cacheable; protected-resource metadata may
  change and is re-fetched on a fresh challenge (RFC 9728 §7.10, §5.2).

## Purpose

For the team that owns the API the tokens are for: what to publish, how to
challenge an unauthenticated request, how to decide a token is acceptable for a
given endpoint, and what to cache. Read it with
[SECURITY.md](SECURITY.md) for the token model and [OAUTH.md](OAUTH.md) for the
AS-side flow. The operator-side steps that pair with this contract (register the
identifier, publish the document, set the challenge, rotate) are in
[OPERATIONS.md](OPERATIONS.md#resource-server-onboarding-rfc-9728).

## Scope and non-goals

In scope:

- The protected-resource metadata document the RS publishes.
- The `WWW-Authenticate` challenge the RS returns to an unauthenticated client.
- The audience and scope checks the RS performs on every request.
- How the RS caches authorization-server metadata and keys.

Out of scope, and deliberately not done here:

- This repository does not host a resource server and adds **no** RS route to
  `src/routes.rs`. The RS is a separate deployable.
- The AS metadata document (`/.well-known/oauth-authorization-server`, RFC 8414)
  never carries a `resource_metadata` member. `resource_metadata` is a
  `WWW-Authenticate` parameter owned by the RS (RFC 9728 §5.1), not an AS
  metadata member (RFC 9728 §4).
- No wildcard resource identifier, redirect URI, or CORS origin is introduced by
  this contract.

## Specification reference

| Section | Title | What it fixes here |
| --- | --- | --- |
| RFC 9728 §2 | Protected Resource Metadata | The member set the RS may publish (`resource`, `authorization_servers`, `jwks_uri`, `scopes_supported`, `bearer_methods_supported`, and more). |
| RFC 9728 §3 | Obtaining Protected Resource Metadata | The well-known URL is derived from the resource identifier. |
| RFC 9728 §3.2 | Protected Resource Metadata Response | A `200 OK` with `application/json` whose members are a subset of §2. |
| RFC 9728 §3.3 | Protected Resource Metadata Validation | The returned `resource` must equal the resource identifier used to build the well-known URL. |
| RFC 9728 §4 | Authorization Server Metadata | Defines `protected_resources` on the AS side. It does **not** add `resource_metadata` to the AS document. |
| RFC 9728 §5.1 | WWW-Authenticate Response | Introduces the `resource_metadata` parameter carrying the metadata URL. |
| RFC 9728 §7.2 | Scopes | `scopes_supported` is the supported set, not a request-everything hint. |
| RFC 9728 §7.3 | Impersonation Attacks | Exact `resource` match defeats resource impersonation. |
| RFC 9728 §7.4 | Audience-Restricted Access Tokens | The RS must check the token audience; a token minted for one RS must not be usable at another. |
| RFC 9728 §7.10 | Metadata Caching | Caching guidance for AS metadata and keys. |

Related specifications: RFC 8414 (AS metadata), RFC 7662 (token introspection),
RFC 8707 (resource indicators), RFC 6750 (Bearer token usage), RFC 9449 (DPoP).

## The protected-resource metadata document

The RS publishes its metadata at a well-known URL derived from its resource
identifier (RFC 9728 §3). For a resource identifier with no path component, that
is `/.well-known/oauth-protected-resource` at the resource host. If the resource
identifier has a path, the terminating slash is removed and the path suffix is
inserted before it (`/.well-known/oauth-protected-resource/resource1`). The
document is fetched with an HTTP `GET` and returns `200 OK` with
`Content-Type: application/json` (RFC 9728 §3.2). Members with zero values are
omitted.

| Member | Required | Meaning here |
| --- | --- | --- |
| `resource` | Yes | The RS's own resource identifier, an absolute `https` URL with no fragment. It must equal the identifier the well-known URL was derived from. |
| `authorization_servers` | No | JSON array of AS issuer identifiers that can be used with this resource. For this AS, the issuer is the `issuer` config value (for example `https://auth.example.com`). |
| `jwks_uri` | No | URL of the RS's **own** JWK Set, for keys the RS uses to sign resource responses. This is not the AS key set. |
| `bearer_methods_supported` | No | How the RS accepts a bearer token. Emit `["header"]` only; this AS rejects tokens in the URI query. |
| `scopes_supported` | Recommended | Scope values that can be requested for this resource. It is a supported set, not a hint to request all of them (RFC 9728 §7.2). |
| `resource_name` | Recommended | Human-readable name for display. |
| `resource_documentation`, `resource_policy_uri`, `resource_tos_uri` | No | Human-readable links. |
| `tls_client_certificate_bound_access_tokens` | No | Whether the RS accepts RFC 8705 mTLS-bound tokens. |
| `dpop_signing_alg_values_supported`, `dpop_bound_access_tokens_required` | No | DPoP support. Use the same allowlist this AS uses for DPoP proofs: `ES256`, `EdDSA`, `RS256`. |
| `resource_signing_alg_values_supported` | No | JWS algorithms the RS supports for signing resource responses. `none` must not be used. |

Example document for an Orders API protected by this AS:

```http
GET /.well-known/oauth-protected-resource HTTP/1.1
Host: api.example.com
```

```json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "jwks_uri": "https://api.example.com/.well-known/jwks.json",
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["orders:read", "orders:write"],
  "resource_name": "Orders API",
  "resource_documentation": "https://api.example.com/docs",
  "tls_client_certificate_bound_access_tokens": true,
  "dpop_signing_alg_values_supported": ["ES256", "EdDSA", "RS256"],
  "dpop_bound_access_tokens_required": false
}
```

`scopes_supported` here must be the runtime scope catalog this AS actually
enables (the `scopes` table), not a hardcoded list. A scope the AS does not
enable cannot be requested, so advertising it only misleads clients.

## The challenge

An unauthenticated or invalid-token request gets an RFC 6750 `401` with a
`WWW-Authenticate` header carrying the `resource_metadata` parameter (RFC 9728
§5.1). The parameter value is the absolute `https` URL of the metadata document
from the section above. The parameter may be combined with others such as
`max_age` (RFC 9470) and may be used with schemes other than `Bearer`, such as
`DPoP` (RFC 9449).

```http
GET /orders/42 HTTP/1.1
Host: api.example.com
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
```

Rules:

- The RS sends this challenge when no credentials are presented or when the
  presented token is not acceptable. It does not send it alongside a success.
- If the RS later needs to point clients at a changed metadata document, it
  re-sends a fresh challenge with the `resource_metadata` value; clients re-fetch
  and re-validate on receipt (RFC 9728 §5.2).
- The RS does not invent the metadata URL ad hoc. The value is the URL derived
  from its resource identifier as in the section above.

## Discovery flow

The client starts with no knowledge of the AS (RFC 9728 §5):

1. The client calls the resource without a token.
2. The RS replies `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
3. The client fetches the protected-resource metadata from that URL.
4. The client validates it (RFC 9728 §3.3), then reads `authorization_servers`.
5. The client builds the AS metadata URL from an issuer and fetches it
   (RFC 8414).
6. The client runs the authorization-code flow and obtains an access token.
7. The client calls the resource again with `Authorization: Bearer <token>`.
8. The RS accepts the token only after the audience and scope checks below.

## Token enforcement

The RS accepts a request only when the token is active, is bound to the RS, and
carries the scope the endpoint needs. All three checks run on every request; a
pass on one never substitutes for another.

### Audience match

RFC 9728 §7.4: without audience-restricted tokens, a malicious resource server
could coax a client into a token it can then replay at a legitimate resource.
The defense is a per-resource audience. The RS must reject any token whose
audience does not include its own `resource` identifier. RFC 8707 resource
indicators are the mechanism by which the client binds the token to this RS.

Two cases:

- JWT access tokens: the RS verifies the signature against the AS key set, then
  checks that the token's `aud` contains the RS's `resource` value. A missing or
  non-matching `aud` is a reject.
- Opaque access tokens (this AS's default): the RS obtains the token's claims by
  calling `POST /introspect` at the AS (RFC 7662) and requires an active result
  whose scope it can trust, in a deployment where the token is bound to this RS
  at mint time via the RFC 8707 `resource` parameter. A token the AS bound to a
  different resource is a reject.

Either way the rule is the same: a token minted for one resource is not accepted
at another. Do not skip the audience check because the client cooperated.

### Scope check

The RS maps each endpoint to the scope it requires, then requires that scope to
be present in the token. For introspection, the `scope` member is the
space-delimited granted scope (RFC 7662 §2.2). For JWT tokens, read `scope` (or
`scp`) and treat a missing value as no scope, which is a reject. A token with a
broader scope than the endpoint needs is still acceptable if it contains the
required scope; a token missing it is `403` with an RFC 6750 `insufficient_scope`
challenge. Scope is never widened by the RS.

### Sender constraint

When the AS bound the token to a key or certificate, the RS must re-verify the
proof of possession on every use: a DPoP proof for `cnf.jkt`, or the client
certificate for `cnf.x5t#S256` (RFC 9449, RFC 8705). The introspection `cnf`
member reports the binding. A token bound to a key is not acceptable without a
fresh, valid proof.

### Introspection integration

When the RS uses RFC 7662 introspection, the request is client-authenticated and
the active response carries `scope`, `client_id`, `token_type`, `exp`, `iat`,
`sub`, `aud`, and `cnf`. `aud` is a JSON array of the resource identifiers the
token is bound to (the RFC 9068 §2.2 array shape, used here for opaque and JWT
tokens alike) and is omitted when the token has no bound audience. An inactive
response is exactly `{"active": false}` with no other member. The RS treats
`active: false` as a reject and never infers activity from anything else.

This AS additionally accepts a repeated `resource` parameter on the
introspection request as a LOCAL EXTENSION to RFC 7662, which defines no
`resource` parameter. When present, the token's `aud` must include every
requested member (set inclusion, so a token pinned to a superset stays active);
a token that does not include every requested member returns the inactive shape.
A requested value that is not an enabled catalog row (or a request while
resource indicators are disabled) is `invalid_target` before the lookup, matching
the other endpoints. An RS uses this to ask whether a token is bound to its own
resource identifier.

## Validating the metadata document

RFC 9728 §3.3: the `resource` member returned by the metadata document must be
identical to the resource identifier value the well-known URL was built from
(and, when discovery started from a `resource_metadata` challenge, to the URL
the client used to reach the resource). If the values differ, the client must
discard the document. This exact-match rule is what defeats resource
impersonation (RFC 9728 §7.3). Comparisons are code-point equality with no
Unicode normalization (RFC 9728 §6).

If the document carries `signed_metadata`, the client must verify that the JWT
was signed by a key belonging to the issuer it trusts; an invalid signature or
untrusted issuer is an error.

## Caching

- AS metadata and the AS JWKS are cacheable. Cache them with a positive
  lifetime and refresh in the background; do not fetch them on every request.
- Protected-resource metadata may change. A fresh `WWW-Authenticate` challenge
  signals that it may have changed; re-fetch and re-validate then
  (RFC 9728 §5.2).
- Key sets rotate. Retain the previous signing keys for verification across a
  rotation window so in-flight tokens still verify; never treat an empty key set
  as "accept all".
- Never weaken a check to keep a cache warm. A stale key set that fails to
  verify a token is a reject, not a reason to skip verification.

## This authorization server's side

The AS side of this contract is narrow and fixed:

- The AS metadata document at `/.well-known/oauth-authorization-server`
  (`src/protocol/metadata.rs`, `AuthorizationServerMetadata`) never contains a
  `resource_metadata` member. That member is a `WWW-Authenticate` parameter owned
  by the RS (RFC 9728 §5.1), so placing it in the AS document would be wrong.
- RFC 9728 §4 defines one AS-side member, `protected_resources`, which lists the
  protected resources usable with this AS. It is emitted only when
  `protected_resources_enabled` is set, using the identifiers in
  `protected_resource_ids`; both default off and empty. The identifiers are
  validated at load (absolute `https`, host, no wildcard/userinfo/fragment/
  query, no duplicates) and the flag requires `resource_indicators_enabled`.
  Until enabled, the AS advertises no `protected_resources` and clients rely on
  the RS metadata alone.
- Tokens are opaque by default and hashed at rest, so the RS validates them by
  introspection (RFC 7662) rather than by local verification. A client can be
  opted into JWT access tokens, in which case the AS advertises `jwks_uri` and
  the RS may verify locally; local verification cannot observe revocation or
  `user disable` before `exp`, so a sensitive RS still introspects. A JWT access
  token always carries a non-empty `aud`; a JWT-format client must request at
  least one `resource` and the AS rejects an empty audience with
  `invalid_target`. See
  [OAUTH.md](OAUTH.md#the-resource-server-trade-off).
- RFC 8707 resource indicators are honored only when `resource_indicators_enabled`
  is set (default off). The RS should confirm with the operator whether tokens
  are audience-restricted in a given deployment before relying on the `aud`
  check alone.

Because the AS mints opaque tokens by default, an RS paired with this AS
introspects at `POST /introspect` and enforces the scope and binding from the
response, plus the audience guarantee the AS applied at mint time.

## Resource-server implementation checklist

- [ ] Publish the protected-resource metadata at the well-known URL derived from
      the resource identifier, as `application/json`, with `resource` set to
      that same identifier (RFC 9728 §3.2, §3.3).
- [ ] Return `WWW-Authenticate: Bearer resource_metadata="..."` on `401`
      (RFC 9728 §5.1).
- [ ] Reject a token whose audience does not include the RS's resource
      identifier (RFC 9728 §7.4).
- [ ] Require the endpoint's scope and return `insufficient_scope` when absent.
- [ ] Re-verify sender-constraint proofs on every use.
- [ ] Cache AS metadata and keys with a positive lifetime; re-fetch on a fresh
      challenge (RFC 9728 §7.10, §5.2).
- [ ] Never place `resource_metadata` in any AS metadata document (RFC 9728 §4).

## File and directory references

- `src/protocol/metadata.rs` for the AS metadata document, which carries no
  `resource_metadata`.
- `src/protocol/introspect.rs` for the RFC 7662 introspection response an RS
  consumes.
- `src/routes.rs` for the AS route table, which contains no RS route.
- [OAUTH.md](OAUTH.md) and [SECURITY.md](SECURITY.md) for the AS flow and token
  model.

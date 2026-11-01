# Documentation

Everything an operator, an integrator, a resource-server team, and a contributor
needs, one guide per subject. The [project README](../README.md) is the short
version: it states what the server is and links here.

## Purpose

This index tells you which guide answers your question and in which order to
read them. Each guide is self-contained on its subject and authoritative for
it; where two touch, the guide that owns the behavior wins and the other links
to it.

## Start here

- **Run it locally.** [QUICKSTART.md](QUICKSTART.md) takes a checkout to a
  server on `https://localhost:8080`, an administrator, and a token. Then
  [CONFIGURATION.md](CONFIGURATION.md) for the keys and
  [OPERATIONS.md](OPERATIONS.md) for the command surface.
- **Deploy it.** [DEPLOYMENT.md](DEPLOYMENT.md) covers the image, the cluster
  contract, the reverse proxy, and supply-chain verification;
  [RUNBOOK.md](RUNBOOK.md) is the on-call procedure for the admin bootstrap and
  for a full-database disclosure.
- **Integrate a client.** [OAUTH.md](OAUTH.md) for endpoints, grants, PKCE,
  error codes, metadata, and CIMD; [QUICKSTART.md](QUICKSTART.md) for the
  end-to-end authorization-code walkthrough; [OPERATIONS.md](OPERATIONS.md) for
  MCP client registration and DCR access tokens.
- **Build a resource server.** [RS-CONTRACT.md](RS-CONTRACT.md) is written so an
  independent resource-server team can implement discovery, the challenge, token
  enforcement, and caching from that document alone.
- **Change the code.** [ARCHITECTURE.md](ARCHITECTURE.md) for the module map and
  request lifecycle, then [CONTRIBUTING.md](CONTRIBUTING.md) for the gates,
  [DATABASE.md](DATABASE.md) and [REDIS.md](REDIS.md) for the two stores,
  [SECURITY.md](SECURITY.md) for the invariants, and
  [TEST-COVERAGE.md](TEST-COVERAGE.md) for the measured baseline.

## Guide index

| Guide | Read it when you are... | It answers |
| --- | --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | running it for the first time | what do I type to get a server and a token? |
| [CONFIGURATION.md](CONFIGURATION.md) | building an environment | what is this key, its default, and its validation rule? |
| [OPERATIONS.md](OPERATIONS.md) | administering a live install | which command, with which flags, in which order? |
| [RUNBOOK.md](RUNBOOK.md) | on call | how do I bootstrap and replace an admin, or respond to a database disclosure? |
| [DEPLOYMENT.md](DEPLOYMENT.md) | shipping to a cluster | what does the image contain and what does the runtime require? |
| [ARCHITECTURE.md](ARCHITECTURE.md) | reading the source | where does this live, and what happens per request? |
| [OAUTH.md](OAUTH.md) | integrating a client | which endpoint, grant, scope, error code, and metadata field? |
| [RS-CONTRACT.md](RS-CONTRACT.md) | protecting an API | how does an RFC 9728 resource server validate a token? |
| [SECURITY.md](SECURITY.md) | reviewing or auditing | what is the threat model and which properties are enforced? |
| [DATABASE.md](DATABASE.md) | changing a table or query | what is the schema, the migration lifecycle, and how is PII stored? |
| [REDIS.md](REDIS.md) | changing ephemeral state | which key namespace, TTL, and durability rule applies? |
| [CONTRIBUTING.md](CONTRIBUTING.md) | opening a change | build, gates, coverage, fuzzing, conventions, doc contract |
| [TEST-COVERAGE.md](TEST-COVERAGE.md) | judging test evidence | what is the measured coverage and how do I reproduce it? |
| [CHANGELOG.md](CHANGELOG.md) | checking a release | what changed, and does it break my client? |
| [../SECURITY.md](../SECURITY.md) | reporting a vulnerability | where do I send it, and what is the disclosure policy? |
| [../AGENTS.md](../AGENTS.md) | briefing an AI agent or a new maintainer | the module map and the repository rules |

## Conventions

Every guide follows the same shape, so you can jump to the part you need:
a `## Purpose` paragraph, the body, `## Edge cases`, `## Operational runbook`,
and `## File and directory references`.

Documentation is part of a change, not a follow-up. The rules that bind a code
change to a guide live in
[CONTRIBUTING.md](CONTRIBUTING.md#documentation-contract), and the repository
rules live in [../AGENTS.md](../AGENTS.md). Relative links are validated by CI,
so run the same check before opening a change:

```bash
python3 scripts/check_doc_links.py
```

## File and directory references

- [../README.md](../README.md) for the short project landing page.
- `docs/` for the guides above; this file is its index.
- `scripts/check_doc_links.py` for the link check CI runs.
- [../AGENTS.md](../AGENTS.md) for the module map and the documentation contract
  summarized above.

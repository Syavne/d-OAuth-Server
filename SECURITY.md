# Security Policy

How to report a vulnerability in d-OAuth-Server, and what to expect.
The threat model and token design live in the separate
[threat-model guide](docs/SECURITY.md); this file is only the reporting
process.

> [!IMPORTANT]
> Placeholder contact — not yet configured.
> No reporting address exists in the repo yet (checked README and docs;
> only `example.com` operational placeholders were found). Replace
> `REPLACE-ME--security-contact@example.invalid` below with Efren's
> preferred contact before publishing. `.invalid` never resolves, so the
> placeholder cannot receive mail.

## Reporting contact

- Email: `REPLACE-ME--security-contact@example.invalid`
  (**placeholder — see the note above**).
- Alternative: open a private security advisory on the repository instead
  of a public issue.

## Scope

In scope: this repository — the OAuth endpoints, token handling, key
management, login/consent/device pages, CLI admin surface, and container
configuration. Out of scope: third-party dependencies (report those
upstream, but tell us if you think we are affected), and production
deployments run by others (report those to the deployment's operator).

## What to include in a report

- Affected version or commit, and how to reproduce the issue.
- The impact as you see it (what an attacker gains, and the preconditions).
- Any logs or proof-of-concept output, with secrets, tokens, and key
  material redacted.

## What to expect

- Acknowledgement of your report within 5 business days.
- A fix timeline once the issue is confirmed; we will keep you updated if
  the timeline slips.
- Credit in the changelog on request, once the fix is released.
- Please do not disclose the issue publicly until a fix is available and
  we have agreed a disclosure date with you.

## Safe harbor

Good-faith research reported through this process and confined to systems
you are authorized to test will not be treated as abuse. Do not access
other users' data, degrade the service, or retain data beyond what is
needed to demonstrate the issue.

## security.txt

A template for operators lives at
[`.well-known/security.txt`](.well-known/security.txt) (same placeholder
contact). If you deploy this server at an origin, serve that file's content
at `<origin>/.well-known/security.txt` and replace the placeholders with
your deployment's contact and canonical policy URL first.

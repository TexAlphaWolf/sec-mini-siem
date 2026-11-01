# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting instead: open the **Security** tab of this repository and choose
**Report a vulnerability**. Include what you found, how to reproduce it, and the version or commit
you tested. This is a personal project, so I answer on a best-effort basis, usually within a week.

## What is in scope

Mini-SIEM reads log data that an attacker can influence, so the most interesting reports are about:

- **Parsers and the rule engine**: input that crashes them, makes them skip events, or bypasses a
  detection rule (log evasion).
- **The dashboard and API**: cross-site scripting through log content, injection, authentication
  bypass on `POST /ingest`, denial of service through oversized or malformed requests.
- **The Docker setup**: ways to escape the container hardening or leak secrets.

## Known limitations (not vulnerabilities)

These are documented design limits, listed in the README:

- Read endpoints (`/api/*`) are open unless `MINISIEM_READ_TOKEN` is set. The token is a single
  shared secret over plain HTTP: for anything beyond localhost put a reverse proxy with TLS in
  front.
- Detection state is kept in memory and resets when the process restarts.

## Security measures already in place

- Logs are treated as hostile: parsers validate what they extract, and the dashboard never renders
  log data as HTML (a test fails the build if it does).
- A strict Content-Security-Policy and other security headers on every response.
- Request bodies are size-limited; the optional ingest and read tokens are compared in constant
  time, and the dashboard keeps its token only in `sessionStorage` (forgotten when the tab closes).
- CI runs CodeQL and `pip-audit`, and Dependabot proposes dependency updates.

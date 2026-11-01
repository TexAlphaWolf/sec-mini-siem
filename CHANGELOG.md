# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] - 2026-11-01

### Added
- Database migrations with Alembic. The schema is created and upgraded automatically at startup
  (guarded by a PostgreSQL advisory lock); databases made by 0.1.0 are adopted without data loss.
  `minisiem db upgrade` and `minisiem db current` run it by hand
- Static type checking with mypy, run in CI
- Animated demo of the dashboard in the README
- Notifications to Telegram, a webhook (`json` or `discord`) and email, with a severity filter,
  an age filter, a per-minute limit and `minisiem notify-test`
- GeoIP: country, city and network owner of public source addresses in alerts and top sources,
  from a local MaxMind GeoLite2 database (`MINISIEM_GEOIP_DB`)
- `docs/configuration.md`: every setting in one place
- `journald` source (`journalctl -o json`): sshd and sudo events, read by the same rules as `auth`
- `windows` source: Security and System events as JSON lines (PowerShell export or Winlogbeat)
  and eight `win-*` rules: logon brute force and spraying, Remote Desktop logon, new user,
  administrator group change, cleared logs, new service, new scheduled task
- `docs/log-sources.md`, and journald and Windows sample logs
- "Distinct values" thresholds (`distinct: username`) and a new `ssh-password-spraying` rule;
  `ssh-user-enumeration` now counts different usernames instead of events
- Detection state is rebuilt from the database at startup (`serve` and `ingest --follow`), so a
  restart no longer forgets an attack in progress or raises its alert twice
- `minisiem rules export`: the rules as Sigma detection and correlation rules
- `MINISIEM_READ_TOKEN`: optional bearer token for `GET /api/*`; the dashboard asks for it and
  keeps it in `sessionStorage`
- Retention: `MINISIEM_RETENTION_DAYS` (purge at startup, then hourly) and `minisiem purge --days N`
- Database settings from `POSTGRES_*` variables, so passwords may contain any character
- CI job that runs the whole test suite against PostgreSQL 16, next to the SQLite matrix
- `TEST_DATABASE_URL` setting to run the tests on any database
- Detection-as-code tests: every rule has log lines that must fire it and benign ones that must
  not, and CI fails if a rule has no tests
- Coverage reporting in CI, with a minimum of 85%
- Dependabot no longer proposes major or minor Python upgrades of the Docker image
- Security policy, Dependabot updates, CodeQL analysis and a `pip-audit` job in CI
- Container hardening in `docker-compose.yml`: read-only filesystem, no Linux capabilities,
  `no-new-privileges`

### Changed
- Tests run with warnings as errors; the CLI and tests now close their database engines
- Python 3.14 added to the CI test matrix; the Docker image now uses `python:3.14-slim`
- GitHub Actions updated to versions that run on Node.js 24

### Fixed
- The access-token form of the dashboard was visible even when no token is required
- The app now releases its database connection when startup fails (for example on a bad setting)
- `web-sqli-probe` now catches comment-based evasion (`UNION/**/SELECT`) and no longer fires on
  ordinary text such as "credit union selection" or "color 1=1"
- A log line containing a NUL byte made PostgreSQL reject the whole batch, which could be abused
  to evade logging. NUL bytes are now stored as the visible text `\x00`.

## [0.1.0] - 2026-11-01

### Added
- Parsers for Linux auth logs (sshd, sudo) and the nginx/Apache combined access log format
- Sigma-inspired YAML rule engine with field modifiers (`contains`, `startswith`, `endswith`,
  `re`, `gte`, `lte`) and sliding-window thresholds
- Ten detection rules, each tagged with its MITRE ATT&CK technique
- FastAPI service with a JSON API (alerts, events, stats) and an ingest endpoint with an
  optional bearer token
- Dependency-free dashboard that never renders log data as HTML
- Command line interface: `serve`, `ingest` (with `--follow`) and `rules check`
- Docker Compose setup with PostgreSQL and a configurable host port
- Anonymised sample logs, a test suite and CI on GitHub Actions

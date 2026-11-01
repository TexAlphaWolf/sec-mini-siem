# Mini-SIEM

[![CI](https://github.com/TexAlphaWolf/sec-mini-siem/actions/workflows/ci.yml/badge.svg)](https://github.com/TexAlphaWolf/sec-mini-siem/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

![Mini-SIEM dashboard](docs/dashboard.png)

A small, readable SIEM. It parses Linux auth logs and web server access logs, detects attacks with
Sigma-style YAML rules, stores everything in PostgreSQL, and shows alerts in a dashboard.

Built to be understood in an afternoon: about 1,200 lines of Python, no message queue, no
framework magic.

## What it detects

Ten rules ship by default, each tagged with its MITRE ATT&CK technique:

| Rule | Severity | Detects |
|------|----------|---------|
| `ssh-bruteforce` | high | 5+ failed SSH logins from one IP in 60 s |
| `ssh-user-enumeration` | medium | 3+ attempts on non-existent users in 5 min |
| `ssh-root-attempts` | medium | 3+ failed logins for `root` in 5 min |
| `ssh-root-login` | medium | successful direct root login |
| `sudo-repeated-failures` | medium | 3+ failed `sudo` authentications by one user in 10 min |
| `web-scanner-404` | medium | 20+ `404`s from one IP in 60 s (directory brute-forcing) |
| `web-sensitive-file-probe` | medium | repeated requests for `/.env`, `/.git/`, `/wp-login.php`, ... |
| `web-path-traversal` | high | `../`, `/etc/passwd` in a request |
| `web-sqli-probe` | high | `union select` (also with SQL comments), `or 1=1`, `sleep(` in a request |
| `web-scanner-user-agent` | medium | sqlmap, nikto, nmap, ... user agents |

Adding your own takes a few lines of YAML: see [docs/writing-rules.md](docs/writing-rules.md).

```yaml
id: ssh-bruteforce
title: SSH brute-force attempt
severity: high
tags: [attack.credential_access, attack.t1110]
match:
  event_type: [ssh_failed_password, ssh_invalid_user]
threshold:
  count: 5
  window: 60s
  group_by: src_ip
```

## Quick start

You need Docker with Compose.

```bash
git clone https://github.com/TexAlphaWolf/sec-mini-siem.git && cd sec-mini-siem
cp .env.example .env            # then set POSTGRES_PASSWORD in .env
docker compose up -d --build
docker compose exec app minisiem ingest auth /data/auth.log --year 2026
docker compose exec app minisiem ingest nginx /data/access.log
```

Open <http://127.0.0.1:8000> (or the port you set in `MINISIEM_PORT`). The sample logs contain a brute-force run, user enumeration, a root
login, failed `sudo` attempts, a directory scanner, and SQL injection and path traversal probes. They
use only [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation IP addresses.

### Troubleshooting

- **"ports are not available ... forbidden by its access permissions" (Windows)**: the port is
  in use or reserved by the system. Set another one in `.env` (for example `MINISIEM_PORT=8088`)
  and run `docker compose up -d` again. `netsh interface ipv4 show excludedportrange protocol=tcp`
  lists the ranges Windows has reserved.
- **`POSTGRES_PASSWORD` error**: copy `.env.example` to `.env` and set a password first.

## Run it on your own logs

```bash
# one-off import
docker compose exec app minisiem ingest auth /var/log/auth.log

# keep following a file, like tail -f (mount it into the container first)
minisiem ingest auth /var/log/auth.log --follow

# or push lines from any host over HTTP
curl -X POST --data-binary @/var/log/auth.log \
     -H "Authorization: Bearer $MINISIEM_API_TOKEN" \
     "http://127.0.0.1:8000/ingest/auth?year=2026"
```

Syslog timestamps have no timezone: set `MINISIEM_LOG_TZ` (for example `Europe/Rome`) to match the
machine that wrote the logs.

## Develop without Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov                # tests and coverage; SQLite by default,
                            # TEST_DATABASE_URL=postgresql+psycopg://... for PostgreSQL
ruff check .
minisiem rules check        # validate rules
minisiem serve              # SQLite file by default; http://127.0.0.1:8000
```

## How it works

```mermaid
flowchart LR
    L[Log files / HTTP] --> P[Parser]
    P -->|Event| R[Rule engine]
    R -->|events + alerts| DB[(PostgreSQL)]
    DB --> API[FastAPI]
    API --> UI[Dashboard]
```

1. **Parse**: each line becomes a normalised event (UTC time, IP, user, type, extra fields).
2. **Detect**: rules match on those fields. Threshold rules count events in a sliding window per
   group and alert once per window, so one attack does not create thousands of alerts.
3. **Store and explore**: events and alerts go to SQL; the dashboard reads them through the API.

Details and design decisions: [docs/architecture.md](docs/architecture.md).

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | Liveness and number of loaded rules |
| `POST` | `/ingest/{source}` | Ingest raw lines (`auth` or `nginx`), body is `text/plain` |
| `GET` | `/api/alerts` | Alerts; filters `severity`, `rule_id`, `limit` |
| `GET` | `/api/events` | Events; filters `source`, `event_type`, `src_ip`, `limit` |
| `GET` | `/api/stats` | Totals, alerts by severity, top sources and rules, hourly timeline |

Interactive docs are at `/docs`.

## Security notes

This is a tool for watching hostile traffic, so it is built to be safe to run near it.

- **Logs are untrusted.** Attackers control usernames, URLs and user agents. The dashboard writes
  everything with `textContent`, never as HTML, and sends a strict Content-Security-Policy. A test
  fails the build if `innerHTML` or similar DOM APIs appear.
- **Local by default.** `docker-compose.yml` binds to `127.0.0.1`. Put a reverse proxy with TLS
  in front before exposing the service.
- **Optional tokens.** `MINISIEM_API_TOKEN` requires a bearer token on `POST /ingest`;
  `MINISIEM_READ_TOKEN` does the same for `GET /api/*`, and the dashboard then asks for it.
- **Bounded input.** Request bodies are capped at 5 MB and read as a stream.
- **No secrets in git.** `.env` is ignored; Compose refuses to start without a database password.
- **Container hardening.** The app runs as a non-root user, with a read-only filesystem, all
  Linux capabilities dropped and `no-new-privileges`.
- **Reporting.** Found a vulnerability? See [SECURITY.md](SECURITY.md).

Only run it against logs from systems you own or are authorised to monitor.

## Limitations

- Detection state is in memory: run a single worker, and expect windows to reset on restart.
- Parsers cover `sshd`, `sudo` and the nginx/Apache combined format.
- Retention is off by default: set `MINISIEM_RETENTION_DAYS` or run `minisiem purge --days N`.

## Roadmap

- [ ] Notifications (Telegram, email) when an alert fires
- [ ] GeoIP enrichment of source addresses
- [ ] "Distinct values" thresholds (for example 10 different usernames from one IP)
- [ ] Windows Event Log and journald parsers
- [ ] Persist detection state across restarts
- [ ] Export alerts in Sigma-compatible form

## Project layout

```
rules/               detection rules (YAML)
sample_logs/         anonymised demo logs
scripts/             sample log generator
src/minisiem/
  parsers/           auth.log and access.log parsers
  rules.py           rule loading and the detection engine
  pipeline.py        parse -> detect -> store
  api.py             FastAPI app
  retention.py       delete events and alerts older than N days
  cli.py             minisiem serve | ingest | purge | rules check
  static/            dashboard (HTML, CSS, JS)
tests/               pytest suite
docs/                architecture and rule-writing guide
```

## License

MIT, see [LICENSE](LICENSE).

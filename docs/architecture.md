# Architecture

Mini-SIEM is deliberately small: one process, one database, no message queue. Each stage is a
plain module you can read in a few minutes.

```mermaid
flowchart LR
    A[auth.log] -->|minisiem ingest| P
    B[nginx access.log] -->|minisiem ingest --follow| P
    C[Any host] -->|POST /ingest/source| P
    subgraph P[Pipeline]
        direction LR
        D[Parser<br/>raw line to Event] --> E[Rule engine<br/>match + thresholds]
    end
    E -->|events| DB[(PostgreSQL<br/>or SQLite)]
    E -->|alerts| DB
    DB --> API[FastAPI<br/>/api/events /api/alerts /api/stats]
    API --> UI[Dashboard]
```

## Stages

| Stage | Module | What it does |
|-------|--------|--------------|
| Parse | `parsers/` | Turns a raw line into a normalised `Event` (UTC timestamp, source IP, user, event type, extra fields). Lines it cannot parse are counted as `skipped`, never guessed. |
| Detect | `rules.py` | Loads YAML rules, matches events against them, and applies sliding-window thresholds. |
| Store | `pipeline.py`, `db.py` | Writes events and alerts to SQL in one transaction per batch. |
| Serve | `api.py`, `static/` | JSON API plus a dependency-free dashboard. |

## Design decisions

**Normalise first, then detect.** Rules never see raw text. They match on fields such as
`event_type`, `src_ip` or `status`, so one rule works regardless of how the log was formatted.

**Sigma-inspired rules, not full Sigma.** The rule format borrows Sigma's ideas (field matching,
modifiers, ATT&CK tags) but stays small enough to implement in about 150 lines. Converting to or
from full Sigma is a possible future step.

**Alert once per window.** After a threshold rule fires for a group (for example one IP), that
group is silenced for one window. A sustained attack gives one alert per window instead of one
per log line.

**Time order matters.** The engine evaluates events in timestamp order. A batch is sorted before
it is evaluated.

**Naive UTC everywhere.** Timestamps are converted to UTC on parse and stored without a zone, so
SQLite and PostgreSQL behave the same. The API adds a `Z` suffix.

## Notifications and GeoIP

After a batch of alerts is stored, the pipeline hands them to a `Notifier`. It filters by severity
and age, applies the per-minute limit and delivers on its own thread through a bounded queue, so a
slow or broken channel can never delay or lose ingestion. GeoIP is looked up at read time (API)
and at send time (notifications) from a local MaxMind file; nothing is stored in the database.

## Changing the schema

The schema is versioned with Alembic (`src/minisiem/migrations/`). `init_db` runs at startup and
upgrades the database to the latest revision; on PostgreSQL it holds an advisory lock so several
containers starting together do not race. A database created by version 0.1.0 (no
`alembic_version` table) is stamped as revision `0001` and then upgraded, keeping its data.

To change the schema, edit the models in `db.py`, then generate a migration and review it:

```bash
alembic revision --autogenerate -m "describe the change" --rev-id 0002
minisiem db current     # revision of the configured database and the latest one
```

A test compares the migrated schema with the models and fails if they drift apart.

## Known limitations

- **Detection state is in memory.** Sliding windows live in the process, so run a single worker;
  a shared store (for example Redis) would be needed to scale out. After a restart the windows
  are rebuilt: the app replays the stored events of the last window (the longest window of any
  rule, counted back from the newest stored event) and re-applies the silence of stored alerts.
  `minisiem ingest` of a single file starts clean on purpose; `--follow` and `serve` restore.
- **Batches arriving out of order** across requests can miss a threshold that spans them.
- **One shared token per direction.** `MINISIEM_API_TOKEN` protects `POST /ingest` and
  `MINISIEM_READ_TOKEN` protects `GET /api/*`; there are no users or roles. Bind to localhost
  (the default in `docker-compose.yml`) or put a reverse proxy with TLS in front.
- **Retention is by event time.** With `MINISIEM_RETENTION_DAYS` set, the app deletes older rows
  at startup and then hourly; `minisiem purge --days N` does it once. Importing an old log file
  while a short retention is set deletes it again at the next pass. Retention is off by default.

## Treating logs as hostile input

Attackers control a lot of what ends up in logs: usernames, URLs, user agents. Two rules follow:

1. Parsers validate what they extract (for example, an IP field must be a valid IP or the line is
   dropped).
2. The dashboard writes every value with `textContent`, never `innerHTML`. A test fails the build
   if forbidden DOM APIs appear in `dashboard.js`, and a strict Content-Security-Policy is sent
   with every response.

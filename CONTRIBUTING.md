# Contributing

Issues and pull requests are welcome.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check .
mypy
minisiem rules check rules
pytest --cov        # TEST_DATABASE_URL=postgresql+psycopg://... to run on PostgreSQL
```

CI runs the same checks on Python 3.11 to 3.14, plus the whole suite on PostgreSQL 16.

## Guidelines

- **New rule:** add `rules/<id>.yml` and test lines that must fire it and benign ones that must
  not (CI fails if a rule has no tests). See [docs/writing-rules.md](docs/writing-rules.md).
- **New log format:** add a parser with tests on real, anonymised lines.
- **Schema change:** generate an Alembic migration (see
  [docs/architecture.md](docs/architecture.md#changing-the-schema)).
- **Logs are hostile.** Never render log data as HTML; the dashboard uses `textContent` only.
- Keep the changelog up to date under a new heading.

"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import URL


@dataclass(frozen=True)
class Settings:
    database_url: str
    rules_dir: Path
    log_timezone: str
    api_token: str | None
    read_token: str | None = None
    retention_days: int = 0


def _database_url() -> str:
    """DATABASE_URL if set; else PostgreSQL from POSTGRES_* parts; else a local SQLite file.

    Building the URL from parts means the password can contain any character: SQLAlchemy
    escapes it, so nobody has to URL-encode it by hand.
    """
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    host = os.environ.get("POSTGRES_HOST")
    if host:
        url = URL.create(
            "postgresql+psycopg",
            username=os.environ.get("POSTGRES_USER", "minisiem"),
            password=os.environ.get("POSTGRES_PASSWORD") or None,
            host=host,
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            database=os.environ.get("POSTGRES_DB", "minisiem"),
        )
        return url.render_as_string(hide_password=False)
    return "sqlite:///./minisiem.db"


def _retention_days() -> int:
    raw = os.environ.get("MINISIEM_RETENTION_DAYS", "0").strip() or "0"
    try:
        days = int(raw)
    except ValueError:
        raise ValueError(f"MINISIEM_RETENTION_DAYS must be a whole number, got {raw!r}") from None
    if days < 0:
        raise ValueError("MINISIEM_RETENTION_DAYS cannot be negative")
    return days


def load_settings() -> Settings:
    """Build settings from the environment.

    DATABASE_URL           SQLAlchemy URL (overrides the POSTGRES_* variables)
    POSTGRES_HOST/_PORT/_USER/_PASSWORD/_DB
                           PostgreSQL connection parts; used when DATABASE_URL is not set
    MINISIEM_RULES_DIR     directory with *.yml rule files (default: ./rules)
    MINISIEM_LOG_TZ        timezone of syslog timestamps, which carry none (default: UTC)
    MINISIEM_API_TOKEN     if set, POST /ingest requires "Authorization: Bearer <token>"
    MINISIEM_READ_TOKEN    if set, GET /api/* requires "Authorization: Bearer <token>"
    MINISIEM_RETENTION_DAYS
                           delete events and alerts older than this many days (0 = keep all)
    """
    return Settings(
        database_url=_database_url(),
        rules_dir=Path(os.environ.get("MINISIEM_RULES_DIR", "rules")),
        log_timezone=os.environ.get("MINISIEM_LOG_TZ", "UTC"),
        api_token=os.environ.get("MINISIEM_API_TOKEN") or None,
        read_token=os.environ.get("MINISIEM_READ_TOKEN") or None,
        retention_days=_retention_days(),
    )

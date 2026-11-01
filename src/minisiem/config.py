"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    rules_dir: Path
    log_timezone: str
    api_token: str | None


def load_settings() -> Settings:
    """Build settings from the environment.

    DATABASE_URL        SQLAlchemy URL (default: a local SQLite file)
    MINISIEM_RULES_DIR  directory with *.yml rule files (default: ./rules)
    MINISIEM_LOG_TZ     timezone of syslog timestamps, which carry none (default: UTC)
    MINISIEM_API_TOKEN  if set, POST /ingest requires "Authorization: Bearer <token>"
    """
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./minisiem.db"),
        rules_dir=Path(os.environ.get("MINISIEM_RULES_DIR", "rules")),
        log_timezone=os.environ.get("MINISIEM_LOG_TZ", "UTC"),
        api_token=os.environ.get("MINISIEM_API_TOKEN") or None,
    )

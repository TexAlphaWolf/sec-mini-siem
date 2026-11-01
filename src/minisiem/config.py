"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.engine import URL


class ConfigError(ValueError):
    """A setting is missing, incomplete or invalid."""


@dataclass(frozen=True)
class NotifySettings:
    """Where alerts are sent. Every channel is optional; with none set, nothing is sent."""

    min_severity: str = "high"
    max_age_minutes: int = 60
    max_per_minute: int = 20
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    webhook_url: str | None = None
    webhook_token: str | None = None
    webhook_format: str = "json"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: tuple[str, ...] = ()


@dataclass(frozen=True)
class Settings:
    database_url: str
    rules_dir: Path
    log_timezone: str
    api_token: str | None
    read_token: str | None = None
    retention_days: int = 0
    notify: NotifySettings = field(default_factory=NotifySettings)
    geoip_db: Path | None = None
    geoip_asn_db: Path | None = None


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
        raise ConfigError(f"MINISIEM_RETENTION_DAYS must be a whole number, got {raw!r}") from None
    if days < 0:
        raise ConfigError("MINISIEM_RETENTION_DAYS cannot be negative")
    return days


def _whole_number(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip() or str(default)
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _text(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


def _path(name: str) -> Path | None:
    value = _text(name)
    return Path(value) if value else None


def _notify_settings() -> NotifySettings:
    recipients = tuple(
        item.strip() for item in os.environ.get("MINISIEM_SMTP_TO", "").split(",") if item.strip()
    )
    return NotifySettings(
        min_severity=(_text("MINISIEM_NOTIFY_MIN_SEVERITY") or "high").lower(),
        max_age_minutes=_whole_number("MINISIEM_NOTIFY_MAX_AGE_MINUTES", 60),
        max_per_minute=_whole_number("MINISIEM_NOTIFY_MAX_PER_MINUTE", 20, minimum=1),
        telegram_token=_text("MINISIEM_TELEGRAM_TOKEN"),
        telegram_chat_id=_text("MINISIEM_TELEGRAM_CHAT_ID"),
        webhook_url=_text("MINISIEM_WEBHOOK_URL"),
        webhook_token=_text("MINISIEM_WEBHOOK_TOKEN"),
        webhook_format=(_text("MINISIEM_WEBHOOK_FORMAT") or "json").lower(),
        smtp_host=_text("MINISIEM_SMTP_HOST"),
        smtp_port=_whole_number("MINISIEM_SMTP_PORT", 587, minimum=1),
        smtp_security=(_text("MINISIEM_SMTP_SECURITY") or "starttls").lower(),
        smtp_user=_text("MINISIEM_SMTP_USER"),
        smtp_password=_text("MINISIEM_SMTP_PASSWORD"),
        smtp_from=_text("MINISIEM_SMTP_FROM"),
        smtp_to=recipients,
    )


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
    MINISIEM_GEOIP_DB      path of a MaxMind GeoLite2 City or Country database (.mmdb)
    MINISIEM_GEOIP_ASN_DB  optional GeoLite2 ASN database
    MINISIEM_NOTIFY_*, MINISIEM_TELEGRAM_*, MINISIEM_WEBHOOK_*, MINISIEM_SMTP_*
                           notification channels: see docs/configuration.md
    """
    return Settings(
        database_url=_database_url(),
        rules_dir=Path(os.environ.get("MINISIEM_RULES_DIR", "rules")),
        log_timezone=os.environ.get("MINISIEM_LOG_TZ", "UTC"),
        api_token=os.environ.get("MINISIEM_API_TOKEN") or None,
        read_token=os.environ.get("MINISIEM_READ_TOKEN") or None,
        retention_days=_retention_days(),
        notify=_notify_settings(),
        geoip_db=_path("MINISIEM_GEOIP_DB"),
        geoip_asn_db=_path("MINISIEM_GEOIP_ASN_DB"),
    )

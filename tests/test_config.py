from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from minisiem.config import ConfigError, load_settings

DB_VARS = (
    "DATABASE_URL", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "POSTGRES_DB", "MINISIEM_RETENTION_DAYS", "MINISIEM_READ_TOKEN", "MINISIEM_GEOIP_DB",
    "MINISIEM_GEOIP_ASN_DB", "MINISIEM_NOTIFY_MIN_SEVERITY", "MINISIEM_NOTIFY_MAX_AGE_MINUTES",
    "MINISIEM_NOTIFY_MAX_PER_MINUTE", "MINISIEM_TELEGRAM_TOKEN", "MINISIEM_TELEGRAM_CHAT_ID",
    "MINISIEM_WEBHOOK_URL", "MINISIEM_WEBHOOK_TOKEN", "MINISIEM_WEBHOOK_FORMAT",
    "MINISIEM_SMTP_HOST", "MINISIEM_SMTP_PORT", "MINISIEM_SMTP_SECURITY", "MINISIEM_SMTP_USER",
    "MINISIEM_SMTP_PASSWORD", "MINISIEM_SMTP_FROM", "MINISIEM_SMTP_TO",
)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in DB_VARS:
        monkeypatch.delenv(name, raising=False)


def test_default_is_a_local_sqlite_file():
    assert load_settings().database_url == "sqlite:///./minisiem.db"


def test_explicit_database_url_wins(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///x.db")
    monkeypatch.setenv("POSTGRES_HOST", "db")
    assert load_settings().database_url == "sqlite:///x.db"


@pytest.mark.parametrize("password", ["plain", "p@ss/w:rd%40#?", "with space & symbols!"])
def test_postgres_password_may_contain_any_character(monkeypatch, password):
    monkeypatch.setenv("POSTGRES_HOST", "db")
    monkeypatch.setenv("POSTGRES_PASSWORD", password)
    url = make_url(load_settings().database_url)
    assert url.drivername == "postgresql+psycopg"
    assert (url.host, url.port, url.username, url.database) == ("db", 5432, "minisiem", "minisiem")
    assert url.password == password


def test_retention_and_read_token(monkeypatch):
    monkeypatch.setenv("MINISIEM_RETENTION_DAYS", "30")
    monkeypatch.setenv("MINISIEM_READ_TOKEN", "t")
    settings = load_settings()
    assert settings.retention_days == 30
    assert settings.read_token == "t"


@pytest.mark.parametrize("value", ["soon", "-5"])
def test_invalid_retention_is_rejected(monkeypatch, value):
    monkeypatch.setenv("MINISIEM_RETENTION_DAYS", value)
    with pytest.raises(ValueError, match="MINISIEM_RETENTION_DAYS"):
        load_settings()


def test_notification_defaults_send_nothing():
    notify = load_settings().notify
    assert (notify.min_severity, notify.max_age_minutes, notify.max_per_minute) == ("high", 60, 20)
    assert not (notify.telegram_token or notify.webhook_url or notify.smtp_host)


def test_notification_settings_are_read_from_the_environment(monkeypatch):
    values = {
        "MINISIEM_NOTIFY_MIN_SEVERITY": "Medium", "MINISIEM_TELEGRAM_TOKEN": " tok ",
        "MINISIEM_TELEGRAM_CHAT_ID": "42", "MINISIEM_WEBHOOK_URL": "https://h.example/x",
        "MINISIEM_WEBHOOK_FORMAT": "Discord", "MINISIEM_SMTP_HOST": "mail",
        "MINISIEM_SMTP_PORT": "465", "MINISIEM_SMTP_SECURITY": "SSL",
        "MINISIEM_SMTP_FROM": "a@example.com", "MINISIEM_SMTP_TO": "b@example.com, c@example.com,",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    notify = load_settings().notify
    assert notify.min_severity == "medium" and notify.webhook_format == "discord"
    assert notify.telegram_token == "tok" and notify.telegram_chat_id == "42"
    assert (notify.smtp_port, notify.smtp_security) == (465, "ssl")
    assert notify.smtp_to == ("b@example.com", "c@example.com")


@pytest.mark.parametrize(
    ("name", "value"),
    [("MINISIEM_SMTP_PORT", "abc"), ("MINISIEM_NOTIFY_MAX_PER_MINUTE", "0"),
     ("MINISIEM_NOTIFY_MAX_AGE_MINUTES", "-1")],
)
def test_invalid_numbers_name_the_setting(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError, match=name):
        load_settings()


def test_geoip_paths(monkeypatch):
    monkeypatch.setenv("MINISIEM_GEOIP_DB", "/geoip/city.mmdb")
    settings = load_settings()
    assert str(settings.geoip_db) == "/geoip/city.mmdb" and settings.geoip_asn_db is None

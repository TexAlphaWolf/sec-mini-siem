from __future__ import annotations

import pytest
from sqlalchemy.engine import make_url

from minisiem.config import load_settings

DB_VARS = (
    "DATABASE_URL", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "POSTGRES_DB", "MINISIEM_RETENTION_DAYS", "MINISIEM_READ_TOKEN",
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

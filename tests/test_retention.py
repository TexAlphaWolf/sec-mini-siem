from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from minisiem.cli import main
from minisiem.db import AlertRow, EventRow, init_db, make_session_factory
from minisiem.retention import purge_older_than


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture
def populated(database_url):
    """A database with one old and one recent event and alert."""
    engine, session_factory = make_session_factory(database_url)
    init_db(engine)
    now = _now()
    with session_factory() as session, session.begin():
        for age in (timedelta(days=100), timedelta(hours=1)):
            session.add(EventRow(ts=now - age, source="auth", event_type="x", raw="r"))
            session.add(
                AlertRow(ts=now - age, rule_id="r", title="t", severity="low", event_count=1)
            )
    yield database_url, session_factory
    engine.dispose()


def _counts(session_factory) -> tuple[int, int]:
    with session_factory() as session:
        return (
            session.scalar(select(func.count(EventRow.id))),
            session.scalar(select(func.count(AlertRow.id))),
        )


def test_purge_deletes_only_old_rows(populated):
    _, session_factory = populated
    assert purge_older_than(session_factory, 30) == (1, 1)
    assert _counts(session_factory) == (1, 1)


def test_purge_with_a_long_window_keeps_everything(populated):
    _, session_factory = populated
    assert purge_older_than(session_factory, 365) == (0, 0)
    assert _counts(session_factory) == (2, 2)


def test_purge_rejects_a_window_below_one_day(populated):
    _, session_factory = populated
    with pytest.raises(ValueError):
        purge_older_than(session_factory, 0)


def test_cli_purge(populated, rules_dir, monkeypatch, capsys):
    database_url, session_factory = populated
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("MINISIEM_RULES_DIR", str(rules_dir))
    assert main(["purge", "--days", "30"]) == 0
    assert "deleted events=1 alerts=1" in capsys.readouterr().out
    assert _counts(session_factory) == (1, 1)


def test_cli_purge_needs_a_window(populated, monkeypatch, capsys):
    database_url, _ = populated
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.delenv("MINISIEM_RETENTION_DAYS", raising=False)
    assert main(["purge"]) == 1
    assert "--days" in capsys.readouterr().err

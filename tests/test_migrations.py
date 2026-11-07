from __future__ import annotations

from datetime import datetime

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select, text

from minisiem.cli import main
from minisiem.db import (
    INITIAL_REVISION,
    MIGRATIONS_DIR,
    Base,
    EventRow,
    alembic_config,
    current_revision,
    head_revision,
    init_db,
    make_session_factory,
)

TABLES = {"events", "alerts"}


@pytest.fixture
def engine(database_url):
    engine, _ = make_session_factory(database_url)
    yield engine
    engine.dispose()


def tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


def test_a_new_database_is_created_at_the_latest_revision(engine):
    assert current_revision(engine) is None
    init_db(engine)
    assert tables(engine) == TABLES
    assert current_revision(engine) == head_revision()


def test_running_it_again_changes_nothing(engine):
    init_db(engine)
    init_db(engine)
    assert current_revision(engine) == head_revision()


def test_a_database_from_before_migrations_is_adopted_with_its_data(engine):
    Base.metadata.create_all(engine)  # what earlier versions did
    with engine.begin() as connection:
        connection.execute(
            EventRow.__table__.insert().values(
                ts=datetime(2026, 10, 20, 9),
                source="auth",
                host="",
                event_type="x",
                raw="kept",
                fields={},
            )
        )
    assert current_revision(engine) is None

    init_db(engine)

    assert current_revision(engine) == head_revision()
    with engine.connect() as connection:
        assert connection.scalar(select(EventRow.raw)) == "kept"


def test_the_migrations_produce_exactly_the_schema_of_the_models(engine):
    init_db(engine)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, Base.metadata) == []


def test_downgrade_removes_the_tables(engine):
    init_db(engine)
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
    assert tables(engine) == set()


def test_initial_revision_is_the_first_one():
    assert head_revision() == INITIAL_REVISION  # update INITIAL_REVISION only if history is rebuilt


def test_the_alembic_command_line_finds_the_database_from_the_environment(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    command.upgrade(config, "head")  # no connection given: env.py opens its own
    engine = create_engine(url)
    assert tables(engine) == TABLES
    engine.dispose()


def test_cli_db_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'db.db'}")
    assert main(["db", "current"]) == 0
    assert f"current=none head={head_revision()}" in capsys.readouterr().out
    assert main(["db", "upgrade"]) == 0
    assert f"database is at revision {head_revision()}" in capsys.readouterr().out
    assert main(["db", "current"]) == 0
    assert f"current={head_revision()}" in capsys.readouterr().out


def test_the_recorded_revision_is_trusted_over_the_tables(engine):
    # Documented limit: the revision table is trusted. A database whose tables were dropped
    # by hand but kept its revision is not repaired.
    init_db(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alerts"))
    init_db(engine)
    assert "alerts" not in tables(engine)

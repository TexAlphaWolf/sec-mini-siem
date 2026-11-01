"""Database models, migrations and session helpers (SQLAlchemy 2.0, Alembic).

All datetimes are stored as naive UTC so SQLite and PostgreSQL behave the same.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(255), default="")
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw: Mapped[str] = mapped_column(Text)
    fields: Mapped[dict] = mapped_column(JSON, default=dict)


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    group_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


def make_session_factory(url: str) -> tuple[Engine, sessionmaker]:
    """Create the engine and a session factory for `url`."""
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)
    else:
        engine = create_engine(url, pool_pre_ping=True)
    return engine, sessionmaker(engine, expire_on_commit=False)


MIGRATIONS_DIR = Path(__file__).parent / "migrations"
INITIAL_REVISION = "0001"
_LOCK_KEY = 7316419  # PostgreSQL advisory lock: one process migrates at a time


def alembic_config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    if connection is not None:
        config.attributes["connection"] = connection
    return config


@lru_cache(maxsize=1)
def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    assert head is not None
    return head


def current_revision(engine: Engine) -> str | None:
    """The schema revision of the database, or None if it has never been migrated."""
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def init_db(engine: Engine) -> None:
    """Bring the database to the latest schema, creating it on the first run.

    A database made by a version from before migrations existed (tables, but no revision) is
    recognised and marked as being at the initial revision, so existing data is kept.
    """
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            # If the app and a CLI command start together, the second one waits here.
            connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEY})
        current = MigrationContext.configure(connection).get_current_revision()
        if current == head_revision():
            return
        config = alembic_config(connection)
        if current is None and inspect(connection).has_table("events"):
            command.stamp(config, INITIAL_REVISION)
        command.upgrade(config, "head")

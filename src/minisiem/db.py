"""Database models and session helpers (SQLAlchemy 2.0).

All datetimes are stored as naive UTC so SQLite and PostgreSQL behave the same.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine
from sqlalchemy.engine import Engine
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


def init_db(engine: Engine) -> None:
    """Create tables if they do not exist yet."""
    Base.metadata.create_all(engine)

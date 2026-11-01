"""Alembic environment.

Used in two ways: by the app (`init_db` passes an open connection), and by the `alembic` command
for developers (it then connects to DATABASE_URL, like the app does).
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection
from sqlalchemy.pool import NullPool

from minisiem.config import load_settings
from minisiem.db import Base

config = context.config
target_metadata = Base.metadata


def _migrate(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _migrate(connection)
        return
    engine = create_engine(load_settings().database_url, poolclass=NullPool)
    try:
        with engine.begin() as new_connection:
            _migrate(new_connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline migrations are not supported; run them against a database")
run_migrations_online()

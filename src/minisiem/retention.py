"""Retention: delete events and alerts older than a number of days."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import sessionmaker

from .db import AlertRow, EventRow


def purge_older_than(
    session_factory: sessionmaker, days: int, now: datetime | None = None
) -> tuple[int, int]:
    """Delete rows whose event time is older than `days`. Returns (events, alerts) deleted.

    The age is the time written in the log, not the time of ingestion: importing an old log
    file while a short retention is set will delete it again at the next purge.
    """
    if days < 1:
        raise ValueError("days must be at least 1")
    moment = now if now is not None else datetime.now(UTC).replace(tzinfo=None)
    cutoff = moment - timedelta(days=days)
    with session_factory() as session, session.begin():
        events = session.execute(delete(EventRow).where(EventRow.ts < cutoff)).rowcount
        alerts = session.execute(delete(AlertRow).where(AlertRow.ts < cutoff)).rowcount
    return events, alerts

"""The ingest pipeline: parse -> detect -> store."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from .db import AlertRow, EventRow
from .events import Event
from .notify import Notifier
from .parsers import parse_lines
from .rules import Rule, RuleEngine


@dataclass
class IngestResult:
    parsed: int
    skipped: int
    alerts: int


class Pipeline:
    """Turns raw log lines into stored events and alerts.

    A single engine holds the sliding-window state, so run one process (one uvicorn worker).
    A lock serialises ingestion because the web server handles requests in a thread pool.
    """

    def __init__(
        self,
        session_factory: sessionmaker,
        rules: list[Rule],
        tz: str = "UTC",
        notifier: Notifier | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._notifier = notifier
        self._engine = RuleEngine(rules)
        self._tz = tz
        self._lock = threading.Lock()

    @property
    def rule_count(self) -> int:
        return len(self._engine.rules)

    def restore_state(self) -> int:
        """Rebuild the detection windows from the database after a restart.

        Replays the stored events of the last window (relative to the newest stored event) and
        re-applies the silence of stored alerts, so an attack in progress neither loses its
        count nor raises a second alert. Returns the number of events replayed.
        """
        horizon = self._engine.horizon_seconds
        if horizon == 0:
            return 0
        replayed = 0
        with self._session_factory() as session:
            latest = session.scalar(select(func.max(EventRow.ts)))
            if latest is None:
                return 0
            since = latest - timedelta(seconds=horizon)
            alerts = [
                tuple(row)
                for row in session.execute(
                    select(AlertRow.rule_id, AlertRow.group_key, AlertRow.ts).where(
                        AlertRow.ts >= since
                    )
                )
            ]
            rows = session.scalars(
                select(EventRow)
                .where(EventRow.ts >= since)
                .order_by(EventRow.ts, EventRow.id)
                .execution_options(yield_per=1000)
            )

            def events() -> Iterator[Event]:
                nonlocal replayed
                for row in rows:
                    replayed += 1
                    yield Event(
                        ts=row.ts,
                        source=row.source,
                        event_type=row.event_type,
                        host=row.host,
                        src_ip=row.src_ip,
                        username=row.username,
                        raw=row.raw,
                        fields=row.fields or {},
                    )

            with self._lock:
                self._engine.restore(events(), alerts)
        return replayed

    def ingest(self, source: str, lines: Iterable[str], year: int | None = None) -> IngestResult:
        # PostgreSQL text columns reject NUL (0x00) bytes. If we let one through, a single hostile
        # line makes the whole batch fail, which attackers could abuse to hide their traffic.
        # Make NULs visible instead: they are stored as the four characters \x00.
        safe_lines = (line.replace("\x00", "\\x00") for line in lines)
        events, skipped = parse_lines(source, safe_lines, tz=self._tz, year=year)
        events.sort(key=lambda e: e.ts)  # the engine expects time order

        with self._lock:
            alerts = [alert for event in events for alert in self._engine.evaluate(event)]

        with self._session_factory() as session, session.begin():
            session.add_all(
                EventRow(
                    ts=e.ts,
                    source=e.source,
                    host=e.host,
                    event_type=e.event_type,
                    src_ip=e.src_ip,
                    username=e.username,
                    raw=e.raw[:2000],
                    fields=e.fields,
                )
                for e in events
            )
            session.add_all(
                AlertRow(
                    ts=a.ts,
                    rule_id=a.rule_id,
                    title=a.title,
                    severity=a.severity,
                    src_ip=a.src_ip,
                    group_key=a.group_key,
                    event_count=a.event_count,
                    tags=a.tags,
                    details=a.details,
                )
                for a in alerts
            )
        if self._notifier is not None and alerts:
            self._notifier.submit(alerts)  # after the commit: a stored alert is never lost
        return IngestResult(parsed=len(events), skipped=skipped, alerts=len(alerts))

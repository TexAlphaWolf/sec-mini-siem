"""The ingest pipeline: parse -> detect -> store."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.orm import sessionmaker

from .db import AlertRow, EventRow
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

    def __init__(self, session_factory: sessionmaker, rules: list[Rule], tz: str = "UTC") -> None:
        self._session_factory = session_factory
        self._engine = RuleEngine(rules)
        self._tz = tz
        self._lock = threading.Lock()

    @property
    def rule_count(self) -> int:
        return len(self._engine.rules)

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
        return IngestResult(parsed=len(events), skipped=skipped, alerts=len(alerts))

"""Log parsers. Each turns one raw line into a normalised `Event`."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from ..events import Event
from .auth import parse_auth_line
from .journald import parse_journald_line
from .nginx import parse_nginx_line
from .windows import parse_windows_line

PARSERS = {
    "auth": parse_auth_line,
    "nginx": parse_nginx_line,
    "journald": parse_journald_line,
    "windows": parse_windows_line,
}


def parse_lines(
    source: str,
    lines: Iterable[str],
    *,
    tz: str = "UTC",
    year: int | None = None,
) -> tuple[list[Event], int]:
    """Parse many lines. Returns (events, number_of_lines_skipped).

    Blank lines are ignored silently; lines the parser does not understand are counted.
    """
    try:
        parser = PARSERS[source]
    except KeyError:
        raise ValueError(f"unknown log source {source!r}; choose from {sorted(PARSERS)}") from None

    now = datetime.now(UTC)
    events: list[Event] = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        event = parser(line, tz=tz, year=year, now=now)
        if event is None:
            skipped += 1
        else:
            events.append(event)
    return events, skipped

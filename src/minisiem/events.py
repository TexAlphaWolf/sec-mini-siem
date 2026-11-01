"""The normalised event: the common shape every parser produces."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """A single log line, normalised.

    `ts` is always a naive datetime in UTC. Source-specific details live in `fields`.
    """

    ts: datetime
    source: str
    event_type: str
    host: str = ""
    src_ip: str | None = None
    username: str | None = None
    raw: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def match_view(self) -> dict[str, Any]:
        """Flat dict that rules are evaluated against."""
        view: dict[str, Any] = dict(self.fields)
        view.update(
            source=self.source,
            event_type=self.event_type,
            host=self.host,
            src_ip=self.src_ip,
            username=self.username,
        )
        return view

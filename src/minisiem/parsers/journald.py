"""Parser for systemd-journald logs exported as JSON, one object per line.

    journalctl -o json --since yesterday | minisiem ingest journald -

The interesting part of an entry is its MESSAGE, which is the same text sshd and sudo write to
auth.log, so the message parsing is shared with the `auth` parser and the same rules apply.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from ..events import Event
from .auth import classify_message
from .common import clean_ip

_EPOCH = datetime(1970, 1, 1)
_MAX_MESSAGE = 4096


def _realtime(value: Any) -> datetime | None:
    """__REALTIME_TIMESTAMP is microseconds since the Unix epoch, as a string."""
    try:
        return _EPOCH + timedelta(microseconds=int(value))
    except (TypeError, ValueError, OverflowError):
        return None


def _message(value: Any) -> str | None:
    """MESSAGE is text, or a list of byte values when the entry holds binary data."""
    if isinstance(value, str):
        return value[:_MAX_MESSAGE].strip()
    if isinstance(value, list) and all(isinstance(b, int) and 0 <= b <= 255 for b in value):
        return bytes(value[:_MAX_MESSAGE]).decode("utf-8", errors="replace").strip()
    return None


def parse_journald_line(
    line: str,
    *,
    tz: str = "UTC",
    year: int | None = None,
    now: datetime | None = None,
) -> Event | None:
    """Parse one `journalctl -o json` line. Returns None for entries we do not understand."""
    line = line.strip().lstrip("﻿")
    try:
        doc = json.loads(line)
    except (ValueError, RecursionError):  # not JSON, or nested so deeply that it is an attack
        return None
    if not isinstance(doc, dict):
        return None

    ts = _realtime(doc.get("__REALTIME_TIMESTAMP"))
    message = _message(doc.get("MESSAGE"))
    program = doc.get("SYSLOG_IDENTIFIER") or doc.get("_COMM")
    if ts is None or message is None or not isinstance(program, str):
        return None

    classified = classify_message(program, message)
    if classified is None:
        return None
    event_type, username, raw_ip, fields = classified

    src_ip = clean_ip(raw_ip)
    if raw_ip is not None and src_ip is None:
        return None  # an address field that is not an address: do not trust the entry

    fields["program"] = program
    pid = doc.get("_PID")
    if isinstance(pid, str) and pid.isdigit():
        fields["pid"] = int(pid)
    unit = doc.get("_SYSTEMD_UNIT")
    if isinstance(unit, str):
        fields["unit"] = unit[:128]
    host = doc.get("_HOSTNAME")
    return Event(
        ts=ts,
        source="journald",
        event_type=event_type,
        host=host[:255] if isinstance(host, str) else "",
        src_ip=src_ip,
        username=username,
        raw=line,
        fields=fields,
    )



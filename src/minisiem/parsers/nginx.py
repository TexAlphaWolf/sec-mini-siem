"""Parser for the nginx / Apache "combined" access log format."""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import unquote_plus

from ..events import Event
from .auth import MONTHS
from .common import clean_ip, to_utc_naive

_COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] \"(?P<req>[^\"]*)\" "
    r"(?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\")?"
)
_TS = re.compile(
    r"^(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) "
    r"(?P<off>[+-]\d{4})$"
)


def _parse_ts(value: str) -> datetime | None:
    m = _TS.match(value)
    if not m or m["mon"] not in MONTHS:
        return None
    try:
        moment = datetime.strptime(
            f"{m['y']}-{MONTHS[m['mon']]:02d}-{m['d']} {m['h']}:{m['mi']}:{m['s']} {m['off']}",
            "%Y-%m-%d %H:%M:%S %z",
        )
    except ValueError:
        return None
    return to_utc_naive(moment)


def parse_nginx_line(
    line: str,
    *,
    tz: str = "UTC",  # noqa: ARG001 - access logs carry their own offset
    year: int | None = None,  # noqa: ARG001
    now: datetime | None = None,  # noqa: ARG001
) -> Event | None:
    """Parse one access-log line. Returns None for lines we do not understand."""
    line = line.strip()
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = _parse_ts(m["ts"])
    src_ip = clean_ip(m["ip"])
    if ts is None or src_ip is None:
        return None

    parts = m["req"].split(" ")
    if len(parts) == 3:
        method, path, protocol = parts
    else:  # garbage request line (binary probes, TLS sent to a plain port, ...)
        method, path, protocol = "", m["req"], ""

    username = None if m["user"] == "-" else m["user"]
    size = int(m["size"]) if m["size"].isdigit() else 0
    return Event(
        ts=ts,
        source="nginx",
        event_type="http_request",
        host="",
        src_ip=src_ip,
        username=username,
        raw=line,
        fields={
            "http_method": method,
            "path": path,
            # Decoded once, so rules can match "union select" instead of "union%20select".
            "path_decoded": unquote_plus(path),
            "protocol": protocol,
            "status": int(m["status"]),
            "bytes": size,
            "referrer": m["ref"] if m["ref"] not in (None, "-") else None,
            "user_agent": m["ua"] or None,
        },
    )

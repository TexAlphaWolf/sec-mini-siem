"""Parser for Linux authentication logs (auth.log / secure): sshd and sudo."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo

from ..events import Event
from .common import clean_ip, to_utc_naive

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_HEAD = r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
# Classic syslog: "Oct 20 09:12:03 web01 sshd[2211]: ..."
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+" + _HEAD
)
# rsyslog / journald ISO format: "2026-10-20T09:12:03.123456+02:00 web01 sshd[2211]: ..."
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+" + _HEAD
)

_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO_FAIL = re.compile(
    r"^(?P<user>\S+)\s+:\s+(?P<n>\d+) incorrect password attempts?\s*;"
    r"(?:.*?USER=(?P<target>\S+))?(?:.*?COMMAND=(?P<cmd>.*))?$"
)
_SUDO_CMD = re.compile(
    r"^(?P<user>\S+)\s+:\s+(?:TTY=\S+\s+;\s+)?PWD=(?P<pwd>.*?)\s+;\s+"
    r"USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.*)$"
)


def _zone(name: str) -> tzinfo:
    return UTC if name.upper() == "UTC" else ZoneInfo(name)


def _syslog_ts(
    mon: str, day: str, hms: str, tz: str, year: int | None, now: datetime
) -> datetime | None:
    """Syslog timestamps have no year or zone: assume `tz`, and `year` (or the current one)."""
    month = MONTHS.get(mon)
    if month is None:
        return None
    hour, minute, second = (int(p) for p in hms.split(":"))
    zone = _zone(tz)
    chosen_year = year or now.year
    try:
        moment = datetime(chosen_year, month, int(day), hour, minute, second, tzinfo=zone)
        # A December line read in January belongs to last year.
        if year is None and moment.astimezone(UTC) > now + timedelta(days=1):
            moment = moment.replace(year=chosen_year - 1)
    except ValueError:
        return None
    return to_utc_naive(moment)


def _iso_ts(value: str, tz: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_zone(tz))
    return to_utc_naive(moment)


def classify_message(
    prog: str, msg: str
) -> tuple[str, str | None, str | None, dict[str, Any]] | None:
    """Return (event_type, username, ip, fields) for a message we understand."""
    if prog == "sshd":
        if m := _FAILED.match(msg):
            fields = {
                "auth_method": m["method"],
                "invalid_user": bool(m["invalid"]),
                "port": int(m["port"]),
            }
            return "ssh_failed_password", m["user"], m["ip"], fields
        if m := _INVALID.match(msg):
            port = int(m["port"]) if m["port"] else None
            return "ssh_invalid_user", m["user"] or None, m["ip"], {"port": port}
        if m := _ACCEPTED.match(msg):
            fields = {"auth_method": m["method"], "port": int(m["port"])}
            return "ssh_accepted", m["user"], m["ip"], fields
    elif prog == "sudo":
        if m := _SUDO_FAIL.match(msg):
            fields = {
                "attempts": int(m["n"]),
                "target_user": m["target"],
                "command": m["cmd"],
            }
            return "sudo_failure", m["user"], None, fields
        if m := _SUDO_CMD.match(msg):
            fields = {"target_user": m["target"], "command": m["cmd"], "pwd": m["pwd"]}
            return "sudo_command", m["user"], None, fields
    return None


def parse_auth_line(
    line: str,
    *,
    tz: str = "UTC",
    year: int | None = None,
    now: datetime | None = None,
) -> Event | None:
    """Parse one auth.log line. Returns None for lines we do not understand."""
    now = now or datetime.now(UTC)
    line = line.strip()

    if m := _SYSLOG.match(line):
        ts = _syslog_ts(m["mon"], m["day"], m["hms"], tz, year, now)
    elif m := _ISO.match(line):
        ts = _iso_ts(m["ts"], tz)
    else:
        return None
    if ts is None:
        return None

    classified = classify_message(m["prog"], m["msg"])
    if classified is None:
        return None
    event_type, username, raw_ip, fields = classified

    src_ip = clean_ip(raw_ip)
    if raw_ip is not None and src_ip is None:
        return None  # an address field that is not an address: do not trust the line

    fields["program"] = m["prog"]
    if m["pid"]:
        fields["pid"] = int(m["pid"])
    return Event(
        ts=ts,
        source="auth",
        event_type=event_type,
        host=m["host"],
        src_ip=src_ip,
        username=username,
        raw=line,
        fields=fields,
    )

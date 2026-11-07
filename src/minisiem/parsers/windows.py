"""Parser for Windows event logs exported as JSON, one event per line.

Two layouts are understood. The first is what the PowerShell snippet in docs/log-sources.md
writes; the second is the layout of Winlogbeat (the Elastic shipper):

    {"TimeCreated": "2026-10-20T09:12:03.123Z", "EventID": 4625, "Computer": "WIN-DESK01",
     "Channel": "Security", "Data": {"TargetUserName": "alice", "IpAddress": "203.0.113.5", ...}}

    {"@timestamp": "...", "winlog": {"event_id": "4625", "computer_name": "...",
     "channel": "Security", "event_data": {...}}}

Only events that matter for detection are kept (see `_HANDLERS`); anything else is skipped.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from ..events import Event
from .common import clean_ip, to_utc_naive

_MAX_VALUE = 256
_MAX_PATH = 512

Classified = tuple[str, str | None, str | None, dict[str, Any]]


def _get(data: dict[str, str], key: str, limit: int = _MAX_VALUE) -> str | None:
    """A value from the event data; Windows writes "-" for "nothing"."""
    value = data.get(key)
    if value is None or value in ("", "-"):
        return None
    return value[:limit]


def _number(value: str | None) -> int | None:
    return int(value) if value is not None and value.isdigit() else None


def _logon(event_type: str) -> Callable[[dict[str, str]], Classified]:
    def handle(data: dict[str, str]) -> Classified:
        fields = {
            "logon_type": _number(_get(data, "LogonType")),
            "domain": _get(data, "TargetDomainName"),
            "workstation": _get(data, "WorkstationName"),
            "auth_package": _get(data, "AuthenticationPackageName"),
            "status": _get(data, "Status"),
            "sub_status": _get(data, "SubStatus"),
        }
        username = _get(data, "TargetUserName")
        return event_type, username, clean_ip(_get(data, "IpAddress")), fields

    return handle


def _privileged_logon(data: dict[str, str]) -> Classified:
    return (
        "win_privileged_logon",
        _get(data, "SubjectUserName"),
        None,
        {"domain": _get(data, "SubjectDomainName")},
    )


def _user_created(data: dict[str, str]) -> Classified:
    fields = {"created_by": _get(data, "SubjectUserName")}
    return "win_user_created", _get(data, "TargetUserName"), None, fields


def _group_member_added(data: dict[str, str]) -> Classified:
    fields = {
        "group": _get(data, "TargetUserName"),
        "member": _get(data, "MemberName"),
        "member_sid": _get(data, "MemberSid"),
    }
    return "win_group_member_added", _get(data, "SubjectUserName"), None, fields


def _log_cleared(data: dict[str, str]) -> Classified:
    return "win_audit_log_cleared", _get(data, "SubjectUserName"), None, {}


def _service_installed(data: dict[str, str]) -> Classified:
    fields = {
        "service_name": _get(data, "ServiceName"),
        "image_path": _get(data, "ImageFileName", _MAX_PATH),
        "start_type": _get(data, "StartType"),
    }
    return "win_service_installed", _get(data, "AccountName"), None, fields


def _task_created(data: dict[str, str]) -> Classified:
    fields = {"task_name": _get(data, "TaskName", _MAX_PATH)}
    return "win_scheduled_task_created", _get(data, "SubjectUserName"), None, fields


# Event ID -> how to read it. IDs are the standard ones of the Security and System logs.
_HANDLERS: dict[int, Callable[[dict[str, str]], Classified]] = {
    4624: _logon("win_logon_success"),
    4625: _logon("win_logon_failed"),
    4672: _privileged_logon,
    4698: _task_created,
    4720: _user_created,
    4728: _group_member_added,  # member added to a global security group
    4732: _group_member_added,  # ... to a local security group
    4756: _group_member_added,  # ... to a universal security group
    1102: _log_cleared,  # Security log cleared
    104: _log_cleared,  # another log (for example System) cleared
    7045: _service_installed,
}


def _text(value: Any) -> str | None:
    """Event data values are text; accept numbers and booleans too, nothing nested."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


def _record(doc: dict[str, Any]) -> tuple[str, Any, str, str, Any] | None:
    """(timestamp text, event id, computer, channel, data) from either supported layout."""
    winlog = doc.get("winlog")
    if isinstance(winlog, dict):  # Winlogbeat
        return (
            str(doc.get("@timestamp", "")),
            winlog.get("event_id"),
            str(winlog.get("computer_name") or ""),
            str(winlog.get("channel") or ""),
            winlog.get("event_data"),
        )
    if "EventID" in doc:  # the PowerShell snippet
        return (
            str(doc.get("TimeCreated", "")),
            doc.get("EventID"),
            str(doc.get("Computer") or ""),
            str(doc.get("Channel") or ""),
            doc.get("Data"),
        )
    return None


def parse_windows_line(
    line: str,
    *,
    tz: str = "UTC",
    year: int | None = None,
    now: datetime | None = None,
) -> Event | None:
    """Parse one exported Windows event. Returns None for events we do not understand."""
    line = line.strip().lstrip("﻿")  # PowerShell 5 writes a byte-order mark
    try:
        doc = json.loads(line)
    except (ValueError, RecursionError):  # not JSON, or nested so deeply that it is an attack
        return None
    if not isinstance(doc, dict) or (record := _record(doc)) is None:
        return None
    stamp, event_id, computer, channel, raw_data = record

    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        handler = _HANDLERS.get(int(event_id))
    except (ValueError, TypeError):
        return None
    if handler is None:
        return None
    if moment.tzinfo is None:
        return None  # a time without a zone cannot be placed reliably
    if raw_data is not None and not isinstance(raw_data, dict):
        return None

    data = {
        str(key): text
        for key, value in (raw_data or {}).items()
        if (text := _text(value)) is not None
    }
    event_type, username, src_ip, fields = handler(data)
    fields = {k: v for k, v in fields.items() if v is not None}
    fields["event_id"] = int(event_id)
    if channel:
        fields["channel"] = channel[:64]
    return Event(
        ts=to_utc_naive(moment),
        source="windows",
        event_type=event_type,
        host=computer[:255],
        src_ip=src_ip,
        username=username,
        raw=line,
        fields=fields,
    )

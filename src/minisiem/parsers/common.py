"""Helpers shared by the log parsers."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime


def clean_ip(value: str | None) -> str | None:
    """Return the normalised IP address, or None if `value` is not a valid IP."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def to_utc_naive(moment: datetime) -> datetime:
    """Convert an aware datetime to naive UTC."""
    return moment.astimezone(UTC).replace(tzinfo=None)

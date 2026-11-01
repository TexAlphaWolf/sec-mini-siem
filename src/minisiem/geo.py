"""GeoIP enrichment from a local MaxMind GeoLite2 database.

The lookup is done on the machine itself: attacker addresses are never sent to a third party.
MaxMind's databases are free but need an account and a licence key, and they may not be
redistributed, so none is shipped here. Download one and point MINISIEM_GEOIP_DB at it.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Any

import maxminddb

_MAX_TEXT = 64


def _name(node: Any) -> str | None:
    """The English name of a GeoIP record node such as {"names": {"en": "Germany"}}."""
    if isinstance(node, dict):
        names = node.get("names")
        if isinstance(names, dict) and isinstance(names.get("en"), str):
            return names["en"][:_MAX_TEXT]
    return None


class GeoIP:
    """Looks up the country, city and network owner of public IP addresses."""

    def __init__(self, city_reader: Any | None, asn_reader: Any | None = None) -> None:
        self._city = city_reader
        self._asn = asn_reader
        # Attackers repeat themselves, so remember recent answers.
        self.lookup = lru_cache(maxsize=4096)(self._lookup)

    @classmethod
    def open(cls, city_path: Path | None, asn_path: Path | None = None) -> GeoIP | None:
        """Open the configured databases; None when GeoIP is not configured."""
        if city_path is None and asn_path is None:
            return None
        city = cls._open_reader(city_path, "MINISIEM_GEOIP_DB") if city_path else None
        asn = cls._open_reader(asn_path, "MINISIEM_GEOIP_ASN_DB") if asn_path else None
        return cls(city, asn)

    @staticmethod
    def _open_reader(path: Path, setting: str) -> Any:
        try:
            return maxminddb.open_database(str(path))
        except FileNotFoundError:
            raise ValueError(f"{setting}: file not found: {path}") from None
        except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
            raise ValueError(f"{setting}: {path} is not a usable .mmdb database ({exc})") from exc

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()

    def _lookup(self, ip: str | None) -> dict[str, Any] | None:
        if not ip:
            return None
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None  # private, loopback, documentation ranges... nothing to look up
        except ValueError:
            return None

        result: dict[str, Any] = {}
        record = self._get(self._city, ip)
        if record:
            country = record.get("country") or record.get("registered_country")
            if isinstance(country, dict) and isinstance(country.get("iso_code"), str):
                result["country_code"] = country["iso_code"][:8]
            if name := _name(country):
                result["country"] = name
            if city := _name(record.get("city")):
                result["city"] = city
        record = self._get(self._asn, ip)
        if record:
            number = record.get("autonomous_system_number")
            if isinstance(number, int):
                result["asn"] = number
            org = record.get("autonomous_system_organization")
            if isinstance(org, str):
                result["org"] = org[:_MAX_TEXT]
        return result or None

    @staticmethod
    def _get(reader: Any, ip: str) -> dict[str, Any] | None:
        if reader is None:
            return None
        try:
            record = reader.get(ip)
        except (ValueError, maxminddb.InvalidDatabaseError, OSError):
            return None
        return record if isinstance(record, dict) else None


def describe(geo: dict[str, Any] | None) -> str:
    """A short text such as "Berlin, Germany (AS3320 Deutsche Telekom)" for messages."""
    if not geo:
        return ""
    place = ", ".join(str(part) for part in (geo.get("city"), geo.get("country")) if part)
    if not place and geo.get("country_code"):
        place = str(geo["country_code"])
    if "asn" in geo:
        owner = f"AS{geo['asn']}" + (f" {geo['org']}" if geo.get("org") else "")
        place = f"{place} ({owner})" if place else owner
    return place

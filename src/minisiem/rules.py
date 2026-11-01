"""Sigma-inspired detection rules and the engine that evaluates them.

A rule is a YAML file:

    id: ssh-bruteforce
    title: SSH brute-force attempt
    severity: high                      # low | medium | high | critical
    tags: [attack.credential_access, attack.t1110]
    match:                              # all keys must match (AND) ...
      event_type: [ssh_failed_password, ssh_invalid_user]   # ... any listed value (OR)
    threshold:                          # optional: fire only after N matches
      count: 5
      window: 60s                       # s, m, h or d
      group_by: src_ip                  # count separately per value of this field

Field modifiers: `field|contains`, `field|startswith`, `field|endswith`,
`field|re` (regex), `field|gte`, `field|lte`. Text comparisons are case-insensitive.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .events import Event

SEVERITIES = ("low", "medium", "high", "critical")
_OPS = ("equals", "contains", "startswith", "endswith", "re", "gte", "lte")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_DURATION_RE = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RuleError(ValueError):
    """A rule file is invalid."""


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    values: tuple[Any, ...]

    def test(self, data: dict[str, Any]) -> bool:
        actual = data.get(self.field)
        if actual is None:
            return False
        return any(_compare(self.op, actual, expected) for expected in self.values)


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if op in ("gte", "lte"):
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return left >= right if op == "gte" else left <= right
    if op == "re":
        return expected.search(str(actual)) is not None
    left, right = str(actual).lower(), str(expected).lower()
    if op == "contains":
        return right in left
    if op == "startswith":
        return left.startswith(right)
    if op == "endswith":
        return left.endswith(right)
    return left == right


@dataclass(frozen=True)
class Threshold:
    count: int
    window_seconds: int
    group_by: str | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    tags: tuple[str, ...]
    conditions: tuple[Condition, ...]
    threshold: Threshold | None = None
    path: str = ""

    def matches(self, data: dict[str, Any]) -> bool:
        return all(condition.test(data) for condition in self.conditions)


@dataclass
class Alert:
    ts: datetime
    rule_id: str
    title: str
    severity: str
    tags: list[str]
    src_ip: str | None
    group_key: str | None
    event_count: int
    details: dict[str, Any] = field(default_factory=dict)


# -------------------------------------------------------------------------- loading


def parse_duration(value: Any) -> int:
    """'60s' / '5m' / '1h' / '1d' (or a plain positive int of seconds) -> seconds."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    match = _DURATION_RE.match(str(value).strip().lower())
    if not match or int(match[1]) <= 0:
        raise RuleError(f"invalid duration {value!r}; use e.g. 60s, 5m, 1h")
    return int(match[1]) * _UNITS[match[2]]


def _build_condition(key: str, raw_value: Any) -> Condition:
    name, _, op = key.partition("|")
    op = op or "equals"
    if not name:
        raise RuleError(f"empty field name in match key {key!r}")
    if op not in _OPS:
        raise RuleError(f"unknown modifier {op!r} in {key!r}; use one of {', '.join(_OPS)}")
    raw_values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not raw_values:
        raise RuleError(f"empty value list for {key!r}")
    if op == "re":
        try:
            values: tuple[Any, ...] = tuple(re.compile(str(v), re.IGNORECASE) for v in raw_values)
        except re.error as exc:
            raise RuleError(f"invalid regex in {key!r}: {exc}") from exc
    else:
        values = tuple(raw_values)
    return Condition(field=name, op=op, values=values)


def _build_rule(doc: Any, path: Path) -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("a rule file must contain a YAML mapping")
    for key in ("id", "title", "severity", "match"):
        if key not in doc:
            raise RuleError(f"missing required key {key!r}")

    rule_id = str(doc["id"])
    if not _ID_RE.match(rule_id):
        raise RuleError(f"invalid id {rule_id!r}; use lowercase letters, digits, '-' and '_'")
    severity = str(doc["severity"]).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"invalid severity {severity!r}; use one of {', '.join(SEVERITIES)}")
    match = doc["match"]
    if not isinstance(match, dict) or not match:
        raise RuleError("'match' must be a non-empty mapping")

    threshold = None
    if (raw := doc.get("threshold")) is not None:
        if not isinstance(raw, dict) or "count" not in raw or "window" not in raw:
            raise RuleError("'threshold' needs 'count' and 'window'")
        count = raw["count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuleError("threshold 'count' must be a positive integer")
        group_by = raw.get("group_by")
        if group_by is not None and not isinstance(group_by, str):
            raise RuleError("threshold 'group_by' must be a field name")
        threshold = Threshold(count, parse_duration(raw["window"]), group_by)

    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        raise RuleError("'tags' must be a list")

    return Rule(
        id=rule_id,
        title=str(doc["title"]),
        severity=severity,
        description=str(doc.get("description", "")).strip(),
        tags=tuple(str(t) for t in tags),
        conditions=tuple(_build_condition(str(k), v) for k, v in match.items()),
        threshold=threshold,
        path=str(path),
    )


def load_rules(directory: str | Path) -> list[Rule]:
    """Load every *.yml / *.yaml rule in `directory`. Raises RuleError on the first problem."""
    directory = Path(directory)
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not files:
        raise RuleError(f"no rule files found in {directory}")

    rules: list[Rule] = []
    seen: dict[str, Path] = {}
    for path in files:
        try:
            rule = _build_rule(yaml.safe_load(path.read_text(encoding="utf-8")), path)
        except yaml.YAMLError as exc:
            raise RuleError(f"{path.name}: invalid YAML: {exc}") from exc
        except RuleError as exc:
            raise RuleError(f"{path.name}: {exc}") from exc
        if rule.id in seen:
            raise RuleError(
                f"{path.name}: duplicate rule id {rule.id!r} (also in {seen[rule.id].name})"
            )
        seen[rule.id] = path
        rules.append(rule)
    return rules


# --------------------------------------------------------------------------- engine


class RuleEngine:
    """Evaluates events against rules, one at a time, in timestamp order.

    Threshold rules keep a sliding window of timestamps per (rule, group). After a threshold
    alert fires, that group is silenced for one window so a sustained attack produces one alert
    per window, not one per log line. State lives in memory: restarting the process resets it.
    """

    _SWEEP_EVERY = 5000

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        self._windows: dict[tuple[str, str], deque[datetime]] = {}
        self._silenced_until: dict[tuple[str, str], datetime] = {}
        self._max_window = max(
            (r.threshold.window_seconds for r in rules if r.threshold), default=0
        )
        self._calls = 0

    def evaluate(self, event: Event) -> list[Alert]:
        data = event.match_view()
        alerts: list[Alert] = []
        self._calls += 1
        if self._calls % self._SWEEP_EVERY == 0:
            self._sweep(event.ts)

        for rule in self.rules:
            if not rule.matches(data):
                continue
            if rule.threshold is None:
                alerts.append(self._alert(rule, event, 1, None, {}))
            elif alert := self._check_threshold(rule, rule.threshold, event, data):
                alerts.append(alert)
        return alerts

    def _check_threshold(
        self, rule: Rule, threshold: Threshold, event: Event, data: dict[str, Any]
    ) -> Alert | None:
        if threshold.group_by:
            group_value = data.get(threshold.group_by)
            if group_value is None:
                return None  # cannot attribute this event to a group
            group_key = str(group_value)
        else:
            group_key = "*"

        key = (rule.id, group_key)
        window = self._windows.setdefault(key, deque())
        window.append(event.ts)
        cutoff = event.ts - timedelta(seconds=threshold.window_seconds)
        while window and window[0] < cutoff:
            window.popleft()

        silenced = self._silenced_until.get(key)
        if silenced is not None and event.ts < silenced:
            return None
        if len(window) < threshold.count:
            return None

        details = {
            "group_by": threshold.group_by,
            "window_seconds": threshold.window_seconds,
            "threshold": threshold.count,
            "first_seen": window[0].isoformat() + "Z",
            "last_seen": event.ts.isoformat() + "Z",
        }
        alert = self._alert(rule, event, len(window), group_key, details)
        self._silenced_until[key] = event.ts + timedelta(seconds=threshold.window_seconds)
        window.clear()
        return alert

    @staticmethod
    def _alert(
        rule: Rule, event: Event, count: int, group_key: str | None, details: dict[str, Any]
    ) -> Alert:
        details = {
            **details,
            "event_type": event.event_type,
            "username": event.username,
            "host": event.host,
            "sample": event.raw[:300],
        }
        return Alert(
            ts=event.ts,
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            tags=list(rule.tags),
            src_ip=event.src_ip,
            group_key=group_key,
            event_count=count,
            details=details,
        )

    def _sweep(self, now: datetime) -> None:
        """Drop state for groups that have been quiet for longer than any window."""
        horizon = timedelta(seconds=self._max_window)
        for key in [k for k, w in self._windows.items() if not w or now - w[-1] > horizon]:
            del self._windows[key]
        for key in [k for k, until in self._silenced_until.items() if until < now]:
            del self._silenced_until[key]

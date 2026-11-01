"""Export Mini-SIEM rules as Sigma rules (https://sigmahq.io).

Each rule becomes a Sigma detection rule. A rule with a threshold also gets a Sigma v2
*correlation* rule (`event_count`, or `value_count` for "distinct" thresholds) that points at it.

Two things to know before using the output elsewhere:

* Field names are Mini-SIEM's own (`src_ip`, `username`, `path_decoded`, ...). A Sigma backend
  needs a pipeline that maps them to the field names of your log store.
* Mini-SIEM silences a group for one window after it alerts. Sigma has no such concept, so
  a `count: 1` threshold is exported as the plain detection rule.
"""

from __future__ import annotations

import uuid
from typing import Any

import yaml

from .rules import Condition, Rule

# Fixed namespace: the same rule id always gives the same Sigma id.
_NAMESPACE = uuid.UUID("5d0a8f0e-6c1e-4f55-9f43-6d1f3a6f2b7a")

_MODIFIERS = {
    "equals": "",
    "contains": "|contains",
    "startswith": "|startswith",
    "endswith": "|endswith",
    "re": "|re|i",  # Mini-SIEM matches regular expressions case-insensitively
    "gte": "|gte",
    "lte": "|lte",
}


def _sigma_id(name: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, name))


def _selection(conditions: tuple[Condition, ...]) -> dict[str, Any]:
    selection: dict[str, Any] = {}
    for condition in conditions:
        values = [v.pattern if condition.op == "re" else v for v in condition.values]
        selection[condition.field + _MODIFIERS[condition.op]] = (
            values[0] if len(values) == 1 else values
        )
    return selection


def _logsource(rule: Rule) -> dict[str, str]:
    types: list[str] = []
    for condition in rule.conditions:
        if condition.field == "event_type":
            types += [str(v) for v in condition.values]
    if types and all(t.startswith(("ssh_", "sudo_")) for t in types):
        return {"product": "linux", "service": "auth"}
    if types and all(t == "http_request" for t in types):
        return {"category": "webserver"}
    return {"product": "any"}


def to_sigma(rule: Rule) -> list[dict[str, Any]]:
    """The Sigma documents for one rule: the detection and, with a threshold, a correlation."""
    detection: dict[str, Any] = {
        "title": rule.title,
        "id": _sigma_id(rule.id),
        "name": rule.id,
        "status": "experimental",
        "description": rule.description or rule.title,
        "author": "Mini-SIEM",
        "tags": list(rule.tags),
        "logsource": _logsource(rule),
        "detection": {"selection": _selection(rule.conditions), "condition": "selection"},
        "level": rule.severity,
    }
    threshold = rule.threshold
    if threshold is None or (threshold.count == 1 and not threshold.distinct):
        return [detection]

    condition: dict[str, Any] = {"gte": threshold.count}
    if threshold.distinct:
        condition["field"] = threshold.distinct
    correlation: dict[str, Any] = {
        "title": f"{rule.title} (threshold)",
        "id": _sigma_id(f"{rule.id}:correlation"),
        "name": f"{rule.id}-threshold",
        "status": "experimental",
        "description": rule.description or rule.title,
        "author": "Mini-SIEM",
        "tags": list(rule.tags),
        "correlation": {
            "type": "value_count" if threshold.distinct else "event_count",
            "rules": [rule.id],
            **({"group-by": [threshold.group_by]} if threshold.group_by else {}),
            "timespan": f"{threshold.window_seconds}s",
            "condition": condition,
        },
        "level": rule.severity,
    }
    return [detection, correlation]


def export_sigma(rules: list[Rule]) -> str:
    """All rules as one multi-document YAML stream."""
    documents = [doc for rule in rules for doc in to_sigma(rule)]
    return yaml.safe_dump_all(
        documents, sort_keys=False, allow_unicode=True, explicit_start=True, width=100
    )

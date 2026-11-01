from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from minisiem.events import Event
from minisiem.rules import RuleEngine, RuleError, load_rules, parse_duration

T0 = datetime(2026, 10, 20, 9, 0, 0)


def write_rule(tmp_path, body: str):
    (tmp_path / "r.yml").write_text(body, encoding="utf-8")
    return tmp_path


def ssh_fail(offset_s: float, ip: str = "203.0.113.50") -> Event:
    return Event(
        ts=T0 + timedelta(seconds=offset_s),
        source="auth",
        event_type="ssh_failed_password",
        src_ip=ip,
        username="admin",
        raw="x",
    )


def http(path: str, status: int = 200, ua: str = "curl/8", offset_s: float = 0) -> Event:
    return Event(
        ts=T0 + timedelta(seconds=offset_s),
        source="nginx",
        event_type="http_request",
        src_ip="203.0.113.9",
        raw="x",
        fields={"path": path, "path_decoded": path, "status": status, "user_agent": ua},
    )


@pytest.fixture
def engine(rules_dir):
    return RuleEngine(load_rules(rules_dir))


def ids(alerts):
    return [a.rule_id for a in alerts]


def test_shipped_rules_load_and_ids_are_unique(rules_dir):
    rules = load_rules(rules_dir)
    assert len(rules) >= 10
    assert len({r.id for r in rules}) == len(rules)


def test_threshold_not_reached(engine):
    alerts = [a for i in range(4) for a in engine.evaluate(ssh_fail(i))]
    assert "ssh-bruteforce" not in ids(alerts)


def test_threshold_reached_fires_once_and_then_is_silenced(engine):
    alerts = [a for i in range(12) for a in engine.evaluate(ssh_fail(i))]
    brute = [a for a in alerts if a.rule_id == "ssh-bruteforce"]
    assert len(brute) == 1
    assert brute[0].event_count == 5
    assert brute[0].src_ip == "203.0.113.50"
    assert brute[0].severity == "high"
    assert brute[0].details["window_seconds"] == 60


def test_attack_that_continues_alerts_again_in_the_next_window(engine):
    alerts = [a for i in range(0, 200, 5) for a in engine.evaluate(ssh_fail(i))]
    brute = [a for a in alerts if a.rule_id == "ssh-bruteforce"]
    assert len(brute) >= 2


def test_slow_attempts_outside_the_window_do_not_fire(engine):
    alerts = [a for i in range(10) for a in engine.evaluate(ssh_fail(i * 30))]  # 1 per 30s, 5m total
    assert "ssh-bruteforce" not in ids(alerts)


def test_groups_are_counted_separately(engine):
    alerts = []
    for i in range(4):
        alerts += engine.evaluate(ssh_fail(i, ip="203.0.113.1"))
        alerts += engine.evaluate(ssh_fail(i, ip="203.0.113.2"))
    assert "ssh-bruteforce" not in ids(alerts)


def test_event_without_the_group_field_is_ignored(engine):
    event = ssh_fail(0)
    event.src_ip = None
    assert engine.evaluate(event) == []


def test_single_event_rule_with_contains_is_case_insensitive(engine):
    alerts = engine.evaluate(http("/search?q=1 UNION SELECT password FROM users"))
    assert "web-sqli-probe" in ids(alerts)
    assert engine.evaluate(http("/index.html")) == []


def test_path_traversal_and_scanner_user_agent(engine):
    assert "web-path-traversal" in ids(engine.evaluate(http("/download?f=../../etc/passwd")))
    assert "web-scanner-user-agent" in ids(engine.evaluate(http("/", ua="Mozilla/5.0 (Nikto/2.5)")))


def test_404_burst_rule_needs_twenty_requests(engine):
    alerts = [a for i in range(19) for a in engine.evaluate(http("/x", status=404, offset_s=i))]
    assert "web-scanner-404" not in ids(alerts)
    alerts = engine.evaluate(http("/x", status=404, offset_s=19))
    assert "web-scanner-404" in ids(alerts)


def test_regex_and_numeric_modifiers(tmp_path):
    rules = load_rules(
        write_rule(
            tmp_path,
            "id: r\ntitle: T\nseverity: low\nmatch:\n  path|re: '^/api/v[0-9]+/'\n  status|gte: 500\n",
        )
    )
    engine = RuleEngine(rules)
    assert engine.evaluate(http("/api/v2/users", status=503))
    assert not engine.evaluate(http("/api/v2/users", status=200))
    assert not engine.evaluate(http("/other", status=503))


@pytest.mark.parametrize(
    "body, message",
    [
        ("id: r\ntitle: T\nseverity: urgent\nmatch: {a: 1}\n", "invalid severity"),
        ("id: r\ntitle: T\nseverity: low\n", "missing required key"),
        ("id: r\ntitle: T\nseverity: low\nmatch: {}\n", "non-empty mapping"),
        ("id: R!\ntitle: T\nseverity: low\nmatch: {a: 1}\n", "invalid id"),
        ("id: r\ntitle: T\nseverity: low\nmatch: {'a|nope': 1}\n", "unknown modifier"),
        ("id: r\ntitle: T\nseverity: low\nmatch: {'a|re': '['}\n", "invalid regex"),
        ("id: r\ntitle: T\nseverity: low\nmatch: {a: 1}\nthreshold: {count: 3, window: soon}\n", "invalid duration"),
        ("id: r\ntitle: T\nseverity: low\nmatch: {a: 1}\nthreshold: {count: 0, window: 1m}\n", "positive integer"),
        ("- just\n- a list\n", "YAML mapping"),
    ],
)
def test_invalid_rules_are_rejected_with_a_clear_message(tmp_path, body, message):
    with pytest.raises(RuleError, match=message):
        load_rules(write_rule(tmp_path, body))


def test_duplicate_rule_ids_are_rejected(tmp_path):
    body = "id: same\ntitle: T\nseverity: low\nmatch: {a: 1}\n"
    (tmp_path / "a.yml").write_text(body, encoding="utf-8")
    (tmp_path / "b.yml").write_text(body, encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(tmp_path)


def test_missing_or_empty_rules_directory(tmp_path):
    with pytest.raises(RuleError, match="not found"):
        load_rules(tmp_path / "nope")
    with pytest.raises(RuleError, match="no rule files"):
        load_rules(tmp_path)


def test_parse_duration():
    assert parse_duration("60s") == 60
    assert parse_duration("5m") == 300
    assert parse_duration("2h") == 7200
    assert parse_duration(90) == 90
    with pytest.raises(RuleError):
        parse_duration("0m")

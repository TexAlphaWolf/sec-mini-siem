"""Detection as code: every shipped rule must fire on an attack and stay quiet on benign traffic.

Each case is a list of real log lines, run through the parsers and the rule engine exactly as in
production. Adding a rule without adding cases here fails `test_every_shipped_rule_has_tests`.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from minisiem.parsers import parse_lines
from minisiem.rules import RuleEngine, load_rules

T0 = datetime(2026, 10, 20, 9, 0, 0)
UA_BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


def _stamp(sec: float) -> datetime:
    return T0 + timedelta(seconds=sec)


# --- auth.log lines ----------------------------------------------------------------------------


def _syslog(sec: float, message: str, program: str = "sshd") -> str:
    t = _stamp(sec)
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} web01 {program}[1]: {message}"


def failed(sec, user="admin", ip="203.0.113.50"):
    return _syslog(sec, f"Failed password for {user} from {ip} port 4242 ssh2")


def invalid(sec, user="test", ip="203.0.113.50"):
    return _syslog(sec, f"Invalid user {user} from {ip} port 4242")


def accepted(sec, user, ip="192.0.2.10"):
    return _syslog(sec, f"Accepted publickey for {user} from {ip} port 4242 ssh2: ED25519 SHA256:x")


def sudo_fail(sec, user="bob"):
    message = (
        f"    {user} : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/{user} ; "
        "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )
    return _syslog(sec, message, program="sudo")


def sudo_ok(sec, user="alice"):
    message = f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update"
    return _syslog(sec, message, program="sudo")


# --- access.log lines --------------------------------------------------------------------------


def web(sec, path="/", status=200, ip="203.0.113.77", ua=UA_BROWSER):
    t = _stamp(sec)
    return (
        f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}"'
    )


# --- the cases ---------------------------------------------------------------------------------

CASES: dict[str, tuple[str, dict[str, list[list[str]]]]] = {
    "ssh-bruteforce": (
        "auth",
        {
            "fires": [
                [failed(i) for i in range(5)],
                [invalid(i) for i in range(5)],
            ],
            "quiet": [
                [failed(i) for i in range(4)],  # one short of the threshold
                [failed(i, ip=f"203.0.113.{i + 1}") for i in range(5)],  # five different IPs
                [failed(i * 60) for i in range(5)],  # five failures, a minute apart
                [accepted(i, "alice") for i in range(10)],  # successful logins
            ],
        },
    ),
    "ssh-user-enumeration": (
        "auth",
        {
            "fires": [[invalid(i * 30, user=f"user{i}") for i in range(3)]],
            "quiet": [
                [invalid(i * 30, user=f"user{i}") for i in range(2)],  # two different names
                [invalid(i * 30) for i in range(6)],  # one name tried again and again
                [invalid(i * 30, user=f"user{i}", ip=f"203.0.113.{i + 1}") for i in range(3)],
                [failed(i * 30) for i in range(5)],  # wrong password for an existing user
            ],
        },
    ),
    "ssh-password-spraying": (
        "auth",
        {
            "fires": [[failed(i * 20, user=f"user{i}") for i in range(5)]],
            "quiet": [
                [failed(i * 20, user=f"user{i}") for i in range(4)],  # one account short
                [failed(i * 20) for i in range(10)],  # brute force on a single account
                [failed(i * 20, user=f"user{i}", ip=f"203.0.113.{i + 1}") for i in range(5)],
                [failed(i * 300, user=f"user{i}") for i in range(5)],  # too slow for the window
            ],
        },
    ),
    "ssh-root-attempts": (
        "auth",
        {
            "fires": [[failed(i * 30, user="root") for i in range(3)]],
            "quiet": [
                [failed(i * 30, user="root") for i in range(2)],
                [failed(i * 30, user="alice") for i in range(3)],
            ],
        },
    ),
    "ssh-root-login": (
        "auth",
        {
            "fires": [[accepted(0, "root")]],
            "quiet": [[accepted(0, "alice")]],
        },
    ),
    "sudo-repeated-failures": (
        "auth",
        {
            "fires": [[sudo_fail(i * 60) for i in range(3)]],
            "quiet": [
                [sudo_fail(i * 60) for i in range(2)],
                [sudo_fail(i * 60, user=name) for i, name in enumerate(("amy", "bob", "cat"))],
                [sudo_ok(i * 60) for i in range(5)],
            ],
        },
    ),
    "web-scanner-404": (
        "nginx",
        {
            "fires": [[web(i, f"/x{i}", 404) for i in range(20)]],
            "quiet": [
                [web(i, f"/x{i}", 404) for i in range(19)],
                [web(i, f"/x{i}", 200) for i in range(20)],
                [web(i, "/x", 404, ip=f"203.0.113.{i + 1}") for i in range(20)],
            ],
        },
    ),
    "web-sensitive-file-probe": (
        "nginx",
        {
            "fires": [
                [web(0, "/.env", 404), web(1, "/.git/config", 404), web(2, "/wp-login.php", 404)],
                [web(0, "/%2Eenv"), web(1, "/%2Egit/config"), web(2, "/phpmyadmin/")],  # encoded
            ],
            "quiet": [
                [web(0, "/.env", 404), web(1, "/wp-login.php", 404)],  # two probes only
                [web(i, "/products") for i in range(5)],
            ],
        },
    ),
    "web-path-traversal": (
        "nginx",
        {
            "fires": [
                [web(0, "/download?file=../../../../etc/passwd")],
                [web(0, "/download?file=..%2F..%2F..%2Fetc%2Fshadow")],  # URL-encoded
                [web(0, "/static/..\\..\\windows\\win.ini")],
            ],
            "quiet": [
                [web(0, "/download?file=report.pdf")],
                [web(0, "/docs/v1.2/readme")],
            ],
        },
    ),
    "web-sqli-probe": (
        "nginx",
        {
            "fires": [
                [web(0, "/products?id=1%20UNION%20SELECT%20NULL--")],
                [web(0, "/products?id=1%27%20OR%201%3D1--")],
                [web(0, "/products?id=1/**/UNION/**/ALL/**/SELECT/**/1")],  # comment evasion
                [web(0, "/search?q=1%20AND%20SLEEP(5)")],
                [web(0, "/x?q=information_schema.tables")],
            ],
            "quiet": [
                [web(0, "/products?id=42")],
                [web(0, "/search?q=credit+union+selection")],  # "union select" inside two words
                [web(0, "/search?q=color+1%3D1")],  # "or 1=1" inside "color"
            ],
        },
    ),
    "web-scanner-user-agent": (
        "nginx",
        {
            "fires": [
                [web(0, ua="sqlmap/1.7.2#stable (https://sqlmap.org)")],
                [web(0, ua="Mozilla/5.0 (compatible; Nmap Scripting Engine)")],
            ],
            "quiet": [
                [web(0)],
                [web(0, ua="curl/8.5.0")],
            ],
        },
    ),
}


def _params():
    for rule_id, (source, cases) in CASES.items():
        for i, lines in enumerate(cases["fires"]):
            yield pytest.param(rule_id, source, lines, True, id=f"{rule_id}-fires-{i}")
        for i, lines in enumerate(cases["quiet"]):
            yield pytest.param(rule_id, source, lines, False, id=f"{rule_id}-quiet-{i}")


def fired_rules(source: str, lines: list[str], rules_dir) -> set[str]:
    events, skipped = parse_lines(source, lines, tz="UTC", year=2026)
    assert skipped == 0, "every test line must be understood by the parser"
    events.sort(key=lambda e: e.ts)
    engine = RuleEngine(load_rules(rules_dir))
    return {alert.rule_id for event in events for alert in engine.evaluate(event)}


@pytest.mark.parametrize(("rule_id", "source", "lines", "should_fire"), list(_params()))
def test_rule_behaviour(rule_id, source, lines, should_fire, rules_dir):
    fired = fired_rules(source, lines, rules_dir)
    if should_fire:
        assert rule_id in fired, f"{rule_id} should have fired, got {sorted(fired)}"
    else:
        assert rule_id not in fired, f"{rule_id} should have stayed quiet"


def test_every_shipped_rule_has_tests(rules_dir):
    shipped = {rule.id for rule in load_rules(rules_dir)}
    assert shipped == set(CASES), (
        f"rules without tests: {sorted(shipped - set(CASES))}; "
        f"tests for missing rules: {sorted(set(CASES) - shipped)}"
    )


def test_every_rule_has_an_attack_and_a_benign_case():
    for rule_id, (_, cases) in CASES.items():
        assert cases["fires"], f"{rule_id}: add at least one case that must fire"
        assert cases["quiet"], f"{rule_id}: add at least one case that must stay quiet"

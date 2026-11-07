from __future__ import annotations

import json
from datetime import datetime, timedelta

from minisiem.parsers import parse_lines
from minisiem.parsers.journald import parse_journald_line
from minisiem.rules import RuleEngine, load_rules

T0 = datetime(2026, 10, 20, 9, 0, 0)
EPOCH = datetime(1970, 1, 1)


def entry(message, *, sec: float = 0, ident: str = "sshd", **extra) -> str:
    micros = (T0 + timedelta(seconds=sec) - EPOCH) // timedelta(microseconds=1)
    doc = {
        "__REALTIME_TIMESTAMP": str(micros),
        "_HOSTNAME": "db01",
        "SYSLOG_IDENTIFIER": ident,
        "_PID": "812",
        "_SYSTEMD_UNIT": "ssh.service",
        "MESSAGE": message,
        **extra,
    }
    return json.dumps(doc)


def test_failed_password_is_read_like_in_auth_log():
    e = parse_journald_line(
        entry("Failed password for invalid user admin from 203.0.113.50 port 4242 ssh2")
    )
    assert e is not None
    assert (e.source, e.event_type) == ("journald", "ssh_failed_password")
    assert (e.username, e.src_ip, e.host) == ("admin", "203.0.113.50", "db01")
    assert e.ts == T0
    assert e.fields["invalid_user"] is True
    assert e.fields["pid"] == 812
    assert e.fields["unit"] == "ssh.service"


def test_microseconds_are_kept():
    line = entry("Accepted publickey for alice from 192.0.2.10 port 22 ssh2: ED25519 SHA256:x")
    doc = json.loads(line)
    doc["__REALTIME_TIMESTAMP"] = str(int(doc["__REALTIME_TIMESTAMP"]) + 250_000)
    e = parse_journald_line(json.dumps(doc))
    assert e.ts == T0 + timedelta(microseconds=250_000)


def test_sudo_message_with_leading_spaces():
    e = parse_journald_line(
        entry(
            "    bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
            ident="sudo",
        )
    )
    assert e.event_type == "sudo_failure"
    assert e.username == "bob"


def test_message_stored_as_bytes_is_decoded():
    text = "Invalid user test from 203.0.113.5 port 5555"
    e = parse_journald_line(entry(list(text.encode())))
    assert e is not None and e.event_type == "ssh_invalid_user"


def test_program_falls_back_to_comm():
    doc = json.loads(entry("Invalid user x from 203.0.113.5 port 1"))
    del doc["SYSLOG_IDENTIFIER"]
    doc["_COMM"] = "sshd"
    assert parse_journald_line(json.dumps(doc)) is not None


def test_a_bom_at_the_start_is_ignored():
    assert parse_journald_line("\ufeff" + entry("Invalid user x from 203.0.113.5 port 1"))


def test_things_that_are_not_understood_are_skipped():
    hostile = [
        "not json at all",
        "[1, 2, 3]",
        "[" * 50_000,  # absurdly deep nesting
        "{}",
        entry("Started Session 3 of User alice.", ident="systemd"),
        entry(42),
        entry([1, 2, 300]),  # not valid bytes
        entry("Invalid user x from 203.0.113.5 port 1", **{"__REALTIME_TIMESTAMP": "soon"}),
        entry("Invalid user x from 203.0.113.5 port 1", **{"__REALTIME_TIMESTAMP": "9" * 40}),
        entry("Failed password for root from <script>alert(1)</script> port 22 ssh2"),
        entry("Invalid user x from 203.0.113.5 port 1", ident=7),
    ]
    events, skipped = parse_lines("journald", hostile)
    assert events == [] and skipped == len(hostile)


def test_hostile_content_stays_data():
    payload = "<img/src=x/onerror=alert(1)>"
    e = parse_journald_line(entry(f"Invalid user {payload} from 203.0.113.5 port 1"))
    assert e.username == payload  # kept as plain text; the dashboard never renders it as HTML


def test_the_same_rules_fire_for_journald_events():
    engine = RuleEngine(load_rules("rules"))
    lines = [
        entry(f"Failed password for admin from 203.0.113.50 port {4000 + i} ssh2", sec=i)
        for i in range(5)
    ]
    events, skipped = parse_lines("journald", lines)
    assert skipped == 0
    fired = {a.rule_id for e in events for a in engine.evaluate(e)}
    assert "ssh-bruteforce" in fired

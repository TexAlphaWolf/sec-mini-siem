from __future__ import annotations

from datetime import datetime

from minisiem.parsers import parse_lines
from minisiem.parsers.auth import parse_auth_line
from minisiem.parsers.nginx import parse_nginx_line

NOW = datetime(2026, 10, 22, 12, 0, 0).astimezone()  # aware, any zone


def auth(line: str, **kwargs):
    return parse_auth_line(line, year=2026, now=NOW, **kwargs)


def test_failed_password_for_invalid_user():
    e = auth("Oct 20 09:12:03 web01 sshd[2211]: Failed password for invalid user admin from 203.0.113.50 port 4242 ssh2")
    assert e is not None
    assert e.event_type == "ssh_failed_password"
    assert e.username == "admin"
    assert e.src_ip == "203.0.113.50"
    assert e.host == "web01"
    assert e.fields["invalid_user"] is True
    assert e.fields["port"] == 4242
    assert e.ts == datetime(2026, 10, 20, 9, 12, 3)


def test_failed_password_for_existing_user():
    e = auth("Oct 20 09:12:03 web01 sshd[1]: Failed password for root from 198.51.100.23 port 22 ssh2")
    assert e.username == "root"
    assert e.fields["invalid_user"] is False


def test_invalid_user_and_accepted():
    invalid = auth("Oct 20 09:12:03 web01 sshd[1]: Invalid user test from 203.0.113.5 port 5555")
    assert invalid.event_type == "ssh_invalid_user"
    ok = auth("Oct  5 09:12:03 web01 sshd[1]: Accepted publickey for alice from 192.0.2.10 port 51122 ssh2: ED25519 SHA256:abc")
    assert ok.event_type == "ssh_accepted"
    assert ok.username == "alice"
    assert ok.ts.day == 5


def test_sudo_failure_and_command():
    fail = auth("Oct 20 10:30:00 web01 sudo:     bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    assert fail.event_type == "sudo_failure"
    assert fail.username == "bob"
    assert fail.fields["attempts"] == 3
    assert fail.fields["command"] == "/usr/bin/cat /etc/shadow"
    assert fail.src_ip is None

    ok = auth("Oct 20 10:40:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
    assert ok.event_type == "sudo_command"
    assert ok.fields["command"] == "/usr/bin/apt update"


def test_syslog_timezone_is_converted_to_utc():
    # Europe/Rome is UTC+2 on 20 October 2026 (DST ends on the 25th).
    e = auth("Oct 20 10:00:00 web01 sshd[1]: Invalid user x from 203.0.113.5 port 1", tz="Europe/Rome")
    assert e.ts == datetime(2026, 10, 20, 8, 0, 0)


def test_iso_timestamp_format():
    e = parse_auth_line(
        "2026-10-20T10:00:00.123456+02:00 web01 sshd[1]: Invalid user x from 203.0.113.5 port 1",
        now=NOW,
    )
    assert e.ts == datetime(2026, 10, 20, 8, 0, 0, 123456)


def test_december_line_read_in_january_belongs_to_previous_year():
    now = datetime(2027, 1, 2, 12, 0, 0).astimezone()
    e = parse_auth_line("Dec 31 23:59:00 web01 sshd[1]: Invalid user x from 203.0.113.5 port 1", now=now)
    assert e.ts.year == 2026


def test_invalid_ip_and_noise_are_rejected():
    assert auth("Oct 20 09:12:03 web01 sshd[1]: Invalid user x from not-an-ip port 1") is None
    assert auth("Oct 20 09:12:03 web01 CRON[1]: pam_unix(cron:session): session opened") is None
    assert auth("complete garbage") is None


def test_nginx_combined_line():
    e = parse_nginx_line(
        '203.0.113.77 - - [20/Oct/2026:10:50:01 +0200] "GET /products?id=1%27%20OR%201%3D1-- HTTP/1.1" '
        '404 153 "-" "sqlmap/1.7"'
    )
    assert e is not None
    assert e.event_type == "http_request"
    assert e.src_ip == "203.0.113.77"
    assert e.ts == datetime(2026, 10, 20, 8, 50, 1)  # +0200 -> UTC
    assert e.fields["status"] == 404
    assert e.fields["http_method"] == "GET"
    assert e.fields["path_decoded"] == "/products?id=1' OR 1=1--"
    assert e.fields["user_agent"] == "sqlmap/1.7"


def test_nginx_garbage_request_line_is_kept():
    e = parse_nginx_line('203.0.113.9 - - [20/Oct/2026:10:50:01 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert e is not None
    assert e.fields["http_method"] == ""
    assert e.fields["status"] == 400


def test_parse_lines_counts_skipped_and_ignores_blanks():
    lines = [
        "Oct 20 09:12:03 web01 sshd[1]: Invalid user x from 203.0.113.5 port 1",
        "",
        "not a log line",
    ]
    events, skipped = parse_lines("auth", lines, year=2026)
    assert len(events) == 1
    assert skipped == 1


def test_unknown_source_is_a_clear_error():
    try:
        parse_lines("syslog9000", [])
    except ValueError as exc:
        assert "unknown log source" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")

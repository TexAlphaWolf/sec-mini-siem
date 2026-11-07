#!/usr/bin/env python3
"""Generate deterministic, anonymised sample logs for the demo.

Only RFC 5737 documentation addresses are used (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so nothing here points at a real host.

    python scripts/generate_sample_logs.py
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_logs"
BASE = datetime(2026, 10, 20, 8, 0, 0)  # treated as UTC
HOST = "web01"
rng = random.Random(42)


def syslog(ts: datetime, prog: str, pid: int | None, msg: str) -> str:
    tag = f"{prog}[{pid}]" if pid else prog
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {HOST} {tag}: {msg}"


def auth_lines() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []

    # Normal logins.
    for minutes, user, ip in [
        (5, "alice", "192.0.2.10"),
        (100, "alice", "192.0.2.10"),
        (135, "bob", "192.0.2.11"),
    ]:
        ts = BASE + timedelta(minutes=minutes)
        port = rng.randint(40000, 60000)
        rows.append(
            (
                ts,
                syslog(
                    ts,
                    "sshd",
                    2100 + minutes,
                    f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:xxxx",
                ),
            )
        )

    # SSH brute force from 203.0.113.50: a dictionary of usernames, a few seconds apart.
    ts = BASE + timedelta(hours=1, minutes=12)
    users = [
        "admin",
        "test",
        "oracle",
        "ubuntu",
        "pi",
        "postgres",
        "git",
        "deploy",
        "user",
        "guest",
    ]
    for i in range(14):
        ts += timedelta(seconds=rng.randint(2, 4))
        user = users[i % len(users)]
        port = rng.randint(30000, 60000)
        rows.append(
            (ts, syslog(ts, "sshd", 3000 + i, f"Invalid user {user} from 203.0.113.50 port {port}"))
        )
        rows.append(
            (
                ts,
                syslog(
                    ts,
                    "sshd",
                    3000 + i,
                    f"Failed password for invalid user {user} from 203.0.113.50 port {port} ssh2",
                ),
            )
        )

    # Account guessing, then root attempts, then a root login from 198.51.100.23.
    ts = BASE + timedelta(hours=1, minutes=30)
    for user in ["test1", "backup", "support", "ftpuser"]:
        ts += timedelta(seconds=30)
        rows.append(
            (
                ts,
                syslog(
                    ts,
                    "sshd",
                    3300,
                    f"Invalid user {user} from 198.51.100.23 port {rng.randint(30000, 60000)}",
                ),
            )
        )
    for _ in range(4):
        ts += timedelta(seconds=25)
        rows.append(
            (
                ts,
                syslog(
                    ts,
                    "sshd",
                    3301,
                    f"Failed password for root from 198.51.100.23 port {rng.randint(30000, 60000)} ssh2",
                ),
            )
        )
    ts += timedelta(seconds=40)
    rows.append(
        (
            ts,
            syslog(
                ts,
                "sshd",
                3302,
                f"Accepted password for root from 198.51.100.23 port {rng.randint(30000, 60000)} ssh2",
            ),
        )
    )

    # Three failed sudo attempts by bob, then a normal sudo command by alice.
    ts = BASE + timedelta(hours=2, minutes=30)
    for _ in range(3):
        ts += timedelta(minutes=2)
        rows.append(
            (
                ts,
                syslog(
                    ts,
                    "sudo",
                    None,
                    "    bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
                ),
            )
        )
    ts += timedelta(minutes=6)
    rows.append(
        (
            ts,
            syslog(
                ts,
                "sudo",
                None,
                "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
            ),
        )
    )

    return sorted(rows, key=lambda r: r[0])


def nginx_line(
    ts: datetime, ip: str, method: str, path: str, status: int, size: int, ua: str
) -> str:
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def access_lines() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []
    browser = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

    # Normal visitors.
    pages = [
        "/",
        "/index.html",
        "/about",
        "/products",
        "/contact",
        "/static/app.css",
        "/static/app.js",
    ]
    for _ in range(90):
        ts = BASE + timedelta(seconds=rng.randint(0, 4 * 3600))
        ip = f"192.0.2.{rng.randint(20, 80)}"
        status = rng.choice([200, 200, 200, 304])
        rows.append(
            (
                ts,
                nginx_line(
                    ts, ip, "GET", rng.choice(pages), status, rng.randint(300, 9000), browser
                ),
            )
        )

    # Directory scanner from 203.0.113.77 (Nikto): many 404s plus probes for sensitive files.
    ts = BASE + timedelta(hours=1, minutes=50)
    guesses = [
        "/admin",
        "/backup.zip",
        "/db.sql",
        "/config.php",
        "/test",
        "/old",
        "/login",
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/phpmyadmin/",
        "/xmlrpc.php",
    ]
    for i in range(45):
        ts += timedelta(seconds=1)
        path = (
            guesses[i % len(guesses)]
            if i % 4 == 0
            else f"/{rng.choice(['a', 'b', 'c'])}{rng.randint(100, 999)}"
        )
        rows.append((ts, nginx_line(ts, "203.0.113.77", "GET", path, 404, 153, "Nikto/2.5.0")))

    # Injection attempts from 198.51.100.99 (sqlmap).
    ts = BASE + timedelta(hours=2, minutes=5)
    sqlmap = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    for path in [
        "/products?id=1%27%20OR%201%3D1--",
        "/products?id=1%20UNION%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--",
        "/search?q=1%20AND%20SLEEP(5)",
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2F..%2F..%2Fetc%2Fshadow",
    ]:
        ts += timedelta(seconds=rng.randint(2, 5))
        rows.append((ts, nginx_line(ts, "198.51.100.99", "GET", path, 400, 150, sqlmap)))

    return sorted(rows, key=lambda r: r[0])


EPOCH = datetime(1970, 1, 1)


def journal_entry(ts: datetime, ident: str, pid: int, msg: str) -> str:
    """One `journalctl -o json` line (only the fields the parser reads, plus a few usual ones)."""
    micros = (ts - EPOCH) // timedelta(microseconds=1)
    entry = {
        "__REALTIME_TIMESTAMP": str(micros),
        "_HOSTNAME": "db01",
        "SYSLOG_IDENTIFIER": ident,
        "_PID": str(pid),
        "_SYSTEMD_UNIT": "ssh.service" if ident == "sshd" else "session-3.scope",
        "PRIORITY": "5",
        "MESSAGE": msg,
    }
    return json.dumps(entry, separators=(",", ":"))


def journal_lines() -> list[tuple[datetime, str]]:
    """The same kinds of events as auth.log, but from a systemd host (db01)."""
    rows: list[tuple[datetime, str]] = []
    ts = BASE + timedelta(minutes=20)
    rows.append(
        (
            ts,
            journal_entry(
                ts,
                "sshd",
                4100,
                "Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:xxxx",
            ),
        )
    )

    # Password spraying from 203.0.113.61: one or two tries for each of many accounts.
    ts = BASE + timedelta(hours=1, minutes=5)
    for i, user in enumerate(
        ["admin", "deploy", "jenkins", "postgres", "backup", "grafana", "ubuntu", "git"]
    ):
        ts += timedelta(seconds=rng.randint(20, 40))
        port = rng.randint(30000, 60000)
        rows.append(
            (
                ts,
                journal_entry(
                    ts,
                    "sshd",
                    4200 + i,
                    f"Failed password for {user} from 203.0.113.61 port {port} ssh2",
                ),
            )
        )

    ts = BASE + timedelta(hours=2, minutes=10)
    for _ in range(3):
        ts += timedelta(minutes=1)
        rows.append(
            (
                ts,
                journal_entry(
                    ts,
                    "sudo",
                    4300,
                    "    carol : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/less /var/log/syslog",
                ),
            )
        )
    return sorted(rows, key=lambda r: r[0])


def windows_event(ts: datetime, event_id: int, channel: str, data: dict[str, str]) -> str:
    """One event in the layout written by the PowerShell snippet in docs/log-sources.md."""
    entry = {
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",  # PowerShell gives 7 digits
        "EventID": event_id,
        "Computer": "WIN-DESK01",
        "Channel": channel,
        "Data": data,
    }
    return json.dumps(entry, separators=(",", ":"))


def windows_lines() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []

    def add(ts: datetime, event_id: int, channel: str, data: dict[str, str]) -> None:
        rows.append((ts, windows_event(ts, event_id, channel, data)))

    # Everyday: the owner logs on at the console.
    ts = BASE + timedelta(minutes=2)
    add(
        ts,
        4624,
        "Security",
        {
            "TargetUserName": "luca",
            "TargetDomainName": "WIN-DESK01",
            "LogonType": "2",
            "IpAddress": "-",
            "WorkstationName": "WIN-DESK01",
            "AuthenticationPackageName": "Negotiate",
        },
    )

    # Remote Desktop brute force from 198.51.100.77: rapid failures, then a successful RDP logon.
    ts = BASE + timedelta(hours=1, minutes=40)
    for user in ["administrator", "admin", "luca", "guest", "user", "test", "support"]:
        ts += timedelta(seconds=rng.randint(3, 6))
        add(
            ts,
            4625,
            "Security",
            {
                "TargetUserName": user,
                "TargetDomainName": "WIN-DESK01",
                "LogonType": "3",
                "IpAddress": "198.51.100.77",
                "WorkstationName": "-",
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
            },
        )
    ts += timedelta(seconds=20)
    add(
        ts,
        4624,
        "Security",
        {
            "TargetUserName": "administrator",
            "TargetDomainName": "WIN-DESK01",
            "LogonType": "10",
            "IpAddress": "198.51.100.77",
            "WorkstationName": "-",
            "AuthenticationPackageName": "Negotiate",
        },
    )
    ts += timedelta(seconds=2)
    add(
        ts,
        4672,
        "Security",
        {"SubjectUserName": "administrator", "SubjectDomainName": "WIN-DESK01"},
    )

    # What an intruder does next: a new account, made an administrator, a service and a task.
    ts += timedelta(minutes=3)
    add(
        ts,
        4720,
        "Security",
        {"TargetUserName": "support$helper", "SubjectUserName": "administrator"},
    )
    ts += timedelta(seconds=15)
    add(
        ts,
        4732,
        "Security",
        {
            "TargetUserName": "Administrators",
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1111111111-2222222222-3333333333-1005",
            "SubjectUserName": "administrator",
        },
    )
    ts += timedelta(minutes=1)
    add(
        ts,
        7045,
        "System",
        {
            "ServiceName": "UpdateHelper",
            "ImageFileName": "C:\\Users\\Public\\uh.exe",
            "StartType": "auto start",
            "AccountName": "LocalSystem",
        },
    )
    ts += timedelta(seconds=30)
    add(
        ts,
        4698,
        "Security",
        {"TaskName": "\\Microsoft\\Windows\\UpdateHelper", "SubjectUserName": "administrator"},
    )
    ts += timedelta(minutes=2)
    add(ts, 1102, "Security", {})
    return sorted(rows, key=lambda r: r[0])


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text(
        "\n".join(line for _, line in auth_lines()) + "\n", encoding="utf-8"
    )
    (OUT / "access.log").write_text(
        "\n".join(line for _, line in access_lines()) + "\n", encoding="utf-8"
    )
    (OUT / "journal.jsonl").write_text(
        "\n".join(line for _, line in journal_lines()) + "\n", encoding="utf-8"
    )
    (OUT / "windows-security.jsonl").write_text(
        "\n".join(line for _, line in windows_lines()) + "\n", encoding="utf-8"
    )
    print(f"wrote auth.log, access.log, journal.jsonl and windows-security.jsonl to {OUT}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
from datetime import datetime

import pytest

from minisiem.parsers import parse_lines
from minisiem.parsers.windows import parse_windows_line

STAMP = "2026-10-20T09:12:03.1234567Z"  # PowerShell writes seven fractional digits


def record(event_id, data=None, channel="Security", **extra) -> str:
    doc = {
        "TimeCreated": STAMP,
        "EventID": event_id,
        "Computer": "WIN-DESK01",
        "Channel": channel,
        "Data": data or {},
        **extra,
    }
    return json.dumps(doc)


def test_failed_logon():
    e = parse_windows_line(
        record(4625, {"TargetUserName": "alice", "LogonType": "3", "IpAddress": "198.51.100.77",
                      "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "-"})
    )
    assert (e.source, e.event_type) == ("windows", "win_logon_failed")
    assert (e.username, e.src_ip, e.host) == ("alice", "198.51.100.77", "WIN-DESK01")
    assert e.ts == datetime(2026, 10, 20, 9, 12, 3, 123456)
    assert e.fields["logon_type"] == 3
    assert e.fields["status"] == "0xc000006d"
    assert "workstation" not in e.fields  # "-" means "nothing"
    assert e.fields["event_id"] == 4625 and e.fields["channel"] == "Security"


def test_successful_rdp_logon_and_local_logon_without_an_address():
    rdp = parse_windows_line(record(4624, {"TargetUserName": "bob", "LogonType": "10", "IpAddress": "192.0.2.9"}))
    assert rdp.event_type == "win_logon_success" and rdp.fields["logon_type"] == 10
    local = parse_windows_line(record(4624, {"TargetUserName": "bob", "LogonType": "2", "IpAddress": "-"}))
    assert local.src_ip is None


def test_ipv6_addresses_are_normalised():
    e = parse_windows_line(record(4625, {"TargetUserName": "a", "IpAddress": "2001:DB8:0:0::1"}))
    assert e.src_ip == "2001:db8::1"


def test_account_and_group_events():
    created = parse_windows_line(record(4720, {"TargetUserName": "newuser", "SubjectUserName": "admin"}))
    assert (created.event_type, created.username, created.fields["created_by"]) == ("win_user_created", "newuser", "admin")
    for event_id in (4728, 4732, 4756):
        added = parse_windows_line(record(event_id, {"TargetUserName": "Administrators", "SubjectUserName": "admin", "MemberSid": "S-1-5-21-1"}))
        assert added.event_type == "win_group_member_added"
        assert added.fields["group"] == "Administrators"
        assert added.username == "admin"


def test_persistence_and_cleanup_events():
    service = parse_windows_line(
        record(7045, {"ServiceName": "Updater", "ImageFileName": "C:\\Users\\Public\\u.exe", "AccountName": "LocalSystem"}, channel="System")
    )
    assert service.event_type == "win_service_installed"
    assert service.fields["image_path"] == "C:\\Users\\Public\\u.exe"
    task = parse_windows_line(record(4698, {"TaskName": "\\Updater", "SubjectUserName": "admin"}))
    assert task.event_type == "win_scheduled_task_created" and task.fields["task_name"] == "\\Updater"
    for event_id in (1102, 104):
        assert parse_windows_line(record(event_id)).event_type == "win_audit_log_cleared"


def test_privileged_logon():
    e = parse_windows_line(record(4672, {"SubjectUserName": "admin"}))
    assert (e.event_type, e.username) == ("win_privileged_logon", "admin")


def test_winlogbeat_layout():
    line = json.dumps({
        "@timestamp": "2026-10-20T09:12:03.123Z",
        "winlog": {
            "event_id": "4625",
            "computer_name": "srv01",
            "channel": "Security",
            "event_data": {"TargetUserName": "alice", "IpAddress": "203.0.113.9", "LogonType": "10"},
        },
    })
    e = parse_windows_line(line)
    assert (e.event_type, e.host, e.src_ip, e.fields["logon_type"]) == ("win_logon_failed", "srv01", "203.0.113.9", 10)


def test_a_utf8_bom_from_powershell_5_is_ignored():
    assert parse_windows_line("\ufeff" + record(4625, {"TargetUserName": "a"})) is not None


def test_event_data_values_are_capped():
    e = parse_windows_line(record(4625, {"TargetUserName": "x" * 5000}))
    assert len(e.username) == 256


def test_things_that_are_not_understood_are_skipped():
    hostile = [
        "plain text",
        "[]",
        "{" * 50_000,
        "{}",
        record(9999),  # an event we do not read
        record("abc"),
        record(None),
        record([4625]),
        json.dumps({"TimeCreated": "yesterday", "EventID": 4625}),
        json.dumps({"TimeCreated": "2026-10-20T09:12:03", "EventID": 4625}),  # no time zone
        record(4625, Data="not a mapping"),
        json.dumps({"winlog": "nope"}),
    ]
    events, skipped = parse_lines("windows", hostile)
    assert events == [] and skipped == len(hostile)


@pytest.mark.parametrize("bad_ip", ["<script>", "999.1.1.1", "", "-"])
def test_an_invalid_address_never_becomes_a_source_ip(bad_ip):
    e = parse_windows_line(record(4625, {"TargetUserName": "a", "IpAddress": bad_ip}))
    assert e is not None and e.src_ip is None


def test_nested_values_in_event_data_are_dropped():
    e = parse_windows_line(record(4625, {"TargetUserName": {"evil": "object"}, "IpAddress": "192.0.2.1"}))
    assert e.username is None and e.src_ip == "192.0.2.1"

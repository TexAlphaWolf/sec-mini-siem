from __future__ import annotations

import json
import logging
import smtplib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from minisiem.api import create_app
from minisiem.cli import main
from minisiem.config import ConfigError, NotifySettings, Settings
from minisiem.db import init_db, make_session_factory
from minisiem.notify import (
    EmailChannel,
    Notifier,
    NotifyError,
    TelegramChannel,
    WebhookChannel,
    build_notifier,
    format_alert,
)
from minisiem.pipeline import Pipeline
from minisiem.rules import Alert, load_rules

NOW = datetime(2026, 10, 20, 12, 0, 0)


def make_alert(severity="high", age_minutes=1, **overrides) -> Alert:
    values = {
        "ts": NOW - timedelta(minutes=age_minutes),
        "rule_id": "ssh-bruteforce",
        "title": "SSH brute-force attempt",
        "severity": severity,
        "tags": ["attack.t1110"],
        "src_ip": "203.0.113.50",
        "group_key": "203.0.113.50",
        "event_count": 5,
        "details": {"username": "admin", "host": "web01"},
    }
    return Alert(**{**values, **overrides})


class FakeChannel:
    name = "fake"

    def __init__(self, fail: Exception | None = None):
        self.sent: list[tuple[str, str, dict | None]] = []
        self.fail = fail

    def send(self, subject, body, alert):
        if self.fail:
            raise self.fail
        self.sent.append((subject, body, alert))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def notifier_for(channel, *, now=NOW, clock=None, **settings) -> Notifier:
    return Notifier([channel], NotifySettings(**settings), now=lambda: now, clock=clock or Clock())


# --- formatting -----------------------------------------------------------------------------


def test_message_has_the_essentials():
    subject, body = format_alert(make_alert(), {"city": "Berlin", "country": "Germany"})
    assert subject == "[HIGH] SSH brute-force attempt"
    assert "Source: 203.0.113.50 - Berlin, Germany" in body
    assert "Rule: ssh-bruteforce" in body
    assert "Time: 2026-10-20 11:59:00 UTC" in body
    assert "Events: 5" in body and "User: admin" in body and "Host: web01" in body


def test_hostile_values_are_flattened_and_cut():
    nasty = "bob\nBcc: evil@example.com\r\x1b[31m" + "x" * 500
    _, body = format_alert(make_alert(details={"username": nasty, "values": ["a\nb", "c"]}))
    assert "\r" not in body and "\x1b" not in body
    user_line = next(line for line in body.splitlines() if line.startswith("User:"))
    assert "Bcc:" in user_line and len(user_line) <= 130  # one line, whatever it said
    assert "Values: ab, c" in body


# --- filtering and rate limiting ------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "minimum", "expected"),
    [
        ("low", "high", False),
        ("medium", "high", False),
        ("high", "high", True),
        ("critical", "high", True),
        ("low", "low", True),
    ],
)
def test_severity_filter(severity, minimum, expected):
    notifier = notifier_for(FakeChannel(), min_severity=minimum)
    assert notifier.wanted(make_alert(severity)) is expected


def test_old_alerts_are_history_not_news():
    notifier = notifier_for(FakeChannel(), max_age_minutes=60)
    assert notifier.wanted(make_alert(age_minutes=30))
    assert not notifier.wanted(make_alert(age_minutes=61))
    unlimited = notifier_for(FakeChannel(), max_age_minutes=0)
    assert unlimited.wanted(make_alert(age_minutes=100000))


def test_rate_limit_holds_alerts_back_and_then_sends_one_summary():
    channel, clock = FakeChannel(), Clock()
    notifier = notifier_for(channel, clock=clock, max_per_minute=3)
    sent = [notifier.deliver(make_alert()) for _ in range(5)]
    assert sent == [True, True, True, False, False]
    assert len(channel.sent) == 3

    clock.t += 61  # the window has passed
    assert notifier.deliver(make_alert()) is True
    subjects = [subject for subject, _, _ in channel.sent]
    assert subjects[3] == "Mini-SIEM: 2 more alerts not sent"
    assert subjects[4].startswith("[HIGH]")


def test_a_failing_channel_is_logged_without_secrets_and_does_not_stop_the_others(caplog):
    broken = FakeChannel(fail=RuntimeError("https://api.example.com/bot123456:SECRET/send failed"))
    working = FakeChannel()
    notifier = Notifier([broken, working], NotifySettings(), now=lambda: NOW, clock=Clock())
    with caplog.at_level(logging.WARNING, logger="minisiem.notify"):
        notifier.deliver(make_alert())
    assert len(working.sent) == 1
    assert "SECRET" not in caplog.text and "RuntimeError" in caplog.text


def test_the_queue_is_bounded():
    notifier = notifier_for(FakeChannel())
    notifier.QUEUE_SIZE = 2
    notifier._queue = type(notifier._queue)(2)
    assert notifier.submit([make_alert() for _ in range(5)]) == 2


def test_background_delivery_and_clean_shutdown():
    channel = FakeChannel()
    notifier = notifier_for(channel)
    notifier.start()
    assert notifier.submit([make_alert(), make_alert("low")]) == 1  # the low one is filtered out
    notifier.close()
    assert len(channel.sent) == 1


# --- channels -------------------------------------------------------------------------------


def test_webhook_json_payload_and_bearer_token(http_server):
    channel = WebhookChannel(http_server.url + "/hook", token="t0ken")
    alert = {"rule_id": "x"}
    channel.send("subject", "the body", alert)
    request = http_server.requests[0]
    assert request["path"] == "/hook"
    assert request["headers"]["Authorization"] == "Bearer t0ken"
    assert json.loads(request["body"]) == {"text": "the body", "alert": alert}


def test_webhook_discord_format(http_server):
    WebhookChannel(http_server.url, fmt="discord").send("s", "hello", None)
    assert json.loads(http_server.requests[0]["body"]) == {"content": "hello"}


def test_webhook_errors_are_reported_as_short_codes(http_server):
    http_server.status = 500
    with pytest.raises(NotifyError, match="^HTTP 500$"):
        WebhookChannel(http_server.url).send("s", "b", None)


def test_redirects_are_not_followed(http_server):
    http_server.redirect = True
    with pytest.raises(NotifyError, match="^HTTP 302$"):
        WebhookChannel(http_server.url, token="secret").send("s", "b", None)
    assert len(http_server.requests) == 1  # nothing was sent to the redirect target


def test_unreachable_host_does_not_leak_the_url():
    with pytest.raises(NotifyError) as caught:
        WebhookChannel("http://127.0.0.1:9/hook-with-secret", timeout=2).send("s", "b", None)
    assert "secret" not in str(caught.value)


def test_telegram_request(http_server):
    channel = TelegramChannel("123:ABC", "-100200", base_url=http_server.url)
    channel.send("s", "<b>not markup</b>", None)
    request = http_server.requests[0]
    assert request["path"] == "/bot123:ABC/sendMessage"
    payload = json.loads(request["body"])
    assert payload["chat_id"] == "-100200" and payload["text"] == "<b>not markup</b>"
    assert "parse_mode" not in payload


def test_telegram_failure_does_not_leak_the_token(http_server):
    http_server.status = 401
    with pytest.raises(NotifyError) as caught:
        TelegramChannel("123:ABC", "1", base_url=http_server.url).send("s", "b", None)
    assert "ABC" not in str(caught.value)


class FakeSMTP:
    instances: list[FakeSMTP] = []

    def __init__(self, host, port, timeout=None, context=None):
        self.args = (host, port)
        self.calls: list[str] = []
        self.message = None
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append("quit")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(f"login:{user}:{password}")

    def send_message(self, message):
        self.message = message


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_email_with_starttls_and_login(fake_smtp):
    channel = EmailChannel(
        "mail.example.com",
        587,
        "siem@example.com",
        ["a@example.com", "b@example.com"],
        "starttls",
        "user",
        "pw",
    )
    channel.send("[HIGH] Something", "body text", None)
    smtp = fake_smtp.instances[0]
    assert smtp.args == ("mail.example.com", 587)
    assert smtp.calls == ["starttls", "login:user:pw", "quit"]
    assert smtp.message["Subject"] == "[HIGH] Something"
    assert smtp.message["To"] == "a@example.com, b@example.com"
    assert smtp.message.get_content().strip() == "body text"


def test_email_without_encryption_or_login(fake_smtp):
    EmailChannel("relay", 25, "a@example.com", ["b@example.com"], "none").send("s", "b", None)
    assert fake_smtp.instances[0].calls == ["quit"]


def test_email_errors_are_short(monkeypatch):
    class Broken(FakeSMTP):
        def send_message(self, message):
            raise smtplib.SMTPRecipientsRefused({"a@example.com": (550, b"password=hunter2")})

    monkeypatch.setattr(smtplib, "SMTP", Broken)
    with pytest.raises(NotifyError) as caught:
        EmailChannel("relay", 25, "a@example.com", ["b@example.com"], "none").send("s", "b", None)
    assert "hunter2" not in str(caught.value)


# --- configuration --------------------------------------------------------------------------


def test_no_channel_means_no_notifier():
    assert build_notifier(NotifySettings()) is None


def test_channels_are_built_from_settings():
    settings = NotifySettings(
        telegram_token="t",
        telegram_chat_id="c",
        webhook_url="https://hooks.example.com/x",
        smtp_host="mail",
        smtp_from="a@example.com",
        smtp_to=("b@example.com",),
    )
    names = [c.name for c in build_notifier(settings).channels]
    assert names == ["telegram", "webhook", "email"]


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (NotifySettings(telegram_token="t"), "Telegram needs both"),
        (NotifySettings(telegram_chat_id="c"), "Telegram needs both"),
        (NotifySettings(webhook_url="ftp://example.com"), "http:// or https://"),
        (NotifySettings(webhook_url="not a url"), "http:// or https://"),
        (NotifySettings(webhook_url="https://x.example", webhook_format="xml"), "WEBHOOK_FORMAT"),
        (NotifySettings(smtp_host="mail"), "SMTP_FROM and MINISIEM_SMTP_TO"),
        (
            NotifySettings(
                smtp_host="m", smtp_from="a@b.c", smtp_to=("d@e.f",), smtp_security="tls"
            ),
            "SMTP_SECURITY",
        ),
        (
            NotifySettings(smtp_host="m", smtp_from="a@b.c", smtp_to=("d@e.f",), smtp_password="p"),
            "needs MINISIEM_SMTP_USER",
        ),
        (NotifySettings(min_severity="urgent", webhook_url="https://x.example"), "MIN_SEVERITY"),
    ],
)
def test_bad_notification_settings_are_rejected_with_a_clear_message(settings, message):
    with pytest.raises(ConfigError, match=message):
        build_notifier(settings)


# --- end to end -----------------------------------------------------------------------------


def recent_failed_logons(count=5) -> list[str]:
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    data = {"TargetUserName": "admin", "LogonType": "3", "IpAddress": "198.51.100.77"}
    doc = {
        "TimeCreated": stamp,
        "EventID": 4625,
        "Computer": "WIN-DESK01",
        "Channel": "Security",
        "Data": data,
    }
    return [json.dumps(doc) for _ in range(count)]


def test_pipeline_sends_new_alerts_but_not_old_ones(database_url, rules_dir, sample_dir):
    engine, session_factory = make_session_factory(database_url)
    init_db(engine)
    channel = FakeChannel()
    notifier = Notifier([channel], NotifySettings())
    pipeline = Pipeline(session_factory, load_rules(rules_dir), notifier=notifier)

    notifier.start()
    old = sample_dir / "windows-security.jsonl"
    assert pipeline.ingest("windows", old.read_text(encoding="utf-8").splitlines()).alerts > 0
    assert pipeline.ingest("windows", recent_failed_logons()).alerts == 1
    notifier.close()
    engine.dispose()

    assert [s for s, _, _ in channel.sent] == ["[HIGH] Windows logon brute-force attempt"]


def test_app_notifies_a_webhook_and_shuts_down_cleanly(database_url, rules_dir, http_server):
    settings = Settings(
        database_url=database_url,
        rules_dir=rules_dir,
        log_timezone="UTC",
        api_token=None,
        notify=NotifySettings(webhook_url=http_server.url + "/siem"),
    )
    with TestClient(create_app(settings)) as client:
        body = "\n".join(recent_failed_logons()).encode()
        result = client.post(
            "/ingest/windows", content=body, headers={"content-type": "text/plain"}
        )
        assert result.json()["alerts"] == 1
    # leaving the block stopped the app, which flushes the notification queue
    payload = json.loads(http_server.requests[0]["body"])
    assert payload["alert"]["rule_id"] == "win-logon-bruteforce"
    assert "198.51.100.77" in payload["text"]


def test_app_refuses_to_start_with_half_set_channels(database_url, rules_dir):
    settings = Settings(
        database_url=database_url,
        rules_dir=rules_dir,
        log_timezone="UTC",
        api_token=None,
        notify=NotifySettings(telegram_token="only-a-token"),
    )
    with pytest.raises(ConfigError), TestClient(create_app(settings)):
        pass


# --- command line ---------------------------------------------------------------------------


def test_cli_notify_test(monkeypatch, capsys, http_server):
    monkeypatch.setenv("MINISIEM_WEBHOOK_URL", http_server.url)
    assert main(["notify-test"]) == 0
    assert "webhook: sent" in capsys.readouterr().out
    assert "notifications work" in json.loads(http_server.requests[0]["body"])["text"]

    http_server.status = 503
    assert main(["notify-test"]) == 1
    assert "webhook: FAILED (HTTP 503)" in capsys.readouterr().out


def test_cli_notify_test_without_channels(monkeypatch, capsys):
    for name in ("MINISIEM_WEBHOOK_URL", "MINISIEM_TELEGRAM_TOKEN", "MINISIEM_SMTP_HOST"):
        monkeypatch.delenv(name, raising=False)
    assert main(["notify-test"]) == 1
    assert "no notification channel" in capsys.readouterr().err


def test_cli_notify_test_reports_bad_settings(monkeypatch, capsys):
    monkeypatch.setenv("MINISIEM_TELEGRAM_TOKEN", "t")
    monkeypatch.delenv("MINISIEM_TELEGRAM_CHAT_ID", raising=False)
    assert main(["notify-test"]) == 1
    assert "Telegram needs both" in capsys.readouterr().err


def test_cli_follow_announces_new_alerts_but_a_plain_import_does_not(
    tmp_path, rules_dir, database_url, monkeypatch, http_server, capsys
):
    log = tmp_path / "windows.jsonl"
    log.write_text("\n".join(recent_failed_logons()) + "\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("MINISIEM_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("MINISIEM_WEBHOOK_URL", http_server.url)

    assert main(["ingest", "windows", str(log)]) == 0  # an import is history
    assert http_server.requests == []

    # A fresh database for the follower: it would otherwise remember the import above
    # (restoring state) and treat the same lines as the attack it has already seen.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'follow.db'}")

    def stop(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr("minisiem.cli.time.sleep", stop)
    assert main(["ingest", "windows", str(log), "--follow"]) == 0
    assert "following" in capsys.readouterr().out
    assert len(http_server.requests) == 1


def test_cli_follow_reports_a_bad_geoip_setting(
    tmp_path, rules_dir, database_url, monkeypatch, capsys
):
    log = tmp_path / "windows.jsonl"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("MINISIEM_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("MINISIEM_GEOIP_DB", str(tmp_path / "missing.mmdb"))
    assert main(["ingest", "windows", str(log), "--follow"]) == 1
    assert "file not found" in capsys.readouterr().err

"""Alert notifications: Telegram, a webhook and email.

Design rules, because alerts are built from attacker-controlled log lines:

* Messages are plain text. Anything that comes from a log is stripped of control characters and
  cut short, and never goes into an email header.
* Sending never blocks or breaks ingestion: alerts go through a bounded queue to one worker
  thread, and a failing channel is logged (without its URL or credentials) and skipped.
* A flood of alerts, such as importing a large old log file, cannot flood the phone: only recent
  alerts are sent, at most N per minute, and the rest is reported as one summary message.
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlparse

from .config import ConfigError, NotifySettings
from .geo import GeoIP, describe
from .rules import SEVERITIES, Alert

log = logging.getLogger("minisiem.notify")

WEBHOOK_FORMATS = ("json", "discord")
SMTP_SECURITY = ("starttls", "ssl", "none")


class NotifyError(Exception):
    """Delivery failed. The message never contains a URL or a credential."""


# --------------------------------------------------------------------------- formatting


def _clean(value: Any, limit: int = 120) -> str:
    """Printable characters only (no newlines or control codes), cut to `limit`."""
    return "".join(ch for ch in str(value) if ch.isprintable())[:limit]


def format_alert(alert: Alert, geo: dict[str, Any] | None = None) -> tuple[str, str]:
    """(subject, plain-text body) for an alert."""
    subject = f"[{_clean(alert.severity).upper()}] {_clean(alert.title)}"
    source = _clean(alert.src_ip or "-")
    if where := describe(geo):
        source += f" - {_clean(where)}"
    lines = [
        subject,
        f"Source: {source}",
        f"Rule: {_clean(alert.rule_id)}",
        f"Time: {alert.ts:%Y-%m-%d %H:%M:%S} UTC",
    ]
    if alert.event_count > 1:
        lines.append(f"Events: {alert.event_count}")
    details = alert.details
    if details.get("username"):
        lines.append(f"User: {_clean(details['username'])}")
    if details.get("host"):
        lines.append(f"Host: {_clean(details['host'])}")
    if isinstance(details.get("values"), list) and details["values"]:
        lines.append("Values: " + ", ".join(_clean(v, 40) for v in details["values"][:10]))
    return subject, "\n".join(lines)


def alert_json(alert: Alert, geo: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ts": alert.ts.isoformat() + "Z",
        "rule_id": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "group_key": alert.group_key,
        "event_count": alert.event_count,
        "tags": alert.tags,
        "geo": geo,
        "details": alert.details,
    }


# ----------------------------------------------------------------------------- channels


class Channel(Protocol):
    name: str

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: an error is better than sending a token somewhere new."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        raise NotifyError(f"HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise NotifyError(type(exc.reason).__name__) from None
    except (OSError, ValueError) as exc:
        raise NotifyError(type(exc).__name__) from None
    if not 200 <= status < 300:
        raise NotifyError(f"HTTP {status}")


class TelegramChannel:
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        base_url: str = "https://api.telegram.org",
        timeout: float = 10,
    ) -> None:
        self._url = f"{base_url.rstrip('/')}/bot{token}/sendMessage"
        self._chat_id = chat_id
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        # No parse_mode: Telegram shows the text as it is, so log data cannot inject markup.
        payload = {"chat_id": self._chat_id, "text": body[:4000], "disable_web_page_preview": True}
        _post_json(self._url, payload, {}, self._timeout)


class WebhookChannel:
    name = "webhook"

    def __init__(
        self, url: str, token: str | None = None, fmt: str = "json", timeout: float = 10
    ) -> None:
        self._url = url
        self._token = token
        self._format = fmt
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        if self._format == "discord":
            payload: dict[str, Any] = {"content": body[:1900]}
        else:
            # "text" is what Slack, Mattermost and Rocket.Chat incoming webhooks read.
            payload = {"text": body, "alert": alert}
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        _post_json(self._url, payload, headers, self._timeout)


class EmailChannel:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: Iterable[str],
        security: str = "starttls",
        user: str | None = None,
        password: str | None = None,
        timeout: float = 15,
    ) -> None:
        self._host, self._port, self._security = host, port, security
        self._sender, self._recipients = sender, list(recipients)
        self._user, self._password = user, password
        self._timeout = timeout

    def send(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(body)
        try:
            context = ssl.create_default_context()
            if self._security == "ssl":
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                    self._host, self._port, timeout=self._timeout, context=context
                )
            else:
                smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
            with smtp:
                if self._security == "starttls":
                    smtp.starttls(context=context)
                if self._user:
                    smtp.login(self._user, self._password or "")
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError, ValueError) as exc:
            raise NotifyError(type(exc).__name__) from None


# ----------------------------------------------------------------------------- notifier


class Notifier:
    """Filters alerts, applies the rate limit and delivers them on a background thread."""

    QUEUE_SIZE = 1000

    def __init__(
        self,
        channels: list[Channel],
        settings: NotifySettings,
        geo: GeoIP | None = None,
        *,
        now: Callable[[], datetime] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.channels = channels
        self._rank = SEVERITIES.index(settings.min_severity)
        self._max_age = timedelta(minutes=settings.max_age_minutes)
        self._max_per_minute = settings.max_per_minute
        self._geo = geo
        self._now = now or (lambda: datetime.now(UTC).replace(tzinfo=None))
        self._clock = clock
        self._recent: deque[float] = deque()
        self._suppressed = 0
        self._queue: queue.Queue[Alert | None] = queue.Queue(self.QUEUE_SIZE)
        self._thread: threading.Thread | None = None

    # -- filtering and queueing

    def wanted(self, alert: Alert) -> bool:
        if SEVERITIES.index(alert.severity) < self._rank:
            return False
        # Old alerts (an imported log file) are history, not news. Age 0 turns the check off.
        return not self._max_age or self._now() - alert.ts <= self._max_age

    def submit(self, alerts: Iterable[Alert]) -> int:
        """Queue the alerts that deserve a message. Never blocks. Returns how many were queued."""
        queued = 0
        for alert in alerts:
            if not self.wanted(alert):
                continue
            try:
                self._queue.put_nowait(alert)
                queued += 1
            except queue.Full:
                log.warning("notification queue is full; dropping alerts")
                break
        return queued

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="minisiem-notify", daemon=True)
        self._thread.start()

    def close(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        try:
            self._queue.put(None, timeout=1.0)
        except queue.Full:
            return
        self._thread.join(timeout)

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=60.0 if self._suppressed else None)
            except queue.Empty:
                self._flush_summary()
                continue
            if item is None:
                self._flush_summary()
                return
            self.deliver(item)

    # -- delivery

    def _has_room(self) -> bool:
        now = self._clock()
        while self._recent and now - self._recent[0] >= 60.0:
            self._recent.popleft()
        return len(self._recent) < self._max_per_minute

    def deliver(self, alert: Alert) -> bool:
        """Send one alert now (rate limited). Returns False when it was held back."""
        if not self._has_room():
            self._suppressed += 1
            return False
        self._flush_summary()
        if not self._has_room():  # the summary used the last free slot
            self._suppressed += 1
            return False
        self._recent.append(self._clock())
        geo = self._geo.lookup(alert.src_ip) if self._geo else None
        subject, body = format_alert(alert, geo)
        self._send_all(subject, body, alert_json(alert, geo))
        return True

    def _flush_summary(self) -> None:
        if not self._suppressed or not self._has_room():
            return
        count, self._suppressed = self._suppressed, 0
        self._recent.append(self._clock())
        subject = f"Mini-SIEM: {count} more alert{'s' if count != 1 else ''} not sent"
        body = (
            f"{subject}\nThe limit of {self._max_per_minute} messages per minute was reached.\n"
            "Open the dashboard to see them all."
        )
        self._send_all(subject, body, None)

    def _send_all(self, subject: str, body: str, alert: dict[str, Any] | None) -> None:
        for channel in self.channels:
            try:
                channel.send(subject, body, alert)
            except Exception as exc:  # one broken channel must not stop the others
                log.warning("notification via %s failed: %s", channel.name, _failure(exc))

    def send_test(self) -> list[tuple[str, str | None]]:
        """Send a test message on every channel. Returns (channel, error or None)."""
        results: list[tuple[str, str | None]] = []
        for channel in self.channels:
            try:
                channel.send("Mini-SIEM test", "Mini-SIEM test message: notifications work.", None)
                results.append((channel.name, None))
            except Exception as exc:
                results.append((channel.name, _failure(exc)))
        return results


def _failure(exc: Exception) -> str:
    """A description of a failure that cannot contain a URL or a credential."""
    return str(exc) if isinstance(exc, NotifyError) else type(exc).__name__


# ------------------------------------------------------------------------------ building


def _check_url(url: str) -> None:
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError("MINISIEM_WEBHOOK_URL must be an http:// or https:// URL")


def build_notifier(settings: NotifySettings, geo: GeoIP | None = None) -> Notifier | None:
    """Create the notifier for the configured channels, or None when there are none."""
    if settings.min_severity not in SEVERITIES:
        raise ConfigError(
            f"MINISIEM_NOTIFY_MIN_SEVERITY must be one of {', '.join(SEVERITIES)}"
        )
    channels: list[Channel] = []

    if settings.telegram_token or settings.telegram_chat_id:
        if not (settings.telegram_token and settings.telegram_chat_id):
            raise ConfigError("Telegram needs both MINISIEM_TELEGRAM_TOKEN and _CHAT_ID")
        channels.append(TelegramChannel(settings.telegram_token, settings.telegram_chat_id))

    if settings.webhook_url:
        _check_url(settings.webhook_url)
        if settings.webhook_format not in WEBHOOK_FORMATS:
            raise ConfigError(
                f"MINISIEM_WEBHOOK_FORMAT must be one of {', '.join(WEBHOOK_FORMATS)}"
            )
        channels.append(
            WebhookChannel(settings.webhook_url, settings.webhook_token, settings.webhook_format)
        )

    if settings.smtp_host:
        if not (settings.smtp_from and settings.smtp_to):
            raise ConfigError("Email needs MINISIEM_SMTP_FROM and MINISIEM_SMTP_TO")
        if settings.smtp_security not in SMTP_SECURITY:
            raise ConfigError(f"MINISIEM_SMTP_SECURITY must be one of {', '.join(SMTP_SECURITY)}")
        if settings.smtp_password and not settings.smtp_user:
            raise ConfigError("MINISIEM_SMTP_PASSWORD needs MINISIEM_SMTP_USER")
        channels.append(
            EmailChannel(
                settings.smtp_host,
                settings.smtp_port,
                settings.smtp_from,
                settings.smtp_to,
                settings.smtp_security,
                settings.smtp_user,
                settings.smtp_password,
            )
        )

    return Notifier(channels, settings, geo) if channels else None

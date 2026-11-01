from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from minisiem import api as api_module
from minisiem.api import STATIC_DIR, create_app
from minisiem.config import Settings


def make_client(database_url, rules_dir, token: str | None = None) -> TestClient:
    settings = Settings(
        database_url=database_url,
        rules_dir=rules_dir,
        log_timezone="UTC",
        api_token=token,
    )
    return TestClient(create_app(settings))


@pytest.fixture
def client(database_url, rules_dir):
    with make_client(database_url, rules_dir) as c:
        yield c


def post_log(client: TestClient, source: str, path, **kwargs):
    return client.post(
        f"/ingest/{source}",
        content=path.read_bytes(),
        headers={"content-type": "text/plain"},
        **kwargs,
    )


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["rules"] >= 10


def test_end_to_end_sample_logs_produce_the_expected_alerts(client, sample_dir):
    auth = post_log(client, "auth", sample_dir / "auth.log", params={"year": 2026})
    assert auth.status_code == 200
    assert auth.json()["skipped"] == 0
    assert auth.json()["alerts"] > 0

    access = post_log(client, "nginx", sample_dir / "access.log")
    assert access.status_code == 200
    assert access.json()["skipped"] == 0

    fired = {a["rule_id"] for a in client.get("/api/alerts?limit=500").json()}
    assert fired >= {
        "ssh-bruteforce",
        "ssh-user-enumeration",
        "ssh-root-attempts",
        "ssh-root-login",
        "sudo-repeated-failures",
        "web-scanner-404",
        "web-sensitive-file-probe",
        "web-path-traversal",
        "web-sqli-probe",
        "web-scanner-user-agent",
    }

    stats = client.get("/api/stats").json()
    assert stats["events"] > 100
    assert stats["alerts"] >= 10
    assert stats["top_sources"][0]["alerts"] >= 1
    assert sum(p["count"] for p in stats["timeline"]) > 0
    assert set(stats["alerts_by_severity"]) <= {"low", "medium", "high", "critical"}


def test_alert_and_event_filters(client, sample_dir):
    post_log(client, "auth", sample_dir / "auth.log", params={"year": 2026})
    high = client.get("/api/alerts", params={"severity": "high"}).json()
    assert high and all(a["severity"] == "high" for a in high)
    brute = client.get("/api/alerts", params={"rule_id": "ssh-bruteforce"}).json()
    assert brute and brute[0]["src_ip"] == "203.0.113.50"
    events = client.get("/api/events", params={"src_ip": "203.0.113.50", "limit": 5}).json()
    assert len(events) == 5 and all(e["src_ip"] == "203.0.113.50" for e in events)


def test_unknown_source_is_404(client):
    assert client.post("/ingest/nope", content=b"x").status_code == 404


def test_token_is_required_for_ingest_when_configured(database_url, rules_dir, sample_dir):
    with make_client(database_url, rules_dir, token="s3cret") as c:
        body = (sample_dir / "auth.log").read_bytes()
        assert c.post("/ingest/auth", content=body).status_code == 401
        bad = c.post("/ingest/auth", content=body, headers={"Authorization": "Bearer wrong"})
        assert bad.status_code == 401
        good = c.post("/ingest/auth", content=body, headers={"Authorization": "Bearer s3cret"})
        assert good.status_code == 200
        assert c.get("/health").status_code == 200  # read-only endpoints stay open


def test_oversized_body_is_rejected(client, monkeypatch):
    monkeypatch.setattr(api_module, "MAX_INGEST_BYTES", 100)
    assert client.post("/ingest/auth", content=b"x" * 500).status_code == 413


def test_hostile_log_content_is_returned_as_data_not_markup(client):
    line = "Oct 20 08:00:00 web01 sshd[1]: Failed password for <script>alert(1)</script> from 203.0.113.5 port 22 ssh2"
    assert client.post("/ingest/auth", content=line.encode(), params={"year": 2026}).json()["parsed"] == 1
    event = client.get("/api/events").json()[0]
    assert event["username"] == "<script>alert(1)</script>"


def test_log_lines_with_nul_bytes_do_not_break_ingest(client):
    """PostgreSQL text columns reject NUL (0x00); a hostile log line must not lose the batch."""
    line = (
        '203.0.113.9 - - [20/Oct/2026:10:50:01 +0000] "GET /a HTTP/1.1" 200 5 "-" "evil\x00agent"'
    )
    response = client.post("/ingest/nginx", content=line.encode())
    assert response.status_code == 200
    assert response.json()["parsed"] == 1
    stored = client.get("/api/events").json()
    assert len(stored) == 1
    assert "\\x00" in stored[0]["raw"]  # the NUL is kept, as visible text


def test_dashboard_never_renders_log_data_as_html():
    js = (STATIC_DIR / "dashboard.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert forbidden not in js


def test_dashboard_is_served_with_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Mini-SIEM" in response.text
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.get("/static/dashboard.js").status_code == 200

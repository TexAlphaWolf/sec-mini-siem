from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from minisiem.db import Base

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules_dir() -> Path:
    return ROOT / "rules"


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "sample_logs"


@pytest.fixture
def database_url(tmp_path) -> str:
    """A SQLite file by default; PostgreSQL when TEST_DATABASE_URL is set (as in CI).

    With PostgreSQL every test starts from empty tables.
    """
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        return f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    engine.dispose()
    return url


class _Recorder(BaseHTTPRequestHandler):
    """A tiny HTTP server that records every POST it gets."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        self.server.requests.append(
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        if self.server.redirect:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(self.server.status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server(monkeypatch):
    """A local server for notification tests: `.requests`, `.status`, `.redirect`, `.url`."""
    for name in (
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.requests = []
    server.status = 200
    server.redirect = False
    server.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)

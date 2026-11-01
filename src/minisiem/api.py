"""HTTP API and dashboard (FastAPI)."""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func, select
from starlette.concurrency import run_in_threadpool

from . import __version__
from .config import Settings, load_settings
from .db import AlertRow, EventRow, init_db, make_session_factory
from .parsers import PARSERS
from .pipeline import Pipeline
from .retention import purge_older_than
from .rules import load_rules

log = logging.getLogger("minisiem")

STATIC_DIR = Path(__file__).parent / "static"
RETENTION_INTERVAL_SECONDS = 3600
MAX_INGEST_BYTES = 5 * 1024 * 1024

# The dashboard loads no third-party code and uses no inline scripts or styles.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _iso(moment: datetime) -> str:
    return moment.isoformat() + "Z"  # stored as naive UTC


def _event_dict(row: EventRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "ts": _iso(row.ts),
        "source": row.source,
        "host": row.host,
        "event_type": row.event_type,
        "src_ip": row.src_ip,
        "username": row.username,
        "raw": row.raw,
        "fields": row.fields,
    }


def _alert_dict(row: AlertRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "ts": _iso(row.ts),
        "rule_id": row.rule_id,
        "title": row.title,
        "severity": row.severity,
        "src_ip": row.src_ip,
        "group_key": row.group_key,
        "event_count": row.event_count,
        "tags": row.tags,
        "details": row.details,
    }


def _check_bearer(request: Request, token: str | None) -> None:
    """Require `token` as a bearer token; do nothing when no token is configured."""
    if not token:
        return
    header = request.headers.get("authorization", "")
    supplied = header[7:] if header.lower().startswith("bearer ") else ""
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_ingest_token(request: Request) -> None:
    """If MINISIEM_API_TOKEN is set, POST /ingest needs it as a bearer token."""
    _check_bearer(request, request.app.state.settings.api_token)


def require_read_token(request: Request) -> None:
    """If MINISIEM_READ_TOKEN is set, GET /api/* needs it as a bearer token."""
    _check_bearer(request, request.app.state.settings.read_token)


async def _purge_once(session_factory, days: int) -> None:  # noqa: ANN001
    """One retention pass; a failure is logged, never fatal."""
    try:
        events, alerts = await run_in_threadpool(purge_older_than, session_factory, days)
        if events or alerts:
            log.info("retention: deleted %d events and %d alerts", events, alerts)
    except Exception:
        log.exception("retention purge failed")


async def _retention_loop(session_factory, days: int) -> None:  # noqa: ANN001
    """Repeat the purge once an hour (the first pass runs at startup)."""
    while True:
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)
        await _purge_once(session_factory, days)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine, session_factory = make_session_factory(settings.database_url)
        init_db(engine)
        rules = load_rules(settings.rules_dir)  # fail fast on a broken rule
        app.state.settings = settings
        app.state.session_factory = session_factory
        app.state.pipeline = Pipeline(session_factory, rules, settings.log_timezone)
        purger = None
        if settings.retention_days > 0:
            # The first purge runs before the app accepts requests.
            await _purge_once(session_factory, settings.retention_days)
            purger = asyncio.create_task(_retention_loop(session_factory, settings.retention_days))
        try:
            yield
        finally:
            if purger is not None:
                purger.cancel()
            engine.dispose()

    app = FastAPI(title="Mini-SIEM", version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    def health(request: Request) -> dict[str, Any]:
        pipeline = request.app.state.pipeline
        return {"status": "ok", "version": __version__, "rules": pipeline.rule_count}

    @app.post("/ingest/{source}", dependencies=[Depends(require_ingest_token)])
    async def ingest(
        source: str,
        request: Request,
        year: int | None = Query(None, ge=2000, le=2100, description="Year for syslog lines"),
    ) -> dict[str, int]:
        """Ingest raw log lines (text/plain body, one event per line)."""
        if source not in PARSERS:
            raise HTTPException(404, f"unknown source {source!r}; choose from {sorted(PARSERS)}")

        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_INGEST_BYTES:
            raise HTTPException(413, "request body too large")
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_INGEST_BYTES:
                raise HTTPException(413, "request body too large")
            chunks.append(chunk)

        lines = b"".join(chunks).decode("utf-8", errors="replace").splitlines()
        result = await run_in_threadpool(request.app.state.pipeline.ingest, source, lines, year)
        return asdict(result)

    @app.get("/api/events", dependencies=[Depends(require_read_token)])
    def list_events(
        request: Request,
        limit: int = Query(100, ge=1, le=500),
        source: str | None = None,
        event_type: str | None = None,
        src_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        query = select(EventRow).order_by(EventRow.ts.desc(), EventRow.id.desc()).limit(limit)
        if source:
            query = query.where(EventRow.source == source)
        if event_type:
            query = query.where(EventRow.event_type == event_type)
        if src_ip:
            query = query.where(EventRow.src_ip == src_ip)
        with request.app.state.session_factory() as session:
            return [_event_dict(row) for row in session.scalars(query)]

    @app.get("/api/alerts", dependencies=[Depends(require_read_token)])
    def list_alerts(
        request: Request,
        limit: int = Query(100, ge=1, le=500),
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = select(AlertRow).order_by(AlertRow.ts.desc(), AlertRow.id.desc()).limit(limit)
        if severity:
            query = query.where(AlertRow.severity == severity)
        if rule_id:
            query = query.where(AlertRow.rule_id == rule_id)
        with request.app.state.session_factory() as session:
            return [_alert_dict(row) for row in session.scalars(query)]

    @app.get("/api/stats", dependencies=[Depends(require_read_token)])
    def stats(request: Request, hours: int = Query(24, ge=1, le=168)) -> dict[str, Any]:
        with request.app.state.session_factory() as session:
            total_events = session.scalar(select(func.count(EventRow.id))) or 0
            total_alerts = session.scalar(select(func.count(AlertRow.id))) or 0
            by_severity = {
                sev: n
                for sev, n in session.execute(
                    select(AlertRow.severity, func.count()).group_by(AlertRow.severity)
                )
            }
            count = func.count().label("n")
            top_sources = [
                {"src_ip": ip, "alerts": n}
                for ip, n in session.execute(
                    select(AlertRow.src_ip, count)
                    .where(AlertRow.src_ip.is_not(None))
                    .group_by(AlertRow.src_ip)
                    .order_by(desc("n"))
                    .limit(5)
                )
            ]
            top_rules = [
                {"rule_id": rule_id, "title": title, "alerts": n}
                for rule_id, title, n in session.execute(
                    select(AlertRow.rule_id, AlertRow.title, count)
                    .group_by(AlertRow.rule_id, AlertRow.title)
                    .order_by(desc("n"))
                    .limit(5)
                )
            ]

            # The timeline ends at the newest alert (not "now"), so old data still shows up.
            timeline: list[dict[str, Any]] = []
            latest = session.scalar(select(func.max(AlertRow.ts)))
            if latest is not None:
                end = latest.replace(minute=0, second=0, microsecond=0)
                start = end - timedelta(hours=hours - 1)
                buckets = {start + timedelta(hours=i): 0 for i in range(hours)}
                for ts in session.scalars(select(AlertRow.ts).where(AlertRow.ts >= start)):
                    buckets[ts.replace(minute=0, second=0, microsecond=0)] += 1
                timeline = [{"hour": _iso(h), "count": n} for h, n in buckets.items()]

        return {
            "events": total_events,
            "alerts": total_alerts,
            "alerts_by_severity": by_severity,
            "top_sources": top_sources,
            "top_rules": top_rules,
            "timeline": timeline,
        }

    return app

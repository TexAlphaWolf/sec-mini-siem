"""Distinct-value thresholds and rebuilding the detection state after a restart."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from minisiem.db import init_db, make_session_factory
from minisiem.events import Event
from minisiem.pipeline import Pipeline
from minisiem.rules import RuleEngine, RuleError, load_rules

T0 = datetime(2026, 10, 20, 9, 0, 0)


def failed_line(sec: float, user: str = "admin", ip: str = "203.0.113.50") -> str:
    t = T0 + timedelta(seconds=sec)
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} web01 sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def event(sec: float, user: str | None, ip: str = "203.0.113.50") -> Event:
    return Event(
        ts=T0 + timedelta(seconds=sec),
        source="auth",
        event_type="ssh_failed_password",
        src_ip=ip,
        username=user,
        raw="x",
    )


def make_engine(tmp_path, threshold: str) -> RuleEngine:
    body = (
        "id: spray\ntitle: Spray\nseverity: high\n"
        "match: {event_type: ssh_failed_password}\n"
        f"threshold: {threshold}\n"
    )
    (tmp_path / "r.yml").write_text(body, encoding="utf-8")
    return RuleEngine(load_rules(tmp_path))


# --- distinct thresholds -----------------------------------------------------------------------


def test_distinct_counts_values_not_events(tmp_path):
    engine = make_engine(tmp_path, "{count: 3, window: 5m, group_by: src_ip, distinct: username}")
    alerts = [a for i in range(10) for a in engine.evaluate(event(i, "admin"))]
    assert alerts == []  # ten events, one value
    alerts = engine.evaluate(event(11, "root")) + engine.evaluate(event(12, "bob"))
    assert len(alerts) == 1
    assert alerts[0].event_count == 3
    assert alerts[0].details["distinct"] == "username"
    assert alerts[0].details["values"] == ["admin", "bob", "root"]


def test_distinct_values_leave_the_window_with_their_events(tmp_path):
    engine = make_engine(tmp_path, "{count: 3, window: 60s, group_by: src_ip, distinct: username}")
    alerts = engine.evaluate(event(0, "a")) + engine.evaluate(event(10, "b"))
    alerts += engine.evaluate(event(100, "c"))  # a and b are older than 60 s by now
    assert alerts == []


def test_a_repeated_value_keeps_counting_once_even_after_one_copy_expires(tmp_path):
    engine = make_engine(tmp_path, "{count: 3, window: 60s, group_by: src_ip, distinct: username}")
    alerts = engine.evaluate(event(0, "a")) + engine.evaluate(event(50, "a"))
    alerts += engine.evaluate(event(70, "b"))  # the first "a" expired, the second is still in
    alerts += engine.evaluate(event(80, "c"))
    assert len(alerts) == 1


def test_event_without_the_distinct_field_is_ignored(tmp_path):
    engine = make_engine(tmp_path, "{count: 1, window: 5m, group_by: src_ip, distinct: username}")
    assert engine.evaluate(event(0, None)) == []


def test_very_long_values_are_cut_in_the_alert(tmp_path):
    engine = make_engine(tmp_path, "{count: 1, window: 5m, group_by: src_ip, distinct: username}")
    alert = engine.evaluate(event(0, "x" * 500))[0]
    assert alert.details["values"] == ["x" * 64]


@pytest.mark.parametrize(
    ("threshold", "message"),
    [
        ("{count: 3, window: 5m, distinct: 7}", "must be a field name"),
        ("{count: 3, window: 5m, group_by: src_ip, distinct: src_ip}", "must be different"),
    ],
)
def test_invalid_distinct_settings_are_rejected(tmp_path, threshold, message):
    with pytest.raises(RuleError, match=message):
        make_engine(tmp_path, threshold)


# --- restoring state after a restart -------------------------------------------------------------


@pytest.fixture
def pipeline_factory(database_url, rules_dir):
    engines = []

    def build() -> Pipeline:
        engine, session_factory = make_session_factory(database_url)
        init_db(engine)
        engines.append(engine)
        return Pipeline(session_factory, load_rules(rules_dir))

    yield build
    for engine in engines:
        engine.dispose()


def ingest(pipeline: Pipeline, lines: list[str]):
    return pipeline.ingest("auth", lines, year=2026)


def test_without_restoring_a_restart_forgets_the_attack_so_far(pipeline_factory):
    ingest(pipeline_factory(), [failed_line(i) for i in range(4)])
    assert ingest(pipeline_factory(), [failed_line(4)]).alerts == 0


def test_a_restart_in_the_middle_of_an_attack_does_not_lose_the_count(pipeline_factory):
    ingest(pipeline_factory(), [failed_line(i) for i in range(4)])
    after = pipeline_factory()
    assert after.restore_state() == 4
    assert ingest(after, [failed_line(4)]).alerts == 1  # the fifth failure completes the window


def test_a_restart_does_not_raise_the_same_alert_twice(pipeline_factory):
    first = ingest(pipeline_factory(), [failed_line(i) for i in range(5)])
    assert first.alerts == 1
    after = pipeline_factory()
    after.restore_state()
    assert ingest(after, [failed_line(10 + i) for i in range(5)]).alerts == 0


def test_silence_survives_even_when_the_causing_events_are_outside_the_replay(pipeline_factory):
    ingest(pipeline_factory(), [failed_line(i) for i in range(5)])  # alert at t=4, silent to t=64
    after = pipeline_factory()
    after.restore_state()
    # An unrelated, much later event moves "the newest event" forward, so the replay window
    # no longer contains the five failures; the stored alert still keeps the group silent.
    assert ingest(after, [failed_line(30 + i) for i in range(5)]).alerts == 0


def test_restoring_an_empty_database_is_a_no_op(pipeline_factory):
    assert pipeline_factory().restore_state() == 0

from __future__ import annotations

from sqlalchemy import func, select

from minisiem.cli import main
from minisiem.db import AlertRow, make_session_factory


def test_rules_check_ok(rules_dir, capsys):
    assert main(["rules", "check", str(rules_dir)]) == 0
    out = capsys.readouterr().out
    assert "rules OK" in out
    assert "ssh-bruteforce" in out


def test_rules_check_reports_errors(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("id: x\ntitle: T\nseverity: nope\nmatch: {a: 1}\n", encoding="utf-8")
    assert main(["rules", "check", str(tmp_path)]) == 1
    assert "invalid severity" in capsys.readouterr().err


def test_ingest_file_writes_alerts_to_the_database(
    database_url, rules_dir, sample_dir, monkeypatch, capsys
):
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("MINISIEM_RULES_DIR", str(rules_dir))

    assert main(["ingest", "auth", str(sample_dir / "auth.log"), "--year", "2026"]) == 0
    assert "alerts=" in capsys.readouterr().out

    engine, session_factory = make_session_factory(database_url)
    with session_factory() as session:
        assert session.scalar(select(func.count(AlertRow.id))) > 0
    engine.dispose()


def test_ingest_missing_file_is_an_error(tmp_path, rules_dir, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    monkeypatch.setenv("MINISIEM_RULES_DIR", str(rules_dir))
    assert main(["ingest", "auth", str(tmp_path / "missing.log")]) == 1
    assert "no such file" in capsys.readouterr().err

from __future__ import annotations

import yaml

from minisiem.cli import main
from minisiem.rules import load_rules
from minisiem.sigma import export_sigma, to_sigma


def documents(rules_dir) -> list[dict]:
    return list(yaml.safe_load_all(export_sigma(load_rules(rules_dir))))


def by_name(docs: list[dict]) -> dict[str, dict]:
    return {d["name"]: d for d in docs}


def test_every_rule_is_exported_with_unique_ids(rules_dir):
    docs = documents(rules_dir)
    rules = load_rules(rules_dir)
    assert {r.id for r in rules} <= {d["name"] for d in docs}
    ids = [d["id"] for d in docs]
    assert len(ids) == len(set(ids))


def test_export_is_stable(rules_dir):
    assert export_sigma(load_rules(rules_dir)) == export_sigma(load_rules(rules_dir))


def test_detection_rules_have_the_sigma_basics(rules_dir):
    for doc in documents(rules_dir):
        assert doc["title"] and doc["level"] in {"low", "medium", "high", "critical"}
        assert doc["status"] == "experimental"
        assert ("detection" in doc) != ("correlation" in doc)


def test_modifiers_are_translated(rules_dir):
    sqli = by_name(documents(rules_dir))["web-sqli-probe"]
    selection = sqli["detection"]["selection"]
    assert selection["event_type"] == "http_request"
    patterns = selection["path_decoded|re|i"]
    assert isinstance(patterns, list) and len(patterns) == 5
    assert sqli["logsource"] == {"category": "webserver"}


def test_event_count_correlation(rules_dir):
    docs = by_name(documents(rules_dir))
    brute = docs["ssh-bruteforce-threshold"]["correlation"]
    assert brute == {
        "type": "event_count",
        "rules": ["ssh-bruteforce"],
        "group-by": ["src_ip"],
        "timespan": "60s",
        "condition": {"gte": 5},
    }
    assert docs["ssh-bruteforce"]["logsource"] == {"product": "linux", "service": "auth"}


def test_distinct_thresholds_become_value_count(rules_dir):
    spray = by_name(documents(rules_dir))["ssh-password-spraying-threshold"]["correlation"]
    assert spray["type"] == "value_count"
    assert spray["condition"] == {"gte": 5, "field": "username"}
    assert spray["timespan"] == "600s"


def test_count_one_thresholds_export_only_the_detection(rules_dir):
    docs = by_name(documents(rules_dir))
    assert "web-sqli-probe" in docs
    assert "web-sqli-probe-threshold" not in docs


def test_every_correlation_points_at_an_exported_rule(rules_dir):
    docs = documents(rules_dir)
    names = {d["name"] for d in docs}
    for doc in docs:
        if "correlation" in doc:
            assert set(doc["correlation"]["rules"]) <= names


def test_single_event_rule_is_one_document(rules_dir):
    rule = next(r for r in load_rules(rules_dir) if r.id == "ssh-root-login")
    assert len(to_sigma(rule)) == 1


def test_cli_export_to_stdout_and_file(rules_dir, tmp_path, capsys):
    assert main(["rules", "export", str(rules_dir)]) == 0
    printed = capsys.readouterr().out
    assert list(yaml.safe_load_all(printed))

    target = tmp_path / "sigma.yml"
    assert main(["rules", "export", str(rules_dir), "-o", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == printed


def test_cli_export_reports_broken_rules(tmp_path, capsys):
    (tmp_path / "bad.yml").write_text("id: x\n", encoding="utf-8")
    assert main(["rules", "export", str(tmp_path)]) == 1
    assert "missing required key" in capsys.readouterr().err

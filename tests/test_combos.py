"""Combination contracts: rules that intentionally co-fire across passes."""

import json

from nginxvet.demo import run_demo
from nginxvet.render import render_sarif
from nginxvet.scanner import scan_paths


def _scan(tmp_path, text):
    path = tmp_path / "nginx.conf"
    path.write_text(text, encoding="utf-8")
    return scan_paths([str(path)])


def _rules(report):
    return {finding.rule for finding in report.findings}


def test_trap_and_missing_header_cofire(tmp_path):
    text = (
        "server { add_header Strict-Transport-Security x always; "
        "location / { add_header X-Debug 1; } }"
    )
    fired = _rules(_scan(tmp_path, text))
    assert {"NGV201", "NGV107", "NGV108"} <= fired


def test_include_trap_fires_both_passes(tmp_path):
    (tmp_path / "snippet.conf").write_text("location /x/ { add_header X-Debug 1; }", encoding="utf-8")
    path = tmp_path / "nginx.conf"
    path.write_text(
        "server { add_header Strict-Transport-Security x always; include snippet.conf; }",
        encoding="utf-8",
    )
    fired = _rules(scan_paths([str(path)]))
    assert {"NGV201", "NGV302"} <= fired


def test_reverted_server_tokens_cofires_dead_setting(tmp_path):
    (tmp_path / "extra.conf").write_text("server_tokens on;", encoding="utf-8")
    path = tmp_path / "nginx.conf"
    path.write_text("http { server_tokens off; include extra.conf; }", encoding="utf-8")
    fired = _rules(scan_paths([str(path)]))
    assert "NGV301" in fired
    assert "NGV101" in fired  # the effective (winning) value is also judged


def test_wildcard_include_records_and_finding(tmp_path):
    (tmp_path / "a.conf").write_text("autoindex on;", encoding="utf-8")
    path = tmp_path / "nginx.conf"
    path.write_text("include *.conf;", encoding="utf-8")
    report = scan_paths([str(path)])
    assert "NGV303" in _rules(report)
    assert any(record.wildcard for record in report.includes)


def test_demo_sarif_contains_every_fired_rule():
    report = run_demo()
    payload = json.loads(render_sarif(report))
    rules = {rule["id"] for rule in payload["runs"][0]["tool"]["driver"]["rules"]}
    assert rules == {finding.rule for finding in report.findings}


def test_all_three_stages_present_in_demo():
    from nginxvet.rules import RULES_BY_ID

    fired = {finding.rule for finding in run_demo().findings}
    stages = {RULES_BY_ID[rule_id].stage for rule_id in fired}
    assert stages == {"directive", "relation", "crossfile"}


def test_evidence_unique_per_finding():
    report = run_demo()
    keys = [(f.path, f.line, f.offset, f.rule) for f in report.findings]
    assert len(keys) == len(set(keys))


def test_report_fail_on_respects_severity_order():
    report = run_demo()
    assert report.should_fail("critical") is True
    assert report.should_fail("note") is True
    assert report.should_fail("none") is False

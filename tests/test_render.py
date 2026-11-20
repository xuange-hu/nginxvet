"""Renderer contract: text, JSON and SARIF 2.1.0 shapes."""

import json

from nginxvet.demo import run_demo
from nginxvet.render import render, render_json, render_sarif, render_text


def test_text_ends_with_summary():
    out = render_text(run_demo())
    assert "finding(s) across" in out


def test_text_shows_fix_by_default_and_hides_on_quiet():
    report = run_demo()
    assert "fix:" in render_text(report)
    assert "fix:" not in render_text(report, quiet=True)


def test_text_shows_evidence_line():
    out = render_text(run_demo())
    assert "(offset " in out and "saw:" in out


def test_json_roundtrips():
    payload = json.loads(render_json(run_demo()))
    assert set(payload) == {"source", "findings", "counts", "rules_run", "includes"}
    assert payload["counts"] == run_demo().counts


def test_json_findings_have_four_evidence_elements():
    payload = json.loads(render_json(run_demo()))
    for finding in payload["findings"]:
        assert finding["path"]
        assert finding["line"] >= 1
        assert finding["offset"] >= 0
        assert finding["saw"]


def test_sarif_valid_envelope():
    payload = json.loads(render_sarif(run_demo()))
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "nginxvet"
    assert run["results"]


def test_sarif_results_have_locations():
    payload = json.loads(render_sarif(run_demo()))
    for result in payload["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["byteOffset"] >= 0
        assert region["snippet"]["text"]


def test_sarif_windows_paths_normalized():
    report = run_demo()
    report.findings[0].where = "C:\\nginx\\nginx.conf"
    payload = json.loads(render_sarif(report))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_rules_unique():
    payload = json.loads(render_sarif(run_demo()))
    ids = [rule["id"] for rule in payload["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_render_dispatch():
    report = run_demo()
    assert render(report, fmt="json").lstrip().startswith("{")
    assert render(report, fmt="sarif").lstrip().startswith("{")
    assert "NGV" in render(report, fmt="text")


def test_render_unknown_format_falls_back_to_text():
    assert render(run_demo(), fmt="yaml").lstrip().startswith("CRITICAL") or "NGV" in render(
        run_demo(), fmt="yaml"
    )

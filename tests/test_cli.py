"""CLI contract: scan, effective, rules, demo, explain and exit codes."""

import json

from nginxvet.__about__ import __version__
from nginxvet.cli import main


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_scan_text_reports_findings(tmp_path, capsys):
    path = _write(tmp_path, "nginx.conf", "server_tokens on;\n")
    assert main(["scan", path]) == 0
    out = capsys.readouterr().out
    assert "NGV101" in out and "fix:" in out


def test_scan_quiet_hides_fixes(tmp_path, capsys):
    path = _write(tmp_path, "nginx.conf", "server_tokens on;\n")
    main(["scan", path, "--quiet"])
    assert "fix:" not in capsys.readouterr().out


def test_scan_json_shape(tmp_path, capsys):
    path = _write(tmp_path, "nginx.conf", "autoindex on;\n")
    main(["scan", path, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["medium"] >= 1
    assert payload["findings"][0]["rule"] == "NGV102"
    assert payload["rules_run"] == 37


def test_scan_sarif_shape(tmp_path, capsys):
    path = _write(tmp_path, "nginx.conf", "autoindex on;\n")
    main(["scan", path, "--format", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "nginxvet"


def test_fail_on_gate_both_directions(tmp_path, capsys):
    clean = _write(tmp_path, "clean.conf", "server_tokens off;\n")
    bad = _write(tmp_path, "bad.conf", "server_tokens on;\n")
    assert main(["scan", clean, "--fail-on", "high"]) == 0
    assert main(["scan", bad, "--fail-on", "low"]) == 1
    assert main(["scan", bad, "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_fail_on_critical(tmp_path):
    bad = _write(tmp_path, "bad.conf", "server { add_header Strict-Transport-Security x always; "
                                        "location / { add_header X-Debug 1; } }")
    assert main(["scan", bad, "--fail-on", "critical"]) == 1


def test_rules_list(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("NGV") >= 37
    assert "NGV201" in out


def test_rules_json(capsys):
    main(["rules", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 37


def test_rules_one(capsys):
    assert main(["rules", "--rule", "ngv201"]) == 0
    assert "inheritance" in capsys.readouterr().out.lower()


def test_unknown_rule_exits_2(capsys):
    assert main(["explain", "NGV999"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_explain_prints_why_and_fix(capsys):
    assert main(["explain", "NGV201"]) == 0
    out = capsys.readouterr().out
    assert "why:" in out and "fix:" in out


def test_demo_runs_without_arguments(capsys):
    assert main(["demo", "--quiet"]) == 0
    assert "finding(s)" in capsys.readouterr().out


def test_demo_json(capsys):
    main(["demo", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["rules_run"] == 37
    assert len(payload["findings"]) >= 37


def test_demo_sarif(capsys):
    main(["demo", "--format", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"][0]["tool"]["driver"]["name"] == "nginxvet"


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_directory(tmp_path, capsys):
    _write(tmp_path, "a.conf", "server_tokens on;\n")
    _write(tmp_path, "b.conf", "autoindex on;\n")
    main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert "NGV101" in out and "NGV102" in out


def test_scan_empty_config_is_clean(tmp_path, capsys):
    path = _write(tmp_path, "nginx.conf", "worker_processes auto;\n")
    assert main(["scan", path, "--fail-on", "critical"]) == 0
    assert "no findings" in capsys.readouterr().out


def test_scan_expands_includes(tmp_path, capsys):
    (tmp_path / "extra.conf").write_text("autoindex on;\n", encoding="utf-8")
    path = _write(tmp_path, "nginx.conf", "include extra.conf;\n")
    main(["scan", path])
    assert "NGV102" in capsys.readouterr().out


def test_scan_missing_path_is_clean(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "gone.conf")]) == 0
    assert "no findings" in capsys.readouterr().out

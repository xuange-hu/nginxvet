"""Pass 3 (NGV3xx): include expansion and cross-file effects."""

from nginxvet.scanner import scan_paths


def _scan(tmp_path, files: dict[str, str], main: str = "nginx.conf"):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_paths([str(tmp_path / main)])


def _rules(report):
    return {finding.rule for finding in report.findings}


def _hits(report, rule_id):
    return [finding for finding in report.findings if finding.rule == rule_id]


def test_include_reverts_server_tokens(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "http { server_tokens off; include extra.conf; }",
            "extra.conf": "server_tokens on;",
        },
    )
    assert "NGV301" in _rules(report)


def test_include_reversion_evidence_in_include_file(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "http { server_tokens off; include extra.conf; }",
            "extra.conf": "server_tokens on;",
        },
    )
    finding = _hits(report, "NGV301")[0]
    assert finding.path.endswith("extra.conf")
    assert finding.line == 1
    assert "server_tokens on" in finding.saw


def test_include_keeping_server_tokens_off_is_quiet(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "http { server_tokens off; include extra.conf; }",
            "extra.conf": "server_tokens off;",
        },
    )
    assert "NGV301" not in _rules(report)


def test_included_location_triggers_header_trap(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": (
                "http { server {\n"
                "  add_header Strict-Transport-Security x always;\n"
                "  add_header Content-Security-Policy x always;\n"
                "  include snippet.conf;\n"
                "} }"
            ),
            "snippet.conf": "location /x/ { add_header X-Debug 1; }",
        },
    )
    assert "NGV302" in _rules(report)
    assert _hits(report, "NGV302")[0].path.endswith("snippet.conf")


def test_included_location_without_add_header_is_quiet(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": (
                "http { server {\n"
                "  add_header Strict-Transport-Security x always;\n"
                "  include snippet.conf;\n"
                "} }"
            ),
            "snippet.conf": "location /x/ { proxy_pass http://x; }",
        },
    )
    assert "NGV302" not in _rules(report)


def test_wildcard_include_fires(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "include conf.d/*.conf;", "conf.d/a.conf": "a b;"})
    assert "NGV303" in _rules(report)


def test_explicit_include_is_quiet(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "include conf.d/a.conf;", "conf.d/a.conf": "a b;"})
    assert "NGV303" not in _rules(report)


def test_inconsistent_tls_on_shared_port(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": (
                "http {\n"
                " server { listen 443 ssl; server_name a.example; ssl_protocols TLSv1 TLSv1.2; }\n"
                " server { listen 443 ssl; server_name b.example; ssl_protocols TLSv1.2; }\n"
                "}"
            )
        },
    )
    assert "NGV304" in _rules(report)


def test_consistent_tls_on_shared_port_is_quiet(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": (
                "http {\n"
                " server { listen 443 ssl; ssl_protocols TLSv1.2; }\n"
                " server { listen 443 ssl; ssl_protocols TLSv1.2; }\n"
                "}"
            )
        },
    )
    assert "NGV304" not in _rules(report)


def test_include_overrides_security_header(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "http { add_header X-Frame-Options SAMEORIGIN always; include extra.conf; }",
            "extra.conf": "add_header X-Frame-Options DENY always;",
        },
    )
    assert "NGV305" in _rules(report)
    assert _hits(report, "NGV305")[0].path.endswith("extra.conf")


def test_include_with_different_header_name_is_quiet(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "http { add_header X-Frame-Options SAMEORIGIN always; include extra.conf; }",
            "extra.conf": "add_header X-Content-Type-Options nosniff always;",
        },
    )
    assert "NGV305" not in _rules(report)


def test_duplicate_include_fires(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "include a.conf;\ninclude a.conf;",
            "a.conf": "server_tokens off;",
        },
    )
    assert "NGV306" in _rules(report)


def test_single_include_is_quiet(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "include a.conf;", "a.conf": "server_tokens off;"})
    assert "NGV306" not in _rules(report)


def test_missing_include_fires(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "include gone.conf;"})
    assert "NGV307" in _rules(report)


def test_missing_include_evidence(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "include gone.conf;"})
    finding = _hits(report, "NGV307")[0]
    assert "gone.conf" in finding.message
    assert finding.line == 1


def test_tls_listener_without_certificate(tmp_path):
    report = _scan(tmp_path, {"nginx.conf": "http { server { listen 443 ssl; } }"})
    assert "NGV308" in _rules(report)


def test_tls_listener_with_certificate_is_quiet(tmp_path):
    text = "http { server { listen 443 ssl; ssl_certificate /etc/ssl/x.crt; } }"
    assert "NGV308" not in _rules(_scan(tmp_path, {"nginx.conf": text}))


def test_report_records_includes(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "include conf.d/*.conf;\ninclude gone.conf;",
            "conf.d/a.conf": "a b;",
        },
    )
    assert len(report.includes) == 2
    assert report.includes[0].resolved == [str(tmp_path / "conf.d" / "a.conf")] or report.includes[0].resolved
    assert report.includes[1].missing is True


def test_nested_include_is_expanded(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": "include a.conf;",
            "a.conf": "include b.conf;",
            "b.conf": "autoindex on;",
        },
    )
    assert "NGV102" in _rules(report)


def test_every_crossfile_rule_can_fire(tmp_path):
    report = _scan(
        tmp_path,
        {
            "nginx.conf": (
                "http {\n"
                " server_tokens off;\n"
                " add_header X-Frame-Options SAMEORIGIN always;\n"
                " include conf.d/*.conf;\n"
                " include conf.d/extra.conf;\n"
                " include gone.conf;\n"
                " server { listen 443 ssl; server_name a; ssl_protocols TLSv1; }\n"
                " server { listen 443 ssl; server_name b; ssl_protocols TLSv1.2; }\n"
                " server { listen 80 ssl; server_name c; }\n"
                "}\n"
            ),
            "conf.d/10-a.conf": "keepalive_timeout 5;",
            "conf.d/extra.conf": "server_tokens on;\nadd_header X-Frame-Options DENY always;",
        },
    )
    fired = _rules(report)
    assert {"NGV301", "NGV303", "NGV304", "NGV305", "NGV306", "NGV307", "NGV308"} <= fired

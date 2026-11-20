"""Pass 1 (NGV1xx): every directive rule fires on the bad value, stays quiet on the good one."""

import pytest

from nginxvet.rules import REGISTRY, RULES_BY_ID
from nginxvet.scanner import scan_paths

# rule id -> (config that must fire, config that must stay quiet)
TRIGGERS = {
    "NGV101": ("server_tokens on;", "server_tokens off;"),
    "NGV102": ("autoindex on;", "autoindex off;"),
    "NGV103": ("ssl_protocols TLSv1 TLSv1.2;", "ssl_protocols TLSv1.2 TLSv1.3;"),
    "NGV104": ("ssl_ciphers RC4:HIGH:MD5;", "ssl_ciphers ECDHE+AESGCM;"),
    "NGV105": (
        "add_header Strict-Transport-Security max-age=100;",
        "add_header Strict-Transport-Security max-age=100 always;",
    ),
    "NGV109": (
        "server { location / { proxy_pass http://x; } }",
        "server { proxy_set_header Host $host; location / { proxy_pass http://x; } }",
    ),
    "NGV110": (
        "server { location / { proxy_pass http://x; } }",
        "server { proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; location / { proxy_pass http://x; } }",
    ),
    "NGV111": ("client_max_body_size 500m;", "client_max_body_size 10m;"),
    "NGV112": ("rewrite ^/x/(.*)$ /x/$uri last;", "rewrite ^/x/(.*)$ /y/$1 last;"),
    "NGV113": ("if ($x) { rewrite ^ /y last; }", "if ($x) { return 403; }"),
    "NGV114": ("resolver 8.8.8.8;", "resolver 8.8.8.8 valid=30s expire=10s;"),
    "NGV115": ("ssl_session_tickets on;", "ssl_session_tickets off;"),
    "NGV116": (
        "server { listen 80; }",
        "server { listen 80; return 301 https://$host$request_uri; }",
    ),
    "NGV117": ("access_log off;", "access_log /var/log/nginx/access.log;"),
    "NGV118": ("deny all; allow 10.0.0.0/8;", "allow 10.0.0.0/8; deny all;"),
    "NGV119": ("listen 80;", "listen 80 reuseport;"),
    "NGV120": ("gzip on;", "gzip off;"),
    "NGV121": ("ssl_prefer_server_ciphers off;", "ssl_prefer_server_ciphers on;"),
}

SECURE_SERVER = (
    "server {\n"
    "  add_header Strict-Transport-Security max-age=100 always;\n"
    "  add_header Content-Security-Policy \"default-src 'self'\" always;\n"
    "  add_header X-Frame-Options DENY always;\n"
    "}"
)


def _scan(tmp_path, text):
    path = tmp_path / "nginx.conf"
    path.write_text(text, encoding="utf-8")
    return scan_paths([str(path)])


def _rules(report):
    return {finding.rule for finding in report.findings}


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_risky_directive_fires(tmp_path, rule_id):
    bad, _good = TRIGGERS[rule_id]
    assert rule_id in _rules(_scan(tmp_path, bad))


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_safe_directive_stays_quiet(tmp_path, rule_id):
    _bad, good = TRIGGERS[rule_id]
    assert rule_id not in _rules(_scan(tmp_path, good))


def test_missing_hsts_fires(tmp_path):
    report = _scan(tmp_path, "server { listen 80; }")
    assert "NGV106" in _rules(report)


def test_missing_csp_fires(tmp_path):
    report = _scan(tmp_path, "server { listen 80; }")
    assert "NGV107" in _rules(report)


def test_missing_frame_options_fires(tmp_path):
    report = _scan(tmp_path, "server { listen 80; }")
    assert "NGV108" in _rules(report)


def test_secure_server_has_no_missing_header_findings(tmp_path):
    fired = _rules(_scan(tmp_path, SECURE_SERVER))
    assert not {"NGV106", "NGV107", "NGV108"} & fired


def test_hsts_only_server_still_missing_csp_and_frame(tmp_path):
    fired = _rules(_scan(tmp_path, "server { add_header Strict-Transport-Security x always; }"))
    assert "NGV107" in fired and "NGV108" in fired
    assert "NGV106" not in fired


def test_every_directive_rule_has_a_trigger():
    expected = set(TRIGGERS) | {"NGV106", "NGV107", "NGV108"}
    assert expected <= {item.id for item in REGISTRY}


def test_registry_has_37_rules():
    assert len(REGISTRY) == 37


def test_registry_ids_unique_and_prefixed():
    ids = [item.id for item in REGISTRY]
    assert len(ids) == len(set(ids))
    assert all(item_id.startswith("NGV") for item_id in ids)


def test_registry_metadata_sane():
    for item in REGISTRY:
        assert item.severity in ("critical", "high", "medium", "low", "note")
        assert item.stage in ("directive", "relation", "crossfile")
        assert 0 <= item.score <= 10
        assert item.why and item.fix


def test_rule_id_lookup():
    assert RULES_BY_ID["NGV201"].stage == "relation"
    assert RULES_BY_ID["NGV301"].stage == "crossfile"


def test_finding_carries_four_evidence_elements(tmp_path):
    report = _scan(tmp_path, "server_tokens on;\n")
    finding = next(finding for finding in report.findings if finding.rule == "NGV101")
    data = finding.to_dict()
    assert data["path"].endswith("nginx.conf")
    assert data["line"] == 1
    assert data["offset"] == 0
    assert data["saw"] == "server_tokens on;"
    assert data["length"] == len("server_tokens on;")


def test_findings_sorted_by_severity(tmp_path):
    text = "autoindex on;\nserver_tokens on;\ngzip on;\n"
    severities = [finding.severity for finding in _scan(tmp_path, text).findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}
    assert severities == sorted(severities, key=lambda value: order[value])


def test_report_rules_run(tmp_path):
    report = _scan(tmp_path, "server_tokens off;")
    assert report.rules_run == 37
    assert len(report.rule_ids) == 37


def test_multiple_violations_of_same_rule(tmp_path):
    report = _scan(tmp_path, "server_tokens on;\nserver_tokens on;\n")
    assert len([finding for finding in report.findings if finding.rule == "NGV101"]) == 2


def test_zero_findings_on_hardened_config(tmp_path):
    text = (
        "http {\n"
        "  server_tokens off;\n"
        "  autoindex off;\n"
        "  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "  ssl_ciphers ECDHE+AESGCM;\n"
        "  ssl_prefer_server_ciphers on;\n"
        "  ssl_session_tickets off;\n"
        "  resolver 1.1.1.1 valid=30s expire=10s;\n"
        "  gzip off;\n"
        "  client_max_body_size 1m;\n"
        "  server {\n"
        "    listen 443 ssl reuseport;\n"
        "    ssl_certificate /etc/ssl/site.crt;\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    add_header Strict-Transport-Security max-age=100 always;\n"
        "    add_header Content-Security-Policy \"default-src 'self'\" always;\n"
        "    add_header X-Frame-Options DENY always;\n"
        "  }\n"
        "}\n"
    )
    fired = _rules(_scan(tmp_path, text))
    assert not {"NGV101", "NGV102", "NGV103", "NGV104", "NGV105", "NGV110", "NGV111", "NGV120"} & fired

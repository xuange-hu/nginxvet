"""Pass 2 (NGV2xx): server/location inheritance and override traps."""

from nginxvet.scanner import scan_paths


def _scan(tmp_path, text):
    path = tmp_path / "nginx.conf"
    path.write_text(text, encoding="utf-8")
    return scan_paths([str(path)])


def _rules(report):
    return {finding.rule for finding in report.findings}


def _hits(report, rule_id):
    return [finding for finding in report.findings if finding.rule == rule_id]


HEADER_SERVER = (
    "server {\n"
    "  add_header Strict-Transport-Security max-age=100 always;\n"
    "  add_header Content-Security-Policy \"default-src 'self'\" always;\n"
    "  add_header X-Frame-Options DENY always;\n"
)


def test_add_header_trap_fires(tmp_path):
    text = HEADER_SERVER + "  location /api/ {\n    add_header X-Debug 1;\n  }\n}"
    assert "NGV201" in _rules(_scan(tmp_path, text))


def test_add_header_trap_absent_without_location_header(tmp_path):
    text = HEADER_SERVER + "  location /api/ {\n    proxy_pass http://x;\n  }\n}"
    assert "NGV201" not in _rules(_scan(tmp_path, text))


def test_add_header_trap_message_lists_lost_headers(tmp_path):
    text = HEADER_SERVER + "  location /api/ { add_header X-Debug 1; }\n}"
    finding = _hits(_scan(tmp_path, text), "NGV201")[0]
    assert "Strict-Transport-Security" in finding.message
    assert "Content-Security-Policy" in finding.message


def test_add_header_trap_evidence_points_at_location(tmp_path):
    text = HEADER_SERVER + "  location /api/ { add_header X-Debug 1; }\n}"
    finding = _hits(_scan(tmp_path, text), "NGV201")[0]
    assert finding.line == 5
    assert "X-Debug" in finding.saw
    assert finding.severity == "critical"


def test_add_header_trap_is_not_a_crossfile_rule_here(tmp_path):
    text = HEADER_SERVER + "  location /api/ { add_header X-Debug 1; }\n}"
    assert "NGV302" not in _rules(_scan(tmp_path, text))


def test_proxy_set_header_trap_fires(tmp_path):
    text = (
        "server {\n  proxy_set_header Host $host;\n"
        "  location /api/ { proxy_pass http://backend; }\n}"
    )
    assert "NGV202" in _rules(_scan(tmp_path, text))


def test_proxy_set_header_trap_absent_when_location_restates_host(tmp_path):
    text = (
        "server {\n  proxy_set_header Host $host;\n"
        "  location /api/ {\n    proxy_set_header Host $host;\n    proxy_pass http://backend;\n  }\n}"
    )
    assert "NGV202" not in _rules(_scan(tmp_path, text))


def test_proxy_set_header_trap_absent_without_server_header(tmp_path):
    text = "server { location /api/ { proxy_pass http://backend; } }"
    assert "NGV202" not in _rules(_scan(tmp_path, text))


def test_try_files_missing_named_location(tmp_path):
    text = "server { location / { try_files $uri @fallback; } }"
    assert "NGV203" in _rules(_scan(tmp_path, text))


def test_try_files_named_location_present(tmp_path):
    text = "server { location / { try_files $uri @fallback; } location @fallback { return 404; } }"
    assert "NGV203" not in _rules(_scan(tmp_path, text))


def test_try_files_without_named_target(tmp_path):
    assert "NGV203" not in _rules(_scan(tmp_path, "server { location / { try_files $uri =404; } }"))


def test_if_return_overrides_location_return(tmp_path):
    text = 'server { location / { return 200 "a"; if ($arg_x) { return 403; } } }'
    assert "NGV204" in _rules(_scan(tmp_path, text))


def test_if_without_location_return_is_quiet(tmp_path):
    text = "server { location / { if ($arg_x) { return 403; } } }"
    assert "NGV204" not in _rules(_scan(tmp_path, text))


def test_regex_capture_without_group(tmp_path):
    text = "server { location ~ \\.php$ { fastcgi_param X /www$1; } }"
    assert "NGV205" in _rules(_scan(tmp_path, text))


def test_regex_capture_with_group_is_quiet(tmp_path):
    text = "server { location ~ ^/(.*)\\.php$ { fastcgi_param X /www$1; } }"
    assert "NGV205" not in _rules(_scan(tmp_path, text))


def test_keepalive_less_upstream_fires(tmp_path):
    text = (
        "upstream backend { server 127.0.0.1:9000; }\n"
        "server { location / { proxy_http_version 1.1; proxy_pass http://backend; } }"
    )
    assert "NGV206" in _rules(_scan(tmp_path, text))


def test_upstream_with_keepalive_is_quiet(tmp_path):
    text = (
        "upstream backend { server 127.0.0.1:9000; keepalive 16; }\n"
        "server { location / { proxy_http_version 1.1; proxy_pass http://backend; } }"
    )
    assert "NGV206" not in _rules(_scan(tmp_path, text))


def test_duplicate_server_name_fires(tmp_path):
    text = "server { server_name example.com; } server { server_name example.com; }"
    assert "NGV207" in _rules(_scan(tmp_path, text))


def test_unique_server_names_quiet(tmp_path):
    text = "server { server_name a.example; } server { server_name b.example; }"
    assert "NGV207" not in _rules(_scan(tmp_path, text))


def test_two_default_servers_fire(tmp_path):
    text = "server { listen 80 default_server; } server { listen 80 default_server; }"
    assert "NGV207" in _rules(_scan(tmp_path, text))


def test_alias_with_try_files_fires(tmp_path):
    text = "server { location /files/ { alias /data/; try_files $uri =404; } }"
    assert "NGV208" in _rules(_scan(tmp_path, text))


def test_root_with_try_files_quiet(tmp_path):
    text = "server { location /files/ { root /data; try_files $uri =404; } }"
    assert "NGV208" not in _rules(_scan(tmp_path, text))


def test_every_relation_rule_can_fire(tmp_path):
    text = (
        HEADER_SERVER
        + "  proxy_set_header Host $host;\n"
        + "  location / {\n"
        "    add_header X-Debug 1;\n"
        "    proxy_pass http://backend;\n"
        "    try_files $uri @gone;\n"
        "  }\n"
        "  location ~ \\.php$ { fastcgi_param X $1; }\n"
        "  location /c/ { return 200 x; if ($x) { return 403; } }\n"
        "  location /a/ { alias /d/; try_files $uri =404; }\n"
        "}\n"
        "upstream backend { server 127.0.0.1:9000; }\n"
        "server { location /u/ { proxy_http_version 1.1; proxy_pass http://backend; } }\n"
        "server { server_name dup.example; }\n"
        "server { server_name dup.example; }\n"
    )
    fired = _rules(_scan(tmp_path, text))
    assert {"NGV201", "NGV202", "NGV203", "NGV204", "NGV205", "NGV206", "NGV207", "NGV208"} <= fired

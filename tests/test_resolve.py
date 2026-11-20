"""Effective-config resolution: add_header inheritance, server and location matching."""

from nginxvet.model import all_blocks
from nginxvet.parser import parse
from nginxvet.resolve import (
    CORE_SECURITY_HEADERS,
    SECURITY_HEADERS,
    EffectiveContext,
    add_headers_at,
    effective_for,
    effective_headers,
    find_location,
    find_server,
    header_trap_at,
)


def _config(text: str, source: str = "nginx.conf"):
    return parse(text, source)


def _server(text: str):
    return all_blocks([_config(text)], "server")[0]


def test_add_headers_at_reads_direct_children_only():
    server = _server(
        "server {\n"
        "  add_header A 1 always;\n"
        "  location / { add_header B 2; }\n"
        "}"
    )
    assert [header.name for header in add_headers_at(server)] == ["a"]


def test_add_headers_at_detects_always():
    server = _server("server { add_header A 1 always; add_header B 2; }")
    assert [header.always for header in add_headers_at(server)] == [True, False]


def test_add_headers_at_preserves_evidence():
    server = _server("server { add_header A 1 always; }")
    header = add_headers_at(server)[0]
    assert header.node.file == "nginx.conf"
    assert header.node.line == 1
    assert header.node.offset > 0


def test_effective_headers_uses_server_level():
    server = _server("server { add_header A 1 always; }")
    headers, level = effective_headers(server)
    assert [item.name for item in headers] == ["a"]
    assert level == "server"


def test_effective_headers_inherits_from_http():
    config = _config("http { add_header A 1 always; server { listen 80; } }")
    server = all_blocks([config], "server")[0]
    headers, level = effective_headers(server)
    assert [item.name for item in headers] == ["a"]
    assert level == "http"


def test_effective_headers_empty_when_nowhere():
    server = _server("server { listen 80; }")
    assert effective_headers(server) == ([], "")


def test_effective_headers_stops_at_nearest_level():
    config = _config(
        "http { add_header A 1 always; server { add_header B 2; location / { } } }"
    )
    location = all_blocks([config], "location")[0]
    headers, level = effective_headers(location)
    assert [item.name for item in headers] == ["b"]
    assert level == "server"


def test_header_trap_returns_lost_security_headers():
    config = _config(
        "server { add_header Strict-Transport-Security x always; "
        "location /api/ { add_header X-Debug 1; } }"
    )
    location = all_blocks([config], "location")[0]
    lost = header_trap_at(location, all_blocks([config], "server")[0])
    assert [item.name for item in lost] == ["strict-transport-security"]


def test_header_trap_empty_when_location_has_no_add_header():
    config = _config("server { add_header A 1; location / { proxy_pass http://x; } }")
    location = all_blocks([config], "location")[0]
    assert header_trap_at(location, all_blocks([config], "server")[0]) == []


def test_header_trap_empty_without_server_headers():
    config = _config("server { location / { add_header X-Debug 1; } }")
    location = all_blocks([config], "location")[0]
    assert header_trap_at(location, all_blocks([config], "server")[0]) == []


def test_find_server_exact_name():
    config = _config(
        "server { server_name a.example; listen 80; } server { server_name b.example; listen 80; }"
    )
    assert "b.example" in find_server([config], "b.example").server_names


def test_find_server_wildcard_name():
    config = _config("server { server_name *.example.com; } server { server_name other.test; }")
    assert "*.example.com" in find_server([config], "www.example.com").server_names


def test_find_server_case_insensitive():
    config = _config("server { server_name Example.COM; }")
    assert find_server([config], "example.com") is not None


def test_find_server_default_server_fallback():
    config = _config("server { server_name a; } server { listen 80 default_server; server_name b; }")
    assert "b" in find_server([config], "unknown.test").server_names


def test_find_server_first_when_no_match():
    config = _config("server { server_name a; } server { server_name b; }")
    assert "a" in find_server([config], "unknown.test").server_names


def test_find_server_none_without_servers():
    assert find_server([_config("http { }")], "x") is None


def test_find_location_exact_wins():
    server = _server(
        "server { location / { root /a; } location = /login { root /b; } location ~ /log { root /c; } }"
    )
    assert find_location(server, "/login").location_path == "/login"


def test_find_location_longest_prefix():
    server = _server("server { location / { root /a; } location /api/ { root /b; } }")
    assert find_location(server, "/api/user").location_path == "/api/"


def test_find_location_regex_overrides_prefix():
    server = _server("server { location / { root /a; } location ~ \\.php$ { root /b; } }")
    assert find_location(server, "/index.php").location_path == "\\.php$"


def test_find_location_named():
    server = _server("server { location @fallback { return 404; } }")
    assert find_location(server, "@fallback").location_modifier == "@"


def test_find_location_empty_path():
    server = _server("server { location / { root /a; } }")
    assert find_location(server, "") is None


def test_effective_for_reports_header_level():
    config = _config(
        "server { add_header Strict-Transport-Security x always; "
        "location /api/ { add_header X-Debug 1; } }"
    )
    context = effective_for([config], "example.com", "/api/")
    assert context.header_level == "location /api/"
    assert context.header_trap is True
    assert context.header_names == ["x-debug"]


def test_effective_for_reports_missing_core_headers():
    context = effective_for([_config("server { listen 80; }")], "example.com")
    assert set(context.missing_core) == set(CORE_SECURITY_HEADERS)


def test_effective_for_trap_lists_lost_names():
    config = _config(
        "server { add_header Strict-Transport-Security x always; "
        "add_header Content-Security-Policy y always; "
        "location /api/ { add_header X-Debug 1; } }"
    )
    context = effective_for([config], "example.com", "/api/")
    assert set(item.name for item in context.lost_headers) == {
        "strict-transport-security",
        "content-security-policy",
    }


def test_effective_context_dict_shape():
    context = effective_for([_config("server { listen 443 ssl; }")], "x")
    payload = context.to_dict()
    assert "headers" in payload
    assert "header_trap" in payload
    assert "missing_core_headers" in payload
    assert payload["ssl"] is True


def test_effective_context_dataclass_defaults():
    context = EffectiveContext()
    assert context.headers == []
    assert context.header_trap is False
    assert context.missing_core == list(CORE_SECURITY_HEADERS)


def test_security_header_constants():
    assert "strict-transport-security" in SECURITY_HEADERS
    assert "content-security-policy" in SECURITY_HEADERS
    assert "x-frame-options" in CORE_SECURITY_HEADERS

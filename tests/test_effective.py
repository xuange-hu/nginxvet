"""The `effective` command: the killer feature in CLI form."""

import json

from nginxvet.cli import main

TRAP_CONFIG = """\
http {
  server {
    listen 443 ssl;
    server_name example.com;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header X-Frame-Options DENY always;

    location /api/ {
      add_header X-Debug 1;
      proxy_pass http://backend;
    }

    location /safe/ {
      proxy_pass http://backend;
    }
  }
}
"""


def _write(tmp_path, text):
    path = tmp_path / "nginx.conf"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_effective_server_level_shows_headers(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    assert main(["effective", "example.com", path]) == 0
    out = capsys.readouterr().out
    assert "strict-transport-security" in out
    assert "content-security-policy" in out
    assert "x-frame-options" in out


def test_effective_location_shows_trap(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    assert main(["effective", "example.com", path, "--location", "/api/user"]) == 0
    out = capsys.readouterr().out
    assert "ADD_HEADER TRAP" in out
    assert "strict-transport-security" in out


def test_effective_safe_location_has_no_trap(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    main(["effective", "example.com", path, "--location", "/safe/x"])
    out = capsys.readouterr().out
    assert "ADD_HEADER TRAP" not in out
    assert "strict-transport-security" in out


def test_effective_json_shape(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    main(["effective", "example.com", path, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["host"] == "example.com"
    assert payload["header_trap"] is False
    assert len(payload["headers"]) == 3


def test_effective_json_location_trap(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    main(["effective", "example.com", path, "--location", "/api/x", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["header_trap"] is True
    assert len(payload["lost_headers"]) >= 1
    assert payload["location"]["saw"].startswith("location /api/")


def test_effective_reports_missing_core_headers(tmp_path, capsys):
    path = _write(tmp_path, "server { server_name x; listen 80; }")
    main(["effective", "x", path])
    assert "MISSING core headers" in capsys.readouterr().out


def test_effective_unknown_host_falls_back(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    assert main(["effective", "not-configured.test", path]) == 0
    assert "example.com" in capsys.readouterr().out


def test_effective_with_no_servers_does_not_crash(tmp_path, capsys):
    path = _write(tmp_path, "http { keepalive_timeout 5; }")
    assert main(["effective", "x", path]) == 0
    assert "no add_header applies" in capsys.readouterr().out


def test_effective_expands_includes(tmp_path, capsys):
    (tmp_path / "snippet.conf").write_text(
        "add_header Strict-Transport-Security x always;", encoding="utf-8"
    )
    path = _write(tmp_path, "server { server_name x; include snippet.conf; }")
    main(["effective", "x", path])
    assert "strict-transport-security" in capsys.readouterr().out


def test_effective_shows_proxy_settings(tmp_path, capsys):
    path = _write(tmp_path, "server { server_name x; proxy_set_header Host $host; }")
    main(["effective", "x", path, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["proxy_set_headers"] == ["Host"]


def test_effective_deterministic(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    main(["effective", "example.com", path, "--location", "/api/x"])
    first = capsys.readouterr().out
    main(["effective", "example.com", path, "--location", "/api/x"])
    assert capsys.readouterr().out == first


def test_effective_host_and_path_in_json(tmp_path, capsys):
    path = _write(tmp_path, TRAP_CONFIG)
    main(["effective", "example.com", path, "--location", "/safe/a", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["host"] == "example.com"
    assert payload["path"] == "/safe/a"

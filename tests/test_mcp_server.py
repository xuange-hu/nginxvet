"""MCP server tests (skipped when the optional mcp extra is absent)."""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from nginxvet.mcp_server import build_server, tool_manifest  # noqa: E402


def _call(name: str, arguments: dict):
    mcp = build_server()
    result = asyncio.run(mcp.call_tool(name, arguments))
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def test_manifest_matches_registered_tools():
    tools = asyncio.run(build_server().list_tools())
    assert {tool.name for tool in tools} == {entry["name"] for entry in tool_manifest()}


def test_six_tools_with_descriptions():
    manifest = tool_manifest()
    assert len(manifest) == 6
    assert all(entry["description"] for entry in manifest)


def test_registered_tools_have_nonempty_descriptions():
    tools = asyncio.run(build_server().list_tools())
    assert len(tools) == 6
    assert all(tool.description for tool in tools)


def test_call_demo_tool():
    payload = _call("nginxvet_demo", {})
    assert payload["counts"]["critical"] >= 1
    assert payload["findings"]


def test_call_rules_tool():
    payload = _call("nginxvet_rules", {})
    assert len(payload) == 37
    assert payload[0]["id"] == "NGV101"


def test_call_explain_tool():
    payload = _call("nginxvet_explain", {"rule_id": "NGV201"})
    assert payload["severity"] == "critical"
    assert _call("nginxvet_explain", {"rule_id": "NGV999"})["error"]


def test_call_effective_tool(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        "server { server_name x; add_header Strict-Transport-Security x always; "
        "location /api/ { add_header X-Debug 1; } }",
        encoding="utf-8",
    )
    payload = _call("nginxvet_effective", {"host": "x", "paths": [str(tmp_path)], "location": "/api/a"})
    assert payload["header_trap"] is True
    assert "strict-transport-security" in [item["name"] for item in payload["lost_headers"]]


def test_call_parse_tool(tmp_path):
    path = tmp_path / "nginx.conf"
    path.write_text("server_tokens on;\n", encoding="utf-8")
    payload = _call("nginxvet_parse", {"path": str(path)})
    assert payload["nodes"][0]["name"] == "server_tokens"
    assert payload["nodes"][0]["offset"] == 0


def test_call_scan_tool(tmp_path):
    path = tmp_path / "nginx.conf"
    path.write_text("autoindex on;\n", encoding="utf-8")
    payload = _call("nginxvet_scan", {"paths": [str(path)]})
    assert payload["counts"]["medium"] >= 1

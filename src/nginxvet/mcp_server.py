"""MCP server: expose nginxvet to Claude Code / Cursor / Cline.

``mcp`` is imported lazily inside ``build_server`` so the core package stays
zero-dependency and importable without the optional extra.
"""

from __future__ import annotations

import json


def tool_manifest() -> list[dict]:
    return [
        {
            "name": "nginxvet_scan",
            "description": (
                "Scan nginx.conf files or directories, expanding includes, and return evidence-backed "
                "findings from all three passes (directive, relation, cross-file)."
            ),
            "args": "paths (list[str]), fail_on (str, default 'none')",
        },
        {
            "name": "nginxvet_effective",
            "description": (
                "Answer 'what security headers really apply here?': resolve the server and location for a host "
                "and path, then show the effective add_header set, missing core headers and any inherited "
                "headers dropped by the add_header trap."
            ),
            "args": "host (str), paths (list[str]), location (str, default '')",
        },
        {
            "name": "nginxvet_demo",
            "description": (
                "Run the embedded demo corpus (a server assembled by several people) and return its findings; "
                "the corpus exercises every rule."
            ),
            "args": "none",
        },
        {
            "name": "nginxvet_rules",
            "description": "Return the full rulebook: id, title, severity, pass, why and fix for all rules.",
            "args": "none",
        },
        {
            "name": "nginxvet_explain",
            "description": "Explain one rule by id (e.g. NGV201) including why it matters and how to fix it.",
            "args": "rule_id (str)",
        },
        {
            "name": "nginxvet_parse",
            "description": (
                "Parse one nginx config file and return its block tree, directives and byte-offset evidence "
                "without running the rules."
            ),
            "args": "path (str)",
        },
    ]


def _summary(report) -> str:
    payload = {
        "source": report.source,
        "counts": report.counts,
        "findings": [finding.to_dict() for finding in report.findings],
    }
    return json.dumps(payload, indent=2)


def build_server():
    from mcp.server.fastmcp import FastMCP

    from .demo import run_demo
    from .parser import expand_includes, filesystem_resolver
    from .resolve import effective_for
    from .rules import RULES_BY_ID
    from .scanner import collect, read_config, scan_paths

    mcp = FastMCP("nginxvet")

    @mcp.tool(name="nginxvet_scan")
    def nginxvet_scan(paths: list[str], fail_on: str = "none") -> str:
        """Scan nginx configs and return all findings with file/line/offset evidence."""
        return _summary(scan_paths(paths))

    @mcp.tool(name="nginxvet_effective")
    def nginxvet_effective(host: str, paths: list[str], location: str = "") -> str:
        """Resolve a host/location and show effective security headers and the add_header trap."""
        files, _missing = collect(list(paths))
        configs = [read_config(path) for path in files]
        expanded, _includes = expand_includes(configs, filesystem_resolver())
        context = effective_for(expanded, host, location)
        return json.dumps(context.to_dict(), indent=2)

    @mcp.tool(name="nginxvet_demo")
    def nginxvet_demo() -> str:
        """Run the embedded demo corpus and return its findings."""
        return _summary(run_demo())

    @mcp.tool(name="nginxvet_rules")
    def nginxvet_rules() -> str:
        """Return the full rulebook as JSON."""
        return json.dumps([item.__dict__ for item in sorted(RULES_BY_ID.values(), key=lambda i: i.id)], indent=2)

    @mcp.tool(name="nginxvet_explain")
    def nginxvet_explain(rule_id: str) -> str:
        """Explain one rule by id."""
        item = RULES_BY_ID.get(rule_id.upper())
        if item is None:
            return json.dumps({"error": f"unknown rule {rule_id!r}"})
        return json.dumps(item.__dict__, indent=2)

    @mcp.tool(name="nginxvet_parse")
    def nginxvet_parse(path: str) -> str:
        """Parse one nginx config file into blocks and directives with byte offsets."""
        from .model import walk

        config = read_config(path)
        payload = {
            "source": config.source,
            "nodes": [node.to_dict() for node in walk(config.roots)],
            "warnings": [{"line": line, "offset": offset, "raw": raw} for line, offset, raw in config.warnings],
        }
        return json.dumps(payload, indent=2)

    return mcp


def main() -> None:
    mcp = build_server()
    mcp.run()


if __name__ == "__main__":
    main()

"""Effective-configuration resolution, centred on ``add_header`` inheritance.

The single most surprising rule in nginx is this: ``add_header`` is **not**
inherited.  nginx inherits directives from the previous level *only if the
current level defines none of the same directive*.  So one innocuous
``add_header X-Debug on;`` inside a location silently drops every
``Strict-Transport-Security``, ``Content-Security-Policy`` and
``X-Frame-Options`` declared at server level.  Single-pass linters never see
it because each line looks correct on its own.

This module computes the headers (and proxy settings) that actually apply to
a server/location, and powers both the ``effective`` command and rules NGV201
/ NGV202 / NGV302.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from .model import Block, ConfigFile, Directive, all_blocks, ancestors

# Headers nginxvet treats as security-relevant when auditing presence.
HSTS = "strict-transport-security"
CSP = "content-security-policy"
FRAME = "x-frame-options"
NOSNIFF = "x-content-type-options"
REFERRER = "referrer-policy"
PERMISSIONS = "permissions-policy"
SECURITY_HEADERS = (HSTS, CSP, FRAME, NOSNIFF, REFERRER, PERMISSIONS)
CORE_SECURITY_HEADERS = (HSTS, CSP, FRAME)


@dataclass
class Header:
    name: str
    value: str
    always: bool
    node: Directive

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "always": self.always,
            "file": self.node.file,
            "line": self.node.line,
            "offset": self.node.offset,
            "saw": self.node.saw,
        }


@dataclass
class EffectiveContext:
    """What actually applies to a host/location, with provenance."""

    host: str = ""
    path: str = ""
    server: Block | None = None
    location: Block | None = None
    headers: list[Header] = field(default_factory=list)
    header_level: str = ""  # where the winning add_header set came from
    lost_headers: list[Header] = field(default_factory=list)  # shadowed by the trap
    proxy_pass: str = ""
    proxy_set_headers: list[str] = field(default_factory=list)
    listening: list[str] = field(default_factory=list)
    ssl: bool = False

    @property
    def header_names(self) -> list[str]:
        return [item.name for item in self.headers]

    @property
    def missing_core(self) -> list[str]:
        present = set(self.header_names)
        return [name for name in CORE_SECURITY_HEADERS if name not in present]

    @property
    def header_trap(self) -> bool:
        return bool(self.lost_headers)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "path": self.path,
            "server": _block_ref(self.server),
            "location": _block_ref(self.location),
            "headers": [item.to_dict() for item in self.headers],
            "header_level": self.header_level,
            "lost_headers": [item.to_dict() for item in self.lost_headers],
            "header_trap": self.header_trap,
            "missing_core_headers": self.missing_core,
            "proxy_pass": self.proxy_pass,
            "proxy_set_headers": self.proxy_set_headers,
            "listening": self.listening,
            "ssl": self.ssl,
        }


def _block_ref(block: Block | None) -> dict | None:
    if block is None:
        return None
    return {
        "kind": block.key,
        "args": block.args,
        "server_names": block.server_names,
        "file": block.file,
        "line": block.line,
        "offset": block.offset,
        "saw": block.saw,
    }


def _level_name(block: Block) -> str:
    if block.key == "server":
        return "server"
    if block.key == "location":
        return f"location {block.location_path}"
    if block.key == "http":
        return "http"
    return block.key


def add_headers_at(block: Block) -> list[Header]:
    """``add_header`` directives written directly in this block (not below)."""
    out: list[Header] = []
    for node in block.body:
        if not isinstance(node, Directive) or node.key != "add_header" or not node.args:
            continue
        name = node.args[0].lower()
        value = node.args[1] if len(node.args) > 1 else ""
        always = "always" in [arg.lower() for arg in node.args[2:]]
        out.append(Header(name=name, value=value, always=always, node=node))
    return out


def effective_headers(block: Block | None) -> tuple[list[Header], str]:
    """Walk up from *block* and stop at the nearest level defining add_header."""
    chain: list[Block] = []
    current = block
    while current is not None:
        chain.append(current)
        parent = current.parent
        current = parent if isinstance(parent, Block) else None
    for level in chain:
        found = add_headers_at(level)
        if found:
            return found, _level_name(level)
    return [], ""


def header_trap_at(location: Block, server: Block | None) -> list[Header]:
    """Server-level headers that a location's own ``add_header`` wipes out.

    Returns the shadowed server headers.  An empty list means either there is
    no server-level header to lose or the location inherits them normally.
    """
    if location.key != "location" or not add_headers_at(location):
        return []
    scope = server
    if scope is None:
        scope = nearest_block(location, "server")
    if scope is None:
        return []
    server_headers, _level = effective_headers(scope)
    own_names = {item.name for item in add_headers_at(location)}
    return [item for item in server_headers if item.name not in own_names]


def nearest_block(node: Block | Directive, key: str) -> Block | None:
    for ancestor in ancestors(node):
        if isinstance(ancestor, Block) and ancestor.key == key:
            return ancestor
    return None


def _span_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern == "_" or pattern == "*":
        return True
    if pattern.startswith("~"):
        try:
            return re.search(pattern[1:], host) is not None
        except re.error:
            return False
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return fnmatch.fnmatchcase(host, pattern)


def find_server(configs: list[ConfigFile], host: str = "") -> Block | None:
    """Pick the server block nginx would use for *host*."""
    servers = [block for block in all_blocks(configs, "server")]
    if not servers:
        return None
    if host:
        for server in servers:
            for name in server.server_names:
                if _span_matches(name, host) and not name.startswith("*"):
                    return server
        for server in servers:
            for name in server.server_names:
                if name.startswith("*.") and _span_matches(name, host):
                    return server
    for server in servers:
        if server.is_default_server:
            return server
    return servers[0]


def find_location(server: Block | None, path: str = "") -> Block | None:
    """Apply nginx's location selection: exact, longest prefix, then regex."""
    if server is None or not path:
        return None
    locations = server.blocks("location")
    for location in locations:
        if location.location_modifier == "=" and location.location_path == path:
            return location
    if path.startswith("@"):
        for location in locations:
            if location.location_modifier == "@" and location.location_path == path:
                return location
        return None
    prefix: Block | None = None
    for location in locations:
        modifier = location.location_modifier
        if modifier in ("~", "~*", "@", "="):
            continue
        candidate = location.location_path or "/"
        if path.startswith(candidate) and (prefix is None or len(candidate) > len(prefix.location_path)):
            prefix = location
    for location in locations:
        modifier = location.location_modifier
        if modifier not in ("~", "~*"):
            continue
        flags = re.IGNORECASE if modifier == "~*" else 0
        try:
            if re.search(location.location_path, path, flags):
                return location
        except re.error:
            continue
    return prefix


def _direct_values(block: Block, key: str) -> list[str]:
    return [
        node.args[0] if node.args else ""
        for node in block.body
        if isinstance(node, Directive) and node.key == key and node.args
    ]


def effective_for(configs: list[ConfigFile], host: str = "", path: str = "") -> EffectiveContext:
    """Compute the effective context for a host and optional location path."""
    server = find_server(configs, host)
    location = find_location(server, path)
    result = EffectiveContext(host=host, path=path, server=server, location=location)
    scope: Block | None = location or server
    if server is not None:
        result.listening = server.listen_ports
        result.ssl = bool(server.is_ssl)
    if scope is not None:
        result.headers, result.header_level = effective_headers(scope)
        if location is not None:
            result.lost_headers = header_trap_at(location, server)
        result.proxy_pass = next(iter(_direct_values(scope, "proxy_pass")), "")
        result.proxy_set_headers = _direct_values(scope, "proxy_set_header")
    return result

"""Object model for nginx configuration analysis.

Every node keeps its source path, line, **byte** offset and raw text.  The
evidence-first design is the point: a finding that cannot point at the exact
directive an operator must edit is only an opinion.

The tree mirrors nginx's own structure (``http`` / ``server`` / ``location`` /
``if`` / ``upstream`` ...).  Includes are expanded by grafting the included
tree into the body at the include position, so a directive from an include
file still carries *its own* path — which is what the cross-file rules need.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}


def collapse(raw: str) -> str:
    """Collapse whitespace so a one-line snippet stays readable."""
    return " ".join(raw.split())[:200]


@dataclass
class Node:
    """Common base for directives and blocks."""

    name: str  # first token, exactly as written
    key: str  # lowercased name, for matching
    args: list[str]
    line: int
    offset: int  # byte offset of the statement in its source file
    length: int  # byte length of the raw statement
    raw: str
    file: str
    parent: Block | None = None
    seq: int = 0  # global traversal order used by "later wins" rules

    @property
    def saw(self) -> str:
        return collapse(self.raw)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "args": self.args,
            "file": self.file,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "length": self.length,
            "saw": self.saw,
        }


@dataclass
class Directive(Node):
    """A single ``name args...;`` statement."""


@dataclass
class Block(Node):
    """A ``name args... { ... }`` block."""

    body: list[Node] = field(default_factory=list)
    closed: bool = True

    def directives(self, key: str | None = None) -> list[Directive]:
        out: list[Directive] = []
        for node in walk(self.body):
            if isinstance(node, Directive) and (key is None or node.key == key):
                out.append(node)
        return out

    def blocks(self, key: str | None = None) -> list[Block]:
        out: list[Block] = []
        for node in walk(self.body):
            if isinstance(node, Block) and (key is None or node.key == key):
                out.append(node)
        return out

    @property
    def location_modifier(self) -> str:
        """``''`` for prefix locations, otherwise ``=``, ``~``, ``~*`` or ``@``."""
        if self.key != "location" or not self.args:
            return ""
        first = self.args[0]
        if first in ("=", "~", "~*"):
            return first
        if first.startswith("@"):
            return "@"
        return ""

    @property
    def location_path(self) -> str:
        """The URI/pattern/named target of a location."""
        if self.key != "location":
            return ""
        if not self.args:
            return ""
        first = self.args[0]
        if first.startswith("@"):
            return first
        if self.location_modifier:
            return self.args[1] if len(self.args) > 1 else ""
        return first

    @property
    def server_names(self) -> list[str]:
        return list(self.directives("server_name")[0].args) if self.directives("server_name") else []

    @property
    def listen_ports(self) -> list[str]:
        out: list[str] = []
        for directive in self.directives("listen"):
            if directive.args:
                out.append(directive.args[0])
        return out

    @property
    def is_default_server(self) -> bool:
        return any("default_server" in directive.args for directive in self.directives("listen"))

    @property
    def is_ssl(self) -> bool:
        for directive in self.directives("listen"):
            if "ssl" in directive.args:
                return True
        return self.directives("ssl_certificate") or self.directives("ssl_protocols")


@dataclass
class ConfigFile:
    """One parsed (possibly include-expanded) configuration tree."""

    source: str
    roots: list[Node] = field(default_factory=list)
    warnings: list[tuple[int, int, str]] = field(default_factory=list)
    virtual: bool = False  # embedded demo corpus, not a path on disk

    @property
    def nodes(self) -> list[Node]:
        out: list[Node] = []
        for root in self.roots:
            out.append(root)
            out.extend(walk(root.body if isinstance(root, Block) else []))
        return out

    @property
    def directives(self) -> list[Directive]:
        return [node for node in self.nodes if isinstance(node, Directive)]

    @property
    def blocks(self) -> list[Block]:
        return [node for node in self.nodes if isinstance(node, Block)]


@dataclass
class IncludeRecord:
    """What one ``include`` directive expanded to (or failed to expand)."""

    arg: str
    source: str
    line: int
    offset: int
    resolved: list[str] = field(default_factory=list)
    wildcard: bool = False
    missing: bool = False
    duplicate: bool = False

    @property
    def saw(self) -> str:
        return f"include {self.arg};"

    def to_dict(self) -> dict:
        return {
            "arg": self.arg,
            "source": self.source,
            "line": self.line,
            "offset": self.offset,
            "resolved": self.resolved,
            "wildcard": self.wildcard,
            "missing": self.missing,
            "duplicate": self.duplicate,
        }


@dataclass
class Finding:
    """One rule conclusion with the four evidence elements.

    ``path`` / ``line`` / ``offset`` / ``saw`` are the evidence; ``where`` is
    kept as a human-friendly alias of ``path`` used by the renderers.
    """

    rule: str
    severity: str
    message: str
    path: str
    line: int
    offset: int
    length: int
    saw: str
    fix: str
    score: int = 0
    where: str = ""

    def __post_init__(self) -> None:
        if not self.where:
            self.where = self.path

    def sort_key(self) -> tuple[int, str, int]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.rule, self.offset)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "where": self.where,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "length": self.length,
            "saw": self.saw,
            "fix": self.fix,
            "score": self.score,
        }


@dataclass
class Report:
    source: str
    targets: list[ConfigFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = field(default_factory=list)
    includes: list[IncludeRecord] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def should_fail(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        limit = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts,
            "rules_run": self.rules_run,
            "includes": [record.to_dict() for record in self.includes],
        }


def walk(nodes: list[Node]):
    """Depth-first traversal of a body (nodes only, blocks are followed)."""
    for node in nodes:
        yield node
        if isinstance(node, Block):
            yield from walk(node.body)


def ancestors(node: Node) -> list[Node]:
    """Ancestors from the immediate parent up to the root."""
    out: list[Node] = []
    parent = node.parent
    while parent is not None:
        out.append(parent)
        parent = parent.parent
    return out


def nearest(node: Node, key: str) -> Block | None:
    """Nearest enclosing block of the given kind."""
    for ancestor in ancestors(node):
        if isinstance(ancestor, Block) and ancestor.key == key:
            return ancestor
    return None


def all_nodes(configs: list[ConfigFile]) -> list[Node]:
    out: list[Node] = []
    for config in configs:
        out.extend(config.nodes)
    return out


def all_directives(configs: list[ConfigFile], key: str | None = None) -> list[Directive]:
    return [n for n in all_nodes(configs) if isinstance(n, Directive) and (key is None or n.key == key)]


def all_blocks(configs: list[ConfigFile], key: str | None = None) -> list[Block]:
    return [n for n in all_nodes(configs) if isinstance(n, Block) and (key is None or n.key == key)]

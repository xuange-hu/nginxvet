"""A small, dependency-free nginx configuration parser.

It understands the pieces that matter for security auditing:

* blocks (``http``, ``server``, ``location``, ``if``, ``upstream``, ...) and
  their nesting,
* directives ending in ``;``, quoted arguments, comments and escaped chars,
* byte offsets and line numbers for every statement (evidence),
* malformed input that produces warnings instead of an exception.

The parser is intentionally permissive: nginx itself accepts many odd
spellings, and a security tool that crashes on an unfamiliar directive is
worse than one that simply ignores it.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass

from .model import Block, ConfigFile, Directive, IncludeRecord, Node


@dataclass
class Token:
    value: str
    raw: str
    line: int
    offset: int  # byte offset


def _b(ch: str) -> int:
    return len(ch.encode("utf-8"))


def tokenize(text: str) -> list[Token]:
    """Turn config text into tokens, preserving raw text and byte offsets."""
    tokens: list[Token] = []
    index = 0
    line = 1
    byte = 0
    size = len(text)
    while index < size:
        ch = text[index]
        if ch == "\n":
            line += 1
            index += 1
            byte += 1
            continue
        if ch.isspace():
            index += 1
            byte += _b(ch)
            continue
        if ch == "#":
            while index < size and text[index] != "\n":
                byte += _b(text[index])
                index += 1
            continue
        if ch in ";{}":
            tokens.append(Token(ch, ch, line, byte))
            index += 1
            byte += 1
            continue

        start_index = index
        start_line = line
        start_byte = byte
        value_parts: list[str] = []
        if ch in ("'", '"'):
            quote = ch
            index += 1
            byte += 1
            while index < size:
                current = text[index]
                if current == "\\" and index + 1 < size:
                    value_parts.append(text[index + 1])
                    byte += _b(current) + _b(text[index + 1])
                    index += 2
                    continue
                if current == quote:
                    index += 1
                    byte += 1
                    break
                if current == "\n":
                    line += 1
                value_parts.append(current)
                byte += _b(current)
                index += 1
        else:
            while index < size:
                current = text[index]
                if current.isspace() or current in ";{}#":
                    break
                if current == "\\" and index + 1 < size and text[index + 1] in " \t\"'\\;{}#":
                    value_parts.append(text[index + 1])
                    byte += _b(current) + _b(text[index + 1])
                    index += 2
                    continue
                value_parts.append(current)
                byte += _b(current)
                index += 1
        raw = text[start_index:index]
        tokens.append(Token("".join(value_parts), raw, start_line, start_byte))
    return tokens


def _statement_raw(tokens: list[Token], terminator: str) -> str:
    body = " ".join(token.raw for token in tokens)
    if not body:
        return terminator
    if terminator == "{":
        return f"{body} {{"
    return f"{body}{terminator}"


def _parse_body(
    tokens: list[Token],
    position: int,
    parent: Block | None,
    source: str,
    warnings: list[tuple[int, int, str]],
) -> tuple[list[Node], int, bool]:
    body: list[Node] = []
    size = len(tokens)
    while position < size:
        token = tokens[position]
        if token.value == "}":
            return body, position + 1, True

        statement: list[Token] = []
        while position < size and tokens[position].value not in (";", "{", "}"):
            statement.append(tokens[position])
            position += 1

        if position >= size:
            if statement:
                warnings.append((statement[0].line, statement[0].offset, _statement_raw(statement, "")))
            break

        terminator = tokens[position].value
        if not statement:
            position += 1
            if terminator == "}":
                return body, position, True
            warnings.append((token.line, token.offset, terminator))
            continue

        first = statement[0]
        name = first.value
        key = name.lower()
        args = [item.value for item in statement[1:]]
        raw = _statement_raw(statement, terminator)

        if terminator == "{":
            block = Block(
                name=name,
                key=key,
                args=args,
                line=first.line,
                offset=first.offset,
                length=len(raw.encode("utf-8")),
                raw=raw,
                file=source,
                parent=parent,
            )
            children, position, closed = _parse_body(tokens, position + 1, block, source, warnings)
            block.body = children
            block.closed = closed
            if not closed:
                warnings.append((block.line, block.offset, raw))
            body.append(block)
            continue

        # ';' — a plain directive.
        body.append(
            Directive(
                name=name,
                key=key,
                args=args,
                line=first.line,
                offset=first.offset,
                length=len(raw.encode("utf-8")),
                raw=raw,
                file=source,
                parent=parent,
            )
        )
        position += 1
    return body, position, False


def parse(text: str, source: str = "") -> ConfigFile:
    """Parse one file's text into a tree plus malformed-statement warnings."""
    warnings: list[tuple[int, int, str]] = []
    tokens = tokenize(text)
    body, _position, closed = _parse_body(tokens, 0, None, source, warnings)
    if not closed and any(token.value == "{" for token in tokens):
        warnings.append((1, 0, "unterminated block"))
    return ConfigFile(source=source, roots=body, warnings=warnings)


def filesystem_resolver(base_dirs: list[str] | None = None):
    """Build an include resolver that reads real files (relative to the includer)."""

    def resolve(arg: str, including_file: str) -> list[tuple[str, str]]:
        pattern = arg.replace("\\", "/")
        roots = list(base_dirs or [])
        directory = os.path.dirname(including_file.replace("\\", "/"))
        if directory and directory not in roots:
            roots.insert(0, directory)
        found: list[str] = []
        for root in roots:
            candidate = pattern if os.path.isabs(pattern) else os.path.join(root, pattern)
            found.extend(sorted(glob.glob(candidate)))
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for path in found:
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized in seen or not os.path.isfile(path):
                continue
            seen.add(normalized)
            with open(path, encoding="utf-8", errors="replace") as handle:
                out.append((path, handle.read()))
        return out

    return resolve


def embedded_resolver(files: dict[str, str]):
    """Build an include resolver over an in-memory corpus (used by ``demo``)."""
    import fnmatch

    def resolve(arg: str, _including_file: str) -> list[tuple[str, str]]:
        pattern = arg.replace("\\", "/").lstrip("/")
        out: list[tuple[str, str]] = []
        for path in sorted(files):
            normalized = path.lstrip("/")
            if fnmatch.fnmatch(normalized, pattern) or normalized.endswith("/" + pattern):
                out.append((path, files[path]))
        return out

    return resolve


def _assign_seq(configs: list[ConfigFile]) -> None:
    sequence = 0
    for config in configs:
        for node in config.nodes:
            node.seq = sequence
            sequence += 1


def expand_includes(
    configs: list[ConfigFile],
    resolver,
) -> tuple[list[ConfigFile], list[IncludeRecord]]:
    """Graft included trees into their parent bodies, returning records.

    The original ``include`` directive is replaced in-place by the included
    file's root nodes.  Those nodes keep the included file's path, which is
    what makes NGV301/NGV302/NGV306 possible.  A depth guard stops cycles.
    """
    records: list[IncludeRecord] = []
    seen_paths: set[str] = set()
    for config in configs:
        seen_paths.add(os.path.normcase(os.path.abspath(config.source)) if not config.virtual else config.source)

    def visit(body: list[Node], depth: int) -> None:
        if depth > 16:
            return
        index = 0
        while index < len(body):
            node = body[index]
            if isinstance(node, Block):
                visit(node.body, depth + 1)
                index += 1
                continue
            if node.key != "include" or not node.args:
                index += 1
                continue
            replacement: list[Node] = []
            for pattern in node.args:
                resolved = resolver(pattern, node.file)
                wildcard = any(char in pattern for char in "*?[")
                record = IncludeRecord(
                    arg=pattern,
                    source=node.file,
                    line=node.line,
                    offset=node.offset,
                    resolved=[path for path, _text in resolved],
                    wildcard=wildcard,
                    missing=not resolved,
                )
                for path, text in resolved:
                    key = path if path.startswith("<") else os.path.normcase(os.path.abspath(path))
                    if key in seen_paths:
                        record.duplicate = True
                        continue
                    seen_paths.add(key)
                    child = parse(text, path)
                    # Nested includes inside an included file resolve against
                    # that file's own path (carried by each directive).
                    visit(child.roots, depth + 1)
                    for root in child.roots:
                        root.parent = node.parent
                    replacement.extend(child.roots)
                records.append(record)
            if replacement:
                body[index : index + 1] = replacement
                index += len(replacement)
            else:
                index += 1

    for config in configs:
        visit(config.roots, 0)
    _assign_seq(configs)
    return configs, records


def parse_sources(sources: list[str], resolver=None) -> tuple[list[ConfigFile], list[IncludeRecord]]:
    """Read and parse real files, then expand includes."""
    configs: list[ConfigFile] = []
    for source in sources:
        with open(source, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        configs.append(parse(text, source))
    resolver = resolver or filesystem_resolver()
    return expand_includes(configs, resolver)

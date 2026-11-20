"""Collect nginx config files and produce a Report via the three-pass engine."""

from __future__ import annotations

import os

from .model import ConfigFile, Report
from .parser import expand_includes, filesystem_resolver, parse
from .rules import REGISTRY, evaluate

MAX_FILE_BYTES = 5 * 1024 * 1024
NAME_SUFFIXES = (".conf",)


def collect(paths: list[str] | str) -> tuple[list[str], list[str]]:
    """Expand files and directories into a deduplicated, sorted file list."""
    if isinstance(paths, str):
        paths = [paths]
    found: list[str] = []
    missing: list[str] = []
    for path in paths:
        if os.path.isfile(path):
            found.append(path)
        elif os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(directory for directory in dirs if not directory.startswith("."))
                for name in sorted(names):
                    if name.endswith(NAME_SUFFIXES):
                        found.append(os.path.join(root, name))
        else:
            missing.append(path)
    seen: set[str] = set()
    out: list[str] = []
    for path in sorted(found):
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out, missing


def read_config(path: str) -> ConfigFile:
    """Parse one file from disk (with a size guard)."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read(MAX_FILE_BYTES)
    return parse(text, path)


def scan_configs(configs: list[ConfigFile], resolver=None) -> Report:
    """Run the full engine over already-parsed trees."""
    resolver = resolver or filesystem_resolver()
    expanded, includes = expand_includes(configs, resolver)
    findings = evaluate(expanded, includes)
    return Report(
        source="embedded corpus" if any(config.virtual for config in configs) else ", ".join(c.source for c in configs),
        targets=expanded,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
        includes=includes,
    )


def scan_paths(paths: list[str] | str) -> Report:
    """Scan real files on disk (includes are resolved relative to the includer)."""
    if isinstance(paths, str):
        paths = [paths]
    files, _missing = collect(list(paths))
    configs = [read_config(path) for path in files]
    return scan_configs(configs)

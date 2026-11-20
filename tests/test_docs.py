"""Docs contract: docs/rules.md is generated and must match the registry."""

import os

from nginxvet.rulebook import full_markdown
from nginxvet.rules import REGISTRY

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_rules_doc_matches_registry():
    path = os.path.join(ROOT, "docs", "rules.md")
    with open(path, encoding="utf-8") as handle:
        on_disk = handle.read()
    assert on_disk == full_markdown()


def test_every_rule_documented():
    text = full_markdown()
    for item in REGISTRY:
        assert f"## {item.id}" in text
        assert item.title in text


def test_generated_doc_mentions_three_passes():
    text = full_markdown()
    assert "`directive`" in text
    assert "`relation`" in text
    assert "`crossfile`" in text


def test_generated_doc_mentions_evidence():
    text = full_markdown()
    assert "byte offset" in text


def test_root_readmes_exist():
    for name in ("README.md", "README_CN.md"):
        with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
            assert "nginxvet" in handle.read()

"""Demo corpus contract: the embedded demo must exercise every rule."""

from nginxvet.demo import DEMO_FILES, demo_targets, run_demo
from nginxvet.rules import REGISTRY


def test_demo_covers_every_rule():
    report = run_demo()
    fired = {finding.rule for finding in report.findings}
    missing = sorted({item.id for item in REGISTRY} - fired)
    assert not missing, f"demo corpus never triggers: {missing}"


def test_demo_coverage_count():
    fired = {finding.rule for finding in run_demo().findings}
    assert len(fired) == len(REGISTRY) == 37


def test_demo_shape():
    report = run_demo()
    assert report.rules_run == len(REGISTRY) == 37
    assert report.counts["critical"] >= 1
    assert report.counts["high"] >= 1
    assert report.counts["medium"] >= 1
    assert report.counts["note"] >= 1


def test_demo_summary_counts_add_up():
    report = run_demo()
    assert sum(report.counts.values()) == len(report.findings)


def test_demo_is_deterministic():
    first = run_demo()
    second = run_demo()
    assert [finding.to_dict() for finding in first.findings] == [finding.to_dict() for finding in second.findings]


def test_demo_has_virtual_files():
    assert len(DEMO_FILES) >= 4
    assert any(name.startswith("conf.d/") for name in DEMO_FILES)


def test_demo_targets_are_independent():
    first = demo_targets()
    second = demo_targets()
    assert len(first) == len(second) == 1
    assert first[0].nodes[0].seq == second[0].nodes[0].seq

"""Fresh-clone contract: a bare checkout must collect without PYTHONPATH tricks."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_collect_without_pythonpath(tmp_path):
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", os.path.join(ROOT, "tests"), "--collect-only", "-q", "-o", "addopts="],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tests collected" in result.stdout or "test" in result.stdout


def test_conftest_injects_src():
    conftest = os.path.join(ROOT, "conftest.py")
    with open(conftest, encoding="utf-8") as handle:
        text = handle.read()
    assert "sys.path.insert" in text
    assert '"src"' in text


def test_core_import_has_no_third_party_modules():
    script = (
        "import sys, json; before=set(sys.modules); import nginxvet, nginxvet.cli, nginxvet.rules; "
        "third=[m for m in set(sys.modules)-before if m in ('yaml','click','rich','mcp','requests')]; "
        "print(json.dumps(third)); assert not third, third"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stdout + result.stderr

"""Packaging contract: zero runtime deps, lazy mcp, importable console scripts."""

import ast
import importlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

THIRD_PARTY = {"mcp", "yaml", "click", "rich", "requests", "pytest"}


def _pyproject() -> str:
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        return handle.read()


def _module_source(name: str) -> str:
    path = os.path.join(ROOT, "src", "nginxvet", name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def test_version_matches_pyproject():
    import nginxvet

    match = re.search(r'(?m)^version = "([^"]+)"', _pyproject())
    assert match and match.group(1) == nginxvet.__version__


def test_console_scripts_resolve():
    for module_name, attr in (("cli", "main"), ("mcp_server", "main")):
        module = importlib.import_module(f"nginxvet.{module_name}")
        assert callable(getattr(module, attr))


def test_console_script_targets_declared():
    assert 'nginxvet = "nginxvet.cli:main"' in _pyproject()
    assert 'nginxvet-mcp = "nginxvet.mcp_server:main"' in _pyproject()


def test_base_dependencies_are_empty():
    assert re.search(r"(?m)^dependencies = \[\]", _pyproject())


def test_mcp_extra_pinned_below_2():
    assert 'mcp = ["mcp>=1.2,<2"]' in _pyproject()


def test_requires_python_310():
    assert 'requires-python = ">=3.10"' in _pyproject()


def _module_scope_imports(tree: ast.AST) -> list[list[str]]:
    out: list[list[str]] = []
    stack = list(getattr(tree, "body", []))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            out.append([alias.name.split(".")[0] for alias in node.names])
        elif isinstance(node, ast.ImportFrom):
            out.append([(node.module or "").split(".")[0]])
        stack.extend(getattr(node, "body", []))
        for field in ("orelse", "finalbody", "handlers"):
            for child in getattr(node, field, []) or []:
                stack.extend(child.body if isinstance(child, ast.ExceptHandler) else [child])
    return out


def test_entrypoint_modules_do_not_import_third_party_at_module_scope():
    for module_name in ("cli.py", "mcp_server.py"):
        tree = ast.parse(_module_source(module_name))
        for names in _module_scope_imports(tree):
            offenders = [name for name in names if name in THIRD_PARTY]
            assert not offenders, f"{module_name} imports {offenders} at module scope"


def test_lazy_mcp_import_is_inside_function():
    source = _module_source("mcp_server.py")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            if "mcp" in names:
                parent_is_function = any(
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) and node in list(ast.walk(parent))
                    for parent in ast.walk(tree)
                )
                assert parent_is_function, "mcp must only be imported inside a function"


def test_no_bare_tomllib_usage():
    for name in os.listdir(os.path.join(ROOT, "src", "nginxvet")):
        if name.endswith(".py"):
            assert "import tomllib" not in _module_source(name)


def test_package_is_typed():
    assert os.path.exists(os.path.join(ROOT, "src", "nginxvet", "py.typed"))

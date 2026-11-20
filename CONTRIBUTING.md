# Contributing

Thanks for helping improve nginxvet.

## Development setup

```console
python -m pip install -e .
python -m pip install pytest ruff "mcp>=1.2,<2"
PYTHONPATH=src python -m pytest -q
python -m ruff check .
```

Use a Python 3.10+ interpreter. The core package must stay free of third-party
runtime dependencies; `mcp` is an optional extra and must be imported lazily
inside `build_server()`.

## Adding a rule

1. Add a `RuleInfo` to `REGISTRY` in `src/nginxvet/rules.py` with a unique `NGV`
   id in the right pass range (1xx / 2xx / 3xx).
2. Implement the check in the matching pass function. Anchor the finding on a
   real directive so the four evidence elements are always present.
3. Add a triggering sample to `tests/test_rules.py`, `test_relations.py` or
   `test_crossfile.py`, plus a negative sample.
4. Extend `src/nginxvet/demo.py` so the corpus fires the new rule —
   `tests/test_demo.py` asserts full coverage.
5. Regenerate `docs/rules.md`:

   ```console
   PYTHONPATH=src python -c "from nginxvet.rulebook import full_markdown; from pathlib import Path; Path('docs/rules.md').write_text(full_markdown(), encoding='utf-8')"
   ```

6. Update the `tests-` badge in **both** README.md and README_CN.md to the new
   `pytest --collect-only -q -o addopts=` number.

## Style

- `ruff` with the repo's fixed `select` list is authoritative.
- Every `open()` call must pass `encoding="utf-8"`.
- Avoid `tomllib`: the package supports Python 3.10.
- Keep prose in rule metadata factual; it is rendered verbatim in the docs.

## Commits

Please write a descriptive commit message and keep the test suite green.

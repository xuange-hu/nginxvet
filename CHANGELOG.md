# Changelog

All notable changes to nginxvet are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-11-20

### Added

- Zero-dependency nginx configuration parser: blocks, directives, quoted
  arguments, byte offsets, line numbers and malformed-line warnings.
- `include` expansion with glob, duplicate and missing-file detection.
- Three-pass engine with 37 `NGV` rules:
  - `directive` (NGV101–NGV121),
  - `relation` (NGV201–NGV208, including the flagship add_header trap),
  - `crossfile` (NGV301–NGV308).
- Effective-header resolution modelling nginx's `add_header` inheritance.
- CLI: `scan`, `effective`, `rules`, `demo`, `explain`, `--fail-on`, `--format`.
- Evidence-first findings (path / line / byte offset / raw snippet) and
  text, JSON and SARIF 2.1.0 renderers.
- Six lazily-imported MCP tools, including `nginxvet_effective`.
- Embedded demo corpus that fires all 37 rules.
- Generated rule documentation and a contract test that keeps it in sync.
- CI: Python 3.10–3.13 matrix, fresh-clone, ruff, badge check, MCP manifest.
- PyPI Trusted Publishing workflow with a preflight skip when unregistered.

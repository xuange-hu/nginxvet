# Security Policy

## Supported versions

Only the latest released version receives fixes.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Email the
maintainer instead with:

- a description of the issue and its impact,
- a minimal nginx config that reproduces it,
- the nginxvet version and Python version used.

You should receive an acknowledgement within a few days. Once a fix is
available, it will be released and credited in the changelog.

## Scope

nginxvet is a static analyser. It reads configuration files and never executes
nginx. It is designed to be safe on untrusted config files: the parser is
permissive, has a depth guard on includes and a file-size limit, and should
report malformed input rather than crash. If you find an input that makes it
crash or hang, that is a security-relevant bug.

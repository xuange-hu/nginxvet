# Promotion drafts (awaiting the author's sign-off — automation never posts)

Four channel drafts for nginxvet. Do not post without explicit confirmation.

---

## Show HN

**Title:** Show HN: nginxvet – the nginx security header bug a line-by-line linter cannot see

**Body:**

nginx has a rule that surprises almost everyone: `add_header` is never merged.
The moment a location defines any `add_header` of its own, every `add_header`
from the server level is discarded inside that location. One debug header can
silently remove HSTS, CSP and X-Frame-Options from an entire URL tree — and
every single line still looks correct in review.

nginxvet is a zero-dependency Python auditor that expands `include` files,
models that inheritance rule, and runs three passes: single directives,
server/location relationships, and cross-file effects. 37 rules, all
evidence-first (path, line, byte offset, raw snippet), SARIF 2.1.0 and
`--fail-on` for CI.

The command I wanted when I wrote it: `nginxvet effective example.com
/etc/nginx/nginx.conf --location /api/user` — it answers "what security headers
actually apply here, and which ones were dropped?"

`pip install git+https://github.com/xuange-hu/nginxvet` · 235 tests ·
`nginxvet demo` fires all 37 rules.

Curious how many production configs are quietly missing their security headers
because of one `add_header` line.

---

## Reddit r/nginx / r/netsec

**Title:** One `add_header` line in a location silently deletes all your server-level security headers

**Body:**

A nginx config can pass `nginx -t`, look perfect in a diff, and still send no
HSTS on half your URLs. The reason: `add_header` is inherited only when the
current level defines none. Add `add_header X-Debug 1;` to a location and the
server-level Strict-Transport-Security, Content-Security-Policy and
X-Frame-Options are gone for that whole location.

gixy is great, but it analyses directives one at a time, so this one is
structurally invisible. I wrote nginxvet (MIT, zero dependencies, Python 3.10+)
to do three passes instead:

1. directive — the risky values themselves (server_tokens, autoindex, weak
   TLS, access_log off, rewrite in if, ...),
2. relation — server/location inheritance: the add_header trap, the
   proxy_set_header equivalent, missing named locations, if-return overrides,
   upstream keepalive,
3. crossfile — what `include` did: hardening reverted by a drop-in, an included
   location that triggers the trap, wildcard ordering, inconsistent TLS on one
   listen address, duplicate/missing includes.

Every finding carries a path, line, byte offset and raw snippet. SARIF output,
`--fail-on high` for CI, and six MCP tools so an agent can ask the `effective`
question directly.

https://github.com/xuange-hu/nginxvet

---

## X (thread)

1/ The most underrated nginx misconfiguration: one `add_header` in a location
   silently drops every server-level security header. HSTS, CSP, XFO — gone.
   Every line looks correct. `nginx -t` says fine.

2/ So I built nginxvet: zero-dependency, three passes (directive / relation /
   cross-file), expands includes and models nginx's real inheritance. The
   flagship rule NGV201 is exactly this trap.

3/ `nginxvet effective example.com nginx.conf --location /api/user` tells you
   what headers actually apply, what's missing, and which ones were dropped.
   37 rules, SARIF, `--fail-on`, 6 MCP tools, 235 tests. MIT:
   https://github.com/xuange-hu/nginxvet

---

## Awesome-list blurb

> [nginxvet](https://github.com/xuange-hu/nginxvet) — Zero-dependency,
> evidence-first nginx config auditor with three passes (directive,
> server/location relation, cross-file), the add_header inheritance trap,
> an `effective` command, SARIF output and an MCP server. (Python, MIT)

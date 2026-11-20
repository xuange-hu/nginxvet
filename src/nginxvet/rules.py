"""The rule engine: 37 rules over three passes.

``directive`` (NGV1xx) reads a single statement, ``relation`` (NGV2xx) reads
the relationship between server and location blocks, ``crossfile`` (NGV3xx)
reads what include expansion did to the effective tree.  The flagship is
NGV201: a location with any ``add_header`` drops every server-level security
header.  NGV202 is the proxy equivalent and NGV302 is its cross-file form.

Every conclusion is anchored on a real directive so the evidence four-tuple
(path / line / byte offset / raw snippet) is always present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Block, ConfigFile, Directive, Finding, IncludeRecord, all_blocks, all_directives
from .resolve import (
    CORE_SECURITY_HEADERS,
    SECURITY_HEADERS,
    add_headers_at,
    effective_headers,
    header_trap_at,
    nearest_block,
)


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    severity: str
    stage: str  # directive | relation | crossfile
    score: int
    why: str
    fix: str


REGISTRY: list[RuleInfo] = [
    RuleInfo("NGV101", "server_tokens exposes the nginx version", "medium", "directive", 5,
             "`server_tokens on` adds the exact nginx version to error pages and the Server response header. "
             "Attackers use that version to pick a known exploit instead of probing blindly.",
             "Set `server_tokens off;` in the http or server context."),
    RuleInfo("NGV102", "Directory listing enabled", "medium", "directive", 6,
             "`autoindex on` turns any directory without an index file into a browsable listing of every file. "
             "Backups, dotfiles and forgotten uploads become public.",
             "Set `autoindex off;` and rely on explicit `index` directives."),
    RuleInfo("NGV103", "Obsolete TLS protocols enabled", "high", "directive", 9,
             "`ssl_protocols` that includes SSLv3, TLSv1 or TLSv1.1 keeps protocols with known downgrade and "
             "cipher weaknesses alive. Modern clients negotiate TLSv1.2/1.3 anyway, so the only real effect is "
             "widening the attack surface.",
             "Use `ssl_protocols TLSv1.2 TLSv1.3;`."),
    RuleInfo("NGV104", "Weak cipher suites offered", "high", "directive", 9,
             "Cipher names containing NULL, EXPORT, RC4, 3DES, DES, MD5, SEED or IDEA are either unauthenticated, "
             "export-grade or trivially distinguishable. Advertising them invites downgrade attacks.",
             "Use a modern cipher string such as `ECDHE+AESGCM:ECDHE+CHACHA20` and disable legacy suites."),
    RuleInfo("NGV105", "Security header missing `always`", "medium", "directive", 6,
             "By default nginx adds headers only for 2xx/3xx responses. Without the `always` parameter a security "
             "header disappears on 4xx/5xx error pages — exactly the pages an attacker can often trigger.",
             "Append `always` to every `add_header` that carries a security header."),
    RuleInfo("NGV106", "HTTP Strict-Transport-Security not set", "medium", "directive", 6,
             "Without HSTS a browser will happily downgrade an HTTPS site to plain HTTP on the first request, "
             "which is enough for an on-path attacker to steal cookies. HSTS must be present at server level so "
             "it survives into every location.",
             "Add `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;` at server level."),
    RuleInfo("NGV107", "Content-Security-Policy not set", "medium", "directive", 6,
             "No CSP means the browser will execute any script the page includes, including injected script from "
             "an XSS flaw. CSP is the last line of defence when output escaping fails.",
             "Add a restrictive `Content-Security-Policy` header at server level."),
    RuleInfo("NGV108", "X-Frame-Options not set", "medium", "directive", 5,
             "Without X-Frame-Options (or CSP frame-ancestors) the site can be embedded in an attacker's iframe and "
             "clicked through — classic clickjacking.",
             "Add `add_header X-Frame-Options SAMEORIGIN always;` at server level."),
    RuleInfo("NGV109", "proxy_pass does not forward the Host header", "medium", "directive", 6,
             "nginx sets `Host` to `$proxy_host` by default, not to the client's Host. Applications that generate "
             "absolute URLs or pick a virtual host from Host then behave incorrectly or leak the internal name.",
             "Add `proxy_set_header Host $host;` in the same scope as `proxy_pass`."),
    RuleInfo("NGV110", "proxy_pass does not forward X-Forwarded-For", "low", "directive", 3,
             "Without X-Forwarded-For the upstream sees only the proxy's IP, so access logs and IP-based rate limits "
             "lose the real client. Conversely, blindly trusting a client-supplied value is also wrong — set it "
             "explicitly from `$remote_addr`.",
             "Add `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`."),
    RuleInfo("NGV111", "client_max_body_size allows very large uploads", "medium", "directive", 5,
             "A multi-hundred-megabyte request body lets a single slow client pin memory and connections. Request "
             "bodies are buffered before the application sees them, so the cost is paid by nginx itself.",
             "Lower `client_max_body_size` to the smallest value the application needs (e.g. 10m)."),
    RuleInfo("NGV112", "rewrite with $uri can loop", "medium", "directive", 6,
             "A `rewrite` that feeds `$uri` back into the replacement and ends in `last`/`break` can re-enter the "
             "same location repeatedly. nginx only bails out after ten internal redirects, meanwhile burning CPU.",
             "Rewrite on a captured variable, not on `$uri`, or guard with a condition on the rewritten path."),
    RuleInfo("NGV113", "rewrite inside an if block", "high", "directive", 8,
             "`if` in location context is evaluated in a separate rewrite phase; combined with `rewrite` it is the "
             "canonical 'if is evil' trap — directives after it may be skipped or run twice.",
             "Move the rewrite to a named location selected with `error_page` / `try_files` instead of `if`."),
    RuleInfo("NGV114", "resolver without valid/expire caching bounds", "medium", "directive", 5,
             "A `resolver` without `valid=` and `expire=` keeps DNS answers far longer than their TTL and can let a "
             "poisoned or stale answer persist. Bound both the positive and negative cache lifetime.",
             "Use `resolver ... valid=30s expire=10s;`."),
    RuleInfo("NGV115", "TLS session tickets enabled without rotation", "low", "directive", 3,
             "Session tickets are encrypted with a key that nginx holds for the lifetime of the process by default; "
             "without ticket-key rotation, a stolen key decrypts all captured sessions.",
             "Set `ssl_session_tickets off;` or rotate `ssl_session_ticket_key` regularly."),
    RuleInfo("NGV116", "Plaintext listener without HTTPS redirect", "medium", "directive", 7,
             "A server listening on port 80 that serves content instead of redirecting to HTTPS sends credentials and "
             "cookies over the wire in clear text.",
             "Add `return 301 https://$host$request_uri;` to the port-80 server."),
    RuleInfo("NGV117", "Access log disabled", "low", "directive", 3,
             "`access_log off` removes the only record of who requested what. During an incident there is nothing to "
             "correlate, and compliance baselines require request logging.",
             "Keep access logging on, or send it to a dedicated structured log."),
    RuleInfo("NGV118", "deny all before allow rule", "medium", "directive", 7,
             "nginx evaluates access rules in order and stops at the first match. A `deny all` placed before an "
             "`allow` makes the allow unreachable — the intended client is blocked and the mistake looks like a "
             "firewall problem.",
             "Put all `allow` rules before `deny all;`."),
    RuleInfo("NGV119", "Listener without reuseport", "low", "directive", 2,
             "On high-traffic servers, accepting connections on a single shared socket serialises workers. "
             "`reuseport` gives each worker its own accept queue and removes that bottleneck.",
             "Add `reuseport` to `listen` on busy servers (low priority on small sites)."),
    RuleInfo("NGV120", "gzip enabled on sensitive content", "note", "directive", 1,
             "Compressing authenticated, secret-dependent responses can leak plaintext through compression side "
             "channels (BREACH). It is fine for static public assets, so this is a note, not a verdict.",
             "Disable gzip for endpoints that reflect secrets, or use `gzip off` there."),
    RuleInfo("NGV121", "Server does not prefer its own cipher order", "low", "directive", 3,
             "With `ssl_prefer_server_ciphers off` the client picks the cipher from the mutually supported list, so "
             "a downgraded client can steer the connection to the weakest acceptable suite.",
             "Set `ssl_prefer_server_ciphers on;`."),
    RuleInfo("NGV201", "add_header inheritance trap (security headers dropped in a location)", "critical", "relation", 10,
             "nginx never merges `add_header`: as soon as a location defines any `add_header` of its own, every "
             "`add_header` from the server and http levels is discarded inside that location. A single debug header "
             "therefore silently removes HSTS, CSP and X-Frame-Options from an entire URL tree — something a "
             "line-by-line audit cannot see.",
             "Repeat all security `add_header` directives inside the location, or move the extra header up to server level."),
    RuleInfo("NGV202", "Location proxy_pass drops server-level proxy_set_header", "medium", "relation", 7,
             "`proxy_set_header` follows the same inheritance rule as `add_header`: a location that defines any of "
             "them loses the server-level ones. A location with its own `proxy_pass` then forwards requests without "
             "the correct Host or X-Forwarded-For.",
             "Restate `proxy_set_header Host $host;` and friends inside the location that has `proxy_pass`."),
    RuleInfo("NGV203", "try_files references a missing named location", "medium", "relation", 6,
             "`try_files ... @fallback` sends the request to a named location. If that location does not exist nginx "
             "returns 500 at runtime — a configuration that validates with `nginx -t` but fails on the first miss.",
             "Define `location @fallback { ... }` in the same server, or remove the named fallback."),
    RuleInfo("NGV204", "if-block return overrides the location return", "medium", "relation", 6,
             "A `return` inside an `if` short-circuits the location's own `return`. Two different status codes or "
             "redirect targets fight, and which one wins depends on request properties that are easy to miss.",
             "Use a single `return` with a `map` variable, or split into a named location."),
    RuleInfo("NGV205", "Regex location uses $1 without a capture group", "medium", "relation", 5,
             "A regex location whose pattern has no capture group leaves `$1` empty. Directives that build a path or "
             "an upstream URL from `$1` then operate on the wrong value.",
             "Add a capturing group to the location regex or use a named capture."),
    RuleInfo("NGV206", "proxy_http_version 1.1 with a keepalive-less upstream", "low", "relation", 3,
             "HTTP/1.1 to an upstream without `keepalive` in its `upstream` block opens a new connection for every "
             "request. The upstream's connection table fills up under modest load.",
             "Add `keepalive N;` to the upstream block and `proxy_set_header Connection \"\";`."),
    RuleInfo("NGV207", "Duplicate server_name or default_server", "medium", "relation", 6,
             "Two servers claiming the same `server_name`, or two `default_server` listeners on the same address, "
             "make routing depend on include order. Requests land on a different vhost than the operator expects.",
             "Give every vhost a unique name and mark exactly one default_server per address."),
    RuleInfo("NGV208", "alias combined with try_files", "medium", "relation", 6,
             "`alias` rewrites the URI by replacing the matched location prefix. Combined with `try_files` the joined "
             "path can escape the alias root when the URI contains `..`, a long-standing path-traversal footgun.",
             "Use `root` instead of `alias` where possible, or avoid `try_files` inside an aliased location."),
    RuleInfo("NGV301", "include file reverts server_tokens to on", "high", "crossfile", 8,
             "The main config turns version disclosure off, but a later-loaded include sets `server_tokens on` again. "
             "A reviewer reading only the main file sees a hardened server that actually leaks its version.",
             "Remove the conflicting line in the include; one setting must have one owner."),
    RuleInfo("NGV302", "include location triggers the add_header trap", "high", "crossfile", 9,
             "Security headers are declared in the main config, but an included location defines its own "
             "`add_header`. The include is where the inheritance trap actually fires, so neither file alone tells "
             "the whole story.",
             "Repeat the security headers in the included location or remove its `add_header`."),
    RuleInfo("NGV303", "include path uses a wildcard", "low", "crossfile", 3,
             "Glob includes depend on directory enumeration order and on which files happen to exist. Adding one "
             "file can silently change precedence and therefore which directive wins.",
             "Include files explicitly, in a deterministic order, or use a single manifest file."),
    RuleInfo("NGV304", "Same listen address with inconsistent TLS settings", "medium", "crossfile", 6,
             "Two server blocks share a listen address but advertise different `ssl_protocols` or `ssl_ciphers`. "
             "Which TLS policy a client gets then depends on which vhost nginx picked first.",
             "Move TLS settings to the http level so every server on that address shares one policy."),
    RuleInfo("NGV305", "include file overrides a security header", "medium", "crossfile", 6,
             "An included file redefines a security header already set in the main config. Header inheritance is "
             "replaced, not merged, so the included value silently becomes the effective one.",
             "Delete the duplicate from the include or make the main config the single owner."),
    RuleInfo("NGV306", "Same file included more than once", "low", "crossfile", 3,
             "The same file is included twice, so every directive in it is applied twice. Duplicate `add_header` "
             "values and duplicated upstream entries are the usual result.",
             "Include the file once, at the point where it is needed."),
    RuleInfo("NGV307", "include matches no file", "medium", "crossfile", 5,
             "An `include` that resolves to nothing is silently accepted by nginx. The settings the operator "
             "expected from that file were never loaded at all.",
             "Fix the path, or delete the include so the missing config is not mistaken for a loaded one."),
    RuleInfo("NGV308", "TLS listener without a certificate", "medium", "crossfile", 6,
             "A server block listens with `ssl` (or declares SSL protocols) but has no `ssl_certificate`. nginx "
             "fails to start or falls back to another server's certificate, depending on the rest of the config.",
             "Add `ssl_certificate` and `ssl_certificate_key` to every TLS server block."),
]

RULES_BY_ID: dict[str, RuleInfo] = {item.id: item for item in REGISTRY}
STAGES = ("directive", "relation", "crossfile")

HEADER_TITLES = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _header_title(name: str) -> str:
    return HEADER_TITLES.get(name, name.title())


@dataclass
class Context:
    configs: list[ConfigFile]
    includes: list[IncludeRecord]
    directives: list[Directive] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.directives = all_directives(self.configs)
        self.blocks = all_blocks(self.configs)

    @property
    def servers(self) -> list[Block]:
        return [block for block in self.blocks if block.key == "server"]

    @property
    def locations(self) -> list[Block]:
        return [block for block in self.blocks if block.key == "location"]


def build_context(configs: list[ConfigFile], includes: list[IncludeRecord] | None = None) -> Context:
    return Context(configs=configs, includes=list(includes or []))


def _finding(info: RuleInfo, node: Directive | Block, message: str) -> Finding:
    return Finding(
        rule=info.id,
        severity=info.severity,
        message=message,
        path=node.file,
        line=node.line,
        offset=node.offset,
        length=node.length,
        saw=node.saw,
        fix=info.fix,
        score=info.score,
    )


def _evidence(
    info: RuleInfo,
    path: str,
    line: int,
    offset: int,
    saw: str,
    message: str,
    length: int | None = None,
) -> Finding:
    return Finding(
        rule=info.id,
        severity=info.severity,
        message=message,
        path=path,
        line=line,
        offset=offset,
        length=length if length is not None else len(saw.encode("utf-8")),
        saw=saw,
        fix=info.fix,
        score=info.score,
    )


def _info(rule_id: str) -> RuleInfo:
    return RULES_BY_ID[rule_id]


def _nearest_level(block: Block | None, key: str) -> list[Directive]:
    """Directives of *key* at the nearest level that defines any (nginx inheritance)."""
    current: Block | None = block
    while current is not None:
        found = [node for node in current.body if isinstance(node, Directive) and node.key == key]
        if found:
            return found
        current = current.parent if isinstance(current.parent, Block) else None
    return []


def _direct(block: Block, key: str) -> list[Directive]:
    return [node for node in block.body if isinstance(node, Directive) and node.key == key]


def _is_on(value: str) -> bool:
    return value.lower() in ("on", "1", "true", "yes")


def _size_bytes(value: str) -> int:
    match = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kmg]?)", value, re.IGNORECASE)
    if not match:
        return 0
    number = float(match.group(1))
    factor = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[match.group(2).lower()]
    return int(number * factor)


def _header_name(directive: Directive) -> str:
    return directive.args[0].lower() if directive.args else ""


# ---------------------------------------------------------------------------
# Pass 1: single directives (NGV1xx)
# ---------------------------------------------------------------------------


def pass_directive(context: Context) -> list[Finding]:
    out: list[Finding] = []

    # NGV101 / NGV102
    for rule_id, key in (("NGV101", "server_tokens"), ("NGV102", "autoindex")):
        for directive in (d for d in context.directives if d.key == key and d.args and _is_on(d.args[0])):
            out.append(_finding(_info(rule_id), directive, f"{key} {directive.args[0]} exposes more than it should"))

    # NGV103
    weak_protocols = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
    for directive in (d for d in context.directives if d.key == "ssl_protocols"):
        weak = [arg for arg in directive.args if arg.lower() in weak_protocols]
        if weak:
            out.append(_finding(_info("NGV103"), directive, f"obsolete TLS protocol(s) enabled: {', '.join(weak)}"))

    # NGV104
    weak_tokens = ("null", "export", "rc4", "3des", "des", "md5", "seed", "idea", "anon")
    for directive in (d for d in context.directives if d.key == "ssl_ciphers"):
        lowered = " ".join(directive.args).lower()
        weak = [token for token in weak_tokens if token in lowered]
        if weak:
            out.append(_finding(_info("NGV104"), directive, f"weak cipher material present: {', '.join(weak)}"))

    # NGV105
    for directive in (d for d in context.directives if d.key == "add_header" and len(d.args) >= 2):
        name = _header_name(directive)
        always = any(arg.lower() == "always" for arg in directive.args[2:])
        if name in SECURITY_HEADERS and not always:
            out.append(_finding(_info("NGV105"), directive, f"{name} is not sent on error responses (missing always)"))

    # NGV106 / NGV107 / NGV108 — missing headers at server level
    missing_rules = (("NGV106", "strict-transport-security"), ("NGV107", "content-security-policy"),
                     ("NGV108", "x-frame-options"))
    for server in context.servers:
        present = {item.name for item in effective_headers(server)[0]}
        for rule_id, header in missing_rules:
            if header not in present:
                out.append(_finding(_info(rule_id), server, f"server has no {header} header at server level"))

    # NGV109 / NGV110 — proxy headers
    for directive in (d for d in context.directives if d.key == "proxy_pass"):
        scope = directive.parent
        names = {arg[0].lower() for arg in (node.args for node in _nearest_level(scope, "proxy_set_header")) if arg}
        if "host" not in names:
            out.append(_finding(_info("NGV109"), directive, "proxy_pass does not set the Host header"))
        if "x-forwarded-for" not in names:
            out.append(_finding(_info("NGV110"), directive, "proxy_pass does not set X-Forwarded-For"))

    # NGV111
    for directive in (d for d in context.directives if d.key == "client_max_body_size" and d.args):
        size = _size_bytes(directive.args[0])
        if size > 100 * 1024 * 1024:
            out.append(_finding(_info("NGV111"), directive, f"client_max_body_size {directive.args[0]} exceeds 100 MiB"))

    # NGV112
    for directive in (d for d in context.directives if d.key == "rewrite" and len(d.args) >= 2):
        if any("$uri" in arg.lower() for arg in directive.args) and directive.args[-1].lower() in ("last", "break"):
            out.append(_finding(_info("NGV112"), directive, "rewrite feeds $uri back with last/break and can loop"))

    # NGV113
    for block in [b for b in context.blocks if b.key == "if"]:
        for directive in _direct(block, "rewrite"):
            out.append(_finding(_info("NGV113"), directive, "rewrite inside an if block (if is evil)"))

    # NGV114
    for directive in (d for d in context.directives if d.key == "resolver"):
        tokens = [arg.lower() for arg in directive.args]
        if not any(token.startswith("valid=") for token in tokens) and not any(
            token.startswith("expire=") for token in tokens
        ):
            out.append(_finding(_info("NGV114"), directive, "resolver has no valid=/expire= cache bounds"))

    # NGV115
    for directive in (d for d in context.directives if d.key == "ssl_session_tickets" and d.args and _is_on(d.args[0])):
        out.append(_finding(_info("NGV115"), directive, "TLS session tickets enabled without key rotation"))

    # NGV116
    for server in context.servers:
        port80 = [d for d in _direct(server, "listen") if d.args and d.args[0] in ("80", "0.0.0.0:80", "[::]:80")]
        if not port80:
            continue
        all_directives_in_server = list(server.directives())
        redirects = [
            d
            for d in all_directives_in_server
            if d.key == "return" and any("https" in arg for arg in d.args)
        ]
        rewrites = [
            d for d in all_directives_in_server if d.key == "rewrite" and any("https" in arg for arg in d.args)
        ]
        if not redirects and not rewrites:
            out.append(_finding(_info("NGV116"), port80[0], "port-80 server does not redirect to HTTPS"))

    # NGV117
    for directive in (d for d in context.directives if d.key == "access_log" and d.args and d.args[0].lower() == "off"):
        out.append(_finding(_info("NGV117"), directive, "access_log off removes the request audit trail"))

    # NGV118 — inside blocks and at file scope
    bodies = [block.body for block in context.blocks]
    bodies.extend(config.roots for config in context.configs)
    for body in bodies:
        deny_indexes = [
            index
            for index, node in enumerate(body)
            if isinstance(node, Directive) and node.key == "deny" and node.args and node.args[0] == "all"
        ]
        for index in deny_indexes:
            later_allow = any(
                isinstance(node, Directive) and node.key == "allow"
                for node in body[index + 1 :]
            )
            if later_allow:
                out.append(_finding(_info("NGV118"), body[index], "deny all precedes an allow rule; the allow is dead"))

    # NGV119
    for directive in (d for d in context.directives if d.key == "listen"):
        if "reuseport" not in [arg.lower() for arg in directive.args]:
            out.append(_finding(_info("NGV119"), directive, "listen without reuseport limits accept throughput"))

    # NGV120
    for directive in (d for d in context.directives if d.key == "gzip" and d.args and _is_on(d.args[0])):
        out.append(_finding(_info("NGV120"), directive, "gzip on can expose secrets through compression side channels"))

    # NGV121
    for directive in (
        d for d in context.directives if d.key == "ssl_prefer_server_ciphers" and d.args and not _is_on(d.args[0])
    ):
        out.append(_finding(_info("NGV121"), directive, "client, not server, chooses the cipher suite"))

    return out


# ---------------------------------------------------------------------------
# Pass 2: server/location relations (NGV2xx)
# ---------------------------------------------------------------------------


def pass_relation(context: Context) -> list[Finding]:
    out: list[Finding] = []

    # NGV201 — the flagship add_header inheritance trap
    for location in context.locations:
        own = add_headers_at(location)
        if not own:
            continue
        server = nearest_block(location, "server")
        lost = header_trap_at(location, server)
        if lost:
            names = ", ".join(sorted({_header_title(item.name) for item in lost}))
            out.append(
                _finding(
                    _info("NGV201"),
                    own[0].node,
                    f"location {location.location_path} defines add_header; {len(lost)} server-level security "
                    f"header(s) are dropped here: {names}",
                )
            )

    # NGV202 — proxy_set_header inheritance trap
    for location in context.locations:
        proxies = _direct(location, "proxy_pass")
        if not proxies or _direct(location, "proxy_set_header"):
            continue
        server = nearest_block(location, "server")
        server_headers = _nearest_level(server, "proxy_set_header")
        important = [node for node in server_headers if node.args and node.args[0].lower() == "host"]
        if important:
            out.append(
                _finding(
                    _info("NGV202"),
                    proxies[0],
                    "location proxy_pass inherits no proxy_set_header, so the server-level Host forwarding is lost",
                )
            )

    # NGV203 — try_files @named missing
    for server in context.servers:
        named = {loc.location_path for loc in server.blocks("location") if loc.location_modifier == "@"}
        for directive in server.directives("try_files"):
            if directive.args and directive.args[-1].startswith("@") and directive.args[-1] not in named:
                out.append(
                    _finding(_info("NGV203"), directive, f"try_files targets missing named location {directive.args[-1]}")
                )

    # NGV204 — if return vs location return
    for server in context.servers:
        for location in server.blocks("location"):
            own_return = _direct(location, "return")
            if not own_return:
                continue
            for if_block in location.blocks("if"):
                for directive in _direct(if_block, "return"):
                    out.append(
                        _finding(_info("NGV204"), directive, "return inside if overrides the location's own return")
                    )

    # NGV205 — regex capture without a group
    for location in context.locations:
        if location.location_modifier not in ("~", "~*"):
            continue
        pattern = location.location_path
        if "(" not in pattern:
            for directive in location.directives():
                if any("$1" in arg for arg in directive.args):
                    out.append(
                        _finding(_info("NGV205"), directive, "regex location has no capture group but $1 is used")
                    )
                    break

    # NGV206 — keepalive-less upstream with HTTP/1.1
    upstreams = {block.args[0]: block for block in context.blocks if block.key == "upstream" and block.args}
    for location in context.locations:
        http11 = _direct(location, "proxy_http_version")
        if not any(d.args and d.args[0] == "1.1" for d in http11):
            continue
        for directive in _direct(location, "proxy_pass"):
            match = re.match(r"https?://([^/;\s]+)", directive.args[0] if directive.args else "")
            name = match.group(1) if match else ""
            upstream = upstreams.get(name)
            if upstream is not None and not _direct(upstream, "keepalive"):
                out.append(
                    _finding(_info("NGV206"), http11[0], f"HTTP/1.1 to upstream {name} without keepalive")
                )
                break

    # NGV207 — duplicate server_name / default_server
    by_name: dict[str, list[tuple[Block, Directive]]] = {}
    for server in context.servers:
        for directive in _direct(server, "server_name"):
            for name in directive.args:
                by_name.setdefault(name.lower(), []).append((server, directive))
    for name, entries in by_name.items():
        if len(entries) > 1:
            out.append(_finding(_info("NGV207"), entries[1][1], f"server_name {name} is claimed by multiple servers"))
    default_by_port: dict[str, list[tuple[Block, Directive]]] = {}
    for server in context.servers:
        for directive in _direct(server, "listen"):
            if "default_server" in directive.args:
                port = directive.args[0].split(":")[-1]
                default_by_port.setdefault(port, []).append((server, directive))
    for port, entries in default_by_port.items():
        if len(entries) > 1:
            out.append(_finding(_info("NGV207"), entries[1][1], f"port {port} has more than one default_server"))

    # NGV208 — alias + try_files
    for location in context.locations:
        aliases = _direct(location, "alias")
        tries = _direct(location, "try_files")
        if aliases and tries:
            out.append(_finding(_info("NGV208"), aliases[0], "alias combined with try_files can escape the alias root"))

    return out


# ---------------------------------------------------------------------------
# Pass 3: cross-file / include effects (NGV3xx)
# ---------------------------------------------------------------------------


def pass_crossfile(context: Context) -> list[Finding]:
    out: list[Finding] = []

    # NGV301 — server_tokens reverted by an include
    last_off: dict[int, Directive] = {}
    for directive in sorted((d for d in context.directives if d.key == "server_tokens"), key=lambda d: d.seq):
        value = directive.args[0].lower() if directive.args else ""
        scope = id(directive.parent)
        if value == "off":
            last_off[scope] = directive
        elif _is_on(value) and scope in last_off and directive.file != last_off[scope].file:
            previous = last_off[scope]
            out.append(
                _finding(
                    _info("NGV301"),
                    directive,
                    f"include file {directive.file} reverts server_tokens to on after {previous.file} set it off",
                )
            )

    # NGV302 — include location triggers the header trap
    for location in context.locations:
        own = add_headers_at(location)
        if not own:
            continue
        server = nearest_block(location, "server")
        lost = header_trap_at(location, server)
        if not lost:
            continue
        main_file = server.file if server is not None else ""
        if location.file != main_file or any(item.node.file != main_file for item in lost):
            out.append(
                _finding(
                    _info("NGV302"),
                    own[0].node,
                    "security headers are declared in the main config but an included location's add_header "
                    "drops them (add_header inheritance trap across files)",
                )
            )

    # NGV303 / NGV306 / NGV307 — include records
    for record in context.includes:
        if record.wildcard:
            out.append(
                _evidence(_info("NGV303"), record.source, record.line, record.offset, record.saw,
                          f"include {record.arg} uses a wildcard; precedence depends on directory order")
            )
        if record.duplicate:
            out.append(
                _evidence(_info("NGV306"), record.source, record.line, record.offset, record.saw,
                          f"include {record.arg} was already included; directives are applied twice")
            )
        if record.missing:
            out.append(
                _evidence(_info("NGV307"), record.source, record.line, record.offset, record.saw,
                          f"include {record.arg} matched no file; expected config was never loaded")
            )

    # NGV304 — same listen, inconsistent TLS policy
    by_port: dict[str, list[Block]] = {}
    for server in context.servers:
        for port in server.listen_ports:
            by_port.setdefault(port.split(":")[-1], []).append(server)
    for port, servers in by_port.items():
        if len(servers) < 2:
            continue
        policies: dict[str, set[str]] = {}
        for server in servers:
            protocols = _direct(server, "ssl_protocols")
            if not protocols:
                continue
            key = id(server)
            policies[key] = set(protocols[0].args)
        if len(set(frozenset(value) for value in policies.values())) > 1:
            later = servers[-1]
            anchor = _direct(later, "ssl_protocols") or _direct(later, "listen")
            out.append(
                _finding(_info("NGV304"), anchor[0], f"servers sharing port {port} advertise different TLS policies")
            )

    # NGV305 — include redefines a security header
    seen_headers: dict[tuple[str, str], Directive] = {}
    for directive in sorted(
        (d for d in context.directives if d.key == "add_header" and len(d.args) >= 2), key=lambda d: d.seq
    ):
        name = _header_name(directive)
        if name not in CORE_SECURITY_HEADERS:
            continue
        server = nearest_block(directive, "server") or nearest_block(directive, "http")
        scope = id(server)
        key = (name, str(scope))
        if key in seen_headers and seen_headers[key].file != directive.file:
            out.append(
                _finding(
                    _info("NGV305"),
                    directive,
                    f"included file redefines security header {name} from {seen_headers[key].file}",
                )
            )
        seen_headers[key] = directive

    # NGV308 — TLS listener without a certificate
    for server in context.servers:
        if not server.is_ssl:
            continue
        if _direct(server, "ssl_certificate"):
            continue
        anchor = _direct(server, "listen") or _direct(server, "ssl_protocols")
        out.append(
            _finding(_info("NGV308"), anchor[0], "TLS server block has no ssl_certificate directive")
        )

    return out


def evaluate(
    configs: list[ConfigFile],
    includes: list[IncludeRecord] | None = None,
    context: Context | None = None,
) -> list[Finding]:
    """Run all three passes and return findings sorted by severity/rule/offset."""
    if context is None:
        context = build_context(configs, includes)
    findings = pass_directive(context) + pass_relation(context) + pass_crossfile(context)
    return sorted(findings, key=lambda finding: finding.sort_key())

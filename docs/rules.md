# nginxvet rules

37 rules (1 critical, 5 high, 22 medium, 8 low, 1 note), in three passes: `directive`, `relation`, `crossfile`.

- `directive` (NGV1xx) — a single directive and the value it exposes.
- `relation` (NGV2xx) — server/location relationships and inheritance.
- `crossfile` (NGV3xx) — what include expansion does to the effective tree.

Every finding carries path, line, byte offset and the raw snippet.

## NGV101

**server_tokens exposes the nginx version**

- severity: medium (score 5/10)
- pass: directive

`server_tokens on` adds the exact nginx version to error pages and the Server response header. Attackers use that version to pick a known exploit instead of probing blindly.

**Fix:** Set `server_tokens off;` in the http or server context.

## NGV102

**Directory listing enabled**

- severity: medium (score 6/10)
- pass: directive

`autoindex on` turns any directory without an index file into a browsable listing of every file. Backups, dotfiles and forgotten uploads become public.

**Fix:** Set `autoindex off;` and rely on explicit `index` directives.

## NGV103

**Obsolete TLS protocols enabled**

- severity: high (score 9/10)
- pass: directive

`ssl_protocols` that includes SSLv3, TLSv1 or TLSv1.1 keeps protocols with known downgrade and cipher weaknesses alive. Modern clients negotiate TLSv1.2/1.3 anyway, so the only real effect is widening the attack surface.

**Fix:** Use `ssl_protocols TLSv1.2 TLSv1.3;`.

## NGV104

**Weak cipher suites offered**

- severity: high (score 9/10)
- pass: directive

Cipher names containing NULL, EXPORT, RC4, 3DES, DES, MD5, SEED or IDEA are either unauthenticated, export-grade or trivially distinguishable. Advertising them invites downgrade attacks.

**Fix:** Use a modern cipher string such as `ECDHE+AESGCM:ECDHE+CHACHA20` and disable legacy suites.

## NGV105

**Security header missing `always`**

- severity: medium (score 6/10)
- pass: directive

By default nginx adds headers only for 2xx/3xx responses. Without the `always` parameter a security header disappears on 4xx/5xx error pages — exactly the pages an attacker can often trigger.

**Fix:** Append `always` to every `add_header` that carries a security header.

## NGV106

**HTTP Strict-Transport-Security not set**

- severity: medium (score 6/10)
- pass: directive

Without HSTS a browser will happily downgrade an HTTPS site to plain HTTP on the first request, which is enough for an on-path attacker to steal cookies. HSTS must be present at server level so it survives into every location.

**Fix:** Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` at server level.

## NGV107

**Content-Security-Policy not set**

- severity: medium (score 6/10)
- pass: directive

No CSP means the browser will execute any script the page includes, including injected script from an XSS flaw. CSP is the last line of defence when output escaping fails.

**Fix:** Add a restrictive `Content-Security-Policy` header at server level.

## NGV108

**X-Frame-Options not set**

- severity: medium (score 5/10)
- pass: directive

Without X-Frame-Options (or CSP frame-ancestors) the site can be embedded in an attacker's iframe and clicked through — classic clickjacking.

**Fix:** Add `add_header X-Frame-Options SAMEORIGIN always;` at server level.

## NGV109

**proxy_pass does not forward the Host header**

- severity: medium (score 6/10)
- pass: directive

nginx sets `Host` to `$proxy_host` by default, not to the client's Host. Applications that generate absolute URLs or pick a virtual host from Host then behave incorrectly or leak the internal name.

**Fix:** Add `proxy_set_header Host $host;` in the same scope as `proxy_pass`.

## NGV110

**proxy_pass does not forward X-Forwarded-For**

- severity: low (score 3/10)
- pass: directive

Without X-Forwarded-For the upstream sees only the proxy's IP, so access logs and IP-based rate limits lose the real client. Conversely, blindly trusting a client-supplied value is also wrong — set it explicitly from `$remote_addr`.

**Fix:** Add `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

## NGV111

**client_max_body_size allows very large uploads**

- severity: medium (score 5/10)
- pass: directive

A multi-hundred-megabyte request body lets a single slow client pin memory and connections. Request bodies are buffered before the application sees them, so the cost is paid by nginx itself.

**Fix:** Lower `client_max_body_size` to the smallest value the application needs (e.g. 10m).

## NGV112

**rewrite with $uri can loop**

- severity: medium (score 6/10)
- pass: directive

A `rewrite` that feeds `$uri` back into the replacement and ends in `last`/`break` can re-enter the same location repeatedly. nginx only bails out after ten internal redirects, meanwhile burning CPU.

**Fix:** Rewrite on a captured variable, not on `$uri`, or guard with a condition on the rewritten path.

## NGV113

**rewrite inside an if block**

- severity: high (score 8/10)
- pass: directive

`if` in location context is evaluated in a separate rewrite phase; combined with `rewrite` it is the canonical 'if is evil' trap — directives after it may be skipped or run twice.

**Fix:** Move the rewrite to a named location selected with `error_page` / `try_files` instead of `if`.

## NGV114

**resolver without valid/expire caching bounds**

- severity: medium (score 5/10)
- pass: directive

A `resolver` without `valid=` and `expire=` keeps DNS answers far longer than their TTL and can let a poisoned or stale answer persist. Bound both the positive and negative cache lifetime.

**Fix:** Use `resolver ... valid=30s expire=10s;`.

## NGV115

**TLS session tickets enabled without rotation**

- severity: low (score 3/10)
- pass: directive

Session tickets are encrypted with a key that nginx holds for the lifetime of the process by default; without ticket-key rotation, a stolen key decrypts all captured sessions.

**Fix:** Set `ssl_session_tickets off;` or rotate `ssl_session_ticket_key` regularly.

## NGV116

**Plaintext listener without HTTPS redirect**

- severity: medium (score 7/10)
- pass: directive

A server listening on port 80 that serves content instead of redirecting to HTTPS sends credentials and cookies over the wire in clear text.

**Fix:** Add `return 301 https://$host$request_uri;` to the port-80 server.

## NGV117

**Access log disabled**

- severity: low (score 3/10)
- pass: directive

`access_log off` removes the only record of who requested what. During an incident there is nothing to correlate, and compliance baselines require request logging.

**Fix:** Keep access logging on, or send it to a dedicated structured log.

## NGV118

**deny all before allow rule**

- severity: medium (score 7/10)
- pass: directive

nginx evaluates access rules in order and stops at the first match. A `deny all` placed before an `allow` makes the allow unreachable — the intended client is blocked and the mistake looks like a firewall problem.

**Fix:** Put all `allow` rules before `deny all;`.

## NGV119

**Listener without reuseport**

- severity: low (score 2/10)
- pass: directive

On high-traffic servers, accepting connections on a single shared socket serialises workers. `reuseport` gives each worker its own accept queue and removes that bottleneck.

**Fix:** Add `reuseport` to `listen` on busy servers (low priority on small sites).

## NGV120

**gzip enabled on sensitive content**

- severity: note (score 1/10)
- pass: directive

Compressing authenticated, secret-dependent responses can leak plaintext through compression side channels (BREACH). It is fine for static public assets, so this is a note, not a verdict.

**Fix:** Disable gzip for endpoints that reflect secrets, or use `gzip off` there.

## NGV121

**Server does not prefer its own cipher order**

- severity: low (score 3/10)
- pass: directive

With `ssl_prefer_server_ciphers off` the client picks the cipher from the mutually supported list, so a downgraded client can steer the connection to the weakest acceptable suite.

**Fix:** Set `ssl_prefer_server_ciphers on;`.

## NGV201

**add_header inheritance trap (security headers dropped in a location)**

- severity: critical (score 10/10)
- pass: relation

nginx never merges `add_header`: as soon as a location defines any `add_header` of its own, every `add_header` from the server and http levels is discarded inside that location. A single debug header therefore silently removes HSTS, CSP and X-Frame-Options from an entire URL tree — something a line-by-line audit cannot see.

**Fix:** Repeat all security `add_header` directives inside the location, or move the extra header up to server level.

## NGV202

**Location proxy_pass drops server-level proxy_set_header**

- severity: medium (score 7/10)
- pass: relation

`proxy_set_header` follows the same inheritance rule as `add_header`: a location that defines any of them loses the server-level ones. A location with its own `proxy_pass` then forwards requests without the correct Host or X-Forwarded-For.

**Fix:** Restate `proxy_set_header Host $host;` and friends inside the location that has `proxy_pass`.

## NGV203

**try_files references a missing named location**

- severity: medium (score 6/10)
- pass: relation

`try_files ... @fallback` sends the request to a named location. If that location does not exist nginx returns 500 at runtime — a configuration that validates with `nginx -t` but fails on the first miss.

**Fix:** Define `location @fallback { ... }` in the same server, or remove the named fallback.

## NGV204

**if-block return overrides the location return**

- severity: medium (score 6/10)
- pass: relation

A `return` inside an `if` short-circuits the location's own `return`. Two different status codes or redirect targets fight, and which one wins depends on request properties that are easy to miss.

**Fix:** Use a single `return` with a `map` variable, or split into a named location.

## NGV205

**Regex location uses $1 without a capture group**

- severity: medium (score 5/10)
- pass: relation

A regex location whose pattern has no capture group leaves `$1` empty. Directives that build a path or an upstream URL from `$1` then operate on the wrong value.

**Fix:** Add a capturing group to the location regex or use a named capture.

## NGV206

**proxy_http_version 1.1 with a keepalive-less upstream**

- severity: low (score 3/10)
- pass: relation

HTTP/1.1 to an upstream without `keepalive` in its `upstream` block opens a new connection for every request. The upstream's connection table fills up under modest load.

**Fix:** Add `keepalive N;` to the upstream block and `proxy_set_header Connection "";`.

## NGV207

**Duplicate server_name or default_server**

- severity: medium (score 6/10)
- pass: relation

Two servers claiming the same `server_name`, or two `default_server` listeners on the same address, make routing depend on include order. Requests land on a different vhost than the operator expects.

**Fix:** Give every vhost a unique name and mark exactly one default_server per address.

## NGV208

**alias combined with try_files**

- severity: medium (score 6/10)
- pass: relation

`alias` rewrites the URI by replacing the matched location prefix. Combined with `try_files` the joined path can escape the alias root when the URI contains `..`, a long-standing path-traversal footgun.

**Fix:** Use `root` instead of `alias` where possible, or avoid `try_files` inside an aliased location.

## NGV301

**include file reverts server_tokens to on**

- severity: high (score 8/10)
- pass: crossfile

The main config turns version disclosure off, but a later-loaded include sets `server_tokens on` again. A reviewer reading only the main file sees a hardened server that actually leaks its version.

**Fix:** Remove the conflicting line in the include; one setting must have one owner.

## NGV302

**include location triggers the add_header trap**

- severity: high (score 9/10)
- pass: crossfile

Security headers are declared in the main config, but an included location defines its own `add_header`. The include is where the inheritance trap actually fires, so neither file alone tells the whole story.

**Fix:** Repeat the security headers in the included location or remove its `add_header`.

## NGV303

**include path uses a wildcard**

- severity: low (score 3/10)
- pass: crossfile

Glob includes depend on directory enumeration order and on which files happen to exist. Adding one file can silently change precedence and therefore which directive wins.

**Fix:** Include files explicitly, in a deterministic order, or use a single manifest file.

## NGV304

**Same listen address with inconsistent TLS settings**

- severity: medium (score 6/10)
- pass: crossfile

Two server blocks share a listen address but advertise different `ssl_protocols` or `ssl_ciphers`. Which TLS policy a client gets then depends on which vhost nginx picked first.

**Fix:** Move TLS settings to the http level so every server on that address shares one policy.

## NGV305

**include file overrides a security header**

- severity: medium (score 6/10)
- pass: crossfile

An included file redefines a security header already set in the main config. Header inheritance is replaced, not merged, so the included value silently becomes the effective one.

**Fix:** Delete the duplicate from the include or make the main config the single owner.

## NGV306

**Same file included more than once**

- severity: low (score 3/10)
- pass: crossfile

The same file is included twice, so every directive in it is applied twice. Duplicate `add_header` values and duplicated upstream entries are the usual result.

**Fix:** Include the file once, at the point where it is needed.

## NGV307

**include matches no file**

- severity: medium (score 5/10)
- pass: crossfile

An `include` that resolves to nothing is silently accepted by nginx. The settings the operator expected from that file were never loaded at all.

**Fix:** Fix the path, or delete the include so the missing config is not mistaken for a loaded one.

## NGV308

**TLS listener without a certificate**

- severity: medium (score 6/10)
- pass: crossfile

A server block listens with `ssl` (or declares SSL protocols) but has no `ssl_certificate`. nginx fails to start or falls back to another server's certificate, depending on the rest of the config.

**Fix:** Add `ssl_certificate` and `ssl_certificate_key` to every TLS server block.

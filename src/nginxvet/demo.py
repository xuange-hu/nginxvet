"""Embedded demo corpus: a server assembled by several people over time.

It deliberately exercises every rule in the registry (there is a test).  The
include paths are virtual; ``embedded_resolver`` resolves them against this
dictionary, so no files are written and the demo is deterministic.
"""

from __future__ import annotations

from .model import ConfigFile, Report
from .parser import embedded_resolver, expand_includes, parse
from .rules import REGISTRY, evaluate

MAIN = """\
user nginx;
worker_processes auto;

http {
    server_tokens off;
    add_header X-Frame-Options SAMEORIGIN always;

    include conf.d/*.conf;
    include conf.d/extra.conf;
    include conf.d/missing.conf;

    upstream slowback {
        server 127.0.0.1:9000;
    }

    server {
        listen 80;
        listen 443 ssl;
        server_name example.com www.example.com;
        server_tokens on;
        autoindex on;
        access_log off;
        client_max_body_size 500m;
        gzip on;
        resolver 8.8.8.8;

        ssl_certificate /etc/ssl/site.crt;
        ssl_certificate_key /etc/ssl/site.key;
        ssl_protocols TLSv1 TLSv1.2;
        ssl_ciphers "RC4:HIGH:!aNULL:MD5";
        ssl_prefer_server_ciphers off;
        ssl_session_tickets on;

        proxy_set_header Host $host;

        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header Content-Security-Policy "default-src 'self'";

        include snippets/api.conf;

        location /api/ {
            proxy_pass http://backend;
            add_header X-Debug 1;
        }

        location /proxy/ {
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://backend3;
        }

        location /dl/ {
            alias /var/www/;
            try_files $uri $uri/ @missing;
        }

        location ~ \\.php$ {
            fastcgi_param SCRIPT_FILENAME /var/www$1;
        }

        location /evil/ {
            if ($request_method = POST) {
                rewrite ^ /index.php last;
            }
        }

        location /loop/ {
            rewrite ^/loop/(.*)$ /loop/$uri last;
        }

        location /acl/ {
            deny all;
            allow 10.0.0.0/8;
        }

        location /conflict/ {
            return 200 "a";
            if ($arg_x) {
                return 403;
            }
        }

        location /upstream/ {
            proxy_http_version 1.1;
            proxy_pass http://slowback;
        }
    }

    server {
        listen 443 ssl;
        server_name other.example;
        ssl_protocols TLSv1.2;
    }

    server {
        listen 80 default_server;
        server_name dup.example;
    }

    server {
        listen 80 default_server;
        server_name example.com;
    }
}
"""

BASE = """\
# conf.d/10-base.conf -- vendor baseline.
keepalive_timeout 65;
"""

HEADERS = """\
# conf.d/20-headers.conf -- site-wide defaults.
add_header X-Content-Type-Options nosniff always;
"""

EXTRA = """\
# conf.d/extra.conf -- a late drop-in from a package.
server_tokens on;
add_header X-Frame-Options DENY always;
"""

API_SNIPPET = """\
# snippets/api.conf -- included inside the main server block.
location /included/ {
    add_header X-Debug 1;
    proxy_pass http://apibackend;
}
"""

DEMO_FILES: dict[str, str] = {
    "<demo>/nginx.conf": MAIN,
    "conf.d/10-base.conf": BASE,
    "conf.d/20-headers.conf": HEADERS,
    "conf.d/extra.conf": EXTRA,
    "snippets/api.conf": API_SNIPPET,
}


def demo_targets() -> list[ConfigFile]:
    """Parse the embedded corpus as fresh trees (no shared mutable state)."""
    config = parse(MAIN, "<demo>/nginx.conf")
    config.virtual = True
    expanded, _includes = expand_includes([config], embedded_resolver(DEMO_FILES))
    return expanded


def run_demo() -> Report:
    config = parse(MAIN, "<demo>/nginx.conf")
    config.virtual = True
    expanded, includes = expand_includes([config], embedded_resolver(DEMO_FILES))
    findings = evaluate(expanded, includes)
    return Report(
        source="nginxvet demo (embedded corpus)",
        targets=expanded,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
        includes=includes,
    )

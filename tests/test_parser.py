"""Parser contract: tokens, block tree, byte offsets and malformed input."""

from nginxvet.model import Block, Directive
from nginxvet.parser import embedded_resolver, expand_includes, parse, tokenize


def test_tokenize_plain_directive():
    tokens = tokenize("server_tokens off;")
    pairs = [(token.value, token.raw) for token in tokens]
    assert pairs == [("server_tokens", "server_tokens"), ("off", "off"), (";", ";")]


def test_tokenize_tracks_line_numbers():
    tokens = tokenize("http {\n  server {\n    listen 80;\n  }\n}")
    assert tokens[0].line == 1
    assert any(token.line == 3 and token.value == "80" for token in tokens)


def test_tokenize_byte_offsets_ascii():
    tokens = tokenize("listen 80;")
    assert [token.offset for token in tokens] == [0, 7, 9]


def test_tokenize_byte_offsets_utf8():
    text = "# 注释\nlisten 80;"
    tokens = tokenize(text)
    listen = next(token for token in tokens if token.value == "listen")
    expected = text.index("listen")
    assert listen.offset == len(text[:expected].encode("utf-8"))


def test_tokenize_strips_comments():
    tokens = tokenize("a b; # comment\nc d;")
    assert [token.value for token in tokens] == ["a", "b", ";", "c", "d", ";"]


def test_tokenize_hash_inside_quotes():
    tokens = tokenize('add_header X "#value";')
    values = [token.value for token in tokens]
    assert "#value" in values


def test_tokenize_double_quoted_value():
    tokens = tokenize('add_header CSP "default-src \'self\'";')
    assert any("default-src" in token.value for token in tokens)


def test_tokenize_escaped_space():
    tokens = tokenize("rewrite ^/a\\ b /c;")
    assert any(token.value == "^/a b" for token in tokens)


def test_parse_simple_directive():
    config = parse("server_tokens off;\n", "x.conf")
    assert len(config.roots) == 1
    item = config.roots[0]
    assert isinstance(item, Directive)
    assert (item.key, item.args) == ("server_tokens", ["off"])


def test_parse_block_tree():
    text = "http {\n server {\n  listen 80;\n }\n}\n"
    config = parse(text, "x.conf")
    http = config.roots[0]
    assert isinstance(http, Block) and http.key == "http"
    server = http.body[0]
    assert isinstance(server, Block) and server.key == "server"
    assert server.body[0].key == "listen"


def test_parse_location_with_modifier():
    config = parse("server {\n location ~ \\.php$ {\n  root /w;\n }\n}\n")
    server = config.roots[0]
    location = server.body[0]
    assert location.key == "location"
    assert location.location_modifier == "~"
    assert location.location_path == "\\.php$"


def test_parse_exact_location():
    config = parse("location = /exact { }")
    assert config.roots[0].location_modifier == "="
    assert config.roots[0].location_path == "/exact"


def test_parse_named_location():
    config = parse("location @fallback { }")
    assert config.roots[0].location_modifier == "@"
    assert config.roots[0].location_path == "@fallback"


def test_parse_prefix_location_modifier_empty():
    config = parse("location /api/ { }")
    assert config.roots[0].location_modifier == ""
    assert config.roots[0].location_path == "/api/"


def test_parse_parent_pointers():
    config = parse("http { server { listen 80; } }")
    server = config.roots[0].body[0]
    listen = server.body[0]
    assert listen.parent is server
    assert server.parent is config.roots[0]


def test_parse_evidence_fields():
    text = "server_tokens off;"
    config = parse(text, "x.conf")
    item = config.roots[0]
    assert item.line == 1
    assert item.offset == 0
    assert item.length == len(text)
    assert item.saw == text
    assert item.file == "x.conf"


def test_parse_second_line_offset():
    text = "a b;\nc d;\n"
    config = parse(text, "x.conf")
    assert config.roots[1].offset == 5
    assert text[config.roots[1].offset :].startswith("c d")


def test_parse_unclosed_block_warns():
    config = parse("http { server {", "x.conf")
    assert config.warnings
    assert not config.roots[0].closed


def test_parse_stray_terminator_warns():
    config = parse(";\n", "x.conf")
    assert config.warnings


def test_parse_does_not_crash_on_junk():
    config = parse("@@@ not nginx ;;; { {{ }", "x.conf")
    assert isinstance(config.roots, list)


def test_parse_empty_config():
    config = parse("", "x.conf")
    assert config.roots == []
    assert config.warnings == []


def test_parse_multiple_roots():
    config = parse("events { } http { }")
    assert [node.key for node in config.roots] == ["events", "http"]


def test_parse_include_is_a_directive_before_expansion():
    config = parse("include conf.d/*.conf;", "x.conf")
    assert config.roots[0].key == "include"
    assert config.roots[0].args == ["conf.d/*.conf"]


def test_expand_includes_grafts_nodes():
    config = parse("http {\n include extra.conf;\n}\n", "main.conf")
    files = {"extra.conf": "server_tokens on;\n"}
    expanded, records = expand_includes([config], embedded_resolver(files))
    http = expanded[0].roots[0]
    assert [node.key for node in http.body] == ["server_tokens"]
    assert http.body[0].file == "extra.conf"
    assert len(records) == 1


def test_expand_includes_records_wildcard_and_missing():
    config = parse("include conf.d/*.conf;\ninclude gone.conf;", "main.conf")
    _expanded, records = expand_includes([config], embedded_resolver({"conf.d/a.conf": "a b;"}))
    assert records[0].wildcard is True
    assert records[0].resolved == ["conf.d/a.conf"]
    assert records[1].missing is True


def test_expand_includes_detects_duplicate():
    config = parse("include a.conf;\ninclude a.conf;", "main.conf")
    _expanded, records = expand_includes([config], embedded_resolver({"a.conf": "server_tokens off;"}))
    assert records[0].duplicate is False
    assert records[1].duplicate is True


def test_expand_includes_nested_include():
    config = parse("include a.conf;", "main.conf")
    files = {"a.conf": "include b.conf;", "b.conf": "autoindex on;"}
    expanded, records = expand_includes([config], embedded_resolver(files))
    assert expanded[0].roots[0].key == "autoindex"
    assert len(records) == 2


def test_expand_includes_cycle_is_bounded():
    config = parse("include a.conf;", "main.conf")
    files = {"a.conf": "include a.conf;"}
    # The seen-path guard must stop a self-include from looping forever.
    expanded, records = expand_includes([config], embedded_resolver(files))
    assert len(expanded[0].roots) <= 2
    assert records[0].duplicate is True


def test_expand_includes_assigns_sequential_seq():
    config = parse("a b;\nc d;", "main.conf")
    expanded, _records = expand_includes([config], embedded_resolver({}))
    assert [node.seq for node in expanded[0].roots] == [0, 1]

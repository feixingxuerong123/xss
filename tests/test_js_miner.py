"""Tests for core/js_miner.py -- JS endpoint / sink mining.

Pure string-processing coverage: every extractor family, URI filtering,
dedup, dangerous sinks, script-src / inline extraction, URL resolution
with cross-origin filtering, and the html / js_file mining entrypoints.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.js_miner import (
    extract_endpoints,
    extract_inline_scripts,
    extract_script_srcs,
    find_dangerous_sinks,
    mine_html,
    mine_js_file,
    resolve_urls,
)


class TestExtractEndpoints:
    def test_empty_source(self):
        assert extract_endpoints("") == []

    def test_fetch_extractor(self):
        js = "fetch('/api/users');fetch(\"/api/x\",{})"
        urls = extract_endpoints(js)
        assert ("/api/users", "fetch") in urls
        assert ("/api/x", "fetch") in urls

    def test_axios_jquery_xhr(self):
        js = ("axios.get('/ax/1');$.post('/jq/2');"
              "xhr.open('GET','/xhr/3',true)")
        kinds = {k: u for u, k in extract_endpoints(js)}
        assert kinds["axios"] == "/ax/1"
        assert kinds["jquery"] == "/jq/2"
        assert kinds["xhr"] == "/xhr/3"

    def test_route_location_window_open(self):
        js = ("path: '/users';location.href='/loc/1';"
              "window.open('/win/1')")
        kinds = {k: u for u, k in extract_endpoints(js)}
        assert kinds["route"] == "/users"
        assert kinds["location"] == "/loc/1"
        assert kinds["window_open"] == "/win/1"

    def test_filters_non_http_schemes_and_short(self):
        js = ("fetch('data:text/html,x');fetch('blob:x');"
              "fetch('javascript:x');fetch('#frag');fetch('a')")
        assert extract_endpoints(js) == []

    def test_dedup_within_kind(self):
        js = "fetch('/same');fetch('/same')"
        assert extract_endpoints(js).count(("/same", "fetch")) == 1

    def test_same_url_different_kind_kept(self):
        js = "fetch('/dup');axios.get('/dup')"
        urls = extract_endpoints(js)
        assert ("/dup", "fetch") in urls
        assert ("/dup", "axios") in urls


class TestDangerousSinks:
    def test_empty(self):
        assert find_dangerous_sinks("") == []

    def test_detects_innerhtml_and_eval(self):
        js = "el.innerHTML = userInput; eval(userInput);"
        found = find_dangerous_sinks(js)
        names = {n for n, _ in found}
        assert "innerHTML" in names and "eval(" in names

    def test_message_listener_variants(self):
        for quote in ("'", '"'):
            js = f"window.addEventListener({quote}message{quote}, fn)"
            found = find_dangerous_sinks(js)
            assert any("postMessage" in d for _, d in found), js

    def test_clean_source_has_no_sinks(self):
        assert find_dangerous_sinks("console.log('hi')") == []


class TestScriptExtraction:
    def test_script_src(self):
        html = ("<script src='/a.js'></script>"
                "<SCRIPT SRC='/b.js'></SCRIPT>")
        assert extract_script_srcs(html) == ["/a.js", "/b.js"]

    def test_inline_scripts_exclude_src(self):
        html = ("<script src='/x.js'></script>"
                "<script>fetch('/inline/1')</script>"
                "<script>fetch('/inline/2')</script>")
        blocks = extract_inline_scripts(html)
        assert len(blocks) == 2
        assert "/inline/1" in blocks[0]

    def test_empty_html(self):
        assert extract_script_srcs("") == []
        assert extract_inline_scripts("") == []


class TestResolveUrls:
    def test_relative_resolved(self):
        # urljoin semantics: "/a.js" is ROOT-relative, "js/b.js" is
        # relative to the base path directory.
        out = resolve_urls(["/a.js", "js/b.js"],
                           "http://t/app/")
        assert "http://t/a.js" in out
        assert "http://t/app/js/b.js" in out

    def test_absolute_same_origin_kept(self):
        out = resolve_urls(["http://t/x.js"], "http://t/")
        assert out == ["http://t/x.js"]

    def test_cross_origin_filtered(self):
        out = resolve_urls(["http://evil.test/x.js"], "http://t/")
        assert out == []

    def test_broken_url_yields_base_merge(self):
        # "http://" merges with the base into the bare origin -- harmless
        # (same-host filter keeps it); not a crash.
        out = resolve_urls(["http://", "/ok.js"], "http://t/")
        assert "http://t/ok.js" in out


class TestMineEntrypoints:
    def test_mine_html_full_shape(self):
        html = ("<script src='/app.js'></script>"
                "<script>fetch('/inline/api');"
                "el.innerHTML = d;</script>")
        r = mine_html(html, "http://t/")
        assert r["external_scripts"] == ["http://t/app.js"]
        assert ("/inline/api", "fetch") in r["inline_endpoints"]
        assert any(n == "innerHTML" for n, _ in r["sinks"])
        assert r["external_endpoints"] == []

    def test_mine_js_file(self):
        r = mine_js_file("fetch('/a');document.write(x)")
        assert r["endpoints"] == [("/a", "fetch")]
        assert any(n == "document.write" for n, _ in r["sinks"])

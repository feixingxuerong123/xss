"""Tests for the SPA crawler's pure helpers + scanner_crawl (Phase 43).

Covers the parts of spa_crawler.py / scanner_crawl.py that don't need a real
browser: route-template normalization, URL normalization, scope checks, the
endpoint-registration helpers (driven with a fake ``page`` object), and the
``_abs`` urljoin wrapper.  This lifts spa_crawler off 24% / scanner_crawl off
15% without paying the Playwright startup cost in the unit tier.
"""
from __future__ import annotations
import os
import sys

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core import spa_crawler as spa
from xssentinel.core.scanner_crawl import _abs


def _bare_crawler(scope=None):
    """SpaCrawler instance without running __init__'s browser-less setup
    (only the attributes the helpers touch)."""
    c = spa.SpaCrawler.__new__(spa.SpaCrawler)
    c.scope = scope
    c.verbose = False
    c.requests_made = 0
    c._bump = lambda: None
    return c


class TestRouteTemplate:
    def test_numeric_id_templated(self):
        t = spa._route_template("http://h/users/123/edit?foo=bar")
        assert t == "http://h/users/{id}/edit"

    def test_uuid_templated(self):
        t = spa._route_template(
            "http://h/p/550e8400-e29b-41d4-a716-446655440000")
        assert t == "http://h/p/{uuid}"

    def test_long_hash_templated(self):
        t = spa._route_template("http://h/p/a1b2c3d4e5f6a1b2")
        assert t == "http://h/p/{hash}"

    def test_query_dropped(self):
        # ?id=1 and ?id=2 collapse to the same template (params probed later).
        assert spa._route_template("http://h/s?q=1") == \
            spa._route_template("http://h/s?q=2")

    def test_root_and_static_path_unchanged(self):
        assert spa._route_template("http://h/") == "http://h/"
        assert spa._route_template("http://h/about") == "http://h/about"


class TestNormUrl:
    def test_default_port_stripped(self):
        assert spa._norm_url("http://h:80/p") == "http://h/p"
        assert spa._norm_url("https://h:443/p") == "https://h/p"

    def test_fragment_dropped_case_folded(self):
        assert spa._norm_url("HTTP://H/p#frag") == "http://h/p"

    def test_query_kept(self):
        assert spa._norm_url("http://h/p?a=1") == "http://h/p?a=1"


class TestInScope:
    def test_same_origin_in_scope(self):
        c = _bare_crawler()
        assert c._in_scope("http://h/a/b", "http://h/start") is True

    def test_cross_origin_out_of_scope(self):
        c = _bare_crawler()
        assert c._in_scope("http://evil/x", "http://h/start") is False

    def test_scope_prefix_enforced(self):
        c = _bare_crawler(scope="http://h/app")
        assert c._in_scope("http://h/app/x", "http://h/app") is True
        assert c._in_scope("http://h/other", "http://h/app") is False

    def test_malformed_url_is_out(self):
        c = _bare_crawler()
        assert c._in_scope("ht!tp://[bad", "http://h/") is False


class TestRegisterHelpers:
    def test_register_page_route_dedup(self):
        c = _bare_crawler()
        eps, seen_ep, seen_routes = [], set(), set()
        # Numeric route ids need 2+ digits to template (by design: /page/2
        # style pagination must NOT collapse).  Use /u/10 and /u/22.
        c._register_page(eps, seen_ep, seen_routes, "http://h/u/10", "http://h/")
        c._register_page(eps, seen_ep, seen_routes, "http://h/u/22", "http://h/")
        # /u/10 and /u/22 share the route template /u/{id} -> only ONE endpoint.
        assert len(eps) == 1
        assert eps[0][1] == "GET" and eps[0][2] == {}

    def test_register_page_skips_start_url(self):
        c = _bare_crawler()
        eps, seen_ep, seen_routes = [], set(), set()
        c._register_page(eps, seen_ep, seen_routes, "http://h/", "http://h/")
        assert eps == []

    def test_register_query_links_parses_params(self):
        c = _bare_crawler()
        eps, seen_ep = [], set()
        c._register_query_links(eps, seen_ep,
                                ["http://h/s?q=x&page=2", "http://h/noquery"],
                                "http://h/")
        assert len(eps) == 1
        url, method, params, data = eps[0]
        assert url == "http://h/s" and method == "GET"
        assert set(params) == {"q", "page"} and data == {}

    def test_register_query_links_scope_filter(self):
        c = _bare_crawler()
        eps, seen_ep = [], set()
        c._register_query_links(eps, seen_ep, ["http://evil/s?q=x"],
                                "http://h/")
        assert eps == []

    def test_register_xhr_get_vs_post(self):
        c = _bare_crawler()
        eps, seen_ep = [], set()
        c._register_xhr(eps, seen_ep,
                        [("http://h/api/s?q=1", "GET"),
                         ("http://h/api/c?x=1", "POST")],
                        "http://h/")
        by_method = {m: (u, p, d) for u, m, p, d in eps}
        # GET: params in query slot; POST: params in data slot.
        assert by_method["GET"][1] == {"q": "xss"} and by_method["GET"][2] == {}
        assert by_method["POST"][2] == {"x": "xss"} and by_method["POST"][1] == {}

    def test_register_xhr_dedup(self):
        c = _bare_crawler()
        eps, seen_ep = [], set()
        c._register_xhr(eps, seen_ep,
                        [("http://h/api/s?q=1", "GET"),
                         ("http://h/api/s?q=2", "GET")],  # same template
                        "http://h/")
        assert len(eps) == 1


class TestPlaywrightProbe:
    def test_available_returns_bool(self):
        assert isinstance(spa.SpaCrawler.available(), bool)
        assert isinstance(spa._playwright_available(), bool)


class TestScannerCrawlAbs:
    def test_relative_resolution(self):
        assert _abs("http://h/dir/page", "next") == "http://h/dir/next"

    def test_absolute_path_resolution(self):
        assert _abs("http://h/dir/page", "/root") == "http://h/root"

    def test_full_url_passthrough(self):
        assert _abs("http://h/", "http://other/x") == "http://other/x"

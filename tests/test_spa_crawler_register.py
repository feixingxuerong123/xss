# -*- coding: utf-8 -*-
"""SpaCrawler's discovery methods, pinned.

The small helpers (route templating, URL normalizing, scope check) had
tests; the six methods that actually BUILD the endpoint list --
_extract_dom_links, _register_page, _register_query_links,
_register_forms, _register_xhr -- did not.  Those are where SPA attack
surface comes from, and each one's dedup key decides whether the
scanner probes an endpoint at all.

The Playwright page is faked at the one method the crawler uses:
``page.evaluate(js)`` -- the JS source distinguishes the links probe
(`a[href]`) from the forms probe (`form`), so a dict-keyed responder is
enough.  No browser, no network.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.spa_crawler import SpaCrawler

START = "http://app.test/app"


def _crawler() -> SpaCrawler:
    return SpaCrawler(max_depth=1, scope="http://app.test/app")


class _FakePage:
    """Answers the two evaluate() probes the crawler makes."""

    def __init__(self, links=None, forms=None, explode=False):
        self._links = links or []
        self._forms = forms or []
        self._explode = explode
        self.calls = []

    def evaluate(self, js, *a, **kw):
        self.calls.append(js)
        if self._explode:
            raise RuntimeError("page navigated mid-evaluation")
        if "a[href]" in js:
            return list(self._links)
        if "'form'" in js or '"form"' in js or "form" in js:
            return list(self._forms)
        return []


class TestExtractDomLinks:
    def test_keeps_resolved_http_links_and_drops_schemes(self):
        page = _FakePage(links=[
            "/list?page=2",
            "http://other.test/abs",
            "#anchor",
            "javascript:void(0)",
            "mailto:a@b.c",
            "tel:+123",
            "data:text/html,x",
            "",
            "detail/7",
        ])
        got = _crawler()._extract_dom_links(page, START)
        assert "http://app.test/list?page=2" in got
        assert "http://other.test/abs" in got
        assert "http://app.test/detail/7" in got
        assert all(g.startswith("http") for g in got)
        joined = " ".join(got)
        for scheme in ("javascript:", "mailto:", "tel:", "data:"):
            assert scheme not in joined
        assert not any(g.endswith("#anchor") for g in got)

    def test_page_evaluation_failure_yields_no_links(self):
        assert _crawler()._extract_dom_links(_FakePage(explode=True),
                                             START) == []


class TestRegisterQueryLinks:
    def test_query_params_become_get_endpoints(self):
        eps, seen = [], set()
        _crawler()._register_query_links(
            eps, seen, ["http://app.test/app/list?page=2&tab=posts"], START)
        assert len(eps) == 1
        url, method, params, data = eps[0]
        assert (url, method, data) == ("http://app.test/app/list", "GET", {})
        assert params == {"page": "xss", "tab": "xss"}

    def test_blank_param_value_is_dropped_from_the_endpoint(self):
        # parse_qsl's default drops `q=` (keep_blank_values=False), so a
        # blank param never reaches the probe list.  Documented behaviour.
        eps, seen = [], set()
        _crawler()._register_query_links(
            eps, seen, ["http://app.test/app/list?page=2&q="], START)
        assert len(eps) == 1 and eps[0][2] == {"page": "xss"}

    def test_route_template_dedupes_paginated_ids(self):
        eps, seen = [], set()
        _crawler()._register_query_links(
            eps, seen,
            ["http://app.test/app/u/17?tab=posts",
             "http://app.test/app/u/42?tab=posts"],
            START)
        assert len(eps) == 1, "two ids of one route template must probe once"

    def test_out_of_scope_and_queryless_links_are_skipped(self):
        eps, seen = [], set()
        _crawler()._register_query_links(
            eps, seen,
            ["http://evil.test/x?q=1",
             "http://app.test/outside/app?q=1",
             "http://app.test/app/noquery"],
            START)
        assert eps == [], "cross-origin AND same-host-prefix-escape drop"


class TestRegisterForms:
    def test_post_form_lands_in_data_get_form_in_params(self):
        # The fake returns the POST-evaluation shape: the crawler's own
        # JS already defaulted valueless inputs to "xss".
        page = _FakePage(forms=[
            {"action": "/app/login", "method": "POST",
             "inputs": {"user": "xss", "pass": "x"}},
            {"action": "/app/search", "method": "GET", "inputs": {"q": "x"}},
        ])
        eps, seen = [], set()
        _crawler()._register_forms(page, eps, seen, "http://app.test/app",
                                   START)
        assert len(eps) == 2
        assert eps[0] == ("http://app.test/app/login", "POST", {},
                          {"user": "xss", "pass": "x"})
        assert eps[1][1] == "GET" and eps[1][2] == {"q": "x"}

    def test_relative_action_resolves_and_out_of_scope_drops(self):
        page = _FakePage(forms=[
            {"action": "submit", "method": "POST", "inputs": {"a": "xss"}},
            {"action": "http://evil.test/steal", "method": "POST",
             "inputs": {"a": "xss"}},
        ])
        eps, seen = [], set()
        _crawler()._register_forms(page, eps, seen, "http://app.test/app/",
                                   START)
        assert len(eps) == 1
        assert eps[0][0] == "http://app.test/app/submit"

    def test_inputless_form_is_skipped(self):
        page = _FakePage(forms=[{"action": "/x", "method": "GET",
                                 "inputs": {}}])
        eps, seen = [], set()
        _crawler()._register_forms(page, eps, seen, START, START)
        assert eps == []


class TestRegisterPage:
    def test_start_page_is_not_reregistered(self):
        eps, seen, routes = [], set(), set()
        _crawler()._register_page(eps, seen, routes, START + "?x=1", START)
        assert eps == []

    def test_new_page_registers_once_per_route_template(self):
        # _NUMERIC_ID needs >=2 digits: single-digit segments stay literal
        # on purpose (templating /v1 would collapse API versions).
        eps, seen, routes = [], set(), set()
        c = _crawler()
        c._register_page(eps, seen, routes, "http://app.test/app/u/11", START)
        c._register_page(eps, seen, routes, "http://app.test/app/u/22", START)
        c._register_page(eps, seen, routes, "http://app.test/app/settings",
                         START)
        assert len(eps) == 2, "route templates must dedupe paginated pages"
        assert all(e[1] == "GET" and e[2] == {} and e[3] == {} for e in eps)


class TestRegisterXhr:
    def test_get_xhr_params_and_post_xhr_data(self):
        eps, seen = [], set()
        _crawler()._register_xhr(
            eps, seen,
            [("http://app.test/app/api/search?q=x", "GET"),
             ("http://app.test/app/api/save", "POST")],
            START)
        assert len(eps) == 2
        get_ep = [e for e in eps if e[1] == "GET"][0]
        post_ep = [e for e in eps if e[1] == "POST"][0]
        assert get_ep[2] == {"q": "xss"} and get_ep[3] == {}
        assert post_ep[2] == {} and post_ep[3] == {}

    def test_scope_and_double_dedup(self):
        eps, seen = [], set()
        c = _crawler()
        c._register_xhr(eps, seen,
                        [("http://app.test/app/api/search?q=x", "GET"),
                         ("http://app.test/app/api/search?q=y", "GET"),
                         ("http://evil.test/api?q=x", "GET")],
                        START)
        assert len(eps) == 1
        # a second pass with the same seen set adds nothing
        c._register_xhr(eps, seen,
                        [("http://app.test/app/api/search?q=z", "GET")],
                        START)
        assert len(eps) == 1

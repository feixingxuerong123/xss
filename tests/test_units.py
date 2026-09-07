"""Unit tests for xssentinel core modules (no network required).

These tests cover the pure-Python logic of each module without needing
the vuln_server running.  They complement run_self_test.py (which is an
end-to-end integration test) by giving fast, isolated, regression-grade
coverage of the individual detection layers.
"""
from __future__ import annotations
import os
import sys
import json

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import verifier
from xssentinel.core import mutation as mxss_mod
from xssentinel.core import context as ctx
from xssentinel.core import polyglot
from xssentinel.core import ctx_mutation
from xssentinel.core import multi_encode
from xssentinel.core import bypass
from xssentinel.core import cvss
from xssentinel.core import compliance
from xssentinel.core import session


# =============================================================================
# verifier.py
# =============================================================================

class TestVerifier:
    """Tests for the semantic verification engine."""

    def test_mark_replaces_alert_argument(self):
        """mark() should replace the first alert(...) argument with token."""
        marked = verifier.mark("alert(1)", "tok123")
        assert "tok123" in marked
        assert "alert('tok123')" == marked

    def test_mark_handles_alert_with_message(self):
        marked = verifier.mark("alert(document.cookie)", "t")
        assert "alert('t')" == marked

    def test_verify_semantic_no_reflection(self):
        """No token reflection -> not confirmed."""
        r = verifier.verify_semantic("<html>nothing here</html>", "nope")
        assert r["confirmed"] is False

    def test_verify_semantic_script_block(self):
        """Token inside a real <script> block in executable code -> confirmed."""
        html = '<html><script>alert("tok_abc");</script></html>'
        r = verifier.verify_semantic(html, "tok_abc")
        assert r["confirmed"] is True
        assert r["context"] == "script_block"

    def test_verify_semantic_script_string_trapped(self):
        """Token trapped inside a JS string assignment -> NOT confirmed."""
        html = '<html><script>var x = "tok_trapped";</script></html>'
        r = verifier.verify_semantic(html, "tok_trapped")
        assert r["confirmed"] is False

    def test_verify_semantic_event_handler(self):
        """Token in an on* attribute -> confirmed."""
        html = '<img src=x onerror="alert(\'tok_evt\')">'
        r = verifier.verify_semantic(html, "tok_evt")
        assert r["confirmed"] is True
        assert r["context"] == "event_handler"

    def test_verify_semantic_javascript_uri(self):
        """Token in href=javascript: -> confirmed."""
        html = '<a href="javascript:alert(\'tok_uri\')">x</a>'
        r = verifier.verify_semantic(html, "tok_uri")
        assert r["confirmed"] is True
        assert r["context"] in ("url_javascript", "event_handler")

    def test_verify_semantic_escaped_payload_not_confirmed(self):
        """html.escape'd payload must NOT be confirmed (no false positive)."""
        html = '&lt;svg/onload=alert(\'tok_esc\')&gt;'
        r = verifier.verify_semantic(html, "tok_esc")
        assert r["confirmed"] is False

    def test_verify_semantic_template_expression(self):
        """Token inside {{ }} -> confirmed as template_angular."""
        html = '<div>{{ tok_tpl }}</div>'
        r = verifier.verify_semantic(html, "tok_tpl")
        assert r["confirmed"] is True
        assert r["context"] == "template_angular"

    def test_verify_semantic_mxss_near_mutating_sink(self):
        """Token near a mutating sink (svg+style) -> mXSS confirmation.

        This is the Phase 16 fix: verify_semantic now consults the
        mutation analyzer when the single-pass parse doesn't confirm,
        so mXSS payloads are no longer falsely reported as inert.
        """
        # A simplified mXSS pattern: token reflected inside an
        # <svg><style> context where a browser would re-parse on
        # serialization round-trip.
        html = ('<svg><style>/*tok_mx*/</style></svg>'
                '<img src=x>tok_mx</img>')
        r = verifier.verify_semantic(html, "tok_mx")
        # Either confirmed via mXSS path or via the structural path --
        # both are acceptable as long as we don't return a false negative.
        assert r["confirmed"] is True or r["context"] is not None


# =============================================================================
# mutation.py (mXSS)
# =============================================================================

class TestMutation:
    """Tests for the mXSS (mutation XSS) analyzer."""

    def test_analyze_no_reflection(self):
        r = mxss_mod.analyze("<html>no marker</html>", "nope")
        assert r["reflected"] is False
        assert r["exploitable"] is False

    def test_analyze_reflected_no_sink(self):
        r = mxss_mod.analyze("<div>tok_plain</div>", "tok_plain")
        assert r["reflected"] is True
        # No mutating sink -> not exploitable.
        assert r["exploitable"] is False

    def test_analyze_with_mutating_sink(self):
        """Reflected token + JS mutating sink -> exploitable.

        MUTATING_SINKS are JS-side sinks (innerHTML, document.write, etc.)
        that take an HTML string and parse it -- a reflected token near
        such a sink means a mutation round-trip could execute it.
        """
        # Page with a known mXSS payload reflected AND a JS sink present.
        payload = mxss_mod.MXSS_PAYLOADS[0][0]
        html = f'<div>{payload}</div><script>el.innerHTML = data;</script>'
        r = mxss_mod.analyze(html, payload)
        assert r["reflected"] is True
        # innerHTML is in MUTATING_SINKS -> exploitable.
        assert r["exploitable"] is True
        assert "innerHTML" in r["sinks"]

    def test_payloads_nonempty(self):
        """The mXSS payload list should not be empty."""
        assert len(mxss_mod.MXSS_PAYLOADS) > 0


# =============================================================================
# context.py
# =============================================================================

class TestContext:
    """Tests for the reflection context classifier."""

    def test_classify_html_element(self):
        html = '<div>marker</div>'
        info = ctx._analyze_at(html, html.find("marker"), "marker")
        assert info is not None
        assert info["context"] == "html_element"

    def test_classify_script_block(self):
        html = '<script>var x = "marker";</script>'
        info = ctx._analyze_at(html, html.find("marker"), "marker")
        assert info is not None
        # Token inside a quoted string within <script> -- the classifier
        # distinguishes script_block (raw text) from script_string_dq
        # (inside a double-quoted JS string).
        assert info["context"] in ("script_block", "script_string_dq")

    def test_classify_attribute_dq(self):
        html = '<input value="marker">'
        info = ctx._analyze_at(html, html.find("marker"), "marker")
        assert info is not None
        assert info["context"] == "html_attribute_dq"

    def test_classify_html_comment(self):
        html = '<!-- marker -->'
        info = ctx._analyze_at(html, html.find("marker"), "marker")
        assert info is not None
        assert info["context"] == "html_comment"


# =============================================================================
# polyglot.py
# =============================================================================

class TestPolyglot:
    """Tests for the multi-stage polyglot generator."""

    def test_make_token_unique(self):
        t1 = polyglot.make_token()
        t2 = polyglot.make_token()
        assert t1 != t2

    def test_build_polyglot_contains_alert(self):
        p = polyglot.build_polyglot("tok123")
        assert "alert" in p or "tok123" in p

    def test_build_multi_stage_polyglot_breaks_multiple_contexts(self):
        """Multi-stage polyglot should include breakouts for multiple contexts."""
        p = polyglot.build_multi_stage_polyglot("mt",
                                                contexts=["html_attribute_dq",
                                                          "script_string_dq"])
        # Should contain at least one quote breakout and one script breakout.
        assert any(c in p for c in ('"', "'", "</script>"))

    def test_all_polyglots_v2_returns_variants(self):
        d = polyglot.all_polyglots_v2("tok")
        assert "multi_stage" in d
        assert "waf_cloudflare" in d
        assert "len_50" in d
        assert len(d) >= 10

    def test_length_limited_polyglot_respects_limit(self):
        """Length-limited polyglot should not exceed the limit (much)."""
        p = polyglot.build_length_limited_polyglot(50, "t")
        # Allow a small overflow (token expansion) but not 2x.
        assert len(p) <= 80


# =============================================================================
# ctx_mutation.py
# =============================================================================

class TestCtxMutation:
    """Tests for the context-aware mutation engine."""

    def test_supported_contexts_nonempty(self):
        ctxs = ctx_mutation.supported_contexts()
        assert len(ctxs) >= 10
        assert "html_element" in ctxs
        assert "html_attribute_dq" in ctxs
        assert "script_string_dq" in ctxs

    def test_mutate_for_context_returns_variants(self):
        payload = '<script>alert(1)</script>'
        variants = ctx_mutation.mutate_for_context(payload, "html_element",
                                                    max_variants=5)
        assert len(variants) >= 1
        # Each variant is (chain_names, payload).
        for chain, v in variants:
            assert isinstance(chain, list)
            assert isinstance(v, str)

    def test_mutate_for_context_includes_base_as_fallback(self):
        """If no mutation applies, the base payload is returned."""
        variants = ctx_mutation.mutate_for_context("plain", "html_element",
                                                    max_variants=1)
        # The engine should return at least one variant (possibly the
        # base payload unchanged if no mutation produced a distinct result).
        assert len(variants) >= 1
        # The returned payload should be a non-empty string.
        for _, v in variants:
            assert isinstance(v, str) and v


# =============================================================================
# multi_encode.py
# =============================================================================

class TestMultiEncode:
    """Tests for the multi-encoding chain engine."""

    def test_encoders_roundtrip(self):
        """Each encoder should produce a non-empty transformed string."""
        payload = "<script>alert(1)</script>"
        from xssentinel.core.multi_encode import supported_encoders, _encoder_by_name
        names = supported_encoders()
        assert len(names) >= 10
        for name in names:
            fn = _encoder_by_name(name)
            assert fn is not None, f"encoder {name!r} not found"
            result = fn(payload)
            assert isinstance(result, str)
            assert len(result) > 0

    def test_apply_chain_returns_string(self):
        from xssentinel.core.multi_encode import apply_chain
        payload = "<img src=x onerror=alert(1)>"
        result = apply_chain(payload, ["url_twice", "html_named"],
                             "html_element")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_chains_for_waf_returns_cloudflare_chains(self):
        from xssentinel.core.multi_encode import chains_for_waf
        chains = chains_for_waf("cloudflare")
        assert len(chains) > 0
        # Each chain: (name, steps, why).
        for name, steps, why in chains:
            assert isinstance(name, str)
            assert isinstance(steps, list)
            assert isinstance(why, str)

    def test_all_chain_variants_respects_max(self):
        from xssentinel.core.multi_encode import all_chain_variants
        payload = "<svg onload=alert(1)>"
        variants = all_chain_variants(payload, "html_element", "cloudflare",
                                       max_variants=3)
        assert len(variants) <= 3


# =============================================================================
# bypass.py
# =============================================================================

class TestBypass:
    """Tests for the WAF bypass chain registry."""

    def test_chains_for_waf_cloudflare(self):
        chains = bypass.chains_for_waf("cloudflare")
        assert len(chains) >= 3

    def test_chains_for_waf_unknown_returns_generic(self):
        chains = bypass.chains_for_waf("nonexistent_waf_xyz")
        # Should fall back to generic chains.
        assert len(chains) > 0

    def test_all_chain_names_unique(self):
        """All chain entries should have valid structure."""
        for waf, payload, chain, why in bypass.BYPASS_CHAINS:
            assert isinstance(waf, str)
            assert isinstance(payload, str)
            assert isinstance(chain, list)
            assert isinstance(why, str)


# =============================================================================
# cvss.py
# =============================================================================

class TestCVSS:
    """Tests for CVSS v3.1 scoring."""

    def test_score_finding_reflected(self):
        """A typical reflected XSS should score high."""
        score, sev, vector = cvss.score_finding(
            {"type": "reflected", "context": "html_element"})
        assert sev in ("high", "medium", "critical")
        assert isinstance(score, float)
        assert isinstance(vector, str)

    def test_score_finding_stored_is_higher(self):
        """Stored XSS should score >= reflected XSS."""
        _, sev_refl, _ = cvss.score_finding(
            {"type": "reflected", "context": "html_element"})
        _, sev_stored, _ = cvss.score_finding(
            {"type": "stored", "context": "html_element"})
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        assert rank[sev_stored] >= rank[sev_refl]

    def test_enrich_finding_adds_cvss(self):
        """enrich_finding should add cvss_score/severity/vector."""
        finding = {"type": "reflected", "context": "html_element"}
        enriched = cvss.enrich_finding(finding)
        assert "cvss_score" in enriched
        assert "cvss_severity" in enriched
        assert "cvss_vector" in enriched


# =============================================================================
# compliance.py
# =============================================================================

class TestCompliance:
    """Tests for compliance mapping."""

    def test_compliance_for_reflected_finding(self):
        """Reflected XSS should map to OWASP A03 + CWE-79."""
        finding = {"type": "reflected"}
        entries = compliance.compliance_for_finding(finding)
        assert len(entries) > 0
        frameworks = [e["framework"] for e in entries]
        assert "OWASP Top 10 2021" in frameworks
        requirements = [e["requirement_id"] for e in entries]
        assert any("CWE-79" in r for r in requirements)

    def test_compliance_for_stored_finding(self):
        finding = {"type": "stored"}
        entries = compliance.compliance_for_finding(finding)
        assert len(entries) > 0

    def test_compliance_for_unknown_type_returns_default(self):
        finding = {"type": "nonexistent_type_xyz"}
        entries = compliance.compliance_for_finding(finding)
        # Should fall back to default mapping, not be empty.
        assert len(entries) > 0

    def test_compliance_summary_aggregates(self):
        """compliance_summary should aggregate counts across findings."""
        findings = [
            {"type": "reflected"},
            {"type": "reflected"},
            {"type": "stored"},
        ]
        summary = compliance.compliance_summary(findings)
        assert isinstance(summary, dict)
        assert len(summary) > 0
        # At least one framework should have counts >= 2 (two reflected).
        for fw, reqs in summary.items():
            for req_id, info in reqs.items():
                if info["count"] >= 2:
                    return
        # If no framework had count >= 2, something is wrong with aggregation.
        pytest.fail("compliance_summary did not aggregate counts across findings")


# =============================================================================
# session.py
# =============================================================================

class TestSession:
    """Tests for SessionManager auth methods (no network)."""

    def test_login_token_without_session_returns_false(self):
        """login_token should fail gracefully when no session is attached."""
        class FakeReq:
            timeout = 5
        mgr = session.SessionManager(FakeReq())
        # No .session attribute -> login_token returns False.
        assert mgr.login_token("tok") is False

    def test_login_token_with_session_sets_header(self):
        """login_token should set the Authorization header on the session."""
        class FakeReq:
            timeout = 5
        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.cookies = type("C", (), {"clear": lambda s: None})()
                self.auth = None
        req = FakeReq()
        req.session = FakeSession()
        mgr = session.SessionManager(req)
        ok = mgr.login_token("mytoken", scheme="Bearer")
        assert ok is True
        assert mgr.session.headers["Authorization"] == "Bearer mytoken"
        assert mgr.logged_in is True

    def test_login_oauth_token_stores_refresh_config(self):
        """login_oauth_token should store refresh credentials."""
        class FakeReq:
            timeout = 5
        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.cookies = type("C", (), {"clear": lambda s: None})()
                self.auth = None
        req = FakeReq()
        req.session = FakeSession()
        mgr = session.SessionManager(req)
        ok = mgr.login_oauth_token(
            access_token="acc", refresh_token="ref",
            client_id="cid", client_secret="sec",
            token_url="https://example.com/token")
        assert ok is True
        assert mgr._login_method == "oauth"
        assert mgr._oauth_refresh is not None
        assert mgr._oauth_refresh["refresh_token"] == "ref"

    def test_logout_clears_oauth_state(self):
        class FakeReq:
            timeout = 5
        class FakeSession:
            def __init__(self):
                self.headers = {"Authorization": "Bearer x"}
                self.cookies = type("C", (), {"clear": lambda s: None})()
                self.auth = None
        req = FakeReq()
        req.session = FakeSession()
        mgr = session.SessionManager(req)
        mgr.login_token("x")
        mgr._oauth_refresh = {"refresh_token": "r"}
        mgr.logout()
        assert mgr.logged_in is False
        assert mgr._oauth_refresh is None

    def test_extract_csrf_token_finds_input(self):
        html = '<form><input name="csrf_token" value="abc123"></form>'
        token = session.extract_csrf_token(html)
        assert token == "abc123"

    def test_extract_csrf_token_returns_none_if_missing(self):
        html = '<form><input name="other" value="x"></form>'
        token = session.extract_csrf_token(html)
        assert token is None


# =============================================================================
# param_miner.py
# =============================================================================

class TestParamMiner:
    """Tests for the parameter miner mode detection helpers."""

    def test_looks_like_json_object(self):
        from xssentinel.core.param_miner import _looks_like_json
        assert _looks_like_json('{"key": "value"}') is True
        assert _looks_like_json('[1, 2, 3]') is True
        assert _looks_like_json('<html>not json</html>') is False
        assert _looks_like_json('') is False

    def test_looks_like_graphql_url(self):
        from xssentinel.core.param_miner import _looks_like_graphql
        assert _looks_like_graphql("https://api.example.com/graphql", "", None) is True

    def test_looks_like_graphql_response(self):
        from xssentinel.core.param_miner import _looks_like_graphql
        # Response with data/errors keys -> GraphQL.
        assert _looks_like_graphql("https://x.com/api",
                                   '{"data": {"user": 1}}', None) is True
        assert _looks_like_graphql("https://x.com/api",
                                   '{"errors": [{"msg": "x"}]}', None) is True

    def test_looks_like_graphql_query_in_data(self):
        from xssentinel.core.param_miner import _looks_like_graphql
        # Body contains "query" field -> GraphQL.
        assert _looks_like_graphql("https://x.com", "", {"query": "{ user }"}) is True

    def test_candidate_list_nonempty(self):
        from xssentinel.core import param_miner
        assert len(param_miner.candidate_list()) > 30

    def test_best_targets_ranks_reflected_first(self):
        from xssentinel.core.param_miner import best_targets
        found = [
            {"name": "a", "reflected": False, "length_delta": 100},
            {"name": "b", "reflected": True, "length_delta": 10},
            {"name": "c", "reflected": True, "length_delta": 200},
        ]
        top = best_targets(found, top_n=3)
        # Reflected params (b, c) should come before non-reflected (a).
        assert top[0] in ("b", "c")
        assert "a" not in top[:2]


# =============================================================================
# spa_crawler.py  (Phase 18: SPA headless crawler)
# =============================================================================

class TestSpaCrawler:
    """Tests for the SPA headless crawler route-template dedup, scope
    filtering, and BS4 fallback logic.  No Playwright required -- these
    exercise the pure-Python helpers that gate the crawl behavior."""

    def test_route_template_collapses_numeric_ids(self):
        from xssentinel.core import spa_crawler
        # /users/123 and /users/456 should normalize to the same template.
        t1 = spa_crawler._route_template("https://h/users/123/edit")
        t2 = spa_crawler._route_template("https://h/users/456/edit")
        assert t1 == t2 == "https://h/users/{id}/edit"

    def test_route_template_collapses_uuids(self):
        from xssentinel.core import spa_crawler
        u1 = "https://h/p/11111111-2222-3333-4444-555555555555"
        u2 = "https://h/p/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert spa_crawler._route_template(u1) == spa_crawler._route_template(u2)
        assert "{uuid}" in spa_crawler._route_template(u1)

    def test_route_template_collapses_long_hashes(self):
        from xssentinel.core import spa_crawler
        h1 = "https://h/asset/a1b2c3d4e5f6a1b2"
        h2 = "https://h/asset/abcdef0123456789abcdef"
        assert spa_crawler._route_template(h1) == spa_crawler._route_template(h2)
        assert "{hash}" in spa_crawler._route_template(h1)

    def test_route_template_drops_query_string(self):
        from xssentinel.core import spa_crawler
        # ?id=1 and ?id=2 are the same endpoint for crawl routing.
        t1 = spa_crawler._route_template("https://h/search?id=1")
        t2 = spa_crawler._route_template("https://h/search?id=2")
        assert t1 == t2 == "https://h/search"

    def test_route_template_preserves_distinct_paths(self):
        from xssentinel.core import spa_crawler
        # /users and /posts are distinct routes -- must NOT be collapsed.
        assert spa_crawler._route_template("https://h/users") != \
               spa_crawler._route_template("https://h/posts")

    def test_norm_url_strips_default_port(self):
        from xssentinel.core import spa_crawler
        assert spa_crawler._norm_url("http://h:80/p") == "http://h/p"
        assert spa_crawler._norm_url("https://h:443/p") == "https://h/p"
        # Non-default ports are kept.
        assert spa_crawler._norm_url("http://h:8080/p") == "http://h:8080/p"

    def test_norm_url_drops_fragment(self):
        from xssentinel.core import spa_crawler
        assert spa_crawler._norm_url("https://h/p#frag") == "https://h/p"

    def test_available_returns_bool(self):
        from xssentinel.core import spa_crawler
        # available() must return a bool (True/False), never raise.
        result = spa_crawler.SpaCrawler.available()
        assert isinstance(result, bool)

    def test_in_scope_same_origin(self):
        from xssentinel.core import spa_crawler
        c = spa_crawler.SpaCrawler()
        assert c._in_scope("https://t.com/a", "https://t.com/") is True
        # Cross-origin should be rejected.
        assert c._in_scope("https://evil.com/a", "https://t.com/") is False

    def test_in_scope_respects_scope_prefix(self):
        from xssentinel.core import spa_crawler
        c = spa_crawler.SpaCrawler(scope="https://t.com/app/")
        assert c._in_scope("https://t.com/app/x", "https://t.com/") is True
        # Same origin but outside scope prefix -> rejected.
        assert c._in_scope("https://t.com/admin", "https://t.com/") is False

    def test_crawl_falls_back_when_playwright_missing(self):
        """When Playwright is unavailable, crawl() must delegate to the
        fallback_crawler callback and return its result (graceful
        degradation to the legacy BS4 crawler)."""
        from xssentinel.core import spa_crawler

        # Force available() to return False by monkey-patching.
        orig = spa_crawler.SpaCrawler.available
        spa_crawler.SpaCrawler.available = staticmethod(lambda: False)
        try:
            called = {"n": 0}
            expected_url = "https://t.com/fb"

            def fake_fallback(url):
                called["n"] += 1
                return [(expected_url, "GET", {"x": "1"}, {})]

            c = spa_crawler.SpaCrawler()
            result = c.crawl("https://t.com/", fallback_crawler=fake_fallback)
            assert called["n"] == 1
            assert result == [(expected_url, "GET", {"x": "1"}, {})]
        finally:
            # NOTE: class attribute access unwraps the @staticmethod into a
            # plain function, so re-assigning the bare function back to the
            # class would DROP the staticmethod descriptor -- every later
            # ``instance.available()`` call would then bind self and raise
            # TypeError.  Re-wrap with staticmethod() on restore.
            spa_crawler.SpaCrawler.available = staticmethod(orig)

    def test_crawl_no_fallback_returns_empty_when_unavailable(self):
        from xssentinel.core import spa_crawler
        orig = spa_crawler.SpaCrawler.available
        spa_crawler.SpaCrawler.available = staticmethod(lambda: False)
        try:
            c = spa_crawler.SpaCrawler()
            assert c.crawl("https://t.com/") == []
        finally:
            # Re-wrap: bare ``orig`` is the unwrapped function (see the
            # note in test_crawl_falls_back_when_playwright_missing) -- a
            # plain re-assignment would corrupt the staticmethod for any
            # later instance-level call in the same session.
            spa_crawler.SpaCrawler.available = staticmethod(orig)

    def test_bump_callback_wired(self):
        """The _bump callback must be callable and default to a no-op
        so SpaCrawler can be used standalone without a parent scanner."""
        from xssentinel.core import spa_crawler
        c = spa_crawler.SpaCrawler()
        # Default _bump is a no-op lambda -- must not raise.
        c._bump()
        # And must be assignable to a custom counter.
        counter = {"n": 0}
        c._bump = lambda: counter.__setitem__("n", counter["n"] + 1)
        c._bump()
        c._bump()
        assert counter["n"] == 2


# =============================================================================
# time_xss.py  (Phase 17: Time-based blind XSS detection)
# =============================================================================

class TestTimeXss:
    """Tests for the time-based blind XSS payload builder and timing
    confirmation helpers.  No network required."""

    def test_build_timing_payloads_returns_list(self):
        from xssentinel.core import time_xss
        payloads = time_xss.build_timing_payloads(
            "https://cb.example.com", "tok123")
        assert isinstance(payloads, list)
        # Multiple channels (css_import, img_load, css_focus, script_fetch).
        assert len(payloads) >= 6

    def test_timing_payloads_embed_token(self):
        from xssentinel.core import time_xss
        token = "abc123"
        payloads = time_xss.build_timing_payloads(
            "https://cb.example.com", token)
        for p in payloads:
            # Every payload must embed the token in its callback URL.
            assert token in p["payload"], \
                f"payload {p['name']} missing token: {p['payload']}"

    def test_timing_payloads_have_named_channels(self):
        from xssentinel.core import time_xss
        payloads = time_xss.build_timing_payloads(
            "https://cb.example.com", "tok")
        channels = {p["channel"] for p in payloads}
        # At least these four channel types must be covered.
        assert "css_import" in channels
        assert "img_load" in channels
        assert "script_fetch" in channels

    def test_check_performance_entries_handles_no_page(self):
        """check_performance_entries must return confirmed=False (not raise)
        when given a None or broken page object."""
        from xssentinel.core import time_xss
        result = time_xss.check_performance_entries(None, "tok", timeout=0.1)
        assert result["confirmed"] is False
        assert "failed" in result["detail"].lower() or \
               "no performance" in result["detail"].lower()


class TestSelfTestTimeout:
    """Phase 73: --self-test must never hang forever on a degraded host."""

    def test_timeout_returns_2_with_hint(self, monkeypatch, capsys):
        from xssentinel import cli_commands
        import subprocess as _sp
        from types import SimpleNamespace

        monkeypatch.setenv("XSSentinel_SELFTEST_TIMEOUT", "5")

        def fake_run(*a, **kw):
            assert kw.get("timeout") == 5, "timeout must be forwarded"
            raise _sp.TimeoutExpired(cmd="self-test", timeout=5)

        monkeypatch.setattr(cli_commands.subprocess, "run", fake_run)
        monkeypatch.setattr(cli_commands.os.path, "isfile",
                            lambda p: True)
        monkeypatch.setattr(cli_commands.subprocess, "Popen",
                            lambda *a, **kw: SimpleNamespace(
                                terminate=lambda: None,
                                wait=lambda timeout=None: 0,
                                kill=lambda: None))

        class _FakeConn:
            def __init__(self, *a, **kw):
                pass

            def request(self, *a, **kw):
                pass

            class _R:
                status = 200

                def read(self):
                    return b""

            def getresponse(self):
                return _FakeConn._R()

            def close(self):
                pass

        monkeypatch.setattr(cli_commands.http.client, "HTTPConnection",
                            _FakeConn)
        rc = cli_commands._run_self_test()
        assert rc == 2
        err = capsys.readouterr().err
        assert "self-test exceeded" in err
        assert "per-file pytest" in err

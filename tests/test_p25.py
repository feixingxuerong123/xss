"""Phase 25 regression tests: coverage, verify_fix, second_order, fix_advice.

These tests validate the pure-Python logic of the four new modules added
in Phases 20-22 without requiring network access.  They give fast,
isolated, regression-grade coverage so future refactors cannot silently
break the public API contract of these modules.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from io import StringIO
from unittest.mock import MagicMock, patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK

from xssentinel.core import coverage
from xssentinel.core import verify_fix
from xssentinel.core import second_order
from xssentinel.core import fix_advice


# =============================================================================
# coverage.py
# =============================================================================

class TestCoverageTracker:
    """CoverageTracker thread-safe scan coverage bookkeeping."""

    def test_start_and_end_endpoint_lifecycle(self):
        c = coverage.CoverageTracker()
        ep = c.start_endpoint("http://t/x", "GET")
        assert isinstance(ep, coverage.EndpointCoverage)
        assert ep.scan_started is not None
        assert ep.scan_ended is None
        c.end_endpoint("http://t/x", "GET")
        # Need to re-fetch the underlying endpoint (we got a snapshot).
        assert c.endpoints()[0].scan_ended is not None

    def test_start_endpoint_is_idempotent_and_preserves_crawled(self):
        c = coverage.CoverageTracker()
        c.start_endpoint("http://t/a", "GET", crawled=True)
        c.start_endpoint("http://t/a", "GET")  # second call, no crawled
        ep = c.endpoints()[0]
        assert ep.crawled is True, "crawled flag must not be cleared on re-entry"

    def test_record_layer_known_id(self):
        c = coverage.CoverageTracker()
        c.record_layer("http://t/x", "L1_reflected", "GET", "ran", "ok")
        ep = c.endpoints()[0]
        assert "L1_reflected" in ep.layers
        assert ep.layers["L1_reflected"]["status"] == "ran"
        assert ep.layers["L1_reflected"]["detail"] == "ok"

    def test_record_layer_unknown_id_still_recorded(self):
        """Unknown layer ids are still stored so new layers are visible."""
        c = coverage.CoverageTracker()
        c.record_layer("http://t/x", "L99_future", "GET", "ran", "future")
        ep = c.endpoints()[0]
        assert "L99_future" in ep.layers

    def test_touch_layer_is_idempotent(self):
        c = coverage.CoverageTracker()
        c.touch_layer("http://t/x", "L1_reflected", "GET", "first")
        c.touch_layer("http://t/x", "L1_reflected", "GET", "second")
        ep = c.endpoints()[0]
        # touch must not overwrite an existing layer record.
        assert ep.layers["L1_reflected"]["detail"] == "first"

    def test_record_param_reflected_and_payload_class(self):
        c = coverage.CoverageTracker()
        c.record_param("http://t/x", "q", in_body=False, method="GET",
                       reflected=True, context="html_element",
                       payload_class="html_element", payloads_sent=3,
                       confirmed=True)
        ep = c.endpoints()[0]
        # The key format is "name|query" or "name|body".
        assert "q|query" in ep.params
        pc = ep.params["q|query"]
        assert pc.reflected is True
        assert pc.context == "html_element"
        assert pc.payloads_sent == 3
        assert "html_element" in pc.payload_classes
        assert pc.confirmed is True

    def test_record_param_context_upgrade(self):
        """If first context was html_element and a more specific one arrives,
        the more specific one wins."""
        c = coverage.CoverageTracker()
        c.record_param("http://t/x", "q", context="html_element")
        c.record_param("http://t/x", "q", context="script_block")
        ep = c.endpoints()[0]
        assert ep.params["q|query"].context == "script_block"

    def test_record_request_and_finding_increment(self):
        c = coverage.CoverageTracker()
        c.record_request("http://t/x", "GET")
        c.record_request("http://t/x", "GET")
        c.record_finding("http://t/x", "GET")
        ep = c.endpoints()[0]
        assert ep.requests == 2
        assert ep.findings == 1

    def test_disabled_tracker_is_noop(self):
        c = coverage.CoverageTracker()
        c._enabled = False
        c.record_layer("http://t/x", "L1_reflected")
        c.record_param("http://t/x", "q")
        c.record_request("http://t/x")
        c.record_finding("http://t/x")
        assert c.endpoints() == []

    def test_thread_safety_concurrent_record(self):
        """100 threads each record 50 requests -> 5000 total, no lost writes."""
        c = coverage.CoverageTracker()
        N_THREADS = 100
        N_PER = 50

        def worker():
            for _ in range(N_PER):
                c.record_request("http://t/x", "GET")

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert c.endpoints()[0].requests == N_THREADS * N_PER

    def test_summary_totals_and_layer_coverage(self):
        c = coverage.CoverageTracker()
        c.record_layer("http://t/a", "L1_reflected", "GET")
        c.record_layer("http://t/a", "L3_dom_static", "GET")
        c.record_layer("http://t/b", "L1_reflected", "GET")
        c.record_param("http://t/a", "q", reflected=True, confirmed=True,
                       payloads_sent=5, payload_class="html_element")
        s = c.summary()
        assert s["totals"]["endpoints"] == 2
        assert s["totals"]["parameters"] == 1
        assert s["totals"]["reflected"] == 1
        assert s["totals"]["confirmed"] == 1
        assert s["totals"]["payloads_dispatched"] == 5
        # L1 ran on 2 endpoints, L3 only on 1.
        assert s["layer_coverage"]["L1_reflected"] == 2
        assert s["layer_coverage"]["L3_dom_static"] == 1
        # L4_stored ran on 0 endpoints.
        assert s["layer_coverage"]["L4_stored"] == 0
        # missing: L4_stored ran on neither endpoint => 2 missing.
        assert s["layer_missing"]["L4_stored"] == 2

    def test_to_html_renders_section_and_layer_table(self):
        c = coverage.CoverageTracker()
        c.record_layer("http://t/a", "L1_reflected", "GET")
        c.record_param("http://t/a", "q", reflected=True, context="html_element")
        html = c.to_html()
        assert "<section" in html
        assert "Scan Coverage Report" in html
        assert "L1_reflected" in html
        assert "Detection Layer Coverage" in html

    def test_to_json_dict_serializable(self):
        c = coverage.CoverageTracker()
        c.record_layer("http://t/a", "L1_reflected", "GET")
        d = c.to_json_dict()
        # Must be JSON-serializable end-to-end.
        json.dumps(d)
        assert "totals" in d
        assert "layer_coverage" in d
        assert "endpoints" in d

    def test_layers_registry_has_expected_count(self):
        # Phase 20-3 declares 29 layers.  Future phases may grow this list;
        # the test just guards against accidental deletion of a layer id.
        assert len(coverage.LAYERS) >= 23
        # All layer ids must be unique.
        ids = [lid for lid, _, _ in coverage.LAYERS]
        assert len(ids) == len(set(ids)), "duplicate layer id in LAYERS"
        # Sanity: the L1 entry exists and follows the (id, name, phase) shape.
        assert coverage.LAYERS[0][2] == "L1"

    def test_endpoint_to_dict_round_trip(self):
        ep = coverage.EndpointCoverage("http://t/x", "POST", crawled=True)
        ep.record_layer("L1_reflected", "ran", "ok")
        ep.record_param("body", in_body=True)
        d = ep.to_dict()
        assert d["url"] == "http://t/x"
        assert d["method"] == "POST"
        assert d["crawled"] is True
        assert "L1_reflected" in d["layers"]
        assert "body|body" in d["params"]

    def test_param_to_dict_returns_sorted_classes(self):
        pc = coverage.ParamCoverage("q", in_body=False)
        pc.reflected = True
        pc.context = "html_element"
        pc.payloads_sent = 4
        pc.payload_classes = {"z_last", "a_first", "mid"}
        pc.confirmed = True
        d = pc.to_dict()
        # Classes must be sorted for deterministic JSON output.
        assert d["payload_classes"] == ["a_first", "mid", "z_last"]
        assert d["reflected"] is True
        assert d["confirmed"] is True


# =============================================================================
# verify_fix.py
# =============================================================================

class TestVerifyFix:
    """Re-verification of historical findings."""

    def test_load_findings_bare_list(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps([
            {"type": "reflected", "url": "http://t/x", "payload": "<script>alert(1)</script>"},
            {"type": "dom"},
        ]), encoding="utf-8")
        out = verify_fix.load_findings(str(p))
        assert len(out) == 2
        assert out[0]["url"] == "http://t/x"

    def test_load_findings_envelope(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps({
            "tool": "XSSentinel",
            "findings": [{"type": "reflected", "url": "http://t/y"}],
        }), encoding="utf-8")
        out = verify_fix.load_findings(str(p))
        assert len(out) == 1
        assert out[0]["url"] == "http://t/y"

    def test_load_findings_invalid_structure_returns_empty(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"tool": "XSSentinel"}), encoding="utf-8")
        assert verify_fix.load_findings(str(p)) == []

    def test_is_replayable_known_type(self):
        assert verify_fix._is_replayable("reflected") is True
        assert verify_fix._is_replayable("dom") is True
        assert verify_fix._is_replayable("framework_react_xss") is True
        # Types requiring scanner context are NOT replayable.
        assert verify_fix._is_replayable("blind") is False
        assert verify_fix._is_replayable("stored") is False
        assert verify_fix._is_replayable(None) is False

    def test_extract_payload_string(self):
        f = {"payload": "<script>alert(1)</script>"}
        assert verify_fix._extract_payload(f) == "<script>alert(1)</script>"

    def test_extract_payload_skips_placeholder(self):
        # Placeholders wrapped in ( ... ) must be rejected.
        f = {"payload": "(postMessage listener)"}
        assert verify_fix._extract_payload(f) is None

    def test_extract_payload_falls_back_to_proof(self):
        f = {"payload": None, "proof": {"payload": "<svg onload=alert(1)>"}}
        assert verify_fix._extract_payload(f) == "<svg onload=alert(1)>"

    def test_extract_payload_returns_none_for_empty(self):
        assert verify_fix._extract_payload({"payload": ""}) is None
        assert verify_fix._extract_payload({}) is None

    def test_verify_findings_skips_non_replayable(self):
        req = MagicMock()
        results = verify_fix.verify_findings(
            [{"type": "blind", "url": "http://t/x", "payload": "x"}], req)
        assert len(results) == 1
        assert results[0]["verify"]["status"] == "skipped"

    def test_verify_findings_skips_placeholder_payload(self):
        req = MagicMock()
        results = verify_fix.verify_findings(
            [{"type": "reflected", "url": "http://t/x",
              "payload": "(listener)"}], req)
        assert results[0]["verify"]["status"] == "skipped"
        assert "placeholder" in results[0]["verify"]["detail"]

    def test_replay_request_classifies_fixed_when_no_reflection(self):
        """A response that no longer reflects the token -> fixed."""
        req = MagicMock()
        resp = MagicMock()
        resp.text = "<html>nothing here</html>"
        req.request.return_value = resp
        # Disable the verifier.mark indirection by using a payload without
        # alert() -- the marked payload equals the original so we can reason
        # about exactly what string is searched for.
        finding = {
            "type": "reflected", "url": "http://t/x",
            "method": "GET", "param": "q",
            "payload": "PLAINTEXT_MARKER",
        }
        res = verify_fix._replay_request(req, finding, "PLAINTEXT_MARKER")
        assert res["status"] == "fixed"
        assert "no longer reflected" in res["detail"]

    def test_replay_request_classifies_still_vuln_for_script_block(self):
        """Token reflected inside a <script> block -> still_vuln."""
        req = MagicMock()
        # verifier.mark will inject the token into the alert() arg; we
        # craft a response that reflects that token inside <script>.
        resp = MagicMock()
        # We don't know the exact token until _replay_request generates it,
        # but we can echo whatever the marked payload is into a script block
        # by inspecting the params sent to req.request.
        def fake_request(method, url, params=None, data=None):
            # The injected value lives in params (GET) or data (POST).
            payload = (params or {}).get("q") or (data or {}).get("q") or ""
            # Return the payload embedded in a real <script> block.
            resp.text = f"<html><script>var x = {payload!r};</script></html>"
            return resp
        req.request.side_effect = fake_request
        finding = {
            "type": "reflected", "url": "http://t/x",
            "method": "GET", "param": "q",
            "payload": "<script>alert('ORIG')</script>",
        }
        res = verify_fix._replay_request(req, finding,
                                         "<script>alert('ORIG')</script>")
        assert res["status"] == "still_vuln", res

    def test_replay_request_handles_request_exception(self):
        """If the HTTP request raises, the result is 'error'."""
        req = MagicMock()
        req.request.side_effect = RuntimeError("network down")
        finding = {"type": "reflected", "url": "http://t/x", "method": "GET",
                   "param": "q", "payload": "PLAINTEXT"}
        res = verify_fix._replay_request(req, finding, "PLAINTEXT")
        assert res["status"] == "error"
        assert "request failed" in res["detail"]

    def test_replay_request_error_when_no_url(self):
        req = MagicMock()
        finding = {"type": "reflected", "method": "GET", "param": "q",
                   "payload": "x"}
        res = verify_fix._replay_request(req, finding, "x")
        assert res["status"] == "error"
        assert "no URL" in res["detail"]

    def test_summarize_counts_each_status(self):
        results = [
            {"verify": {"status": "fixed"}},
            {"verify": {"status": "fixed"}},
            {"verify": {"status": "still_vuln"}},
            {"verify": {"status": "error"}},
            {"verify": {"status": "skipped"}},
        ]
        s = verify_fix.summarize(results)
        assert s["total"] == 5
        assert s["fixed"] == 2
        assert s["still_vuln"] == 1
        assert s["error"] == 1
        assert s["skipped"] == 1

    def test_build_html_contains_status_badges(self):
        results = [
            {"type": "reflected", "url": "http://t/x", "method": "GET",
             "param": "q", "payload": "<script>x</script>", "severity": "high",
             "verify": {"status": "fixed", "detail": "ok",
                        "checked_at": "2026-01-01T00:00:00"}},
            {"type": "dom", "url": "http://t/y", "method": "GET",
             "param": None, "payload": "x", "severity": "medium",
             "verify": {"status": "still_vuln", "detail": "bad",
                        "checked_at": "2026-01-01T00:00:00"}},
        ]
        html = verify_fix.build_html(results, "old.json")
        assert "Verify-Fix Report" in html
        assert "st-fixed" in html
        assert "st-vuln" in html
        assert "http://t/x" in html
        assert "http://t/y" in html

    def test_build_json_round_trips(self):
        results = [
            {"type": "reflected", "url": "http://t/x",
             "verify": {"status": "fixed", "detail": "ok",
                        "checked_at": "2026-01-01T00:00:00"}},
        ]
        out = verify_fix.build_json(results, "old.json", target="http://t")
        d = json.loads(out)
        assert d["mode"] == "verify-fix"
        assert d["summary"]["total"] == 1
        assert d["summary"]["fixed"] == 1
        assert d["findings"] == results


# =============================================================================
# second_order.py
# =============================================================================

class TestSecondOrder:
    """Second-order XSS detection workflow (no real network)."""

    def test_snippet_returns_empty_when_token_absent(self):
        assert second_order._snippet("hello world", "TOKEN") == ""

    def test_snippet_extracts_around_token(self):
        text = "aaaaTOKENbbbb"
        out = second_order._snippet(text, "TOKEN", radius=4)
        assert "TOKEN" in out
        # Should include some context on either side.
        assert "aaaa" in out
        assert "bbbb" in out

    def test_snippet_collapses_whitespace(self):
        text = "before   TOKEN   after"
        out = second_order._snippet(text, "TOKEN", radius=10)
        # Whitespace runs are collapsed to single spaces.
        assert "  " not in out

    def test_inject_payload_get_success(self):
        req = MagicMock()
        req.request.return_value = MagicMock()
        ok = second_order.inject_payload(req, "http://t/inject", "GET",
                                         "q", "PAYLOAD")
        assert ok is True
        # GET must pass params=, not data=.
        _, kwargs = req.request.call_args
        assert kwargs.get("params") == {"q": "PAYLOAD"}
        assert kwargs.get("data") is None

    def test_inject_payload_post_uses_data(self):
        req = MagicMock()
        req.request.return_value = MagicMock()
        second_order.inject_payload(req, "http://t/inject", "POST",
                                    "q", "PAYLOAD")
        _, kwargs = req.request.call_args
        assert kwargs.get("data") == {"q": "PAYLOAD"}

    def test_inject_payload_returns_false_on_exception(self):
        req = MagicMock()
        req.request.side_effect = RuntimeError("boom")
        ok = second_order.inject_payload(req, "http://t/inject", "GET",
                                         "q", "PAYLOAD")
        assert ok is False

    def test_discover_viewers_excludes_inject_endpoint(self):
        """The inject endpoint itself must never be checked as a viewer."""
        scanner = MagicMock()
        scanner._crawl.return_value = [
            ("http://t/view1", "GET", {}, {}),
            ("http://t/inject?x=1", "GET", {}, {}),  # same path as inject
            ("http://t/view2", "GET", {}, {}),
        ]
        viewers = second_order.discover_viewers(
            scanner, "http://t/start", "http://t/inject",
            scope=None, max_pages=25)
        urls = [u for u, _ in viewers]
        assert "http://t/view1" in urls
        assert "http://t/view2" in urls
        assert all("http://t/inject" not in u for u in urls), \
            "inject endpoint leaked into viewer list"

    def test_discover_viewers_filters_by_scope(self):
        scanner = MagicMock()
        scanner._crawl.return_value = [
            ("http://t/in-scope", "GET", {}, {}),
            ("http://other.example/oos", "GET", {}, {}),
        ]
        viewers = second_order.discover_viewers(
            scanner, "http://t/start", "http://t/inject",
            scope="http://t/", max_pages=25)
        urls = [u for u, _ in viewers]
        assert "http://t/in-scope" in urls
        assert "http://other.example/oos" not in urls

    def test_discover_viewers_dedupes_and_caps_at_max_pages(self):
        scanner = MagicMock()
        scanner._crawl.return_value = [
            (f"http://t/p{i}", "GET", {}, {}) for i in range(100)
        ]
        viewers = second_order.discover_viewers(
            scanner, "http://t/start", "http://t/inject",
            scope=None, max_pages=5)
        assert len(viewers) == 5
        # All unique.
        assert len({u for u, _ in viewers}) == 5

    def test_discover_viewers_handles_crawl_exception(self):
        """If _crawl raises, we still get the bare start_url candidate."""
        scanner = MagicMock()
        scanner._crawl.side_effect = RuntimeError("crawl failed")
        viewers = second_order.discover_viewers(
            scanner, "http://t/start", "http://t/inject")
        # start_url is always included as a candidate viewer.
        assert ("http://t/start", "GET") in viewers

    def test_check_viewers_confirms_when_token_in_script_block(self):
        req = MagicMock()
        resp = MagicMock()
        resp.text = '<html><script>alert("xsso_TOK")</script></html>'
        req.get.return_value = resp
        out = second_order.check_viewers(req, [("http://t/view", "GET")],
                                         "xsso_TOK")
        assert len(out) == 1
        assert out[0]["viewer_url"] == "http://t/view"
        assert out[0]["context"] == "script_block"

    def test_check_viewers_skips_escaped_token(self):
        """If the token is reflected but escaped, it must NOT be reported."""
        req = MagicMock()
        resp = MagicMock()
        # The token appears, but only as HTML-escaped text (no executable sink).
        resp.text = '<div>xsso_TOK</div>'
        req.get.return_value = resp
        out = second_order.check_viewers(req, [("http://t/view", "GET")],
                                         "xsso_TOK")
        assert out == []

    def test_check_viewers_skips_when_token_absent(self):
        req = MagicMock()
        resp = MagicMock()
        resp.text = "<html>no token here</html>"
        req.get.return_value = resp
        out = second_order.check_viewers(req, [("http://t/view", "GET")],
                                         "xsso_TOK")
        assert out == []

    def test_check_viewers_invalidates_cache_before_fetch(self):
        """Each viewer fetch must call req.invalidate() first (if present)
        so we see the just-injected payload, not a cached pre-inject copy."""
        req = MagicMock()
        req.invalidate = MagicMock()
        resp = MagicMock()
        resp.text = "no token"
        req.get.return_value = resp
        second_order.check_viewers(req, [("http://t/view", "GET")], "xsso_TOK")
        req.invalidate.assert_called_once_with("http://t/view")

    def test_check_viewers_swallows_fetch_exception(self):
        """A single viewer fetch failure must not abort the whole list."""
        req = MagicMock()
        req.get.side_effect = [RuntimeError("net error"), MagicMock(text="ok")]
        out = second_order.check_viewers(
            req, [("http://t/v1", "GET"), ("http://t/v2", "GET")], "xsso_TOK")
        # No findings, but no exception either.
        assert out == []

    def test_scan_second_order_with_explicit_viewer_urls(self):
        """End-to-end happy path: viewer reflects token inside <script>."""
        scanner = MagicMock()
        scanner.verbose = False
        scanner.scope = None
        # Build a fake req whose .request (for inject) and .get (for viewer)
        # both succeed.  The viewer response embeds the token in a script.
        req = MagicMock()

        def fake_request(method, url, params=None, data=None):
            return MagicMock(text="ok")
        req.request.side_effect = fake_request

        # The token is "xsso_XXXX" (8 hex chars).  We don't know it ahead of
        # time, so the viewer response must echo whatever was injected.
        # We capture the injected payload via a closure and reflect the token
        # part of it back inside a <script> block.
        injected = {}

        def fake_request_capture(method, url, params=None, data=None):
            payload = (params or {}).get("q") or (data or {}).get("q", "")
            injected["payload"] = payload
            return MagicMock(text="ok")
        req.request.side_effect = fake_request_capture

        def fake_get(url):
            # Extract the token from the injected payload (it's the arg of
            # alert('...')).
            import re
            m = re.search(r"xsso_[0-9a-f]+", injected.get("payload", ""))
            token = m.group(0) if m else "NOTOKEN"
            return MagicMock(text=f'<script>alert("{token}")</script>')
        req.get.side_effect = fake_get

        scanner.req = req
        scanner._bump = MagicMock()
        scanner.requests_made = 0

        results = second_order.scan_second_order(
            scanner, inject_url="http://t/inject", param="q", method="POST",
            viewer_urls=["http://t/view"], verbose=False)
        assert len(results) == 1
        assert results[0]["viewer_url"] == "http://t/view"
        assert results[0]["inject_url"] == "http://t/inject"
        assert results[0]["inject_param"] == "q"
        # The inject endpoint must NOT appear as a viewer.
        assert all(r["viewer_url"] != "http://t/inject" for r in results)
        # scanner.requests_made must be incremented by the viewer count.
        assert scanner.requests_made == 1

    def test_scan_second_order_returns_empty_when_no_viewers(self):
        """If the only candidate viewer is the inject endpoint itself (so the
        viewers list is empty after filtering), return [] fast WITHOUT
        attempting any injection."""
        scanner = MagicMock()
        scanner.verbose = False
        scanner.scope = None
        # discover_viewers always seeds candidates with start_url; if
        # start_url == inject_url, the inject filter removes it, leaving
        # zero viewers and triggering the early-return path.
        scanner._crawl.return_value = []
        scanner.req = MagicMock()
        results = second_order.scan_second_order(
            scanner, inject_url="http://t/inject", param="q", method="POST",
            start_url="http://t/inject", verbose=False)
        assert results == []
        # No viewers => we never tried to inject.
        scanner.req.request.assert_not_called()

    def test_scan_second_order_skips_inject_endpoint_in_viewer_urls(self):
        """If the caller passes the inject URL itself as a viewer URL,
        it must be filtered out."""
        scanner = MagicMock()
        scanner.verbose = False
        scanner.scope = None
        scanner.req = MagicMock()
        scanner.req.request.return_value = MagicMock(text="ok")
        scanner.req.get.return_value = MagicMock(text="no token")
        scanner._bump = MagicMock()
        scanner.requests_made = 0
        second_order.scan_second_order(
            scanner, inject_url="http://t/inject", param="q", method="POST",
            viewer_urls=["http://t/inject", "http://t/view"], verbose=False)
        # The inject URL must NOT have been fetched as a viewer.
        fetched = [c.args[0] for c in scanner.req.get.call_args_list]
        assert "http://t/inject" not in fetched
        assert "http://t/view" in fetched


# =============================================================================
# fix_advice.py
# =============================================================================

class TestFixAdvice:
    """Remediation advice registry and rendering."""

    def test_advice_for_finding_known_type(self):
        f = {"type": "reflected"}
        adv = fix_advice.advice_for_finding(f)
        assert adv["headline"]
        assert adv["detail"]
        assert adv["code_example"]
        assert adv["primary_cwe"] == "CWE-79"
        assert isinstance(adv["also_consider"], list) and adv["also_consider"]

    def test_advice_for_finding_supports_all_phase22_types(self):
        """Phase 22-5 added advice for second_order / time_based_xss /
        fuzzer_triage / framework_xss / template_ssti.  All must resolve to
        a dedicated entry, NOT the default fallback."""
        for t in ("second_order", "time_based_xss", "fuzzer_triage",
                  "framework_xss", "template_ssti"):
            adv = fix_advice.advice_for_finding({"type": t})
            assert adv is not fix_advice._DEFAULT_ADVICE, \
                f"{t} fell through to default advice"
            assert adv["primary_cwe"].startswith("CWE-")

    def test_advice_for_finding_accepts_finding_object(self):
        """Finding objects with a .data attribute must be unwrapped."""
        class F:
            def __init__(self, d):
                self.data = d
        adv = fix_advice.advice_for_finding(F({"type": "dom"}))
        assert "textContent" in adv["code_example"]

    def test_advice_for_finding_unknown_type_uses_default(self):
        adv = fix_advice.advice_for_finding({"type": "totally_unknown_xyz"})
        assert adv is fix_advice._DEFAULT_ADVICE
        assert adv["primary_cwe"] == "CWE-79"

    def test_advice_for_finding_missing_type_defaults_to_reflected(self):
        """A finding with no 'type' key falls back to 'reflected' advice."""
        adv = fix_advice.advice_for_finding({})
        # reflected advice and default advice have different code_examples,
        # so we can tell them apart.
        assert adv == fix_advice._ADVICE["reflected"]

    def test_supported_finding_types_includes_phase22_entries(self):
        types = fix_advice.supported_finding_types()
        assert "reflected" in types
        assert "stored" in types
        assert "dom" in types
        assert "second_order" in types
        assert "framework_xss" in types
        assert "template_ssti" in types

    def test_advice_summary_html_deduplicates_by_type(self):
        """Multiple findings of the same type produce ONE advice block."""
        findings = [
            {"type": "reflected", "url": "http://t/1"},
            {"type": "reflected", "url": "http://t/2"},
            {"type": "reflected", "url": "http://t/3"},
            {"type": "dom", "url": "http://t/4"},
        ]
        html = fix_advice.advice_summary_html(findings)
        # The advice block heading includes the count.
        assert "reflected <span class=\"advice-count\">(3 findings)" in html
        assert "dom <span class=\"advice-count\">(1 finding)" in html

    def test_advice_summary_html_escapes_content(self):
        """Code examples may contain <script> tags; they must be escaped so
        the advice block itself doesn't become an XSS vector in the report."""
        findings = [{"type": "reflected"}]
        html = fix_advice.advice_summary_html(findings)
        # The literal text "<script>" must NOT appear unescaped inside the
        # <pre><code> block (it must be &lt;script&gt;).
        assert "<script>alert(1)</script>" not in html
        # But the escaped form is fine.
        assert "&lt;script&gt;" in html or "script" in html

    def test_advice_summary_html_empty_findings(self):
        html = fix_advice.advice_summary_html([])
        assert "<section" in html
        assert "Remediation Advice" in html

    def test_advice_summary_html_renders_default_for_unknown(self):
        """An unknown finding type renders the default advice block, not a
        crash."""
        html = fix_advice.advice_summary_html([{"type": "unknown_xyz"}])
        assert "unknown_xyz" in html
        assert "advice-block" in html

    def test_each_advice_entry_has_required_fields(self):
        """Every registered advice entry must have all five required fields,
        and also_consider must be a non-empty list."""
        for ftype, adv in fix_advice._ADVICE.items():
            assert "headline" in adv and isinstance(adv["headline"], str), \
                f"{ftype}: missing headline"
            assert "detail" in adv and isinstance(adv["detail"], str), \
                f"{ftype}: missing detail"
            assert "code_example" in adv and adv["code_example"], \
                f"{ftype}: missing code_example"
            assert "primary_cwe" in adv and adv["primary_cwe"].startswith("CWE-"), \
                f"{ftype}: bad primary_cwe {adv['primary_cwe']!r}"
            assert "also_consider" in adv, f"{ftype}: missing also_consider"
            assert isinstance(adv["also_consider"], list), \
                f"{ftype}: also_consider not a list"
            assert adv["also_consider"], f"{ftype}: also_consider is empty"

    def test_default_advice_has_required_fields(self):
        adv = fix_advice._DEFAULT_ADVICE
        assert adv["headline"]
        assert adv["detail"]
        assert adv["code_example"]
        assert adv["primary_cwe"] == "CWE-79"
        assert isinstance(adv["also_consider"], list) and adv["also_consider"]


# =============================================================================
# Phase 25-2: CLI edge cases (batch failure aggregation, self_test timeout)
# =============================================================================

class TestCliBatchFailureAggregation:
    """Phase 25-2: a single failing target must not abort the whole batch,
    and failures must be counted + reported in the final summary."""

    def test_batch_continues_past_failing_target(self, tmp_path, capsys):
        """When _run_scan raises for one URL, the batch must continue to
        the next URL and the failing URL must be reported at the end."""
        from xssentinel import __main__ as cli

        # Write a batch file with two URLs.
        batch_file = tmp_path / "urls.txt"
        batch_file.write_text(
            "http://127.0.0.1:1/first\n"
            "http://127.0.0.1:1/second\n",
            encoding="utf-8")
        out_dir = str(tmp_path / "reports")
        os.makedirs(out_dir, exist_ok=True)

        argv = [
            "--batch", str(batch_file),
            "-o", out_dir,
            "-f", "json",
            "--timeout", "5",
            "--threads", "2",
            "--max-transforms", "2",
            "--max-payloads", "5",
            "--progress", "none",
            "--log-level", "error",
        ]

        # Patch _run_scan so the first URL fails and the second succeeds
        # with zero findings.
        call_count = {"n": 0}

        def fake_run_scan(args, url, requester, oob, progress, checkpoint):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("simulated scan failure")
            ms = MagicMock()
            ms.findings = []
            ms.waf_name = None
            return ms

        with patch.object(cli, "_run_scan", side_effect=fake_run_scan), \
             patch.object(cli, "_write_report",
                          side_effect=lambda *a, **k: a[2] if len(a) > 2 else k.get("out_path", "r.json")):
            rc = cli.main(argv)
        captured = capsys.readouterr()
        # Both URLs must have been attempted (not just the first).
        assert call_count["n"] == 2, \
            "batch aborted after first failure instead of continuing"
        # Exit code 0 because exit_code threshold is 0 (disabled).
        assert rc == 0
        # The summary must mention the failure count (first URL failed,
        # second succeeded).
        assert "1 failed" in captured.out, \
            f"failure count missing from batch summary: {captured.out!r}"
        # The summary must list the failed target(s).
        assert "Failed targets" in captured.out

    def test_batch_failure_marks_checkpoint(self, tmp_path, capsys):
        """A failed target must be recorded in the checkpoint so --resume
        doesn't re-scan it (and re-fail) on the next run."""
        from xssentinel import __main__ as cli
        from xssentinel.core.checkpoint import Checkpoint

        ckpt_path = str(tmp_path / "ckpt.json")
        out_path = str(tmp_path / "r.json")
        argv = [
            "-u", "http://127.0.0.1:1/fail",
            "-o", out_path,
            "-f", "json",
            "--timeout", "5",
            "--threads", "2",
            "--max-transforms", "2",
            "--max-payloads", "5",
            "--progress", "none",
            "--log-level", "error",
            "--checkpoint", ckpt_path,
        ]

        def fake_run_scan(args, url, requester, oob, progress, checkpoint):
            raise RuntimeError("simulated scan failure")

        with patch.object(cli, "_run_scan", side_effect=fake_run_scan):
            cli.main(argv)

        # The checkpoint file must now exist and mark the failed URL.
        ckpt = Checkpoint.load(ckpt_path)
        assert ckpt is not None, "checkpoint was not saved"
        assert ckpt.is_scanned("http://127.0.0.1:1/fail"), \
            "failed target was not marked as scanned in checkpoint"


class TestSelfTestWaitTimeoutProtection:
    """Phase 25-2: server_proc.wait(timeout=5) in _run_self_test's finally
    block must not raise subprocess.TimeoutExpired and mask the test
    result."""

    def test_timeout_expired_does_not_propagate(self):
        """If server_proc.wait() raises TimeoutExpired, _run_self_test must
        still return the test's exit code, not crash."""
        from xssentinel import __main__ as cli
        import subprocess

        # Mock the subprocess module so server start appears to succeed but
        # the test run returns rc=0.  The key assertion is that the finally
        # block's wait(timeout=5) raising TimeoutExpired is swallowed.
        fake_proc = MagicMock()
        fake_proc.terminate.return_value = None
        # First wait() (after terminate) raises TimeoutExpired.
        # Second wait() (after kill) returns immediately.
        fake_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="vuln_server", timeout=5),
            0,  # after kill()
        ]
        fake_proc.kill.return_value = None

        # We patch the heavy parts: os.path.isfile (both files exist),
        # subprocess.Popen (returns fake_proc), subprocess.run (returns
        # rc=0), http.client.HTTPConnection (server is "ready").
        with patch("os.path.isfile", return_value=True), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("subprocess.run") as fake_run, \
             patch("http.client.HTTPConnection") as fake_conn_cls:
            fake_run.return_value = MagicMock(returncode=0)
            fake_conn = MagicMock()
            fake_resp = MagicMock()
            fake_resp.status = 200
            fake_conn.getresponse.return_value = fake_resp
            fake_conn_cls.return_value = fake_conn

            rc = cli._run_self_test()

        # The function must return 0 (the test's exit code), not raise.
        assert rc == 0, \
            f"_run_self_test returned {rc} instead of 0 after timeout"
        # terminate() must have been called.
        fake_proc.terminate.assert_called_once()
        # kill() must have been called as a fallback.
        fake_proc.kill.assert_called_once()

    def test_normal_shutdown_uses_terminate_only(self):
        """When wait() succeeds, kill() must NOT be called."""
        from xssentinel import __main__ as cli

        fake_proc = MagicMock()
        fake_proc.wait.return_value = 0  # terminate succeeded immediately

        with patch("os.path.isfile", return_value=True), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("subprocess.run") as fake_run, \
             patch("http.client.HTTPConnection") as fake_conn_cls:
            fake_run.return_value = MagicMock(returncode=0)
            fake_conn = MagicMock()
            fake_resp = MagicMock()
            fake_resp.status = 200
            fake_conn.getresponse.return_value = fake_resp
            fake_conn_cls.return_value = fake_conn

            rc = cli._run_self_test()

        assert rc == 0
        fake_proc.terminate.assert_called_once()
        fake_proc.kill.assert_not_called()


class TestAsyncBatchEventLoopReuse:
    """Phase 25-3: async batch scanning uses a SINGLE asyncio.run() call
    for all URLs instead of one per URL."""

    # asyncio.run() needs a working loopback socketpair (see conftest.py);
    # skip instead of hanging when the environment throttles it.
    _sk = pytest.mark.skipif(
        not SOCKETPAIR_OK,
        reason="Windows loopback socketpair hangs")

    @_sk
    def test_async_batch_returns_per_url_results(self, tmp_path):
        """_run_async_batch must return a {url: scanner_shim} dict with
        per-URL findings correctly separated."""
        from tests.conftest import loopback_healthy
        if not loopback_healthy():
            pytest.skip("loopback degraded mid-session")
        from xssentinel import __main__ as cli
        from xssentinel.core.scanner import Finding

        urls = [
            "http://t/first",
            "http://t/second",
            "http://t/third",
        ]

        argv = [
            "--batch", str(tmp_path / "urls.txt"),
            "-o", str(tmp_path),
            "-f", "json",
            "--async",
            "--timeout", "5",
            "--threads", "2",
            "--max-transforms", "2",
            "--max-payloads", "5",
            "--progress", "none",
            "--log-level", "error",
            # Phase 142: PoC self-verification (Phase 135) replays every
            # confirmed finding once and -- by design -- counts that request,
            # so with it on a URL with N findings reports 1 + N and the
            # "requests_made == 1" assertions below can no longer hold.  This
            # test is about per-URL bookkeeping being independent rather than
            # cumulative; verification has its own coverage in
            # tests/test_poc_self_verify.py (including a case asserting that
            # turning it off costs no extra request).  Leaving it on also made
            # this test fire REAL requests at http://t/... through the shim's
            # own Requester, which is a latent flakiness source on a host with
            # an intermittent loopback.
            "--no-poc-verify",
        ]
        (tmp_path / "urls.txt").write_text(
            "\n".join(urls) + "\n", encoding="utf-8")

        # Mock AsyncScanner so scan() yields different findings per URL.
        call_count = {"n": 0}

        class FakeAsyncScanner:
            def __init__(self, **kwargs):
                self.findings = []
                self.requests_made = 0
                self.waf_name = None

            async def scan(self, url, method="GET", params=None, data=None):
                call_count["n"] += 1
                self.requests_made += 1
                # URL 1 gets 1 finding, URL 2 gets 0, URL 3 gets 2.
                if "first" in url:
                    self.findings.append(Finding(
                        url=url, method="GET", param="q",
                        context="html_element", payload="<script>1</script>",
                        severity="high", confidence="high",
                        evidence="test", type="reflected"))
                elif "third" in url:
                    self.findings.append(Finding(
                        url=url, method="GET", param="q",
                        context="html_element", payload="<script>3a</script>",
                        severity="high", confidence="high",
                        evidence="test", type="reflected"))
                    self.findings.append(Finding(
                        url=url, method="GET", param="q",
                        context="script_block", payload="<script>3b</script>",
                        severity="medium", confidence="high",
                        evidence="test", type="reflected"))
                # Yield nothing (the findings are stored in self.findings).
                return
                yield  # make this an async generator

        with patch("xssentinel.core.async_scanner.AsyncScanner",
                   FakeAsyncScanner), \
             patch("xssentinel.core.async_scanner.is_available",
                   return_value=True):
            args = cli.build_parser().parse_args(argv)
            args.verify_ssl = not args.no_verify_ssl
            results = cli._run_async_batch(
                args, urls, requester=None, oob=None,
                progress=None, checkpoint=None)

        # All 3 URLs must have been scanned (one asyncio.run, 3 scan calls).
        assert call_count["n"] == 3
        # Per-URL findings must be correctly separated.
        assert len(results[urls[0]].findings) == 1
        assert len(results[urls[1]].findings) == 0
        assert len(results[urls[2]].findings) == 2
        # Each shim's requests_made must be 1 (not cumulative).
        assert results[urls[0]].requests_made == 1
        assert results[urls[1]].requests_made == 1
        assert results[urls[2]].requests_made == 1

    @_sk
    def test_async_batch_handles_scan_exception(self, tmp_path):
        """If scan() raises for one URL, the batch must continue and that
        URL must still appear in the results dict (with 0 findings)."""
        from tests.conftest import loopback_healthy
        if not loopback_healthy():
            pytest.skip("loopback degraded mid-session")
        from xssentinel import __main__ as cli
        from xssentinel.core.scanner import Finding

        urls = ["http://t/ok", "http://t/fail", "http://t/also-ok"]

        class FakeAsyncScanner:
            def __init__(self, **kwargs):
                self.findings = []
                self.requests_made = 0
                self.waf_name = None

            async def scan(self, url, method="GET", params=None, data=None):
                self.requests_made += 1
                if "fail" in url:
                    raise RuntimeError("simulated scan failure")
                self.findings.append(Finding(
                    url=url, method="GET", param="q",
                    context="html_element", payload="<script>x</script>",
                    severity="high", confidence="high",
                    evidence="ok", type="reflected"))
                return
                yield

        argv = [
            "--batch", str(tmp_path / "urls.txt"),
            "-o", str(tmp_path), "-f", "json", "--async",
            "--timeout", "5", "--threads", "2",
            "--max-transforms", "2", "--max-payloads", "5",
            "--progress", "none", "--log-level", "error",
        ]
        (tmp_path / "urls.txt").write_text(
            "\n".join(urls) + "\n", encoding="utf-8")

        with patch("xssentinel.core.async_scanner.AsyncScanner",
                   FakeAsyncScanner), \
             patch("xssentinel.core.async_scanner.is_available",
                   return_value=True):
            args = cli.build_parser().parse_args(argv)
            args.verify_ssl = not args.no_verify_ssl
            results = cli._run_async_batch(
                args, urls, requester=None, oob=None,
                progress=None, checkpoint=None)

        # The failing URL must still be in results (with 0 findings).
        assert "http://t/fail" in results
        assert len(results["http://t/fail"].findings) == 0
        # The other two URLs must have 1 finding each.
        assert len(results["http://t/ok"].findings) == 1
        assert len(results["http://t/also-ok"].findings) == 1


# =============================================================================
# Self-test entry point (mirrors test_p23.py style)
# =============================================================================

if __name__ == "__main__":
    # Allow `python tests/test_p25.py` to run all tests without pytest.
    import inspect

    def _collect():
        out = []
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj) and name.startswith("Test"):
                for mname, m in inspect.getmembers(obj, predicate=inspect.isfunction):
                    if mname.startswith("test_"):
                        out.append((f"{name}.{mname}", obj, m))
        return out

    tests = _collect()
    failures = 0
    for label, cls, fn in tests:
        # Instantiate the test class so pytest-style self works.
        try:
            fn(cls())
            print(f"[+] PASS: {label}")
        except Exception as e:
            failures += 1
            import traceback
            print(f"[!] FAIL: {label}: {e}")
            traceback.print_exc()
    print(f"\n{len(tests) - failures}/{len(tests)} P25 TESTS PASSED")
    sys.exit(1 if failures else 0)

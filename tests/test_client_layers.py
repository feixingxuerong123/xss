"""Tests for the client-side advanced detection layers (Phase 43).

client_layers.py is ORCHESTRATION: each ``_scan_*`` feeds the page HTML to its
analyzer module and turns a positive result into a ``Finding`` + coverage
record.  We mock the analyzer (``*_mod.analyze_page``) so the orchestration
logic (report gating, severity filtering, exception safety, coverage writes)
is tested deterministically without needing pages that actually trip each
analyzer's heuristics.
"""
from __future__ import annotations
import os
import sys
from unittest.mock import patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.layers import client_layers as cl

PKG = "xssentinel.core.layers.client_layers"


class _MockCoverage:
    def __init__(self):
        self.layers = []
        self.findings = []

    def touch_layer(self, url, layer, method, detail=None):
        self.layers.append(layer)

    def record_finding(self, url, method):
        self.findings.append((url, method))

    def record_request(self, url, method):
        pass


class _MockScanner:
    def __init__(self):
        self.coverage = _MockCoverage()
        self.added = []
        self.verbose = False
        self.req = None

    def _add(self, finding):
        self.added.append(finding)

    def _bump(self):
        pass


def _ftype(f):
    d = f.data if hasattr(f, "data") else f
    return d.get("type")


class TestPostMessage:
    def test_vulnerable_listener_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.pm_mod") as m:
            m.analyze_page.return_value = {
                "vulnerable_count": 1,
                "listeners": [{"sinks_found": ["innerHTML"], "snippet": "..."}],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_postmessage(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "postmessage_xss"
        assert "L8_postmessage" in sc.coverage.layers
        assert sc.coverage.findings  # finding recorded in coverage

    def test_no_listener_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.pm_mod") as m:
            m.analyze_page.return_value = {"vulnerable_count": 0,
                                           "listeners": []}
            cl._scan_postmessage(sc, "http://h/", "<html></html>")
        assert sc.added == []
        assert "L8_postmessage" in sc.coverage.layers  # layer still touched

    def test_analyzer_exception_swallowed(self):
        sc = _MockScanner()
        with patch(f"{PKG}.pm_mod") as m:
            m.analyze_page.side_effect = RuntimeError("boom")
            cl._scan_postmessage(sc, "http://h/", "<html></html>")  # no raise
        assert sc.added == []


class TestPrototype:
    def test_exploitable_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.proto_mod") as m:
            m.analyze_page.return_value = {
                "exploitable": True,
                "merges": [{"description": "recursive merge"}],
                "sinks": [{"gadget": "innerHTML"}],
                "pollution_payloads": ["?__proto__[x]=1"],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_prototype(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "prototype_pollution"

    def test_not_exploitable_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.proto_mod") as m:
            m.analyze_page.return_value = {"exploitable": False}
            cl._scan_prototype(sc, "http://h/", "<html></html>")
        assert sc.added == []


class TestRedirect:
    def test_redirect_sink_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.redirect_mod") as m:
            m.analyze_page.return_value = {
                "exploitable": True,
                "redirect_params_found": ["next"],
                "sinks": [{"sink": "location.href"}],
            }
            m.build_poc_link.return_value = "http://h/?next=javascript:alert(1)//"
            cl._scan_redirect(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "open_redirect_xss"

    def test_no_sink_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.redirect_mod") as m:
            m.analyze_page.return_value = {"exploitable": False}
            cl._scan_redirect(sc, "http://h/", "<html></html>")
        assert sc.added == []


class TestFramework:
    def test_high_severity_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.fw_mod") as m:
            m.analyze_page.return_value = {
                "vulnerable_count": 1,
                "frameworks_detected": ["Vue"],
                "findings": [{"severity": "high", "framework": "Vue",
                              "snippet": "v-html=x", "description": "v-html"}],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_framework(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "framework_vue_xss"

    def test_low_severity_filtered_out(self):
        # Low-severity framework hints (createApp(, eval() without input)
        # must NOT become findings -- that's the FP guard.
        sc = _MockScanner()
        with patch(f"{PKG}.fw_mod") as m:
            m.analyze_page.return_value = {
                "vulnerable_count": 1,
                "frameworks_detected": ["Vue"],
                "findings": [{"severity": "low", "framework": "Vue",
                              "snippet": "createApp(", "description": "hint"}],
            }
            cl._scan_framework(sc, "http://h/", "<html></html>")
        assert sc.added == []

    def test_zero_count_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.fw_mod") as m:
            m.analyze_page.return_value = {"vulnerable_count": 0}
            cl._scan_framework(sc, "http://h/", "<html></html>")
        assert sc.added == []


class TestWebSocket:
    def test_exploitable_handler_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.ws_xss_mod") as m:
            m.analyze_page.return_value = {
                "has_websocket": True,
                "usage": {"ws_urls": ["wss://h/ws"]},
                "uses_insecure_ws": False,
                "handlers": [{"ws_url": "wss://h/ws",
                              "sinks_found": ["innerHTML"]}],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_websocket(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "websocket_xss"

    def test_insecure_ws_reported_medium(self):
        sc = _MockScanner()
        with patch(f"{PKG}.ws_xss_mod") as m:
            m.analyze_page.return_value = {
                "has_websocket": True,
                "usage": {"ws_urls": ["ws://h/ws"]},
                "uses_insecure_ws": True,
                "handlers": [],  # no exploitable sink, but insecure transport
            }
            cl._scan_websocket(sc, "http://h/", "<html></html>")
        assert len(sc.added) == 1
        assert _ftype(sc.added[0]) == "websocket_insecure"

    def test_no_websocket_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.ws_xss_mod") as m:
            m.analyze_page.return_value = {"has_websocket": False}
            cl._scan_websocket(sc, "http://h/", "<html></html>")
        assert sc.added == []


class TestServiceWorkerAndWorker:
    def test_service_worker_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.sw_mod") as m:
            m.analyze_page.return_value = {
                "vulnerable_count": 1,
                "listeners": [{"sw_url": "http://h/sw.js",
                               "sinks_found": ["innerHTML"]}],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_service_worker(sc, "http://h/", "<html></html>")
        assert _ftype(sc.added[0]) == "service_worker_xss"

    def test_web_worker_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.worker_mod") as m:
            m.analyze_page.return_value = {
                "vulnerable_count": 1,
                "workers": [{"worker_url": "http://h/w.js",
                             "sinks_found": ["innerHTML"]}],
            }
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_worker(sc, "http://h/", "<html></html>")
        assert _ftype(sc.added[0]) == "web_worker_xss"


class TestGraphQL:
    def _mock_req(self):
        class _R:
            def post(self, *a, **kw):
                return type("R", (), {"status_code": 200, "text": "{}"})()

            def get(self, *a, **kw):
                return type("R", (), {"status_code": 200, "text": "{}"})()
        return _R()

    def test_client_sink_reported(self):
        sc = _MockScanner()
        with patch(f"{PKG}.gql_mod") as m:
            m.analyze_page.return_value = {
                "has_graphql": True,
                "endpoints": ["/graphql"],
                "markers": {"clients_detected": ["apollo"],
                            "hooks_detected": ["useQuery"]},
                "sinks": [{"has_data_ref": True, "sink_type": "inner_html",
                           "severity": "high", "sink": "innerHTML"}],
            }
            m.DEFAULT_ARGUMENT_PAYLOAD = "<img src=x onerror=alert(1)>"
            m.build_poc_html.return_value = "<html>poc</html>"
            cl._scan_graphql(sc, self._mock_req(), "http://h/", "<html></html>")
        assert any(_ftype(f) == "graphql_xss" for f in sc.added)

    def test_no_graphql_no_finding(self):
        sc = _MockScanner()
        with patch(f"{PKG}.gql_mod") as m:
            m.analyze_page.return_value = {"has_graphql": False}
            cl._scan_graphql(sc, self._mock_req(), "http://h/", "<html></html>")
        assert sc.added == []

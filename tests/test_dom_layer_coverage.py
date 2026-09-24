# -*- coding: utf-8 -*-
"""Phase 152 companion: the coverage matrix must not claim a layer it lost.

`AdvancedLayerMixin._scan_dom` records `L6_dom_dynamic` as the real-browser
confirmation layer.  It used to `touch_layer(...)` BEFORE calling
`engine.analyze(url)` and then swallow any exception into an empty list, so a
Playwright that could not launch (chromium never installed, browser process
died, page crashed) still showed up as `L6_dom_dynamic: ran` in the client's
report while no JS sink on that page had been looked at.  A checked box for an
unexamined class is worse than an empty one, because nothing downstream asks.

These tests drive `_scan_dom` with a fake requester and a fake engine, and check
only the bookkeeping: what ran, what failed, and whether the failure is legible
in the coverage record.
"""
from __future__ import annotations

from xssentinel.core.scanner_layers import AdvancedLayerMixin

PAGE = ("<html><body><div id='out'></div>"
        "<script>document.getElementById('out').innerHTML = "
        "location.hash.slice(1);</script></body></html>")


class _Resp:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.url = "http://target.invalid/spa"


class _Req:
    def __init__(self, text: str):
        self._text = text

    def get(self, url, **kw):
        return _Resp(self._text)


class _Coverage:
    def __init__(self):
        self.layers: dict[str, dict] = {}
        self.requests = 0

    def record_request(self, url, method="GET"):
        self.requests += 1

    def touch_layer(self, url, layer_id, method="GET", detail=""):
        self.layers.setdefault(layer_id, {"status": "ran", "detail": detail})

    def record_layer(self, url, layer_id, method="GET", status="ran",
                     detail=""):
        self.layers[layer_id] = {"status": status, "detail": detail}

    def record_param(self, *a, **k):
        pass

    def record_finding(self, url, method="GET", **k):
        pass


class _RaisingEngine:
    def __init__(self, error):
        self._error = error
        self.calls = 0

    def available(self):
        return True

    def analyze(self, url, marker=None):
        self.calls += 1
        raise self._error


class _WorkingEngine:
    def __init__(self):
        self.calls = 0

    def available(self):
        return True

    def analyze(self, url, marker=None):
        self.calls += 1
        return []


class _Host(AdvancedLayerMixin):
    def __init__(self, engine):
        self._dom_engine = engine
        self.coverage = _Coverage()
        self.verbose = False
        self.findings = []

    def _bump(self, n=1):
        pass

    def _add(self, *a, **k):
        pass


def test_a_failing_browser_is_recorded_as_failed_not_ran():
    eng = _RaisingEngine(RuntimeError("browser has been closed"))
    host = _Host(eng)
    _scan_dom = AdvancedLayerMixin._scan_dom
    _scan_dom(host, _Req(PAGE), "http://target.invalid/spa")
    assert eng.calls == 1, "the engine should have been asked once"
    rec = host.coverage.layers.get("L6_dom_dynamic")
    assert rec is not None, "the layer must appear in the record either way"
    assert rec["status"] == "failed", (
        f"L6 recorded as {rec['status']!r}: a browser that never launched cannot "
        "be reported as a layer that ran")
    assert "browser has been closed" in rec["detail"], (
        "the record must carry the reason, not just the fact")


def test_a_working_browser_still_counts_as_ran():
    eng = _WorkingEngine()
    host = _Host(eng)
    AdvancedLayerMixin._scan_dom(host, _Req(PAGE), "http://target.invalid/spa")
    assert eng.calls == 1
    assert host.coverage.layers["L6_dom_dynamic"]["status"] == "ran"


def test_the_static_layer_is_recorded_even_when_the_browser_layer_fails():
    """L3 (static taint) genuinely ran, so it stays `ran`; only the layer that
    broke changes status.  Marking the whole DOM category failed would hide the
    partial coverage that does exist."""
    host = _Host(_RaisingEngine(RuntimeError("no chromium binary")))
    AdvancedLayerMixin._scan_dom(host, _Req(PAGE), "http://target.invalid/spa")
    assert host.coverage.layers["L3_dom_static"]["status"] == "ran"
    assert host.coverage.layers["L6_dom_dynamic"]["status"] == "failed"


# ---------------------------------------------------------------------------
# The tracker's own arithmetic -- the percentage a reviewer trusts
# ---------------------------------------------------------------------------

def test_a_failed_layer_is_not_counted_as_covered():
    from xssentinel.core.coverage import LAYERS, CoverageTracker

    url = "http://target.invalid/spa"
    tr = CoverageTracker()
    tr.start_endpoint(url)
    tr.record_layer(url, "L3_dom_static")
    tr.record_layer(url, "L6_dom_dynamic", status="failed",
                    detail="RuntimeError: browser has been closed")
    s = tr.summary()
    assert s["layer_coverage"]["L3_dom_static"] == 1
    assert s["layer_coverage"]["L6_dom_dynamic"] == 0, (
        "a layer that reported failure still counted toward coverage: that is "
        "how an unexamined evidence class inflates the percentage a client reads")
    assert s["layer_failed"]["L6_dom_dynamic"] == 1
    total = (sum(s["layer_coverage"].values()) + sum(s["layer_failed"].values())
             + sum(s["layer_missing"].values()))
    assert total == len(LAYERS) * 1, (
        f"ran+failed+missing must account for every layer once per endpoint "
        f"(got {total}, want {len(LAYERS)})")


def test_an_endpoint_that_answered_nothing_is_named_not_merely_scored():
    from xssentinel.core.coverage import CoverageTracker

    url = "http://target.invalid/x"
    tr = CoverageTracker()
    tr.start_endpoint(url)
    tr.record_layer(url, "L1_reflected")
    s = tr.summary()
    assert s["totals"]["endpoints_no_response"] == ["GET " + url]
    html = tr.to_html()
    assert "No response from 1 endpoint" in html, "the warning must be in the HTML"
    assert "untested" in html, (
        "the section used to close with 'zero findings with high layer coverage "
        "= genuinely clean', which this exact report contradicts")

    answered = CoverageTracker()
    answered.start_endpoint(url)
    answered.record_request(url)
    assert answered.summary()["totals"]["endpoints_no_response"] == []
    assert "No response from" not in answered.to_html()

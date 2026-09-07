"""Tests for the AsyncScanner deep paths (Phase 43).

test_async_pipeline.py covers the L1 reflected loop; this file covers the
deeper layers that sat at 39%: L3 DOM streaming, L6 CSP/JSONP, blind-OOB
injection + poll, throttling, link extraction, and the sync-shim bridge.
Everything is mocked (no network, no real browser); the AsyncScanner is
constructed INSIDE the running loop because asyncio.Lock/Semaphore bind to
the current loop on Python 3.9.
"""
from __future__ import annotations
import asyncio
import os
import sys
import time
from unittest.mock import patch

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK
from xssentinel.core import async_scanner as asc_mod
from xssentinel.core.async_scanner import AsyncScanner, _extract_links, is_available

# asyncio.run() needs a working loopback socketpair (see conftest.py).
pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


def _run(fn):
    """Build a scanner inside the loop, run fn(asc), return its result."""
    async def main():
        asc = AsyncScanner(max_concurrent=2, max_payloads=2, max_transforms=1,
                           timeout=5, verbose=False)
        return await fn(asc)
    return asyncio.run(main())


async def _collect(agen):
    out = []
    async for f in agen:
        out.append(f)
    return out


class TestPureHelpers:
    def test_is_available_bool(self):
        assert isinstance(is_available(), bool)

    def test_extract_links_anchors_and_forms(self):
        html = ('<a href="/a">1</a><a href="#frag">x</a>'
                '<a href="javascript:alert(1)">x</a>'
                '<a href="mailto:a@b.c">x</a>'
                '<form action="/go"></form>')
        links = _extract_links(html, "http://h/dir/")
        assert "http://h/a" in links
        assert "http://h/go" in links
        assert not any("javascript:" in l or "mailto:" in l or "#" in l
                       for l in links)

    def test_extract_links_bad_html_returns_list(self):
        assert isinstance(_extract_links("<html><unclosed", "http://h/"), list)


class TestAddFindingAndShim:
    def test_add_finding_appends(self):
        async def fn(asc):
            from xssentinel.core.findings import Finding
            f = Finding(url="http://h/", method="GET", param="q",
                        context="html_element", payload="p",
                        severity="high", confidence="high",
                        evidence="e", type="reflected")
            await asc._add_finding(f)
            return len(asc.findings)
        assert _run(fn) == 1

    def test_shim_aliases_findings_and_bump(self):
        def sync_part():
            asc = AsyncScanner.__new__(AsyncScanner)
            asc.verbose = False
            asc.waf_name = "cloudflare"
            shim = asc_mod._AsyncScannerShim(asc)
            shim._bump()
            shim._bump()
            return shim
        shim = sync_part()
        assert shim.requests_made == 2
        assert shim.waf_name == "cloudflare"
        assert shim.findings is shim._findings  # alias required by adv layers


class TestThrottle:
    def test_zero_delay_returns_immediately(self):
        async def fn(asc):
            asc.per_host_delay = 0
            asc.jitter = 0
            t0 = time.monotonic()
            await asc._throttle("http://h/")
            return time.monotonic() - t0
        assert _run(fn) < 0.1

    def test_per_host_delay_enforced(self):
        async def fn(asc):
            asc.per_host_delay = 0.3
            asc.jitter = 0
            await asc._throttle("http://h/")   # first: no wait
            t0 = time.monotonic()
            await asc._throttle("http://h/")   # second: must wait ~0.3s
            return time.monotonic() - t0
        assert _run(fn) >= 0.25


class TestScanCspAsync:
    def test_bypassable_csp_yields_finding(self):
        async def fn(asc):
            from xssentinel.core.csp import CSPReport
            with patch("xssentinel.core.csp.analyze",
                       return_value=CSPReport(bypassable=True,
                                              weak=["unsafe-inline"])):
                return await _collect(asc._scan_csp_async(
                    "http://h/", {"Content-Security-Policy": "default-src *"}))
        findings = _run(fn)
        assert len(findings) == 1
        assert findings[0].data["type"] == "csp_bypass"
        assert findings[0].data["evidence"] == "unsafe-inline"

    def test_strict_csp_yields_nothing(self):
        async def fn(asc):
            from xssentinel.core.csp import CSPReport
            with patch("xssentinel.core.csp.analyze",
                       return_value=CSPReport(bypassable=False)):
                return await _collect(asc._scan_csp_async(
                    "http://h/", {"Content-Security-Policy": "script-src 'self'"}))
        assert _run(fn) == []


class TestScanDomAsync:
    def test_dom_results_streamed(self):
        async def fn(asc):
            with patch("xssentinel.core.dom.analyze",
                       return_value=[{"sink": "innerHTML", "snippet": "x",
                                      "type": "dom", "context": "innerHTML",
                                      "severity": "high", "detail": "d",
                                      "confidence": "medium"}]):
                return await _collect(asc._scan_dom_async("http://h/", "<html>"))
        findings = _run(fn)
        assert len(findings) == 1
        f = findings[0].data
        assert f["type"] == "dom"
        # Sync parity (Phase 65): static hints are medium/low -- a static
        # heuristic can never be a high-confidence confirmed DOM XSS.
        assert f["severity"] == "medium"
        assert f["confidence"] == "medium"

    def test_dom_exception_swallowed(self):
        async def fn(asc):
            with patch("xssentinel.core.dom.analyze",
                       side_effect=RuntimeError("boom")):
                return await _collect(asc._scan_dom_async("http://h/", "<html>"))
        assert _run(fn) == []


class TestPollOob:
    def test_token_hit_returns_true(self):
        async def fn(asc):
            class _OOB:
                callbacks = ["request to /b_abc123 from 1.2.3.4"]
            asc.oob = _OOB()
            return await asc._poll_oob("abc123")
        assert _run(fn) is True

    def test_no_oob_returns_false(self):
        async def fn(asc):
            asc.oob = None
            return await asc._poll_oob("abc123")
        assert _run(fn) is False

    def test_token_miss_returns_false(self):
        async def fn(asc):
            class _OOB:
                callbacks = ["unrelated"]
            asc.oob = _OOB()
            # Backoff schedule is 0.5+1+2+4+8s; cap it by patching sleep.
            with patch("asyncio.sleep", _instant_sleep):
                return await asc._poll_oob("never")
        assert _run(fn) is False


async def _instant_sleep(_):
    return None


class _BlindResp:
    def __init__(self, text):
        self._t = text
        self.status = 200

    async def text(self):
        return self._t


class _BlindCM:
    def __init__(self, resp):
        self._r = resp

    async def __aenter__(self):
        return self._r

    async def __aexit__(self, *a):
        return False


class _BlindSession:
    """Echoes a fixed body for every request; records what was sent."""

    def __init__(self, text):
        self._text = text
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url,
                           "params": kw.get("params"),
                           "data": kw.get("data")})
        return _BlindCM(_BlindResp(self._text))


class _BlindOOB:
    name = "fake-oob"

    def __init__(self, received=frozenset()):
        self._n = 0
        self.started = 0
        self._received = set(received)

    def start(self):
        self.started += 1

    def token(self):
        self._n += 1
        return f"tok{self._n}"

    def callback_url(self, token):
        return f"http://oob.test/{token}"

    def poll(self, expected, timeout=None):
        return self._received & set(expected)


class TestAsyncBlindParity:
    """Phase 64: async blind mirrors the sync _inject_blind contract."""

    def test_escaped_echo_never_arms_oob(self):
        async def fn(asc):
            sess = _BlindSession("<p>q:&lt;script&gt;escaped&lt;/script&gt;</p>")
            asc.oob = _BlindOOB()
            await _collect(asc._inject_blind_async(
                sess, "http://h/", "GET", {"q": "x"}, {}))
            return asc
        asc = _run(fn)
        assert asc._oob_pending == []
        assert asc._oob_started is False   # listener never started

    def test_executable_echo_arms_pending_with_param_attribution(self):
        async def fn(asc):
            sess = _BlindSession("<p>q:<script>beacon()</script></p>")
            oob = _BlindOOB()
            asc.oob = oob
            await _collect(asc._inject_blind_async(
                sess, "http://h/sink", "GET", {"q": "x"}, {}))
            assert oob.started == 1
            assert len(asc._oob_pending) == 1
            p = asc._oob_pending[0]
            assert p["param"] == "q"          # per-param attribution
            assert p["token"].startswith("tok")
            assert p["payload"].count(oob.callback_url(p["token"])) >= 1
            # The injection really went out on the wire.
            assert any(c["method"] == "GET" and c["url"] == "http://h/sink"
                       for c in sess.calls)
            return asc
        _run(fn)

    def test_collect_yields_confirmed_findings_and_empties_pending(self):
        async def fn(asc):
            oob = _BlindOOB(received={"tok1"})
            asc.oob = oob
            asc._oob_started = True
            asc._oob_pending.append({
                "token": "tok1", "url": "http://h/sink", "method": "GET",
                "param": "q", "payload": "<svg onload=beacon>",
                "context": "blind_oob",
            })
            findings = await _collect(asc.collect_oob_async(timeout=0.1))
            return findings, asc
        findings, asc = _run(fn)
        assert len(findings) == 1
        f = findings[0].data
        assert f["type"] == "blind" and f["param"] == "q"
        assert f["severity"] == "high" and f["confidence"] == "high"
        assert asc._oob_pending == []      # consumed

    def test_keep_listening_rearms_unconfirmed(self):
        async def fn(asc):
            oob = _BlindOOB(received=set())   # nothing beaconed
            asc.oob = oob
            asc.oob_keep_listening = True
            asc._oob_pending.append({
                "token": "tok1", "url": "http://h/sink", "method": "GET",
                "param": "q", "payload": "p", "context": "blind_oob",
            })
            findings = await _collect(asc.collect_oob_async(timeout=0.1))
            return findings, asc
        findings, asc = _run(fn)
        assert findings == []
        assert len(asc._oob_pending) == 1    # re-armed for late beacons


class TestAsyncDomParity:
    """Phase 65: async DOM layer mirrors sync _scan_dom (is_html flag,
    dynamic confirmation, static-hint suppression)."""

    def test_static_analysis_gets_is_html_true(self):
        async def fn(asc):
            with patch("xssentinel.core.dom.analyze",
                       return_value=[]) as m:
                await _collect(asc._scan_dom_async("http://h/", "<html></html>"))
            return m
        m = _run(fn)
        assert m.call_args.kwargs.get("is_html") is True

    def test_dynamic_confirms_and_suppresses_static_hint(self):
        async def fn(asc):
            asc.dom_engine = "playwright"
            fake_engine = type("E", (), {
                "analyze": staticmethod(lambda url: [{
                    "sink": "Element.innerHTML", "snippet": "MARK",
                    "confidence": "high", "detail": "marker executed"}]),
            })
            with patch("xssentinel.core.dom.analyze", return_value=[
                    {"type": "dom", "context": "innerHTML", "snippet": "MARK",
                     "confidence": "medium", "detail": "static hint "
                     "innerHTML sink"}]), \
                 patch("xssentinel.core.async_scanner.dom_engine_mod."
                       "DynamicDomAnalyzer", fake_engine), \
                 patch("xssentinel.core.async_scanner.dom_engine_mod."
                       "page_has_client_js", return_value=True):
                return await _collect(asc._scan_dom_async(
                    "http://h/", "<script>x</script>"))
        findings = _run(fn)
        types = [f.data["type"] for f in findings]
        assert types == ["dom_dynamic"], types      # static hint suppressed
        d = findings[0].data
        assert d["severity"] == "high"
        assert d["headless"]["confirmed"] is True

    def test_static_only_when_engine_static(self):
        async def fn(asc):
            asc.dom_engine = "static"
            assert asc._resolve_dom_engine() is None
            with patch("xssentinel.core.dom.analyze", return_value=[
                    {"type": "dom", "context": "innerHTML", "snippet": "s",
                     "confidence": "medium", "detail": "d"}]):
                return await _collect(asc._scan_dom_async(
                    "http://h/", "<script>x</script>"))
        findings = _run(fn)
        assert [f.data["type"] for f in findings] == ["dom"]

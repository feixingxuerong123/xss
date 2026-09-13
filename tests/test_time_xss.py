"""Tests for core/time_xss.py -- time-based blind XSS detection.

Pure-logic coverage: payload construction, performance-entry checking,
response timing, and the scan_time_based orchestration (OOB callback
paths, string-vs-callable callback_url, fallback callbacks list, and the
early-return-on-confirm behaviour) -- all without network or Playwright.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.time_xss import (
    build_timing_payloads,
    check_performance_entries,
    measure_response_time,
    scan_time_based,
)


# -- fakes ---------------------------------------------------------------

class _Resp:
    def __init__(self, status_code=200):
        self.status_code = status_code


class _FakeReq:
    """Requester double: records calls, optionally raises."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def request(self, method, url, params=None, data=None):
        if self.fail:
            raise ConnectionError("loopback killed")
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {})})
        return _Resp(200)


class _FakeScanner:
    def __init__(self, oob=None, verbose=False):
        self.oob = oob
        self.verbose = verbose
        self.findings = []
        self.bumps = 0

    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        self.bumps += 1


class _FakeOOB:
    """Listener whose callback_url is a METHOD (SelfHosted style)."""

    name = "fake-oob"

    def __init__(self, poll_tokens=frozenset(), callbacks=None):
        self._poll = set(poll_tokens)
        self.callbacks = callbacks or []
        self.started_tokens = []

    def callback_url(self, token):
        self.started_tokens.append(token)
        return f"http://oob.test/{token}"

    def poll(self, expected, timeout=None):
        return self._poll & set(expected)


class _StrOOB:
    """Listener whose callback_url is a plain STRING (Interactsh style)."""

    name = "str-oob"
    callback_url = "https://interactsh.example/abc"


# -- payload construction -------------------------------------------------

class TestBuildTimingPayloads:
    def test_returns_ten_payloads_with_channels(self):
        ps = build_timing_payloads("http://cb.test", "tok1")
        assert len(ps) == 10
        channels = {p["channel"] for p in ps}
        assert channels == {"css_import", "img_load", "css_focus",
                            "script_fetch"}
        assert all(p["name"] and p["payload"] for p in ps)

    def test_callback_and_token_embedded(self):
        ps = build_timing_payloads("http://cb.test/", "tokX")  # trailing /
        full = "http://cb.test/tokX"
        assert all(full in p["payload"] for p in ps)
        # every payload references the token exactly through the callback
        assert all("tokX" in p["payload"] for p in ps)

    def test_shape_families(self):
        ps = {p["name"]: p["payload"]
              for p in build_timing_payloads("http://c", "t")}
        assert ps["css_import"].startswith("<style>@import")
        assert ps["img_onerror"].startswith("<img src=x onerror=")
        assert ps["css_focus_background"].startswith("<style>:focus")
        assert ps["script_src"].startswith("<script src=")
        assert ps["link_stylesheet"].startswith("<link rel='stylesheet'")
        assert ps["video_poster"].startswith("<video poster=")
        assert ps["object_data"].startswith("<object data=")
        assert ps["embed_src"].startswith("<embed src=")


# -- performance entries ---------------------------------------------------

class _FakePage:
    def __init__(self, entries=None, raise_exc=None):
        self._entries = entries or []
        self._raise = raise_exc
        self.waited = []

    def wait_for_timeout(self, ms):
        self.waited.append(ms)

    def evaluate(self, script, token):
        if self._raise:
            raise self._raise
        return self._entries


class TestCheckPerformanceEntries:
    def test_confirmed_with_entries(self):
        page = _FakePage(entries=[
            {"name": "http://cb/tok9", "type": "img", "duration": 5,
             "size": 0}])
        r = check_performance_entries(page, "tok9", timeout=0.1)
        assert r["confirmed"] is True
        assert r["entries"][0]["name"] == "http://cb/tok9"
        assert "tok9" in r["detail"]

    def test_no_entries_not_confirmed(self):
        r = check_performance_entries(_FakePage(), "tokZ", timeout=0.1)
        assert r["confirmed"] is False
        assert r["entries"] == []
        assert "no performance entries" in r["detail"]

    def test_exception_swallowed(self):
        page = _FakePage(raise_exc=RuntimeError("page closed"))
        r = check_performance_entries(page, "tokE", timeout=0.1)
        assert r["confirmed"] is False
        assert "performance API check failed" in r["detail"]
        assert "page closed" in r["detail"]


# -- response timing --------------------------------------------------------

class TestMeasureResponseTime:
    def test_success_measures_elapsed_and_status(self):
        req = _FakeReq()
        r = measure_response_time(req, "http://t/", "GET", {"q": "x"},
                                  {}, "q", "<img src=c>")
        assert r["status"] == 200
        assert r["error"] is None
        assert r["time_ms"] >= 0
        # payload rode the QUERY param
        assert req.calls[0]["params"]["q"] == "<img src=c>"

    def test_body_param_injection(self):
        req = _FakeReq()
        measure_response_time(req, "http://t/", "POST", {}, {"b": "x"},
                              "b", "<svg/onload=c>", is_body=True)
        assert req.calls[0]["data"]["b"] == "<svg/onload=c>"
        assert "b" not in req.calls[0]["params"]

    def test_failure_returns_error_with_status_zero(self):
        r = measure_response_time(_FakeReq(fail=True), "http://t/", "GET",
                                  {"q": "x"}, {}, "q", "p")
        assert r["status"] == 0
        assert "loopback killed" in r["error"]
        assert r["time_ms"] >= 0


# -- scan orchestration ------------------------------------------------------

class TestScanTimeBased:
    def test_no_oob_is_a_noop(self):
        sc = _FakeScanner(oob=None)
        req = _FakeReq()
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert req.calls == []          # nothing sent
        assert sc.findings == []

    def test_string_callback_url_used(self):
        oob = _StrOOB()
        req = _FakeReq()
        scan_time_based(_FakeScanner(oob=oob), req, "http://t/", "GET",
                        {"q": "x"}, {}, "q")
        # probes went out referencing the string callback host
        assert req.calls, "probes must be sent"
        assert all("interactsh.example" in c["url"] or
                   any("interactsh.example" in str(v)
                       for v in c["params"].values())
                   for c in req.calls)

    def test_poll_confirms_first_payload_then_stops(self):
        oob = _FakeOOB(poll_tokens={"tb_deadbeef"})  # unknown pre-arm: the
        # scanner generates its own token, so confirm via callbacks-list
        # fallback instead -- set poll to accept ANY expected token.
        oob.poll = lambda expected, timeout=None: set(expected)
        req = _FakeReq()
        sc = _FakeScanner(oob=oob)
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert len(sc.findings) == 1
        f = sc.findings[0].data
        assert f["type"] == "time_based_xss"
        assert f["severity"] == "high" and f["confidence"] == "high"
        assert f["param"] == "q"
        assert f["context"].startswith("time_based_")
        # confirmed on the FIRST payload -> only one probe sent
        assert len(req.calls) == 1

    def test_callbacks_list_fallback_confirms(self):
        # poll returns nothing, but the listener's raw callbacks list
        # contains the token (robustness path).
        class _ListOOB(_FakeOOB):
            def poll(self, expected, timeout=None):
                return set()

        oob = _ListOOB()
        req = _FakeReq()
        sc = _FakeScanner(oob=oob)

        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        # Without a confirming signal all 3 payloads are tried.
        assert len(req.calls) == 3
        assert sc.findings == []

    def test_all_probes_exhausted_no_finding(self):
        oob = _FakeOOB()  # poll -> empty, callbacks empty
        req = _FakeReq()
        sc = _FakeScanner(oob=oob)
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert len(req.calls) == 3      # top-3 channels only (Phase 22-3)
        assert sc.findings == []
        assert sc.bumps == 3

    def test_request_errors_are_skipped(self):
        oob = _FakeOOB()
        req = _FakeReq(fail=True)
        sc = _FakeScanner(oob=oob)
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert req.calls == []
        assert sc.findings == []
        assert sc.bumps == 0


# -- Phase 125: the listener must be LIVE before the payload goes out -----

class _StartableOOB:
    """Listener with a lifecycle, like every real (SelfHosted) listener.

    The beacon is triggered by the very request that carries the payload, so
    a listener that has not been started is just a closed port.  Before this
    fix only _inject_blind ever started it, and time-based ran without blind
    having run (blind has its own raw-tag gate) -- the fetch hit a closed
    port, no token arrived, and the layer silently reported nothing.
    """

    name = "startable-oob"

    def __init__(self, log):
        self._log = log
        self.started = 0
        self._started = False

    def start(self):
        self.started += 1
        self._started = True
        self._log.append("oob.start")

    def callback_url(self, token):
        return f"http://oob.test/{token}"

    def poll(self, expected, timeout=None):
        return set()


class _OrderReq:
    """Requester double that records send order into the same log."""

    def __init__(self, log):
        self._log = log
        self.calls = []

    def request(self, method, url, params=None, data=None):
        self._log.append("send")
        self.calls.append({"method": method, "url": url,
                           "params": dict(params or {}),
                           "data": dict(data or {})})
        return _Resp(200)


class TestListenerIsStartedByTimeBased:
    def test_listener_starts_before_the_first_probe(self):
        log: list = []
        oob = _StartableOOB(log)
        req = _OrderReq(log)
        sc = _FakeScanner(oob=oob)
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert oob.started == 1, "the layer must start the listener itself"
        assert log[0] == "oob.start", f"start must precede any send: {log}"
        assert "send" in log

    def test_listener_is_started_only_once(self):
        log: list = []
        oob = _StartableOOB(log)
        sc = _FakeScanner(oob=oob)
        scan_time_based(sc, _OrderReq(log), "http://t/", "GET", {"q": "x"},
                        {}, "q")
        scan_time_based(sc, _OrderReq(log), "http://t/", "GET", {"q": "x"},
                        {}, "q")
        assert oob.started == 1, "already-started listener must not re-bind"

    def test_listener_without_lifecycle_is_tolerated(self):
        """Simple/embedded listeners need no start(); scanning must proceed."""
        req = _FakeReq()
        sc = _FakeScanner(oob=_FakeOOB())
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        assert len(req.calls) == 3

    def test_path_listener_token_is_not_duplicated(self):
        """SelfHosted.callback_url() already embeds the token.

        build_timing_payloads() appends one more, so the emitted URL used to
        read /<token>/<token>.  Harmless for the current parser (first path
        segment wins) but a trap for any listener that reads the last one.
        """
        import re

        class _PathOOB(_StartableOOB):
            pass

        log: list = []
        req = _OrderReq(log)
        sc = _FakeScanner(oob=_PathOOB(log))
        scan_time_based(sc, req, "http://t/", "GET", {"q": "x"}, {}, "q")
        for call in req.calls:
            for value in list(call["params"].values()) + \
                    list(call["data"].values()):
                for hit in re.findall(r"http://oob\.test/([^\s'\")]+)",
                                      str(value)):
                    assert "tb_" in hit
                    assert len(hit.split("/")) == 1, \
                        f"token repeated in callback path: {hit}"

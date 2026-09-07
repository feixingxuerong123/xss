"""Phase 95: profile-backed escape convergence.

``is_marker_escaped`` (Phase 27-1) decides "the encoder is solid" by
looking for HTML entities ADJACENT to the reflected marker.  For a plain
alphanumeric marker echoed inside an element body -- the shape every
html.escape-style endpoint produces -- those neighbours are the page's
own structural characters (``>`` of the opening tag, ``<`` of the closing
tag), which no server encodes, so the check returned False on exactly
the endpoints it was written for.  Both engines then paid the full
max_payloads x max_transforms budget (~203 requests in the benchmark)
on reflections that could never execute.

Fix: the sandwich reflection-profile probe carries PROBE_CHARS itself,
so a working encoder MUST reflect them as entities.  When every
breakout-critical character for the reflected context comes back
ENCODED (stripped chars may be restorable by a transform family and
must NOT converge), the engine converges to the small escaped-reflection
budget as if the adjacent-entity check had fired.
"""
from __future__ import annotations

import asyncio
import html
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK
from xssentinel.core import reflection_profile as rp
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.scanner import Scanner

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")

MARKER = "xssm_deadbeef"


# --------------------------------------------------------------------------
# 1. unit: profile_says_encoded context table
# --------------------------------------------------------------------------

def _prof(kept="", encoded="", stripped=""):
    return {"reflected": True, "full_reflection": False,
            "chars_kept": list(kept), "chars_encoded": list(encoded),
            "chars_stripped": list(stripped)}


def test_element_body_converges_when_lt_encoded() -> None:
    # html.escape kills < > " ' as entities -> element body cannot escape
    assert rp.profile_says_encoded(
        _prof(encoded="<"), "html_element") is True
    assert rp.profile_says_encoded(
        _prof(encoded="<>"), "html_element") is True


def test_element_body_keeps_budget_when_lt_merely_stripped() -> None:
    # STRIPPED != encoded: transforms (fullwidth/utf7/...) may restore it
    assert rp.profile_says_encoded(
        _prof(stripped="<"), "html_element") is False


def test_full_reflection_never_converges() -> None:
    assert rp.profile_says_encoded(
        {"full_reflection": True, "chars_encoded": [],
         "chars_kept": list(rp.PROBE_CHARS), "chars_stripped": []},
        "html_element") is False


def test_quoted_attr_converges_on_its_own_quote() -> None:
    assert rp.profile_says_encoded(
        _prof(encoded='"'), "html_attribute_dq") is True
    assert rp.profile_says_encoded(
        _prof(encoded="'"), "html_attribute_sq") is True
    assert rp.profile_says_encoded(
        _prof(encoded="\"'"), "html_attribute_sq") is True
    # the OTHER quote being encoded must not converge a dq attribute:
    # breakout needs the enclosing quote specifically
    assert rp.profile_says_encoded(
        _prof(encoded="'"), "html_attribute_dq") is False


def test_unquoted_attr_needs_gt() -> None:
    assert rp.profile_says_encoded(
        _prof(encoded=">"), "html_attribute_noquote") is True
    assert rp.profile_says_encoded(
        _prof(encoded="<>"), "html_attribute_noquote") is True


def test_unlisted_contexts_never_converge() -> None:
    # javascript: URIs need no special character at all
    for cx in ("url_href", "url_javascript", "meta_refresh",
               "script_block", "html_comment", "css_context",
               "template_angular", "cdata", None, ""):
        assert rp.profile_says_encoded(_prof(encoded="<"), cx) is False, cx


def test_missing_profile_never_converges() -> None:
    assert rp.profile_says_encoded(None, "html_element") is False
    assert rp.profile_says_encoded({}, "html_element") is False


# --------------------------------------------------------------------------
# 2. sync integration: alphanumeric marker + escaped endpoint converges
# --------------------------------------------------------------------------

class _Resp:
    def __init__(self, text):
        self.text = text
        self.headers = {}
        self.status_code = 200


class _SyncReq:
    """Escaped-echo requester: html.escape()s the reflected value.

    This is the shape the Phase 27-1 check was written for and could
    never detect: the bare marker reflects verbatim between structural
    characters, so nothing adjacent to it is ever an entity.
    """

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, **kw):
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        self.calls.append(val)
        return _Resp("<html><body><div>"
                     f"{html.escape(val, quote=True)}"
                     "</div></body></html>")


def _sync_scanner():
    from xssentinel.core.coverage import CoverageTracker
    sc = Scanner.__new__(Scanner)
    sc.verbose = False
    sc.max_payloads = 14
    sc.max_transforms = 12
    sc.waf_name = None
    sc.oob = None
    sc.requests_made = 0
    sc._lock = threading.Lock()
    sc._tl = threading.local()
    sc.coverage = CoverageTracker()
    sc._progress = None
    # Phase 96 tests exercise the confirming path, which consults this
    # in _record; headless replay is out of scope for these unit tests.
    sc.use_headless = False
    sc.json_body = None
    # unit scope: the reflection loop budget is what this suite locks
    sc._run_advanced_layers = lambda *a, **k: None
    return sc


def test_sync_escaped_endpoint_converges_budget() -> None:
    sc = _sync_scanner()
    req = _SyncReq()
    sc._scan_param(req, "http://t/x?a=1", "GET", {"q": "probe"}, {}, "q",
                   False)
    # unfixed: ~1 marker + 1 sandwich probe + 14 payloads x 12 transforms
    #          ~= 170.  Fixed: 1 marker + 1 probe + 3 payloads x <=2
    #          transforms (+polyglots) ~= 11.
    assert len(req.calls) <= 16, (
        f"escaped endpoint still spent {len(req.calls)} requests "
        "(profile-backed convergence did not kick in)")


def test_sync_escaped_endpoint_confirms_nothing() -> None:
    sc = _sync_scanner()
    sc.findings = []
    req = _SyncReq()
    sc._scan_param(req, "http://t/x?a=1", "GET", {"q": "probe"}, {}, "q",
                   False)
    assert not sc.findings, "escaped echo must not confirm"


# --------------------------------------------------------------------------
# 3. async integration: same endpoint shape, same convergence
# --------------------------------------------------------------------------

class _AResp:
    def __init__(self, text):
        self._t = text
        self.headers = {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _AEscSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls.append(dict(params or {}))
        val = (params or {}).get("q", "")
        return _AResp("<html><body><div>"
                      f"{html.escape(val, quote=True)}"
                      "</div></body></html>")


def _aprobe():
    async def run():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
        asc._semaphore = asyncio.Semaphore(4)
        session = _AEscSession()
        out = []
        async for f in asc._probe_param(session, "http://t/x", "GET", "q",
                                        {"q": "probe"}, {}, False, "x"):
            out.append(f)
        return out, session
    return asyncio.run(run())


def test_async_escaped_endpoint_converges_budget() -> None:
    findings, session = _aprobe()
    assert findings == []
    assert len(session.calls) <= 16, (
        f"async escaped endpoint still spent {len(session.calls)} requests")


def test_async_escaped_endpoint_sandwich_probe_fires_once() -> None:
    """The convergence-decision probe is the ONLY xssap_ request.

    It must fire exactly once (to classify the reflection) and the
    capped payload loop must not re-send it or prepend WAF bypass
    chains built from it.
    """
    _, session = _aprobe()
    probe_hits = sum(
        1 for call in session.calls
        for v in call.values() if str(v).startswith("xssap_"))
    assert probe_hits <= 1, (
        f"sandwich probe fired {probe_hits} times, expected exactly 1")


# --------------------------------------------------------------------------
# 4. Phase 96: RCDATA detection -> breakout payload surfacing
# --------------------------------------------------------------------------
#
# Direct injections inside <textarea>/<title>/<xmp> are inert text (the
# verifier's RCDATA gate correctly rejects them), but the closing-tag
# BREAKOUT ("</textarea><svg onload=...>") is fully executable whenever
# the server echoes raw markup.  The payload corpus had no breakout
# entry, so RCDATA endpoints never saw the one vector that works there:
# 4 benchmark cases were silent FNs (neg-rcdata-01..04) and any real
# RCDATA endpoint would have been missed.  Fix shape mirrors Phase 95:
# detect from the marker reflection (zero extra requests), surface
# breakout variants built from the top candidates, verifier unchanged
# (its raw gate was already designed to confirm a breakout AFTER the
# closing tag).

def test_detect_rcdata_tag_matrix() -> None:
    T = "zzq"
    assert rp.detect_rcdata_tag("<textarea>" + T, 10) == "textarea"
    assert rp.detect_rcdata_tag("<TITLE>" + T, 6) == "title"
    assert rp.detect_rcdata_tag("<xmp>" + T, 5) == "xmp"
    # closed before the token -> not inside
    assert rp.detect_rcdata_tag(
        "<textarea>a</textarea>" + T, 22) is None
    # plain element body -> not inside
    assert rp.detect_rcdata_tag("<div>" + T, 5) is None
    # degenerate input
    assert rp.detect_rcdata_tag("", 0) is None
    assert rp.detect_rcdata_tag("<textarea>" + T, -1) is None


def test_profile_carries_rcdata_tag() -> None:
    p = rp.profile_reflection(
        '<body><textarea>zzq"<>=(/);`</textarea></body>', "zzq")
    assert p is not None and p["rcdata_tag"] == "textarea"
    p2 = rp.profile_reflection('<body><div>zzq"<>=(/);`</div></body>', "zzq")
    assert p2 is not None and p2["rcdata_tag"] is None
    p3 = rp.profile_reflection("<body><div>nothing</div></body>", "zzq")
    assert p3 is not None and p3["rcdata_tag"] is None


def test_surface_breakouts_dict_variant() -> None:
    p = {"reflected": True, "full_reflection": False, "rcdata_tag": "title"}
    bases = [{"payload": "<svg onload=alert(1)>", "context": "html_element"},
             {"payload": "<script>alert(1)</script>",
              "context": "html_element"}]
    nb, tag = rp.surface_rcdata_breakouts(p, bases)
    assert tag == "title"
    assert nb[0]["payload"] == "</title><svg onload=alert(1)>"
    assert nb[0]["context"] == "rcdata_breakout"
    # originals are preserved AFTER the variants
    assert nb[2:] == bases
    # no duplicate payload strings
    assert len({b["payload"] for b in nb}) == len(nb)


def test_surface_breakouts_noop_when_not_rcdata() -> None:
    bases = [{"payload": "<svg onload=alert(1)>", "context": "html_element"}]
    for prof in (None, {}, {"rcdata_tag": None}, {"rcdata_tag": ""}):
        nb, tag = rp.surface_rcdata_breakouts(prof, bases)
        assert nb is bases and tag is None, prof


def test_surface_breakout_strs_variant() -> None:
    p = {"rcdata_tag": "xmp"}
    cands = ["<svg onload=alert(1)>", "<script>alert(1)</script>"]
    nb, tag = rp.surface_rcdata_breakout_strs(p, cands)
    assert tag == "xmp"
    assert nb[0] == "</xmp><svg onload=alert(1)>"
    assert nb[2:] == cands
    # empty / no-op paths
    nb2, tag2 = rp.surface_rcdata_breakout_strs(None, cands)
    assert nb2 is cands and tag2 is None


class _SyncRcdataReq:
    """Raw-echo requester: reflects the value verbatim inside <textarea>.

    The Phase 96 FN shape: a direct injection is inert here, but the
    closing-tag breakout executes -- the engine must surface it.
    """

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, **kw):
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        self.calls.append(val)
        return _Resp("<html><body><textarea>"
                     f"{val}</textarea></body></html>")


def test_sync_rcdata_raw_echo_confirms_breakout() -> None:
    sc = _sync_scanner()
    sc.findings = []
    req = _SyncRcdataReq()
    sc._scan_param(req, "http://t/x?a=1", "GET", {"q": "probe"}, {}, "q",
                   False)
    assert sc.findings, (
        "raw RCDATA echo must confirm the closing-tag breakout (Phase 96 FN)")
    # the confirming payload must be a breakout variant, not a direct
    # injection (which stays inert inside the textarea)
    breakouts = [c for c in req.calls if c.startswith("</textarea>")]
    assert breakouts, "no breakout variant was ever dispatched"
    # budget: raw echo confirms within a handful of requests, not 203
    assert len(req.calls) <= 40, (
        f"rcdata breakout spent {len(req.calls)} requests")


def test_sync_rcdata_escaped_echo_confirms_nothing() -> None:
    # html.escape turns </textarea> into &lt;/textarea&gt;: breakout is
    # dead AND Phase 95 convergence must cap the budget
    sc = _sync_scanner()
    sc.findings = []
    req = _SyncReq()
    sc._scan_param(req, "http://t/x?a=1", "GET", {"q": "probe"}, {}, "q",
                   False)
    assert not sc.findings
    assert len(req.calls) <= 16


class _ARcdataSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls.append(dict(params or {}))
        val = (params or {}).get("q", "")
        return _AResp("<html><body><textarea>"
                      f"{val}</textarea></body></html>")


def _aprobe_rcdata():
    async def run():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
        asc._semaphore = asyncio.Semaphore(4)
        session = _ARcdataSession()
        out = []
        async for f in asc._probe_param(session, "http://t/x", "GET", "q",
                                        {"q": "probe"}, {}, False, "x"):
            out.append(f)
        return out, session
    return asyncio.run(run())


def test_async_rcdata_raw_echo_confirms_breakout() -> None:
    findings, session = _aprobe_rcdata()
    assert findings, (
        "async raw RCDATA echo must confirm the breakout (Phase 96 FN)")
    breakout_hits = sum(
        1 for call in session.calls
        for v in call.values() if str(v).startswith("</textarea>"))
    assert breakout_hits >= 1, "async engine never dispatched a breakout"
    assert len(session.calls) <= 40, (
        f"async rcdata breakout spent {len(session.calls)} requests")

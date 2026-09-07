"""Phase 93: escaped-reflection convergence must exist in BOTH engines.

The sync engine has shrunk its budget when the marker reflects but the
input around it is HTML-encoded since Phase 27-1 (3 payloads x 2
transforms instead of max_payloads x max_transforms).  The async engine
had no copy of that logic at all -- the usual async/sync parity gap.

This suite also locks the Phase 93 jitter fix, which is what actually
moved the async benchmark: ``AsyncScanner.jitter`` defaulted to 0.1, and
unlike the sync engine -- where jitter is a ratio of the rate-limit
interval and costs nothing without --rate-limit -- that is an ABSOLUTE
50-150ms sleep in front of EVERY request.  cli_runner never passed it,
so async paid it unconditionally: cProfile on neg-escape-03 showed 0.33s
of scanner work against 22.9s parked in GetQueuedCompletionStatus, i.e.
the process was asleep, not working.
"""
from __future__ import annotations

import asyncio
import html
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy
from xssentinel.core import context as ctx
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.scanner import Scanner
from xssentinel.core.scanner_layers import AdvancedLayerMixin

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")

MARKER = "xssentinel_async_q_ab12"


class _Resp:
    def __init__(self, text):
        self._t = text
        self.headers = {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    """Echoes q raw (live markup) or with an encoded ampersand in front.

    The escaped mode simulates the marker being echoed after an encoded
    ``&`` -- e.g. a multi-parameter URL reflected with its separators
    encoded -- which is the signal ``is_marker_escaped`` looks for.  A
    bare alphanumeric marker alone cannot trigger it (nothing around it
    gets encoded), which is why the convergence path needs this shape.
    """

    def __init__(self, escape=False):
        self.calls = []
        self.escape = escape

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        if self.escape:
            # An encoded & in front of an otherwise fully-escaped echo:
            # inert to a browser, but enough to trip is_marker_escaped.
            body = "&amp;" + html.escape(val)
        else:
            body = val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _probe(escape):
    async def run():
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
        asc._semaphore = asyncio.Semaphore(4)
        session = _Session(escape=escape)
        out = []
        async for f in asc._probe_param(session, "http://t/x", "GET", "q",
                                        {"q": "probe"}, {}, False, "x"):
            out.append(f)
        return out, session
    return asyncio.run(run())


# --------------------------------------------------------------------------
# 1. one canonical implementation, no drift between the three callers
# --------------------------------------------------------------------------

def test_canonical_detects_escaped_reflection() -> None:
    assert ctx.is_marker_escaped("&lt;" + MARKER + "&gt;", MARKER) is True
    assert ctx.is_marker_escaped("&#x27;" + MARKER, MARKER) is True
    assert ctx.is_marker_escaped("&amp;" + MARKER, MARKER) is True
    assert ctx.is_marker_escaped(MARKER, MARKER) is False
    assert ctx.is_marker_escaped("", MARKER) is False
    assert ctx.is_marker_escaped("no marker here", MARKER) is False


def test_sync_scanner_delegates_to_canonical() -> None:
    scanner = Scanner.__new__(Scanner)  # no __init__ side effects needed
    samples = ["&lt;" + MARKER + "&gt;", MARKER,
               "&#x27;" + MARKER + "&#x27;", "plain " + MARKER + " text"]
    for s in samples:
        assert scanner._is_marker_escaped(s, MARKER) == \
            ctx.is_marker_escaped(s, MARKER), s


def test_scanner_layers_delegates_to_canonical() -> None:
    layers = AdvancedLayerMixin.__new__(AdvancedLayerMixin)
    samples = ["&lt;" + MARKER + "&gt;", MARKER,
               "&quot;" + MARKER, "plain " + MARKER + " text"]
    for s in samples:
        assert layers._is_marker_escaped(s, MARKER) == \
            ctx.is_marker_escaped(s, MARKER), s


# --------------------------------------------------------------------------
# 2. the async engine converges on an escaped reflection
# --------------------------------------------------------------------------

def test_escaped_echo_yields_no_finding() -> None:
    findings, _ = _probe(escape=True)
    assert findings == []


def test_escaped_echo_request_budget_is_small() -> None:
    """Order of magnitude below the unconverged ~1 + 14 x 13 = 183.

    Observed: 1 marker probe + 4 payloads x (2 transforms + polyglot)
    = 13 requests.  The bound only has to catch a regression to the
    full budget.
    """
    _, session = _probe(escape=True)
    assert len(session.calls) <= 16, (
        f"escaped reflection still spent {len(session.calls)} requests")


def test_escaped_echo_skips_reflection_profile_probe() -> None:
    """The sandwich probe token must never reach the wire when escaped."""
    _, session = _probe(escape=True)
    for call in session.calls:
        for value in list(call["params"].values()) + list(call["data"].values()):
            assert "xssap_" not in str(value), \
                "reflection-profile sandwich probe still fires when escaped"


def test_build_variants_honours_cap_override() -> None:
    async def run():
        # AsyncScanner must be built inside the loop: its asyncio.Semaphore
        # binds to the running loop on Python 3.9.
        asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
        marked = "alert('t')<svg onload=alert('t')>"
        return (asc._build_variants(marked, "html_element", "t", 2),
                asc._build_variants(marked, "html_element", "t", None))
    capped, full = asyncio.run(run())
    assert 1 <= len(capped) <= 2, capped
    assert len(full) > len(capped), \
        "cap_override=2 must actually shrink the variant ladder"


# --------------------------------------------------------------------------
# 3. convergence and pacing must not cost detection on a live reflection
# --------------------------------------------------------------------------

def test_live_echo_still_confirms() -> None:
    findings, _ = _probe(escape=False)
    assert findings, "async L1 stopped confirming a live reflection"
    assert findings[0].data["type"] == "reflected"
    assert findings[0].data["confidence"] == "high"


def test_default_jitter_is_zero() -> None:
    """The hidden 50-150ms per-request sleep must not come back."""
    import inspect
    sig = inspect.signature(AsyncScanner.__init__)
    assert sig.parameters["jitter"].default == 0.0

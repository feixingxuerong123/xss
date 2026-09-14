# -*- coding: utf-8 -*-
"""Phase 129: escape-consistency property fuzz, wired into the suite.

Three of the false positives found this cycle (Phases 123, 126, 128) lived
in the same blind spot: a payload-shape x context combination that no
hand-written manifest pair covered, where an escaping-blind signal was
promoted to a confirmed finding.  `benchmark/fuzz_escape_matrix.py` explores
the whole generated matrix; this file locks a representative slice of it
into the regression suite so the family cannot come back silently.

The invariant is a property, not a case list:

    if the application HTML-escapes the reflected value, a high/medium
    finding may only appear when the payload's executability does NOT
    depend on an escaped character.

Two guards keep the file honest:
  * a non-vacuity anchor -- raw text MUST confirm, otherwise the assertions
    below prove nothing;
  * a discrimination check -- the contexts where escaping genuinely does
    not help (bare unquoted attribute) MUST still confirm, so an
    over-tightened engine cannot make this file pass by breaking detection.
"""
from __future__ import annotations

import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from benchmark.server import BenchmarkHandler, load_routes
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

PORT = 18878
HIGH_MED = ("high", "medium", "critical")


@pytest.fixture(scope="module")
def fuzz_server():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    from http.server import ThreadingHTTPServer
    BenchmarkHandler.routes = load_routes()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), BenchmarkHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{PORT}"
    server.shutdown()


def _scan(base: str, ctx: str, esc: str = "html", sink: str = "none"):
    url = f"{base}/fuzz/render?ctx={ctx}&esc={esc}&sink={sink}"
    sc = Scanner(requester=Requester(timeout=8), max_payloads=10,
                 max_transforms=6, dom_engine="static", verbose=False)
    sc.scan_target(url, method="GET",
                   params={"q": "xssentinel_bench_probe"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings
            if f.data.get("param") == "q"
            and f.data.get("severity") in HIGH_MED]


def test_anchor_raw_text_confirms(fuzz_server):
    """Non-vacuity: without this, every 'no finding' assertion is free."""
    hits = _scan(fuzz_server, "text", esc="raw")
    assert hits, ("the pipeline must confirm a raw reflection in text "
                  "context -- otherwise this file proves nothing")


@pytest.mark.parametrize("ctx", ["text", "attr_dq", "script_dq", "svg"])
def test_escaped_context_does_not_confirm(fuzz_server, ctx):
    """Escaping kills the break-out in these contexts, so no finding."""
    hits = _scan(fuzz_server, ctx, esc="html")
    assert not hits, (
        f"escaped reflection confirmed in {ctx!r}: "
        f"{[(h.get('type'), str(h.get('payload'))[:60]) for h in hits]}")


@pytest.mark.parametrize("ctx", ["text", "attr_dq"])
def test_escaped_plus_page_sink_does_not_confirm(fuzz_server, ctx):
    """The Phase 123 (clobber) / Phase 128 (mXSS) combination: escaped
    reflection on a page that also carries a mutating sink."""
    hits = _scan(fuzz_server, ctx, esc="html", sink="dom")
    assert not hits, (
        f"escaped reflection next to a page sink confirmed in {ctx!r}: "
        f"{[(h.get('type'), str(h.get('payload'))[:60]) for h in hits]}")


def test_discrimination_bare_attribute_still_confirms(fuzz_server):
    """Escaping does NOT neutralise an unquoted-attribute break-out.

    If this ever stops confirming, the engine has been over-tightened (or
    the target lost the shape) and the invariant tests above would pass for
    the wrong reason.
    """
    hits = _scan(fuzz_server, "attr_bare", esc="html")
    assert hits, ("a bare (unquoted) attribute break-out needs no escaped "
                  "character and must still be reported")

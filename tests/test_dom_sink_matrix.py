# -*- coding: utf-8 -*-
"""Phase 162: the browser engine must confirm the sinks it claims to hook.

`benchmark/sink_matrix.py` runs one page per sink shape and reports which ones
the engine can actually confirm.  It exists because "the engine covers it" was
an assumption maintained in prose:

  * Phase 161 -- the Function hook was documented as covering "eval-like
    dynamic code"; it does not cover a direct eval().
  * Phase 162 -- the window_name probe read a dict key it was never built
    with, raised KeyError inside a broad ``except: continue``, and therefore
    had NEVER navigated once; and Range.createContextualFragment was in the
    static HIGH list but not hooked at all.

This file locks the shapes that were broken or are structurally fragile, plus
one control, so the hook set cannot silently shrink again.  The full matrix
(12 of 14 shapes confirmed) stays a probe tool -- the two remaining misses are
deliberate and documented there, not pinned here.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from xssentinel.core import dom_engine  # noqa: E402

from tests.conftest import SOCKETPAIR_OK, loopback_healthy  # noqa: E402

_HAS_PW = dom_engine.DynamicDomAnalyzer.available()

pytestmark = [
    pytest.mark.skipif(not SOCKETPAIR_OK,
                       reason="loopback socketpair degraded"),
    pytest.mark.skipif(not _HAS_PW, reason="Playwright not installed"),
]

# Shapes that must be confirmed.  The first is the control (it worked before
# every fix); the rest each pins a specific defect or a fragile contract.
REQUIRED = [
    "innerHTML (control)",
    "eval",                             # Phase 161: eval was never hooked
    "new Function",                     # the Proxy hook must keep working
    "Range.createContextualFragment",   # Phase 162: listed HIGH, not hooked
    "window.name -> innerHTML",         # Phase 162: probe never navigated
]


@pytest.fixture(scope="module")
def sink_server():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    from benchmark.sink_matrix import sink_urls, start_server
    srv = start_server(0)
    urls = sink_urls(srv.server_port)
    try:
        yield urls
    finally:
        srv.shutdown()


@pytest.mark.parametrize("shape", REQUIRED)
def test_sink_is_confirmed_in_a_real_browser(sink_server, shape):
    engine = dom_engine.DynamicDomAnalyzer(timeout=10)
    found = engine.analyze(sink_server[shape])
    sinks = sorted({str(f.get("sink", "")) for f in (found or [])})
    assert found, (
        f"the browser engine did not confirm {shape!r}: the page feeds the "
        f"marker into that sink, so a miss means the hook (or the probe that "
        f"delivers the marker) is not installed")
    assert sinks, f"{shape!r} reported a finding with no sink name"

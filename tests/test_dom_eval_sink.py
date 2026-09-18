# -*- coding: utf-8 -*-
"""Phase 161: a direct ``eval()`` is a sink the browser engine must confirm.

The Function-constructor hook was documented as covering "eval-like dynamic
code".  Measured, that is false: ``eval`` is its own global and never routes
through the Function constructor, so the benchmark vector ``dom_search_eval``
(``eval(new URLSearchParams(location.search).get('x'))``) was never
dynamically confirmed -- while its setTimeout twin, same page shape, same
marker, same probes, was.  A page whose only sink is eval() was therefore
unverifiable by the browser engine.

Two contracts, deliberately separated:
  * the injected script installs the hook, guarded, and early enough not to
    be skipped when a browser refuses to let ``window.eval`` be replaced
    (Phase 141: one unguarded throw killed every hook below it);
  * a LIVE browser really confirms that page end to end.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from xssentinel.core import dom_engine  # noqa: E402

from tests.conftest import SOCKETPAIR_OK, loopback_healthy  # noqa: E402

_HAS_PW = dom_engine.DynamicDomAnalyzer.available()

pytestmark = [
    pytest.mark.skipif(not SOCKETPAIR_OK,
                       reason="loopback socketpair degraded"),
]


def test_init_script_hooks_direct_eval():
    js = dom_engine._init_script("MARKER")
    assert "window.eval" in js, "the eval hook is not installed at all"
    assert "hit('eval'" in js, "the eval hook does not record a hit"
    # Guarded: replacing window.eval can throw, and an unguarded throw here
    # would silently skip every hook below it.
    assert re.search(r"try \{\s*var origEval = window\.eval;", js), (
        "the eval hook must be inside a try block")
    # Ordered before the setTimeout hook so a failure above cannot remove it.
    assert js.index("var origEval") < js.index("['setTimeout','setInterval']")


@pytest.mark.skipif(not _HAS_PW, reason="Playwright not installed")
def test_eval_sink_is_confirmed_live():
    """The real browser must observe the marker reaching eval()."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")

    from benchmark.server import BenchmarkHandler, load_routes
    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port
    time.sleep(0.2)
    try:
        from xssentinel.core.scanner import Scanner
        from xssentinel.core.requester import Requester

        # The page reads a SPECIFIC name (x), so the case must carry it --
        # with no query at all the engine has no real parameter to swap and
        # the flow is unreachable.
        url = f"http://127.0.0.1:{port}/dom/search-eval"
        scanner = Scanner(requester=Requester(timeout=10), max_payloads=8,
                          max_transforms=4, dom_engine="auto", verbose=False)
        scanner.scan_target(url, method="GET", params={"x": "probe"},
                            data={}, oob_collect=False)
        scanner.dedup()
        types = {f.data.get("type") for f in scanner.findings}
        assert "dom_dynamic" in types, (
            f"the browser did not confirm the eval sink: {sorted(types)}")
    finally:
        srv.shutdown()

# -*- coding: utf-8 -*-
"""Phase 130: single-quoted attribute contexts were misclassified.

`context._attribute_context()` appends a tail to the (truncated) attribute
segment so a quoted value can be matched at all.  The old tail was `">`,
which can only *close* a double-quoted value: an unterminated single-quoted
value fell through to the regex's unquoted branch and the attribute was
classified `html_attribute_noquote`.

Consequence chain (found by `benchmark/fuzz_context_matrix.py`):

    classification noquote -> space-break-out corpus -> cannot break out
    of `'...'` -> a live single-quote break-out is reported as nothing
    (or diluted into a medium `polyglot_reflection` note).

The double-quoted sibling worked because its tail happened to close it --
the same "two symmetric variants, only one handled" pattern that keeps
biting this project (async/sync duality, dq/sq quote pairs).
"""
from __future__ import annotations

import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.context import _attribute_context

MARK = "XSSCTXMARK"
HIGH_MED = ("high", "medium", "critical")


@pytest.mark.parametrize("segment,expected", [
    ("<input value='%s" % MARK, "html_attribute_sq"),
    ('<input value="%s' % MARK, "html_attribute_dq"),
    ("<input value=%s" % MARK, "html_attribute_noquote"),
    ("<div class='a' id='%s" % MARK, "html_attribute_sq"),
    ('<div class="a" id="%s' % MARK, "html_attribute_dq"),
])
def test_attribute_quote_style_is_classified(segment, expected):
    got = (_attribute_context(segment) or {}).get("context")
    assert got == expected, (
        f"{segment!r}: classified {got!r}, expected {expected!r}")


@pytest.fixture(scope="module")
def fuzz_server():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    from http.server import ThreadingHTTPServer
    from benchmark.server import BenchmarkHandler, load_routes
    BenchmarkHandler.routes = load_routes()
    server = ThreadingHTTPServer(("127.0.0.1", 18879), BenchmarkHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:18879"
    server.shutdown()


def _scan(base: str, ctx: str, esc: str):
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    url = f"{base}/fuzz/render?ctx={ctx}&esc={esc}"
    sc = Scanner(requester=Requester(timeout=8), max_payloads=10,
                 max_transforms=6, dom_engine="static", verbose=False)
    sc.scan_target(url, method="GET",
                   params={"q": "xssentinel_bench_probe"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings
            if f.data.get("param") == "q"
            and f.data.get("severity") in HIGH_MED]


def test_single_quoted_breakout_is_confirmed_through_an_angle_filter(
        fuzz_server):
    """A `'` break-out needs no angle bracket, so escaping angles is no
    defence -- the engine must confirm it, not just note a polyglot."""
    hits = _scan(fuzz_server, "attr_sq", "encode_angles")
    assert hits, ("a single-quoted attribute break-out under an "
                  "angle-escaping filter must be confirmed")
    assert any(h.get("severity") == "high" for h in hits), (
        f"expected a high-severity confirmation, got "
        f"{[(h.get('type'), h.get('severity')) for h in hits]}")

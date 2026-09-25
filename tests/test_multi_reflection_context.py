# -*- coding: utf-8 -*-
"""Phase 177: the primary reflection context must be the executable one.

A parameter is routinely echoed at SEVERAL points in one page (a nav
highlight, an HTML comment, and the actual sink).  Both engines used to
classify the reflection by the FIRST byte-stream occurrence only --
``ctx.rank_contexts`` existed from the start but had zero callers -- so a
marker that landed in an inert comment first and a live script string
second got payloads shaped for the comment, and the script-string corpus
was never consulted.  ``context.analyze_all`` now classifies every
reflection point and picks the primary by execution priority; single-
reflection pages keep exactly the old answer.

This file pins:
  * the classifier contract (priority selection, reflection-order list,
    single-reflection compatibility with ``analyze()``),
  * an end-to-end scan against a fixture page that echoes the parameter
    first into a comment and then into a <script> string -- the confirmed
    finding must carry the SCRIPT context, not the comment's.

Run:  pytest tests/test_multi_reflection_context.py
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core import context as ctx

MARK = "XSSMULTICTX"
HIGH_MED = ("high", "medium", "critical")


# ---------------------------------------------------------------------------
# Classifier contract
# ---------------------------------------------------------------------------

_MULTICTX_PAGE = (
    "<!doctype html><html><head><title>t</title></head><body>"
    "<!-- nav state: %s -->"
    "<p>hello</p>"
    "<script>var q = '%s';</script>"
    "</body></html>" % (MARK, MARK)
)


def test_first_occurrence_alone_is_the_old_bug():
    """``analyze()`` keeps its contract: first occurrence, no priority.

    The docstring documents this shape so the fix below is visibly a
    change in WHO decides, not in what the analyzer sees.
    """
    assert ctx.analyze(_MULTICTX_PAGE, MARK)["context"] == "html_comment"


def test_analyze_all_prefers_the_executable_context():
    sel = ctx.analyze_all(_MULTICTX_PAGE, MARK)
    assert sel["context"] == "script_string_sq", (
        "a live script-string reflection must outrank the comment it "
        "shares the page with")
    assert sel["contexts"] == ["html_comment", "script_string_sq"], (
        "the full context list must stay in reflection order")


def test_analyze_all_single_reflection_matches_analyze():
    """Back-compat: one reflection -> exactly the old answer."""
    body = "<p>hello %s world</p>" % MARK
    assert ctx.analyze_all(body, MARK)["context"] \
        == ctx.analyze(body, MARK)["context"] == "html_element"


def test_analyze_all_inert_only_reflection_stays_inert():
    """Priority must never INVENT an executable context."""
    body = "<!-- only %s here -->" % MARK
    sel = ctx.analyze_all(body, MARK)
    assert sel["context"] == "html_comment"
    assert sel["contexts"] == ["html_comment"]


def test_analyze_all_unreflected_marker():
    assert ctx.analyze_all("<p>nothing here</p>", MARK) == {
        "context": "html_element", "contexts": []}


# ---------------------------------------------------------------------------
# End to end: comment-first / script-second fixture page
# ---------------------------------------------------------------------------

PAGE_TEMPLATE = (
    b"<!doctype html><html><head><title>t</title></head><body>"
    b"<!-- nav state: {V} --><p>hello</p>"
    b"<script>var q = '{V}';</script>"
    b"</body></html>"
)


class _EchoHandler(BaseHTTPRequestHandler):
    """Reflects ?q= VERBATIM at two points: comment first, script second."""

    def do_GET(self):
        from urllib.parse import parse_qs, unquote_plus, urlparse
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        q = unquote_plus(q)
        body = PAGE_TEMPLATE.replace(b"{V}", q.encode("utf-8", "replace"))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a, **kw):  # keep test output clean
        pass


@pytest.fixture(scope="module")
def multictx_server():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    server = ThreadingHTTPServer(("127.0.0.1", 18931), _EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:18931"
    server.shutdown()


def _scan(base: str):
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner
    # No query in the URL itself: a ?q=x there AND params={'q': ...} makes
    # requests merge them into `?q=x&q=<payload>`, and an echo handler that
    # takes the first q silently never reflects the payload.
    sc = Scanner(requester=Requester(timeout=8), max_payloads=10,
                 max_transforms=6, dom_engine="static", verbose=False)
    sc.scan_target(f"{base}/list", method="GET", params={"q": "x"},
                   data={}, oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings
            if f.data.get("param") == "q"
            and f.data.get("severity") in HIGH_MED]


def test_comment_first_script_second_confirms_the_script_context(
        multictx_server):
    """The confirmed finding must be the SCRIPT reflection.

    The old engine classified this page ``html_comment`` and queued the
    comment-breakout corpus; whatever it confirmed, it confirmed with the
    COMMENT context.  The primary context is now the live script string,
    and that is what the finding must say.
    """
    hits = _scan(multictx_server)
    assert hits, ("a raw echo into both a comment and a script string "
                  "must confirm")
    script_hits = [h for h in hits
                   if h.get("context") in ("script_string_sq",
                                           "script_string_dq",
                                           "script_block")]
    assert script_hits, (
        "the confirmed finding must carry the script context the new "
        "priority selects, got contexts "
        f"{sorted({h.get('context') for h in hits})}")
    assert any(h.get("severity") == "high" for h in script_hits), (
        f"expected a high-severity confirmation, got "
        f"{[(h.get('type'), h.get('severity'), h.get('context')) for h in hits]}")

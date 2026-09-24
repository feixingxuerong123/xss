# -*- coding: utf-8 -*-
"""Response-body cap: it must bound memory, and it must admit when it bit.

Two hazards point the same way here.  A target that answers 2 GB makes the worker
OOM -- and after the exit-status work at least that now looks like an incomplete
scan rather than a clean one.  But a cap that silently truncates is worse in the
common case: a reflection 6 MB into an SPA bundle simply stops being visible, and
"0 findings" then means "we stopped looking".  So `_bound()` counts every body it
shortens and the report carries `responses_truncated`; the last test below is the
one that matters -- it proves the failure mode is *detectable*, not just real.

Run:  pytest tests/test_response_cap.py
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from xssentinel.core.requester import Requester  # noqa: E402

BODY = 5 * 1024 * 1024          # 5 MB of filler
MARKER = "XSSV_MARKER_TAIL"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):              # noqa: N802
        if self.path.startswith("/small"):
            payload = b"hello " + MARKER.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        tail = MARKER.encode() if self.path.startswith("/tail") else b""
        filler = b"a" * (BODY - len(tail))
        payload = filler + tail
        if self.path.startswith("/nolength"):
            # chunked: no Content-Length, so the cap has to be enforced while
            # reading rather than by trusting a header that is absent
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            step = 256 * 1024
            for i in range(0, len(payload), step):
                chunk = payload[i:i + step]
                self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):     # silence
        pass


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_a_cap_shortens_the_body_and_says_so(base):
    req = Requester(timeout=10, max_response_bytes=4096)
    resp = req.get(base + "/big")
    assert len(resp.text) <= 4096, "the cap did not bound the read"
    assert getattr(resp, "xss_truncated", False) is True
    assert req.truncated_responses == 1


def test_an_unbounded_requester_sees_the_whole_page(base):
    req = Requester(timeout=10)                       # 0 = unlimited
    resp = req.get(base + "/big")
    assert len(resp.text) == BODY
    assert req.truncated_responses == 0


def test_a_small_declared_body_is_left_alone(base):
    req = Requester(timeout=10, max_response_bytes=4096)
    resp = req.get(base + "/small")
    assert MARKER in resp.text
    assert req.truncated_responses == 0
    assert not getattr(resp, "xss_truncated", False)


def test_a_stream_without_content_length_is_still_bounded(base):
    """The realistic hostile case: a generated body that never declares its size."""
    req = Requester(timeout=20, max_response_bytes=8192)
    resp = req.get(base + "/nolength")
    assert len(resp.text) <= 8192
    assert req.truncated_responses == 1


def test_clones_inherit_the_cap_and_share_the_counter(base):
    parent = Requester(timeout=10, max_response_bytes=4096)
    child = parent.clone()
    assert child.max_response_bytes == 4096
    child.get(base + "/big")
    assert parent.truncated_responses == 1, (
        "the tally must not fragment across clones, or the report under-reports "
        "how much of the scan was bounded")


def test_a_reflection_past_the_cap_is_invisible_but_not_silently(base):
    """The reason the counter exists.

    The marker really is in the response; a capped read cannot see it.  Nothing
    in the scanner can recover that finding -- but `responses_truncated` turns
    "we found nothing" into "we stopped looking at 4 KB", which is the
    difference between a clean target and an unexamined one.
    """
    req = Requester(timeout=10, max_response_bytes=4096)
    resp = req.get(base + "/tail")
    assert MARKER not in resp.text
    assert req.truncated_responses == 1


def test_the_bounded_read_reaches_the_human_report(base):
    """Counting it was only half the job -- the deliverable has to SAY it.

    This is the assertion this file's module docstring claimed to contain and
    did not: `responses_truncated` was written into the JSON artifact and into
    nothing else, so the HTML a client reads reported a clean, complete-looking
    scan over a body it had examined only to the cap.
    """
    from xssentinel.core.report import build_html
    meta = {"generated": "g", "requests_attempted": 12, "requests_failed": 0,
            "responses_truncated": 3}
    html = build_html([], "http://t/", meta)
    assert "BOUNDED READ" in html
    assert "3 response" in html
    # A scan that reached everything is not "incomplete" -- the two banners
    # describe different blind spots and must not be conflated.
    assert "SCAN INCOMPLETE" not in html


def test_an_unbounded_scan_claims_no_bounded_read(base):
    """Reverse: the banner must not become boilerplate on every report."""
    from xssentinel.core.report import build_html
    for meta in ({"requests_attempted": 12, "requests_failed": 0},
                 {"requests_attempted": 12, "requests_failed": 0,
                  "responses_truncated": 0}):
        assert "BOUNDED READ" not in build_html([], "http://t/", meta)

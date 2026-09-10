# -*- coding: utf-8 -*-
"""Phase 110: POST-shaped benchmark cases (upload / stored).

The last two blind-spot families from Phase 108.  They need more than
-u:
  * upload  -> --upload-field + a POST target
  * stored  -> --stored-inject / --stored-view (a dedicated scan entry)

Two things are worth locking:
  1. _case_extra_args() must emit those flags for the new shapes and
     return None for the 117 pre-existing cases (identical command line).
  2. the benchmark server's store must actually round-trip: a POST write
     is rendered by the registered view path (that IS stored XSS).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from benchmark.runner import _case_extra_args, _build_target_url
from tests.conftest import SOCKETPAIR_OK, loopback_healthy


# -- flag construction (pure) ------------------------------------------------

def test_plain_case_needs_no_extra_args():
    case = {"path": "/r/elem01", "param": "q", "ground_truth": "vulnerable"}
    assert _case_extra_args("http://h", case) is None
    assert _build_target_url("http://h", case) == \
        "http://h/r/elem01?q=xssentinel_bench_probe"


def test_upload_case_gets_field_and_post_method():
    case = {"path": "/r/up01", "param": "q", "method": "POST",
            "upload_field": "avatar"}
    extra = _case_extra_args("http://h", case)
    assert "--upload-field" in extra and "avatar" in extra
    assert "--method" in extra and "POST" in extra
    # a body-carried case must keep the URL clean
    assert _build_target_url("http://h", case) == "http://h/r/up01"


def test_stored_case_gets_inject_and_view_urls():
    case = {"path": "/r/st01", "view_path": "/v/st01", "param": "q"}
    extra = _case_extra_args("http://h:9", case)
    assert "--stored-inject" in extra and "http://h:9/r/st01" in extra
    assert "--stored-view" in extra and "http://h:9/v/st01" in extra
    assert "--stored-param" in extra and "q" in extra


# -- the server's store round-trips (integration) ---------------------------

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback degraded (security software/TCP state)")


def _roundtrip(server_path, view_path, payload):
    import threading
    import time
    from http.server import ThreadingHTTPServer
    from urllib.request import build_opener, ProxyHandler, Request

    from benchmark.server import BenchmarkHandler, load_routes

    BenchmarkHandler.routes = load_routes()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    op = build_opener(ProxyHandler({}))       # never use the env proxy
    base = f"http://127.0.0.1:{port}"
    try:
        body = f"q={payload}".encode()
        req = Request(base + server_path, data=body, method="POST",
                      headers={"Content-Type":
                               "application/x-www-form-urlencoded"})
        op.open(req, timeout=6).read()
        return op.open(base + view_path, timeout=6).read().decode(
            "utf-8", "replace")
    finally:
        srv.shutdown()


def test_stored_write_then_view_renders_raw():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    html = _roundtrip("/r/st01", "/v/st01", "<svg onload=alert('p110')>")
    assert "<svg onload=alert('p110')>" in html, (
        "the vulnerable store must render the payload raw -- without this "
        "the stored case can never be detected")


def test_stored_write_escaped_then_view_renders_escaped():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    html = _roundtrip("/s/st01", "/v/st01e", "<svg onload=alert('p110')>")
    assert "<svg onload=" not in html, "the safe twin must not render raw"
    assert "&lt;svg" in html

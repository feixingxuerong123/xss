"""Phase 87: async L8 request-injection layers (decisive capability tests).

The multi-agent audit found that ``AsyncScanner.scan()`` never called
``advanced_layers.run_request_layers`` -- the four request-carrier XSS
classes (header / URL path / cookie / error page) were completely
untested in --async mode (a whole layer of missed findings).  It also
found that ``run_page_layers`` was called without the endpoint params,
so user-controlled-reflection sub-layers (import map, CSSI, dangling
markup) saw no params in async mode.

These tests prove the carriers are BACK, not merely that the code path
exists: a live local HTTP origin echoes the raw User-Agent header and
the raw URL path, and the async scan must produce real header_xss and
path_xss findings (semantic-confirmed, executable context).
"""
from __future__ import annotations
import asyncio
import os
import sys
import threading
from urllib.parse import unquote

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

# asyncio.run() needs a working loopback socketpair (see conftest.py);
# skip instead of hanging when the environment throttles it.
pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


def _echo_origin():
    """Start a local HTTP origin that raw-echoes the User-Agent header
    and the (percent-decoded) request path into the response body.

    Raw echo = the reflected payload stays executable markup, which is
    what header_xss / path_xss semantic confirmation needs.
    """
    import http.server as _http

    class _M(_http.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            path = unquote(self.path)
            body = (f"<html><body>"
                    f"<div id=\"ua\">{ua}</div>"
                    f"<div id=\"path\">{path}</div>"
                    f"</body></html>").encode("utf-8", "replace")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_async_scan(base):
    from xssentinel.core.async_scanner import AsyncScanner

    async def run():
        # Construct INSIDE the running loop: Python 3.9 binds the
        # internal asyncio.Lock() to the current loop (see
        # tests/test_async_pipeline.py).
        asc = AsyncScanner(
            max_concurrent=2, per_host_delay=0, jitter=0,
            max_payloads=4, max_transforms=2, timeout=10)
        out = []
        async for f in asc.scan(base, params={}):
            out.append(f)
        return out
    return asyncio.run(run())


class TestAsyncRequestLayers:
    """Phase 87: the four L8 request carriers are tested in async mode."""

    def test_async_recovers_header_and_path_xss(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv = _echo_origin()
        # Non-root path so the path-XSS layer has a segment to inject into.
        base = f"http://127.0.0.1:{srv.server_address[1]}/echo"
        try:
            found = _run_async_scan(base)
            types = {f.data.get("type") for f in found}
            assert "header_xss" in types, \
                f"header_xss missing, got {sorted(types)}"
            assert "path_xss" in types, \
                f"path_xss missing, got {sorted(types)}"
            hdr = next(f for f in found
                       if f.data.get("type") == "header_xss")
            assert hdr.data.get("param", "").startswith("(header:"), \
                f"unexpected header finding param: {hdr.data.get('param')}"
            assert hdr.data.get("severity") == "high"
        finally:
            srv.shutdown()

    def test_request_layers_coverage_touched(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv = _echo_origin()
        base = f"http://127.0.0.1:{srv.server_address[1]}/echo"
        try:
            _run_async_scan(base)
            # Part 1: the four sub-layers touch coverage when driven by
            # the new sync Requester (proof the transport stack runs).
            from xssentinel.core import advanced_layers
            from xssentinel.core.async_scanner import (AsyncScanner,
                                                       _AsyncScannerShim)

            # The scanner must be constructed INSIDE the running loop
            # (Python 3.9 binds the internal asyncio.Lock to the loop).
            holder = {}

            async def build():
                holder["asc"] = AsyncScanner(
                    max_concurrent=1, per_host_delay=0, jitter=0,
                    max_payloads=2, max_transforms=1, timeout=10)
                holder["req"] = holder["asc"]._get_sync_requester()

            asyncio.run(build())
            asc, req = holder["asc"], holder["req"]
            shim = _AsyncScannerShim(asc)
            advanced_layers.run_request_layers(
                shim, req, base, "GET", {}, {})
            layer_ids = {t[1] for t in shim.coverage.touched}
            assert {"L8_header", "L8_path", "L8_cookie",
                    "L8_error_page"} <= layer_ids, sorted(layer_ids)

            # Part 2: the async wiring itself touches L8_request (spy on
            # run_request_layers; the shim is passed as the first arg).
            captured = {}

            def spy(scanner, *a, **kw):
                captured["touched"] = list(scanner.coverage.touched)
                captured["args"] = a

            async def wiring():
                async for _ in asc._scan_request_layers(
                        base, "GET", {"q": "v"}, {}):
                    pass

            import unittest.mock as _mock
            with _mock.patch.object(advanced_layers, "run_request_layers",
                                    spy):
                asyncio.run(wiring())
            assert "L8_request" in {t[1] for t in captured["touched"]}, \
                captured["touched"]
            # The real sync Requester is passed through (not None).
            assert captured["args"][0] is req, "shim got no sync Requester"
        finally:
            srv.shutdown()

    def test_scan_advanced_page_forwards_params(self):
        """Phase 87: run_page_layers receives the endpoint params in
        async mode (import map / CSSI / dangling markup reflection
        sub-layers need them)."""
        from unittest import mock
        from xssentinel.core import advanced_layers
        from xssentinel.core.async_scanner import AsyncScanner

        captured = {}

        def fake_run_page_layers(shim, req, url, text, params=None):
            captured["params"] = params

        async def run():
            asc = AsyncScanner(
                max_concurrent=1, per_host_delay=0, jitter=0,
                max_payloads=2, max_transforms=1, timeout=10)
            async for _ in asc._scan_advanced_page(
                    "http://127.0.0.1:1/x", "<html></html>",
                    params={"q": "val"}):
                pass

        with mock.patch.object(advanced_layers, "run_page_layers",
                               fake_run_page_layers):
            asyncio.run(run())
        assert captured.get("params") == {"q": "val"}, captured

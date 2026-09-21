"""Phase 171: the header carrier must probe EVERY injectable header.

``_scan_header_xss`` (``core/layers/transport_layers.py``) iterated
``INJECTABLE_HEADERS[:6]`` -- the first six names only.  ``True-Client-IP``,
the header Juice Shop's HTTP-Header XSS challenge reads
(``build/routes/saveLoginIp.js:55``), is the SEVENTH entry, so it was never
put on the wire: a real, hand-confirmed finding on a real target was
unreachable through a one-slice truncation.

Phase 170c located it and proved the rest of the path was intact (reflection
analysis and semantic confirmation both fire once the header is sent).  These
tests lock the contract so the slice cannot come back:

  * every declared header is actually sent (static, no loopback needed)
  * a reflection that ONLY appears on a late header is still confirmed
  * the same holds in ``--async`` mode: the carrier is shared through
    ``_AsyncScannerShim``, so both engines must agree
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import loopback_healthy

from xssentinel.core import header_xss as header_mod
from xssentinel.core.layers import transport_layers


class _Resp:
    """Minimal stand-in for a Requester response."""

    def __init__(self, text: str = "", headers: dict | None = None):
        self.text = text
        self.headers = headers or {}
        self.status_code = 200


class _RecordingRequester:
    """Records which header names were actually put on the wire."""

    def __init__(self, text: str = ""):
        self.sent: list[dict] = []
        self._text = text

    def get(self, url, headers=None, **kw):
        self.sent.append(dict(headers or {}))
        return _Resp(self._text)


class _FakeCoverage:
    def touch_layer(self, *a, **k):
        pass

    def record_request(self, *a, **k):
        pass

    def record_finding(self, *a, **k):
        pass


class _FakeScanner:
    def __init__(self):
        self.coverage = _FakeCoverage()
        self.verbose = False
        self.requests_made = 0
        self.findings: list = []

    def _bump(self):
        self.requests_made += 1

    def _add(self, finding):
        self.findings.append(finding)


def _late_header_origin():
    """Local origin that raw-echoes ONLY ``True-Client-IP``.

    The first six headers in ``INJECTABLE_HEADERS`` are deliberately not
    reflected, so any confirmed header_xss on this origin can only have come
    from a header the old ``[:6]`` slice never sent.
    """
    import http.server as _http

    class _M(_http.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            late = self.headers.get("True-Client-IP", "")
            body = ('<html><body><div id="ip">' + late
                    + "</div></body></html>").encode("utf-8", "replace")
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


class TestHeaderSliceContract:
    """The truncation itself, locked statically (runs without loopback)."""

    def test_every_injectable_header_is_probed(self):
        sc = _FakeScanner()
        req = _RecordingRequester()
        transport_layers._scan_header_xss(sc, req, "http://127.0.0.1:1/x")

        sent: set[str] = set()
        for one_call in req.sent:
            sent.update(one_call.keys())

        declared = header_mod.INJECTABLE_HEADERS
        missing = [h for h in declared if h not in sent]
        assert not missing, (
            f"{len(missing)} of {len(declared)} declared header(s) were never "
            f"sent: {missing}.  The carrier must probe the whole list, not "
            f"a slice of it.")

    def test_true_client_ip_is_not_the_edge_any_more(self):
        """Pin the exact entry the slice used to cut, so re-ordering the list
        is a visible, deliberate change rather than a silent regression."""
        declared = header_mod.INJECTABLE_HEADERS
        assert declared.index("True-Client-IP") == 6, (
            "True-Client-IP moved; if you re-ordered INJECTABLE_HEADERS, "
            "confirm the real-target evidence still lines up")
        assert len(declared) > 6, "the list must stay longer than the old slice"


class TestLateHeaderReflectionIsConfirmed:
    """A reflection reachable only through a late header must be a finding."""

    def test_sync_late_header_reflection(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")

        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        srv = _late_header_origin()
        base = f"http://127.0.0.1:{srv.server_address[1]}/echo"
        try:
            sc = Scanner(requester=Requester(timeout=8), max_payloads=4,
                         max_transforms=2, dom_engine="static", verbose=False)
            sc.scan_target(base, method="GET", params={}, data={},
                           oob_collect=False)
            params = [f.data.get("param") for f in sc.findings
                      if f.data.get("type") == "header_xss"]
            assert "(header:True-Client-IP)" in params, (
                f"a reflection that only the 7th header reaches was not "
                f"confirmed; header findings were {params}")
        finally:
            srv.shutdown()

    def test_async_late_header_reflection(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")

        from xssentinel.core.async_scanner import AsyncScanner

        srv = _late_header_origin()
        base = f"http://127.0.0.1:{srv.server_address[1]}/echo"

        async def run():
            # Construct INSIDE the running loop: Python 3.9 binds the
            # internal asyncio.Lock() to the current loop.
            asc = AsyncScanner(
                max_concurrent=1, per_host_delay=0, jitter=0,
                max_payloads=4, max_transforms=2, timeout=10)
            out = []
            async for f in asc.scan(base, params={}):
                out.append(f)
            return out

        try:
            found = asyncio.run(run())
            params = [f.data.get("param") for f in found
                      if f.data.get("type") == "header_xss"]
            assert "(header:True-Client-IP)" in params, (
                f"async engine missed the late-header reflection that sync "
                f"finds; header findings were {params}")
        finally:
            srv.shutdown()

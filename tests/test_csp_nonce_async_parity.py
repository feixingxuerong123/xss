# -*- coding: utf-8 -*-
"""Phase 100: CSP nonce-leak exploitation must exist on BOTH engines.

The sync scanner has ``_try_csp_nonce`` (Phase 36): a nonce CSP blocks
plain inline payloads, but when the nonce itself is echoed into the
page, a script carrying the REAL nonce executes.  The async engine had
no equivalent -- so ``--async`` silently missed every nonce-leak
endpoint sync reported (benchmark pos-csp-01: sync TP, async FN with a
NORMAL finish, i.e. a real detection gap, not a timeout).

Two async-specific traps this file pins down:
  * the exploit must run on the MARKER-reflection response -- the
    payload loop overwrites ``text`` on every variant, so a late read
    inspects the last payload's response where the marker is gone;
  * the CSP header must come from that same probe response.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")

NONCE = "k8Fj3x9Qm2Rw7Yp4"
CSP = (f"default-src 'self'; script-src 'strict-dynamic' "
       f"'nonce-{NONCE}' 'unsafe-inline'")


class _H(BaseHTTPRequestHandler):
    """Nonce CSP + the nonce leaked in a script tag + raw reflection."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = (f"<!DOCTYPE html><html><head><title>t</title></head><body>"
                f"<script nonce=\"{NONCE}\">var a=1;</script>"
                f"<div>{q}</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_async_detects_csp_nonce_leak():
    from xssentinel.core.async_scanner import AsyncScanner

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        asc = AsyncScanner(max_concurrent=4, max_payloads=6,
                           max_transforms=2, timeout=15,
                           headers={}, cookies={})

        async def run():
            got = []
            async for f in asc.scan(f"http://127.0.0.1:{port}/x",
                                    method="GET", params={"q": "probe"},
                                    data={}):
                got.append(f)
            return got

        findings = asyncio.run(run())
        assert findings, (
            "async engine missed a leaked-CSP-nonce XSS (sync reports it) "
            f"-- requests_made={asc.requests_made}")
        assert any(f"'{NONCE}'" in (f.data.get("payload") or "")
                   or NONCE in (f.data.get("payload") or "")
                   for f in findings), (
            f"finding payload does not carry the leaked nonce: "
            f"{[f.data.get('payload') for f in findings]}")
    finally:
        srv.shutdown()


def test_host_loop_is_not_hijacked_by_scanner_construction():
    """Regression: AsyncScanner must not bind primitives to a host loop.

    py3.9 binds asyncio.Lock() to the loop that is current at
    construction.  Building it in __init__ either raised (host thread
    with no loop) or -- when the constructor installed a loop of its own
    -- bound it to a loop the caller's ``asyncio.run()`` never uses,
    which turned a clean error into a HANG (every ``async with lock``
    awaited a dead loop).  Primitives are now created lazily inside the
    running loop; this test hangs (pytest-timeout failure) if that
    regresses.
    """
    asyncio.set_event_loop(asyncio.new_event_loop())
    from xssentinel.core.async_scanner import AsyncScanner

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        asc = AsyncScanner(max_concurrent=4, max_payloads=4,
                           max_transforms=2, timeout=15)
        assert asc._lock is None, "lock must not be created before a loop runs"

        async def run():
            got = []
            async for f in asc.scan(f"http://127.0.0.1:{port}/x",
                                    method="GET", params={"q": "probe"},
                                    data={}):
                got.append(f)
            return got

        findings = asyncio.run(run())
        assert findings, "host-loop scenario must still detect the leak"
    finally:
        srv.shutdown()


def test_async_csp_nonce_uses_probe_response_not_last_variant():
    """Regression guard for the overwritten-``text`` trap.

    A server whose NONCE only appears on the marker-reflection response
    (and not on later payload responses) must still be exploited: the
    exploit must read the probe snapshot, not ``text`` at loop exit.
    """
    class _Once(_H):
        """Only CLEAN probe responses carry the nonce page; every payload
        response (anything with markup in ``q``) is a flat no-op page.

        Counting requests would not work: the scanner may send baseline
        traffic before the marker probe, which would make the probe itself
        land on a no-op page and end the param before any exploit runs.
        """

        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if "<" in q:
                # A payload: echoed, but the nonce script is NOT present
                # any more -- a bare inline payload cannot execute under a
                # nonce CSP, and a late read of ``text`` finds no nonce.
                body = (f"<!DOCTYPE html><html><body>"
                        f"<div>{q}</div></body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Security-Policy", CSP)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            _H.do_GET(self)

    from xssentinel.core.async_scanner import AsyncScanner

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Once)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        asc = AsyncScanner(max_concurrent=4, max_payloads=4,
                           max_transforms=2, timeout=15,
                           headers={}, cookies={})

        async def run():
            got = []
            async for f in asc.scan(f"http://127.0.0.1:{port}/x",
                                    method="GET", params={"q": "probe"},
                                    data={}):
                got.append(f)
            return got

        findings = asyncio.run(run())
        assert findings and any(
            NONCE in (f.data.get("payload") or "") for f in findings), (
            "nonce exploit read the LAST response instead of the "
            "marker-reflection snapshot")
    finally:
        srv.shutdown()

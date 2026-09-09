# -*- coding: utf-8 -*-
"""Phase 102: WAF-guarded target -- detection + bypass chain, end to end.

A large share of real targets sit behind Cloudflare / ModSecurity / Akamai.
For those the FIRST question is whether the scanner (a) notices the WAF
and (b) still lands a confirmed finding through it.  waf.py (fingerprints)
and bypass.py (per-vendor chains, Phase 91) both existed, and the scanner
appends bypass variants when a WAF is seen -- but nothing exercised the
whole loop against a target that actually BLOCKS the naive payloads.

The fake WAF here is deliberately realistic:
  * it announces itself (Server: cloudflare, CF-RAY, and a Ray ID comment
    in the body) so the fingerprint bites whichever response is inspected
  * it 403s the two PLAIN shapes a WAF signature knows by heart --
    `<script` and `<svg onload=`
  * it passes everything else: case-mixed tags, entity/UTF-7/unicode
    encodings, other event handlers, `javascript:` URIs.

So a scanner that only fires naive payloads ends with zero findings,
while one that detects the WAF and escalates to the bypass chain lands
the hit (verified: the winning payload is an alternative syntax such as
`<svg/onload=...>`, never a blocked one).

Two calibration notes, both learned the hard way on this host:
  * the budget is deliberately SMALL (4x3).  The bypass chain is
    prepended once the WAF is recognised, so it fires early -- while the
    full calibrated budget (~170 variants) is slow enough here that the
    scan intermittently never reached a confirmable variant, which made
    an earlier version of this drill flaky (96s-128s runs, occasional
    zero-finding runs).
  * blocking `onerror=`/`onload=` (any casing, post-decode) as well
    makes the target harder than a real rule-based WAF: at that point
    only large budgets get through, i.e. the test measures the host's
    speed rather than the scanner's bypass logic.
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback degraded (security software/TCP state)")

BLOCKED = ("<script", "<svg onload=")


class _FakeWaf(BaseHTTPRequestHandler):
    """Announces Cloudflare, blocks naive payload shapes, echoes the rest."""

    def log_message(self, *a):
        pass

    def _send(self, status: int, body: bytes, waf: bool = True):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if waf:
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "7c1f2e3a4b5c6d7e-SJC")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, unquote
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        low = unquote(q).lower()
        if any(b in low for b in BLOCKED):
            # Blocked only when the PLAIN signature is present.
            self._send(403, b"<html><body>Sorry, you have been blocked"
                            b" (Cloudflare Ray ID: 7c1f2e3a4b5c6d7e)"
                            b"</body></html>")
            return
        self._send(200, (f"<!-- Cloudflare Ray ID: 7c1f2e3a4b5c6d7e -->"
                        f"<html><body><div>{q}</div></body></html>").encode())


def test_waf_detected_and_bypassed():
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeWaf)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        # Deliberately a SMALL budget: the full calibrated budget (14x12)
        # sends ~170 payload variants and on this host can hit the scan
        # timeout before the bypass chain is reached, which made an
        # earlier version of this drill flaky.  The bypass chain is
        # prepended, so it fires early.
        sc = Scanner(requester=Requester(timeout=20), verbose=False,
                     max_payloads=4, max_transforms=3)
        sc.use_headless = False
        sc.scan_endpoint(f"http://127.0.0.1:{port}/vuln", method="GET",
                         params={"q": "probe"}, data={})
        # (a) the WAF must have been recognised
        assert sc.waf_name, (
            "Cloudflare-looking target was not fingerprinted -- bypass "
            "chains can never fire without it")
        # (b) and a finding must still land through the bypass chain
        assert sc.findings, (
            f"WAF detected ({sc.waf_name}) but no payload got through -- "
            "the bypass chain does not work end to end")
        # the winning payload must NOT be one the WAF blocks, i.e. it
        # really is a bypass and not a naive hit that slipped past
        won = sc.findings[0].data.get("payload") or ""
        assert not any(b in won.lower() for b in BLOCKED), (
            f"finding payload is a naive shape the fake WAF 403s: {won!r}")
    finally:
        srv.shutdown()


def test_no_waf_plain_target_still_works():
    """Control: without WAF headers the same page is detected normally."""
    if not loopback_healthy():
        pytest.skip("loopback degraded")
    from xssentinel.core.requester import Requester
    from xssentinel.core.scanner import Scanner

    class _Plain(_FakeWaf):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self._send(200, f"<html><body><div>{q}</div></body></html>"
                       .encode(), waf=False)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Plain)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        sc = Scanner(requester=Requester(timeout=15), verbose=False)
        sc.use_headless = False
        sc.scan_endpoint(f"http://127.0.0.1:{port}/vuln", method="GET",
                         params={"q": "probe"}, data={})
        assert sc.findings, "plain (non-WAF) target regressed"
    finally:
        srv.shutdown()

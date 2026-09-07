"""Integration tests for the scan ORCHESTRATION (Phase 43).

The last two coverage fortresses: AsyncScanner.scan() (the L1..L7 pipeline
dispatcher) and CrawlMixin._crawl() (the BFS endpoint discoverer).  Both run
against a REAL local HTTP site (stdlib ThreadingHTTPServer) with REAL aiohttp
for the async path -- no session mocks -- so the wiring (baseline request ->
parallel layers -> findings) is exercised end-to-end.

Site map:
    /            index page linking to /vuln and /page2
    /vuln, /page2, /deep   reflect ?q= VERBATIM into a <div> (confirmable)
    /safe        HTML-escapes ?q= (no finding)
"""
from __future__ import annotations
import asyncio
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK

# The async path needs a working loopback socketpair for asyncio.run().
_pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class _Site:
    """Minimal multi-page reflection site on an OS-assigned port."""

    def __init__(self):
        self.server = None
        self.port = None

    def start(self):
        site = self

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                p = urlparse(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                if p.path == "/":
                    # Query-carrying links: _crawl registers these as GET
                    # endpoints WITH params ({"q": "xss"}) so the reflection
                    # layer has a probe point on each discovered page.
                    body = ("<html><body>"
                            "<a href='/vuln?q=home'>vuln</a>"
                            "<a href='/page2?q=home'>p2</a>"
                            "</body></html>")
                elif p.path in ("/vuln", "/page2", "/deep"):
                    body = f"<html><body><div>{q}</div></body></html>"
                elif p.path == "/safe":
                    import html as h
                    body = f"<html><body><div>{h.escape(q)}</div></body></html>"
                else:
                    body = "<html><body>nf</body></html>"
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        # Windows reserves whole low-port ranges: probe upward, then let
        # the OS assign if needed.
        for port in range(8930, 8942):
            try:
                self.server = ThreadingHTTPServer(("127.0.0.1", port), _H)
                break
            except OSError:
                continue
        if self.server is None:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                free = s.getsockname()[1]
            self.server = ThreadingHTTPServer(("127.0.0.1", free), _H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        time.sleep(0.2)

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture(scope="module")
def site():
    # Phase 43: RUNTIME health gate — a long session can degrade the
    # loopback AFTER collection-time probes passed; skip instead of fail.
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session (security software/TCP state)")
    s = _Site()
    s.start()
    yield s
    s.stop()


@pytest.fixture(autouse=True)
def _loopback_guard():
    """Re-check loopback health immediately before EVERY test.

    ``site`` is module-scoped, so it probes loopback once when the module
    starts; a long session can degrade the loopback afterwards, leaving the
    shared server reachable at setup but failing mid-test.  That surfaces as
    a FAILURE on a healthy codebase, which erodes trust in the suite (the
    project's own reruns=1 hack only papers over it).  Probing again at the
    per-test boundary turns those into honest skips.
    """
    from tests.conftest import loopback_healthy
    if not loopback_healthy(timeout=1.5):
        pytest.skip("loopback degraded mid-session "
                    "(security software/TCP state)")


# ---------------------------------------------------------------------------
# Async scan() orchestration (real aiohttp, no session mocks)
# ---------------------------------------------------------------------------

class TestAsyncScanOrchestration:
    @pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair")
    def test_scan_reflective_page_yields_reflected(self, site):
        from xssentinel.core.async_scanner import AsyncScanner

        async def main():
            asc = AsyncScanner(max_concurrent=4, max_payloads=3,
                               max_transforms=2, timeout=8,
                               advanced_layers=False, verbose=False)
            findings = []
            async for f in asc.scan(f"{site.base}/vuln",
                                    params={"q": "probe"}):
                findings.append(f)
            return asc, findings

        asc, findings = asyncio.run(main())
        assert any(f.data["type"] == "reflected" for f in findings), \
            "scan() orchestration failed to confirm a live reflection"
        assert asc.requests_made >= 2  # baseline + probes

    @pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair")
    def test_scan_safe_page_no_findings(self, site):
        from xssentinel.core.async_scanner import AsyncScanner

        async def main():
            asc = AsyncScanner(max_concurrent=4, max_payloads=3,
                               max_transforms=2, timeout=8,
                               advanced_layers=False, verbose=False)
            findings = []
            async for f in asc.scan(f"{site.base}/safe",
                                    params={"q": "probe"}):
                findings.append(f)
            return asc, findings

        asc, findings = asyncio.run(main())
        assert findings == []  # escaped output must not confirm

    @pytest.mark.skipif(not SOCKETPAIR_OK, reason="loopback socketpair")
    def test_scan_aiohttp_missing_raises(self, site):
        from xssentinel.core.async_scanner import AsyncScanner
        from unittest.mock import patch

        async def main():
            asc = AsyncScanner(max_concurrent=2, timeout=5, verbose=False)
            with patch.object(asc, "_aiohttp_available", False):
                async for _ in asc.scan(f"{site.base}/vuln"):
                    pass

        with pytest.raises(RuntimeError):
            asyncio.run(main())


class TestCliAsyncPath:
    """Phase 43 regression: the CLI async runners must fill scan-policy
    defaults BEFORE constructing AsyncScanner -- since Phase 33 the
    argparse defaults for threads/max_payloads/max_transforms are None
    (policy-managed), and the unfilled Nones crashed the constructor
    ('>' not supported between NoneType and int).  max-payloads/
    max-transforms are deliberately OMITTED from argv so the preset-fill
    path is what's under test."""

    def _with_fresh_loop(self, fn):
        """Run fn() with a fresh main-thread event loop.

        Python 3.9: earlier asyncio.run() calls in this process leave NO
        current loop; AsyncScanner.__init__ runs in sync context and needs
        get_event_loop() to succeed (the CLI subprocess always has one, so
        this is test-environment management, not a product issue).
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return fn()
        finally:
            loop.close()
            asyncio.set_event_loop(None)

    def test_run_async_scan_produces_findings(self, site):
        from xssentinel import __main__ as cli
        from xssentinel.cli_runner import _run_async_scan

        argv = ["-u", f"{site.base}/vuln?q=test", "--async",
                "--threads", "2", "--timeout", "8",
                "--progress", "none", "--log-level", "error"]
        args = cli.build_parser().parse_args(argv)
        args.verify_ssl = not args.no_verify_ssl

        def _call():
            return _run_async_scan(args, f"{site.base}/vuln?q=test",
                                   oob=None, progress=None, checkpoint=None)

        shim = self._with_fresh_loop(_call)
        assert shim is not None, "async scan fell back to sync unexpectedly"
        types = [f.data["type"] if hasattr(f, "data") else f.get("type")
                 for f in shim.findings]
        assert "reflected" in types, f"no reflected finding; got {types}"

    def test_run_async_batch_produces_findings(self, site):
        from xssentinel import __main__ as cli
        from xssentinel.cli_runner import _run_async_batch

        urls = [f"{site.base}/vuln?q=a", f"{site.base}/page2?q=b"]
        argv = ["-u", f"{site.base}/vuln?q=test", "--async",
                "--threads", "2", "--timeout", "8",
                "--progress", "none", "--log-level", "error"]
        args = cli.build_parser().parse_args(argv)
        args.verify_ssl = not args.no_verify_ssl

        def _call():
            return _run_async_batch(args, urls, requester=None, oob=None,
                                    progress=None, checkpoint=None)

        results = self._with_fresh_loop(_call)
        total = sum(len(s.findings) for s in results.values())
        assert total >= 1, "async batch produced zero findings across URLs"


# ---------------------------------------------------------------------------
# Sync BFS crawler (CrawlMixin._crawl) + crawl-driven scan
# ---------------------------------------------------------------------------

class TestSyncCrawlBFS:
    def test_crawl_discovers_linked_endpoints(self, site):
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        sc = Scanner(requester=Requester(timeout=8), crawl=True,
                     crawl_depth=1, verbose=False)
        eps = sc._crawl(f"{site.base}/")
        paths = {urlparse(u).path for u, m, p, d in eps}
        assert "/vuln" in paths and "/page2" in paths

    def test_scan_with_crawl_finds_both_pages(self, site):
        """Full scan_target with crawl: index + discovered pages all scanned;
        the reflected endpoints must each produce a finding."""
        from xssentinel.core.requester import Requester
        from xssentinel.core.scanner import Scanner

        sc = Scanner(requester=Requester(timeout=8), crawl=True,
                     crawl_depth=1, use_headless=False,
                     max_payloads=3, max_transforms=2, verbose=False)
        sc.scan_target(f"{site.base}/", method="GET", params={"q": "probe"})
        ftypes = [f.data["type"] if hasattr(f, "data") else f.get("type")
                  for f in sc.findings]
        assert "reflected" in ftypes, \
            f"crawl-scan missed the reflective pages; got {ftypes}"
        assert sc.requests_made > 5  # index + discovered pages + probes

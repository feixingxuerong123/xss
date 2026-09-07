"""Wiring tests for Phase 44 standalone fast checks on the REAL CLI path.

Regression guard for the silent-no-op bug where --sqli-check /
--check-outdated-js parsed fine but were only consumed inside the passive
proxy hook -- on a direct scan the flags did NOTHING.  These tests drive
cli_runner._run_scan with real argparse-parsed args against a live origin
and assert the fast-check findings actually land in the scanner.
"""
from __future__ import annotations
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.cli_runner import _run_scan
from xssentinel.core.requester import Requester
from xssentinel.__main__ import build_parser

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class _FastOrigin:
    """/search: MySQL error echo on quote injection (SQLi-check target),
    also reflects q unsafely (XSS target).  /: page with outdated jQuery."""

    def __init__(self):
        self.server = None

    def start(self):
        class _H(BaseHTTPRequestHandler):
            def _send(self, body, code=200):
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                p = urlparse(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                if p.path == "/search":
                    if "'" in q or '"' in q:
                        self._send(
                            "<pre>SQLSTATE[42000]: Syntax error: You have an "
                            f"error in your SQL syntax near '{q}' at line 1"
                            "</pre>")
                    else:
                        self._send(f"<h1>results for {q}</h1>")
                elif p.path == "/":
                    self._send(
                        "<html><head><script src='/static/js/"
                        "jquery-1.7.2.min.js'></script></head>"
                        "<body>home</body></html>")
                else:
                    self._send("<h1>nf</h1>", 404)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
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


def _run(args_argv: list[str], url: str):
    """Parse real argv and run the sync scan pipeline against url."""
    args = build_parser().parse_args(args_argv + ["-u", url])
    req = Requester(timeout=15)
    from xssentinel.core.progress import NullProgress
    scanner = _run_scan(args, url, req, oob=None, progress=NullProgress(),
                        checkpoint=None)
    return scanner


class TestStandaloneFastChecks:
    @pytest.fixture()
    def origin(self):
        o = _FastOrigin()
        o.start()
        yield o
        o.stop()

    def test_sqli_check_finding_lands(self, origin):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        sc = _run(["--sqli-check", "--scan-policy", "quick",
                   "--max-payloads", "2"],
                  f"{origin.base}/search?q=test")
        types = {f.data.get("type") for f in sc.findings}
        assert "sqli_error_based" in types, (
            "standalone --sqli-check produced no finding; the flag is "
            f"silently not wired. findings={sorted(types)}")

    def test_outdated_js_finding_lands(self, origin):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        sc = _run(["--check-outdated-js", "--scan-policy", "quick",
                   "--max-payloads", "2"],
                  f"{origin.base}/")
        libs = {(f.data.get("type"), f.data.get("library"))
                for f in sc.findings}
        assert ("outdated_js_lib", "jQuery") in libs, (
            "standalone --check-outdated-js produced no finding; the flag "
            f"is silently not wired. findings={sorted(libs)}")

    def test_no_flag_no_fast_findings(self, origin):
        """Without the flags neither fast-check finding type may appear."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        sc = _run(["--scan-policy", "quick", "--max-payloads", "2"],
                  f"{origin.base}/search?q=test")
        types = {f.data.get("type") for f in sc.findings}
        assert "sqli_error_based" not in types, \
            f"sqli finding appeared without --sqli-check: {sorted(types)}"
        assert "outdated_js_lib" not in types, \
            f"outdated-js finding appeared without flag: {sorted(types)}"

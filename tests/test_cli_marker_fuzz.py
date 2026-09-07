"""Tests for the --fuzz-body CLI mode (Phase 80).

Live loopback: an origin that echoes the raw POST body inside an HTML
shell -- the marker-injection equivalent of the mirror fixture.  A
payload at the marker position therefore renders unescaped and is
confirmed by the execution-shape criterion.  The handler's output goes
to stdout (capsys), so the assertions check the printed summary.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import http.server
import threading

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy
from xssentinel.cli_commands import _run_marker_fuzz
from xssentinel.core.requester import Requester

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK, reason="loopback socketpair degraded")


class _EchoBodyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        out = f"<html><div>{body}</div></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def _args(url):
    from types import SimpleNamespace
    return SimpleNamespace(
        url=url, method="POST", fuzz_body='{"filter": FUZZ, "id": 1}',
        fuzz_marker="FUZZ", fuzz_max=5, timeout=10, proxy=None,
        verify_ssl=False, rate_limit=0, params=None)


class TestMarkerFuzzCli:
    def test_confirmed_and_reflected_reported(self, capsys):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                              _EchoBodyHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            args = _args(f"http://127.0.0.1:{srv.server_address[1]}/api")
            rc = _run_marker_fuzz(args)
            out = capsys.readouterr().out
        finally:
            srv.shutdown()
        assert rc == 0
        assert "marker-fuzz" in out
        assert "confirmed" in out
        assert "[CONFIRMED]" in out          # svg onload shape echoed raw

    def test_missing_marker_fails_fast(self, capsys):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                              _EchoBodyHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            args = _args(f"http://127.0.0.1:{srv.server_address[1]}/api")
            args.fuzz_body = '{"no": "marker here"}'
            rc = _run_marker_fuzz(args)
            err = capsys.readouterr().err
        finally:
            srv.shutdown()
        assert rc == 1
        assert "not found in --fuzz-body" in err

    def test_missing_url_fails_fast(self, capsys):
        args = _args("http://irrelevant/")
        args.url = None
        rc = _run_marker_fuzz(args)
        assert rc == 1

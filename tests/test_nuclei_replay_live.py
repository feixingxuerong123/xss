"""Live replay-fidelity tests for the nuclei exporter (Phase 55 固化).

Phase 55 routed header/cookie/path findings through their real transport
(raw templates carrying the request header / Cookie / percent-encoded
path).  Unit tests assert the template SHAPE; these tests prove the
templates actually FIRE against a real origin -- the replay a Phase-49
export could never produce.  They need a real `nuclei` binary (skipped
when absent) and drive it as a subprocess with -duc (offline) against a
loopback fixture that echoes each carrier.
"""
from __future__ import annotations
import http.server
import os
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import report

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_HAS_NUCLEI = shutil.which("nuclei") is not None

pytestmark = [
    pytest.mark.skipif(not SOCKETPAIR_OK,
                       reason="loopback socketpair degraded"),
    pytest.mark.skipif(not _HAS_NUCLEI,
                       reason="nuclei binary not installed"),
]


def _finding(ftype, param, url, payload):
    return {
        "type": ftype, "severity": "high", "param": param,
        "context": "html_element", "payload": payload, "url": url,
        "method": "GET", "detail": "confirmed", "confidence": "high",
        "transform": ["raw"], "poc": {"curl": "", "url": url},
    }


class _EchoOrigin:
    """Echoes User-Agent, a Cookie value, or the last path segment."""

    def __init__(self):
        self.server = None
        self.port = None

    def start(self):
        class _H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                from urllib.parse import unquote
                p = urlparse(self.path)
                if p.path == "/ua":
                    val = self.headers.get("User-Agent", "?")
                elif p.path == "/ck":
                    raw = self.headers.get("Cookie", "")
                    val = raw.replace("sid=", "") or "?"
                else:
                    # Server-side handlers that reflect the URL echo the
                    # DECODED path (PATH_INFO-style), which is what makes a
                    # path-injection echo attackable in the first place.
                    val = unquote(p.path) or "?"
                body = f"<html><body><div>echo:{val}</div></body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        for port in range(9022, 9034):
            try:
                self.server = http.server.ThreadingHTTPServer(
                    ("127.0.0.1", port), _H)
                break
            except OSError:
                continue
        if self.server is None:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                free = s.getsockname()[1]
            self.server = http.server.ThreadingHTTPServer(
                ("127.0.0.1", free), _H)
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


def _run_nuclei(template_path: str, base: str) -> bool:
    """Run one template against the origin; True when it matched."""
    env = {**os.environ, "NO_PROXY": "127.0.0.1,localhost"}
    r = subprocess.run(
        ["nuclei", "-duc", "-silent", "-jsonl", "-u", base, "-t",
         template_path],
        capture_output=True, text=True, timeout=90, env=env)
    if r.returncode != 0:
        return False
    return any('"matched-at"' in ln for ln in r.stdout.splitlines())


class TestNucleiReplayLive:
    @pytest.fixture()
    def origin(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        o = _EchoOrigin()
        o.start()
        yield o
        o.stop()

    def test_header_xss_template_fires_live(self, origin, tmp_path):
        f = _finding(
            "header_xss", "(header:User-Agent)", origin.base + "/ua",
            "<svg/onload=alert('xsshd_live01')>")
        p = report.write_nuclei_dir([f], origin.base, {}, str(tmp_path))[0]
        assert _run_nuclei(p, origin.base), "header replay did not match"

    def test_cookie_xss_template_fires_live(self, origin, tmp_path):
        f = _finding(
            "cookie_xss", "(cookie:sid)", origin.base + "/ck",
            "<svg/onload=alert('xsck_live02')>")
        p = report.write_nuclei_dir([f], origin.base, {}, str(tmp_path))[0]
        assert _run_nuclei(p, origin.base), "cookie replay did not match"

    def test_path_xss_template_fires_live(self, origin, tmp_path):
        payload = "<svg/onload=alert('xspath_live03')>"
        f = _finding("path_xss", "(path)",
                     origin.base + "/p/" + payload, payload)
        p = report.write_nuclei_dir([f], origin.base, {}, str(tmp_path))[0]
        assert _run_nuclei(p, origin.base), "path replay did not match"

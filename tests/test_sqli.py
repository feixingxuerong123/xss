"""Tests for the Phase 44 SQLi error-reflection grep engine.

detect_db_error() fingerprint matching is unit-tested for every DB family
plus the negative path; run_sqli_check() is exercised against a REAL
loopback origin that echoes a MySQL-style error on quote injection.
"""
from __future__ import annotations
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import sqli
from xssentinel.core.requester import Requester

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class TestDetectDbError:
    def test_mysql(self):
        fam, snip = sqli.detect_db_error(
            "You have an error in your SQL syntax; check the manual")
        assert fam == "mysql"
        assert snip

    def test_postgresql(self):
        fam, _ = sqli.detect_db_error('ERROR:  syntax error at or near "id"')
        assert fam == "postgresql"

    def test_mssql(self):
        fam, _ = sqli.detect_db_error(
            "Unclosed quotation mark after the character string 'x'")
        assert fam == "mssql"

    def test_oracle(self):
        fam, _ = sqli.detect_db_error("ORA-01756: quoted string not properly terminated")
        assert fam == "oracle"

    def test_sqlite(self):
        fam, _ = sqli.detect_db_error('sqlite3.OperationalError: near "x": syntax error')
        assert fam == "sqlite"

    def test_generic(self):
        fam, _ = sqli.detect_db_error("A database error occurred, please retry")
        assert fam == "unknown_db"

    def test_clean_page_no_match(self):
        assert sqli.detect_db_error("<html><body>Welcome to my site</body></html>") == (None, None)

    def test_empty(self):
        assert sqli.detect_db_error(None) == (None, None)
        assert sqli.detect_db_error("") == (None, None)


class _SqliOrigin:
    """Origin that echoes a MySQL-style error when ?q= contains a quote."""

    def __init__(self):
        self.server = None
        self.port = None

    def start(self):
        class _H(BaseHTTPRequestHandler):
            def _respond(self, q):
                if "'" in q or '"' in q:
                    body = ("<html><body>You have an error in your SQL "
                            "syntax near '%s'</body></html>" % q).encode()
                else:
                    body = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                p = urlparse(self.path)
                self._respond(parse_qs(p.query).get("q", [""])[0])

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                self._respond(parse_qs(raw).get("q", [""])[0])

            def log_message(self, *a):
                pass

        for port in range(8954, 8966):
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


class _AlwaysErrorOrigin:
    """Origin whose EVERY response contains a MySQL error string.

    Used to exercise run_sqli_check's baseline pre-check: when the no-probe
    request ALREADY echoes a DB error, the endpoint must be skipped (the
    error predates us; not injectable evidence).
    """

    def __init__(self):
        self.server = None

    def start(self):
        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = (b"<html><body>SQLSTATE[42000]: You have an error "
                        b"in your SQL syntax near 'static' at line 1"
                        b"</body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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


class TestRunSqliCheck:
    def test_error_echo_found(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        origin = _SqliOrigin()
        origin.start()
        try:
            req = Requester(timeout=10)
            finds = sqli.run_sqli_check(
                req, f"{origin.base}/vuln", method="GET",
                params={"q": "safe"}, max_probes=7)
            assert finds, "expected at least one SQLi error finding"
            f0 = finds[0]
            assert f0["type"] == "sqli_error_based"
            assert f0["db"] == "mysql"
            assert f0["param"] == "q"
            assert f0["severity"] == "medium"
        finally:
            origin.stop()

    def test_no_params_no_findings(self):
        req = Requester(timeout=5)
        assert sqli.run_sqli_check(req, "http://x/", params={}) == []

    def test_pre_existing_error_not_reported(self):
        """A page whose BASELINE (no probe) already shows a DB error must be
        skipped entirely -- the error predates our injection and is not
        injectable evidence."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")

        origin = _AlwaysErrorOrigin()
        origin.start()
        try:
            req = Requester(timeout=10)
            finds = sqli.run_sqli_check(
                req, f"{origin.base}/search", method="GET",
                params={"q": "anything"}, max_probes=7)
            assert finds == [], (
                "endpoint with pre-existing DB error must be skipped, "
                f"got {len(finds)} finding(s)")
        finally:
            origin.stop()

    def test_post_body_probes(self):
        """POST body params are probed the same way as GET query params."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        origin = _SqliOrigin()
        origin.start()
        try:
            req = Requester(timeout=10)
            finds = sqli.run_sqli_check(
                req, f"{origin.base}/submit", method="POST",
                data={"q": "safe"}, max_probes=7)
            assert finds, "expected SQLi finding from a POST body probe"
            assert finds[0]["param"] == "q"
            assert finds[0]["method"] == "POST"
        finally:
            origin.stop()

"""Phase 45 auth wiring tests.

SessionManager already implemented form / basic / header / cookie / token /
OAuth(+refresh), but the CLI only called the two-step login_with_csrf helper
-- every other method was dead code and nothing kept a session alive during
a long scan.  These tests guard the WIRING, not just the units:

  * each --login-* flag must reach the session (argparse -> _do_login)
  * an expiring session must be refreshed by age (keep_alive)
  * a lost session (401 / redirect to login) must be re-established
"""
from __future__ import annotations
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.cli_runner import _do_login
from xssentinel.core.requester import Requester
from xssentinel.core.session import SessionManager
from xssentinel.__main__ import build_parser

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class _Req:
    """Minimal Requester stand-in (SessionManager only needs .session)."""

    def __init__(self):
        self.real = Requester(timeout=10)
        self.session = self.real.session
        self.timeout = 10


class TestSessionManagerUnits:
    def test_login_header(self):
        r = _Req()
        mgr = SessionManager(r)
        assert mgr.login_header("X-API-Key", "abc123")
        assert r.session.headers["X-API-Key"] == "abc123"
        assert mgr.logged_in

    def test_login_cookie(self):
        r = _Req()
        mgr = SessionManager(r)
        assert mgr.login_cookie("sessionid", "deadbeef", domain="example.com")
        assert r.session.cookies.get("sessionid", domain="example.com") == \
            "deadbeef"

    def test_login_basic(self):
        r = _Req()
        mgr = SessionManager(r)
        assert mgr.login_basic("u", "p")
        assert r.session.auth == ("u", "p")

    def test_login_token_rollback_on_bad_verify(self):
        """A token the endpoint rejects must NOT stay on the session."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"error":"invalid token"}'
                self.send_response(401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = _Req()
            r.session = Requester(timeout=10).session
            mgr = SessionManager(r)
            url = f"http://127.0.0.1:{srv.server_address[1]}/me"
            assert not mgr.login_token("bad-token", verify_url=url)
            assert "Authorization" not in r.session.headers, \
                "rejected token must be rolled back"
            assert not mgr.logged_in
        finally:
            srv.shutdown()

    def test_looks_logged_out_401(self):
        class _Resp:
            status_code = 401
            headers = {}
        mgr = SessionManager(_Req())
        mgr.logged_in = True
        mgr._login_url = "https://app.example.com/login"
        assert mgr.looks_logged_out(_Resp())

    def test_looks_logged_out_redirect_to_login(self):
        class _Resp:
            status_code = 302
            headers = {"Location": "https://app.example.com/login?next=/x"}
        mgr = SessionManager(_Req())
        mgr.logged_in = True
        mgr._login_url = "https://app.example.com/login"
        assert mgr.looks_logged_out(_Resp())

    def test_looks_logged_out_false_for_normal_redirect(self):
        class _Resp:
            status_code = 302
            headers = {"Location": "https://app.example.com/dashboard"}
        mgr = SessionManager(_Req())
        mgr.logged_in = True
        mgr._login_url = "https://app.example.com/login"
        assert not mgr.looks_logged_out(_Resp())

    def test_reauth_restores_form_session(self):
        """After a simulated logout the manager must be able to log in again."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        state = {"authed": False}

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"dashboard" if state["authed"] else b"login page"
                self.send_response(200 if state["authed"] else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode()
                if "user=admin" in raw and "pass=s3cret" in raw:
                    state["authed"] = True
                    self.send_response(200)
                    self.send_header("Set-Cookie", "sid=abc; Path=/")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                else:
                    self.send_response(401)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"no")

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            requester = Requester(timeout=10)
            mgr = SessionManager(requester)
            assert mgr.login_form(f"{base}/login",
                                  {"user": "admin", "pass": "s3cret"},
                                  success_marker="ok")
            # simulate session loss
            state["authed"] = False
            assert mgr.reauth(), "reauth must restore the session"
            assert state["authed"]
        finally:
            srv.shutdown()


class TestCliAuthWiring:
    """Each --login-* flag must actually reach the requester session."""

    def _args(self, argv):
        return build_parser().parse_args(argv + ["-u", "http://example.com/"])

    def test_login_header_flag_wired(self):
        args = self._args(["--login-header", "X-API-Key: abc123"])
        req = Requester(timeout=10)
        mgr = _do_login(req, args)
        assert mgr is not None, "no SessionManager returned"
        assert req.session.headers.get("X-API-Key") == "abc123"

    def test_login_token_flag_wired(self):
        args = self._args(["--login-token", "jwt-xyz"])
        req = Requester(timeout=10)
        _do_login(req, args)
        assert req.session.headers.get("Authorization") == "Bearer jwt-xyz"

    def test_login_token_custom_header_and_scheme(self):
        args = self._args(["--login-token", "k", "--login-token-header",
                           "X-Auth", "--login-token-scheme", ""])
        req = Requester(timeout=10)
        _do_login(req, args)
        assert req.session.headers.get("X-Auth") == "k"
        assert "Authorization" not in req.session.headers

    def test_login_basic_flag_wired(self):
        args = self._args(["--login-basic", "admin:s3cret"])
        req = Requester(timeout=10)
        _do_login(req, args)
        assert req.session.auth == ("admin", "s3cret")

    def test_no_auth_returns_none(self):
        args = self._args([])
        req = Requester(timeout=10)
        assert _do_login(req, args) is None

    def test_auth_refresh_interval_applied(self):
        args = self._args(["--login-token", "t", "--auth-refresh-interval",
                           "60"])
        req = Requester(timeout=10)
        mgr = _do_login(req, args)
        assert mgr.refresh_threshold == 60.0


class TestOAuthRefresh:
    """RFC 6749 refresh_token flow: wire-up + real endpoint round-trip."""

    @staticmethod
    def _token_server():
        served = {"count": 0}

        class _H(BaseHTTPRequestHandler):
            def do_POST(self):
                served["count"] += 1
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode()
                if "grant_type=refresh_token" in raw and "refresh_token=rt1" in raw:
                    payload = (b'{"access_token":"new-access",'
                               b'"refresh_token":"rt2","token_type":"Bearer"}')
                else:
                    payload = b'{"error":"invalid_grant"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, served

    def test_oauth_refresh_rotates_token(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, served = self._token_server()
        try:
            token_url = f"http://127.0.0.1:{srv.server_address[1]}/token"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            assert mgr.login_oauth_token(
                "old-access", refresh_token="rt1", client_id="cid",
                client_secret="csec", token_url=token_url)
            assert mgr._oauth_refresh, "refresh config must be stored"
            # force expiry
            mgr.refresh_threshold = 0
            assert mgr.refresh_if_needed(), "refresh must run and succeed"
            assert req.session.headers["Authorization"] == "Bearer new-access"
            assert mgr._oauth_refresh["refresh_token"] == "rt2"
            assert served["count"] == 1
        finally:
            srv.shutdown()

    def test_keep_alive_refreshes_when_stale(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, _ = self._token_server()
        try:
            token_url = f"http://127.0.0.1:{srv.server_address[1]}/token"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            mgr.login_oauth_token("old", refresh_token="rt1", client_id="cid",
                                  token_url=token_url)
            mgr.refresh_threshold = 0
            assert mgr.keep_alive(probe_url=None, relogin_on_loss=False)
            assert req.session.headers["Authorization"] == "Bearer new-access"
        finally:
            srv.shutdown()

    def test_keep_alive_noop_when_fresh(self):
        srv, served = self._token_server()
        try:
            token_url = f"http://127.0.0.1:{srv.server_address[1]}/token"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            mgr.login_oauth_token("acc", refresh_token="rt1", client_id="cid",
                                  token_url=token_url)
            mgr.refresh_threshold = 3600
            assert not mgr.keep_alive(probe_url=None, relogin_on_loss=False)
            assert served["count"] == 0, "fresh session must not refresh"
        finally:
            srv.shutdown()

    def test_keep_alive_detects_loss_and_reauths(self):
        """Target answers 401 -> session is dead -> re-login happens."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        state = {"authed": False}

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if state["authed"] else 401)
                body = b"ok" if state["authed"] else b"nope"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                state["authed"] = True
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            assert mgr.login_form(f"{base}/login", {"user": "admin"},
                                  success_marker="ok")
            state["authed"] = False          # session dies mid-scan
            mgr.refresh_threshold = 3600     # not an age issue
            assert mgr.keep_alive(probe_url=f"{base}/dashboard",
                                  relogin_on_loss=True), \
                "keep_alive must detect the 401 and re-auth"
            assert state["authed"]
        finally:
            srv.shutdown()


class TestMidScanReauth:
    """Phase 45 response-hook: a session dying MID-scan (single long URL)
    must be re-authenticated immediately via the Requester's on_response
    hook -- keep_alive between batch URLs cannot cover this."""

    @staticmethod
    def _expiring_origin(state):
        """Session valid for 2 requests after login, then 401 until
        re-login (the hook must notice and re-login transparently)."""
        from urllib.parse import urlparse

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle()

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self._handle()

            def _handle(self):
                p = urlparse(self.path)
                if p.path == "/login":
                    state["authed"] = True
                    state["uses"] = 0
                    body = b"welcome ok"
                    self.send_response(200)
                    self.send_header("Set-Cookie", "sess=abc")
                elif "sess=abc" in (self.headers.get("Cookie") or "") \
                        and state["authed"]:
                    state["uses"] += 1
                    if state["uses"] > 2:          # session expired
                        state["authed"] = False
                        body = b"401 login required"
                        self.send_response(401)
                    else:
                        q = p.path.split("/")[-1]
                        body = f"<html>{q}</html>".encode()
                        self.send_response(200)
                else:
                    body = b"401 login required"
                    self.send_response(401)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_hook_reauths_mid_scan(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        state = {"authed": False, "uses": 0}
        srv = self._expiring_origin(state)
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            assert mgr.login_form(f"{base}/login", {"user": "admin"},
                                  success_marker="ok")
            mgr.attach(req)
            mgr.refresh_threshold = 3600        # age-based must NOT fire

            statuses = []
            for i in range(8):                  # session dies after 2 uses
                resp = req.get(f"{base}/page{i}", cache_get=False)
                statuses.append(resp.status_code)
            assert 200 in statuses, "sanity: early requests succeed"
            # Without the hook, every post-expiry request would be 401.
            assert statuses.count(401) == 0, \
                f"mid-scan expiry not auto-re-authenticated: {statuses}"
            assert statuses.count(200) == 8, statuses
            assert state["authed"]
        finally:
            srv.shutdown()

    def test_hook_propagates_to_clones(self):
        """Worker-thread clones own separate sessions; after a re-auth the
        fresh cookie must be copied into the clone that saw the 401."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        state = {"authed": False, "uses": 0}
        srv = self._expiring_origin(state)
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            req = Requester(timeout=10)
            mgr = SessionManager(req)
            assert mgr.login_form(f"{base}/login", {"user": "admin"},
                                  success_marker="ok")
            mgr.attach(req)
            mgr.refresh_threshold = 3600

            clone = req.clone()                  # worker-thread clone
            assert clone.on_response is not None, \
                "clone must carry the response hook"
            statuses = [clone.get(f"{base}/c{i}", cache_get=False
                                  ).status_code for i in range(8)]
            assert statuses.count(200) == 8, \
                f"clone lost the re-authenticated session: {statuses}"
        finally:
            srv.shutdown()

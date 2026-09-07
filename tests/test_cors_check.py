"""Tests for Phase 51 -- target CORS misconfiguration audit.

The pure classification logic (cors_check.classify) is unit-tested across
the policy matrix (reflect+credentials / reflect-only / wildcard /
wildcard+credentials / absent / unrelated allowlist).  The scanner layer
(_scan_cors) is exercised against REAL loopback origins that implement
each CORS policy, verifying probe order (GET first, OPTIONS preflight
fallback), once-per-origin dedup, and the resulting cors_misconfig
findings -- plus a no-finding baseline against a policy-correct origin.
"""
from __future__ import annotations
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core import cors_check
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class TestClassify:
    """The pure CORS policy classification matrix."""

    def test_reflect_origin_with_credentials_is_high(self):
        sev, _ = cors_check.classify(
            cors_check.EVIL_ORIGIN, "true")
        assert sev == "high"

    def test_reflect_origin_without_credentials_is_medium(self):
        sev, reason = cors_check.classify(cors_check.EVIL_ORIGIN, "false")
        assert sev == "medium"
        assert "reflects" in reason

    def test_wildcard_plus_credentials_is_info(self):
        sev, _ = cors_check.classify("*", "true")
        assert sev == "info"

    def test_wildcard_alone_is_not_a_finding(self):
        assert cors_check.classify("*", "false") is None
        assert cors_check.classify("*", "") is None

    def test_no_acao_is_not_a_finding(self):
        assert cors_check.classify("", "true") is None
        assert cors_check.classify(None, None) is None

    def test_unrelated_fixed_allowlist_is_not_a_finding(self):
        # A server may send ACAO for ITS OWN allowlisted partner origin; an
        # attacker-controlled origin that is not echoed is safe.
        assert cors_check.classify("https://trusted.example", "true") is None

    def test_null_origin_reflection_is_caught_like_any_other(self):
        # Browsers send Origin: null from sandboxed iframes / data: pages.
        # Reflection + credentials is the same data-exfil primitive.
        sev, _ = cors_check.classify("null", "true",
                                     evil_origin="null")
        assert sev == "high"


# ---------------------------------------------------------------------------
# Real-origin integration for the scanner layer
# ---------------------------------------------------------------------------
class _CorsOrigin:
    """An origin server implementing a configurable CORS policy."""

    def __init__(self, policy: str):
        # policy: "reflect_creds" | "reflect" | "none" | "preflight_only"
        self.policy = policy
        self.server = None
        self.port = None

    def start(self):
        policy = self.policy

        class _H(BaseHTTPRequestHandler):
            def _cors_headers(self):
                origin = self.headers.get("Origin")
                if policy == "preflight_only":
                    # Only preflight (OPTIONS) responses carry CORS headers.
                    return self.command == "OPTIONS" and origin is not None
                if policy == "reflect_creds":
                    return origin is not None
                if policy == "reflect":
                    return origin is not None
                return False

            def _send(self, code=200, body=b"{}"):
                origin = self.headers.get("Origin")
                self.send_response(code)
                if self._cors_headers():
                    self.send_header("Access-Control-Allow-Origin",
                                     origin or "*")
                    if policy == "reflect_creds":
                        self.send_header(
                            "Access-Control-Allow-Credentials", "true")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._send(body=b'{"ok": 1}')

            def do_OPTIONS(self):
                # Preflight: honour Access-Control-Request-Method.
                self._send(code=204, body=b"")

            def log_message(self, *a):
                pass

        for port in range(8982, 8994):
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


def _make_scanner():
    return Scanner(
        requester=Requester(timeout=10),
        use_headless=False, crawl=False, max_transforms=2,
        max_payloads=2, threads=1, dom_engine="static", verbose=False)


class TestScanCors:
    def _check(self, policy: str):
        origin = _CorsOrigin(policy)
        origin.start()
        try:
            scanner = _make_scanner()
            scanner._scan_cors(scanner.req, origin.base + "/api?x=1")
            return [f.data for f in scanner.findings]
        finally:
            origin.stop()

    def test_reflect_plus_credentials_finding_high(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        out = self._check("reflect_creds")
        assert len(out) == 1
        assert out[0]["type"] == "cors_misconfig"
        assert out[0]["severity"] == "high"
        assert "credentials" in out[0]["detail"]
        assert cors_check.EVIL_ORIGIN in out[0]["evidence"]

    def test_reflect_without_credentials_finding_medium(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        out = self._check("reflect")
        assert len(out) == 1
        assert out[0]["type"] == "cors_misconfig"
        assert out[0]["severity"] == "medium"

    def test_correct_policy_no_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        assert self._check("none") == []

    def test_preflight_only_policy_still_detected(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        # GET returns no CORS headers; the OPTIONS preflight fallback must
        # still surface the reflective policy.
        out = self._check("preflight_only")
        assert len(out) == 1
        assert out[0]["type"] == "cors_misconfig"
        assert out[0]["method"] == "OPTIONS"

    def test_once_per_origin_dedup(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        origin = _CorsOrigin("reflect_creds")
        origin.start()
        try:
            scanner = _make_scanner()
            # Two endpoints on the SAME origin: one finding only.
            scanner._scan_cors(scanner.req, origin.base + "/api?a=1")
            scanner._scan_cors(scanner.req, origin.base + "/other?b=2")
            found = [f for f in scanner.findings
                     if f.data.get("type") == "cors_misconfig"]
            assert len(found) == 1
        finally:
            origin.stop()


class TestAsyncCorsParity:
    """Phase 54: the CORS audit also runs in the async scanner (sync parity)."""

    def _async_findings(self, policy: str):
        import asyncio
        from xssentinel.core.async_scanner import AsyncScanner
        origin = _CorsOrigin(policy)
        origin.start()
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10)
                out = []
                async for f in asc.scan(origin.base + "/api"):
                    out.append(f)
                return out
            return asyncio.run(run()), origin
        except Exception:
            origin.stop()
            raise

    def test_async_finds_reflect_plus_credentials(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        found, origin = self._async_findings("reflect_creds")
        try:
            cors = [f.data for f in found
                    if f.data.get("type") == "cors_misconfig"]
            assert cors, [f.data.get("type") for f in found]
            assert cors[0]["severity"] == "high"
        finally:
            origin.stop()

    def test_async_correct_policy_no_cors_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        found, origin = self._async_findings("none")
        try:
            assert not [f.data for f in found
                        if f.data.get("type") == "cors_misconfig"]
        finally:
            origin.stop()

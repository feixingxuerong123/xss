"""Tests for Phase 53 -- XS-Leaks: mitigation audit + channel library.

audit_mitigations is a pure header matrix (no network).  The channel
catalog / payload builders / demo page are string-level contracts
(targets embedded quoted, one snippet per channel, verdicts pushed to a
well-known sink).  The scanner integration is exercised against real
loopback origins: a headerless HTML page yields one low xs_leak_surface
finding per origin when the opt-in flag is on, an isolated origin does
not, and the default (flag off) changes nothing.
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

from xssentinel.core import xs_leaks
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class TestAuditMitigations:
    """The pure isolation-header audit matrix."""

    def test_no_isolation_headers_is_a_surface(self):
        out = xs_leaks.audit_mitigations({"Content-Type": "text/html"})
        assert out is not None
        assert out["type"] == "xs_leak_surface"
        assert out["severity"] == "low"

    def test_coop_same_origin_isolates(self):
        assert xs_leaks.audit_mitigations(
            {"Cross-Origin-Opener-Policy": "same-origin"}) is None

    def test_corp_isolates(self):
        assert xs_leaks.audit_mitigations(
            {"Cross-Origin-Resource-Policy": "same-origin"}) is None

    def test_coep_require_corp_isolates(self):
        assert xs_leaks.audit_mitigations(
            {"Cross-Origin-Embedder-Policy": "require-corp"}) is None

    def test_frame_guards_isolate(self):
        assert xs_leaks.audit_mitigations(
            {"X-Frame-Options": "DENY"}) is None
        assert xs_leaks.audit_mitigations(
            {"Content-Security-Policy":
             "default-src 'none'; frame-ancestors 'none'"}) is None

    def test_partial_hardening_suppresses_note(self):
        # One header present -> no spammy note.
        assert xs_leaks.audit_mitigations(
            {"X-Frame-Options": "SAMEORIGIN"}) is None

    def test_empty_headers_dict(self):
        assert xs_leaks.audit_mitigations({}) is not None

    def test_evidence_lists_present_headers(self):
        out = xs_leaks.audit_mitigations({})
        assert "(none)" in out["evidence"]


class TestChannels:
    def test_catalog_has_expected_channels(self):
        ids = xs_leaks.channel_ids()
        for c in ("img_oracle", "frame_timing", "window_name",
                  "history_length"):
            assert c in ids
        assert len(ids) == len(xs_leaks.CHANNELS)

    def test_build_snippet_embeds_target_quoted(self):
        js = xs_leaks.build_channel_js(
            "img_oracle", "https://app.example/me")
        assert "app.example" in js
        assert 'https://app.example/me' in js  # quoted JS string present
        assert "__xssentinel_xsleak" in js

    def test_unknown_channel_raises(self):
        with pytest.raises(KeyError):
            xs_leaks.build_channel_js("nope", "https://t/x")

    def test_bad_target_rejected(self):
        with pytest.raises(ValueError):
            xs_leaks.validate_target("javascript:alert(1)")
        with pytest.raises(ValueError):
            xs_leaks.build_channel_js("img_oracle", "file:///etc/passwd")

    def test_every_channel_builds(self):
        for c in xs_leaks.channel_ids():
            js = xs_leaks.build_channel_js(c, "https://app.example/x")
            assert js and "channel:" in js


class TestDemoHtml:
    def test_contains_target_and_channels(self):
        html = xs_leaks.build_demo_html(
            "Leak demo", "https://app.example/api/me",
            channels=["img_oracle", "window_name"])
        assert html.startswith("<!DOCTYPE html>")
        assert "app.example" in html
        assert "v-img_oracle" in html and "v-window_name" in html
        assert "__xssentinel_xsleak" in html

    def test_html_escapes_title(self):
        html = xs_leaks.build_demo_html("<script>x</script>",
                                        "https://t/", channels=["img_oracle"])
        assert "<script>x</script>" not in html
        assert "&lt;script&gt;" in html

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            xs_leaks.build_demo_html("d", "not a url")


# ---------------------------------------------------------------------------
# Scanner integration (opt-in audit)
# ---------------------------------------------------------------------------
class _Origin:
    """Plain HTML echo origin; optionally sends isolation headers."""

    def __init__(self, extra_headers: dict | None = None):
        self.extra_headers = extra_headers or {}
        self.server = None
        self.port = None

    def start(self):
        extra = self.extra_headers

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                p = urlparse(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                body = ("<html><body><div>%s</div></body></html>"
                        % q.replace("<", "&lt;")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        for port in range(9002, 9014):
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


def _scanner(**kw):
    base = dict(use_headless=False, crawl=False, max_transforms=2,
                max_payloads=2, threads=1, dom_engine="static",
                verbose=False)
    base.update(kw)
    return Scanner(requester=Requester(timeout=10), **base)


class TestScanXsLeakAudit:
    def _scan(self, origin, audit):
        scanner = _scanner(xsleak_audit=audit)
        # Direct layer call with a real fetched response (headers only).
        resp = scanner.req.get(origin.base + "/page")
        scanner._scan_xsleak_audit(origin.base + "/page", resp=resp)
        return [f.data for f in scanner.findings]

    def test_surface_found_when_opt_in(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        o = _Origin()
        o.start()
        try:
            out = self._scan(o, audit=True)
            assert len(out) == 1
            assert out[0]["type"] == "xs_leak_surface"
            assert out[0]["severity"] == "low"
        finally:
            o.stop()

    def test_off_by_default_no_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        o = _Origin()
        o.start()
        try:
            assert self._scan(o, audit=False) == []
        finally:
            o.stop()

    def test_isolated_origin_no_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        o = _Origin({"Cross-Origin-Opener-Policy": "same-origin",
                     "Cross-Origin-Resource-Policy": "same-origin"})
        o.start()
        try:
            assert self._scan(o, audit=True) == []
        finally:
            o.stop()

    def test_once_per_origin(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        o = _Origin()
        o.start()
        try:
            scanner = _scanner(xsleak_audit=True)
            scanner._scan_xsleak_audit(o.base + "/a", resp=scanner.req.get(
                o.base + "/a"))
            scanner._scan_xsleak_audit(o.base + "/b", resp=scanner.req.get(
                o.base + "/b"))
            found = [f for f in scanner.findings
                     if f.data.get("type") == "xs_leak_surface"]
            assert len(found) == 1
        finally:
            o.stop()


class TestAsyncXsLeakParity:
    """Phase 54: the opt-in XS-Leaks surface audit also runs async."""

    def _async_findings(self, audit: bool, isolated: bool = False):
        import asyncio
        from xssentinel.core.async_scanner import AsyncScanner
        extra = {"Cross-Origin-Opener-Policy": "same-origin"} if isolated else {}
        o = _Origin(extra)
        o.start()
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10,
                    xsleak_audit=audit)
                out = []
                async for f in asc.scan(o.base + "/page"):
                    out.append(f)
                return out
            return asyncio.run(run()), o
        except Exception:
            o.stop()
            raise

    def test_async_surface_found_when_opt_in(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        found, o = self._async_findings(audit=True)
        try:
            hits = [f.data for f in found
                    if f.data.get("type") == "xs_leak_surface"]
            assert hits, [f.data.get("type") for f in found]
            assert hits[0]["severity"] == "low"
        finally:
            o.stop()

    def test_async_default_off_no_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        found, o = self._async_findings(audit=False)
        try:
            assert not [f.data for f in found
                        if f.data.get("type") == "xs_leak_surface"]
        finally:
            o.stop()

    def test_async_isolated_origin_no_finding(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        found, o = self._async_findings(audit=True, isolated=True)
        try:
            assert not [f.data for f in found
                        if f.data.get("type") == "xs_leak_surface"]
        finally:
            o.stop()

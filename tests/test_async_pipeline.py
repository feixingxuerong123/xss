"""P0-2: first async-scanner tests (Phase 37).

Covers the parity features added to the async L1 path (reflection profile,
generative payloads, position shift) AND the for_context bug that used to
make the async reflected layer silently raise AttributeError (0% coverage
hid it for its entire life).

Runs without pytest-asyncio configuration: async drivers are wrapped in
asyncio.run() from plain test functions, and the aiohttp session is faked.
NOTE: the AsyncScanner must be constructed INSIDE the running loop --
Python 3.9 creates the internal asyncio.Lock() bound to the current loop,
and asyncio.run() clears the main-thread loop when it returns.
"""
from __future__ import annotations
import asyncio
import base64
import html
import os
import sys
import threading

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tests.conftest import SOCKETPAIR_OK, loopback_healthy
from xssentinel.core import payloads as payloads_mod
from xssentinel.core.async_scanner import AsyncScanner

# asyncio.run() needs a working loopback socketpair (see conftest.py);
# skip instead of hanging when the environment throttles it.
pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode().rstrip("=")


class _Resp:
    def __init__(self, text):
        self._t = text
        # Real aiohttp responses always carry headers; the async scanner's
        # CSP gate reads them (defensively), so the fake provides them too.
        self.headers = {}

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    """Fake aiohttp session: echoes q raw (live markup) or HTML-escaped."""

    def __init__(self, escape=False, decode=False):
        self.calls = []
        self.escape = escape
        self.decode = decode

    def _maybe_decode(self, s: str) -> str:
        if not self.decode:
            return s
        for _ in range(2):
            try:
                d = base64.b64decode(
                    s.replace("-", "+").replace("_", "/")
                    + "=" * (-len(s) % 4))
                t = d.decode("utf-8")
                if t.isprintable() and t:
                    s = t
                    continue
            except Exception:
                pass
            break
        return s

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        val = self._maybe_decode(val)
        body = html.escape(val, quote=True) if self.escape else val
        return _Resp(f"<html><body><div>{body}</div></body></html>")


def _collect(params, escape=False, decode=False):
    """Drive _probe_param inside a fresh loop; Scanner built in-loop.

    Phase 132: ``_probe_param`` now hands off to the L7 parameter layers,
    which issue real blocking requests through a sync Requester.  A
    fake-session unit test cannot serve that (the request would leave the
    machine), and every assertion here is about the fake session's call
    list, which the hand-off never touches -- so it is stubbed out.  The
    hand-off is covered by tests/test_async_param_stage_parity.py and by
    benchmark case pos-clobber-01.
    """
    original = AsyncScanner._scan_advanced_param_layers

    async def _noop(self, *a, **k):
        if False:                     # pragma: no cover -- keeps it a gen
            yield None

    AsyncScanner._scan_advanced_param_layers = _noop
    try:
        async def run():
            asc = AsyncScanner(max_concurrent=4, per_host_delay=0, jitter=0)
            asc._semaphore = asyncio.Semaphore(4)
            session = _Session(escape=escape, decode=decode)
            out = []
            async for f in asc._probe_param(session, "http://t/x", "GET", "q",
                                            params, {}, False, "x"):
                out.append(f)
            return out, session

        return asyncio.run(run())
    finally:
        AsyncScanner._scan_advanced_param_layers = original


class TestForContextFixed:
    def test_for_context_exists_and_returns_strings(self):
        out = payloads_mod.for_context("html_element")
        assert out and all(isinstance(x, str) and x for x in out)

    def test_unknown_context_falls_back_to_empty(self):
        assert payloads_mod.for_context("__nope__") == []


class TestAsyncL1:
    def test_live_echo_confirms_reflection(self):
        findings, _ = _collect({"q": "probe"})
        assert findings, "async L1 failed to confirm a live reflection"
        assert findings[0].data["type"] == "reflected"
        assert findings[0].data["confidence"] == "high"

    def test_escaping_echo_reports_nothing(self):
        findings, _ = _collect({"q": "probe"}, escape=True)
        assert findings == []

    def test_pre_encode_path_confirms(self):
        findings, _ = _collect({"q": b64("next=/admin")}, decode=True)
        assert findings, "pre-encoded probe missed on decoding app"
        assert any("pre_encode" in str(f.data.get("transform"))
                   for f in findings)

    def test_position_shift_refires_in_body(self):
        findings, session = _collect({"q": "probe"}, escape=True)
        body_calls = [c for c in session.calls if c["data"].get("q")]
        assert body_calls, "position shift did not re-fire into the body"
        assert findings == []

    def test_profile_probe_does_not_break_plain_flow(self):
        findings, session = _collect({"q": "probe"})
        # The sandwich probe adds requests; the flow still confirms.
        assert findings
        assert len(session.calls) >= 3  # marker + profile + payload probes


class TestAsyncCrawlQueryRetention:
    """Phase 47: a crawled link carrying ?q=hi&debug=1 must be scanned with
    those query params (URL de-parameterised), not with an empty params dict
    -- the old behaviour silently skipped every query-param endpoint."""

    def _drive(self, html: str):
        """Run _crawl_and_scan with _scan_reflected monkeypatched to a
        recorder so no real probing happens (depth 1 = no child fetches)."""

        async def run():
            from xssentinel.core.async_scanner import AsyncScanner
            asc = AsyncScanner(crawl=True, crawl_depth=1,
                               per_host_delay=0, jitter=0)
            asc._semaphore = asyncio.Semaphore(2)
            seen = []

            async def fake_scan(session, url, method, params, data, text):
                seen.append((url, dict(params or {}), dict(data or {}), text))
                return
                yield  # unreachable -- keeps this an async generator

            asc._scan_reflected = fake_scan
            session = _Session()
            async for _f in asc._crawl_and_scan(
                    session, "http://t/page", html):
                pass  # recorder only; no findings expected
            return seen

        return asyncio.run(run())

    def test_query_params_forwarded_and_stripped_from_url(self):
        html = ('<html><body><a href="http://t/page?q=hi&debug=1">link'
                "</a></body></html>")
        seen = self._drive(html)
        assert seen, "crawler did not scan the discovered link"
        url, params, _data, text = seen[0]
        assert url == "http://t/page", f"query not stripped: {url}"
        assert params.get("q") == "xss", f"q param dropped: {params}"
        assert params.get("debug") == "xss", f"debug param dropped: {params}"
        assert "hi" in text  # seed text passed through to the scan layer

    def test_bare_link_scanned_without_params(self):
        html = ('<html><body><a href="http://t/other">plain</a>'
                "</body></html>")
        seen = self._drive(html)
        assert seen, "crawler did not scan the plain link"
        url, params, _data, _text = seen[0]
        assert url == "http://t/other"
        assert params == {}


class TestAsyncUploadParity:
    """Phase 58: multipart upload-filename probing parity (live aiohttp)."""

    @staticmethod
    def _origin():
        import re as _re
        import http.server as _hs

        class _M(_hs.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _echo_filename(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length") or 0))
                m = _re.search(rb'filename="([^"]*)"', body)
                name = m.group(1).decode("utf-8", "replace") if m else ""
                # Raw echo into HTML: an <img onerror> filename becomes
                # executable markup exactly like a real stored-echo app.
                out = ("<html><body><div>up:%s</div></body></html>"
                       % name).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):
                self._echo_filename()

            def log_message(self, *a):
                pass

        srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_async_upload_probe_confirms_upload_xss(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import asyncio as _aio
        from xssentinel.core.async_scanner import AsyncScanner
        srv = self._origin()
        base = f"http://127.0.0.1:{srv.server_address[1]}/up"
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10,
                    upload_fields=["file"])
                out = []
                async for f in asc.scan(base, method="POST",
                                        params={}, data={}):
                    out.append(f)
                return out
            found = _aio.run(run())
            up = [f.data for f in found
                  if f.data.get("type") == "upload_xss"]
            assert up, [f.data.get("type") for f in found]
            assert up[0]["param"] == "file[filename]"
        finally:
            srv.shutdown()

    def test_async_upload_content_confirms_stored_upload(self):
        """Phase 90 (P2): weaponised file CONTENT -- the upload response
        exposes /uploads/<marker>.<ext>, the stored bytes serve the
        weaponised HTML/SVG back -> stored_upload confirmed."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import asyncio as _aio
        import re as _re
        import http.server as _hs
        from xssentinel.core.async_scanner import AsyncScanner

        class _M(_hs.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            _stored = {}

            def _store(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length") or 0))
                m = _re.search(rb'filename="([^"]*)"\r\n'
                               rb'Content-Type: ([^\r\n]+)', body)
                if not m:
                    m = _re.search(rb'filename="([^"]*)"', body)
                name = m.group(1).decode("utf-8", "replace") if m else ""
                # Keep the raw multipart body; carve out the file bytes.
                parts = body.split(b"\r\n\r\n", 1)
                payload = parts[1].rsplit(b"\r\n", 2)[0] \
                    if len(parts) > 1 else b""
                self._stored[name] = payload
                # Expose the stored URL with a PERCENT-ENCODED name so the
                # filename probe cannot confirm an echo (quote-breakout
                # candidates stay inert inside the href) -- the stored-
                # content vector is what must fire here.
                from urllib.parse import quote
                enc = quote(name, safe="")
                out = (f'<html><body>ok <a href="/uploads/{enc}">'
                       "here</a></body></html>").encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):
                self._store()

            def do_GET(self):
                name = self.path.rsplit("/", 1)[-1]
                payload = self._stored.get(name, b"")
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "image/svg+xml" if name.endswith(".svg")
                    else "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}/up"
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10,
                    upload_fields=["file"])
                out = []
                async for f in asc.scan(base, method="POST",
                                        params={}, data={}):
                    out.append(f)
                return out
            found = _aio.run(run())
            stored = [f.data for f in found
                      if f.data.get("type") == "stored_upload"
                      and f.data.get("context") == "uploaded_file_content"]
            assert stored, [f.data.get("type") for f in found]
            assert stored[0]["param"] == "file[content]"
            assert "xssupc_" in stored[0]["payload"]
        finally:
            srv.shutdown()


class TestAsyncCspParity:
    """Phase 62: async CSP analysis reports bypassable policies like sync."""

    def test_async_reports_bypassable_csp(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import asyncio as _aio
        import http.server as _http
        from xssentinel.core.async_scanner import AsyncScanner

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = b"<html><body>csp page</body></html>"
                self.send_response(200)
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}/"
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10)
                out = []
                async for f in asc.scan(base, params={}):
                    out.append(f)
                return out
            found = _aio.run(run())
            csp = [f.data for f in found
                   if f.data.get("type") == "csp_bypass"]
            assert csp, [f.data.get("type") for f in found]
            assert csp[0]["severity"] == "medium"
        finally:
            srv.shutdown()


class TestAsyncPageLayerParity:
    """Phase 63: async page-level layers (postMessage/prototype/SW/...) run
    instead of aborting on the shim's missing coverage attribute."""

    _PAGE = (b"<html><body><div id=out></div><script>\n"
             b"window.addEventListener('message', function (e) {\n"
             b"  document.getElementById('out').innerHTML = e.data;\n"
             b"});\n"
             b"</script></body></html>")

    def test_async_reports_postmessage_page_layer(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import asyncio as _aio
        import http.server as _http
        from xssentinel.core.async_scanner import AsyncScanner

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = TestAsyncPageLayerParity._PAGE
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}/"
        try:
            async def run():
                asc = AsyncScanner(
                    max_concurrent=2, per_host_delay=0, jitter=0,
                    max_payloads=4, max_transforms=2, timeout=10)
                out = []
                async for f in asc.scan(base, params={}):
                    out.append(f)
                return out
            found = _aio.run(run())
            types = {f.data.get("type") for f in found}
            assert "postmessage_xss" in types, sorted(types)
        finally:
            srv.shutdown()

    def test_shim_exposes_coverage(self):
        # The page layers touch scanner.coverage on every call; without it
        # the whole run_page_layers aborted (async reported nothing).
        from xssentinel.core.async_scanner import _AsyncScannerShim
        shim = _AsyncScannerShim.__new__(_AsyncScannerShim)
        shim.coverage = _AsyncScannerShim._NullCoverage()
        shim.coverage.touch_layer("http://t/", "L8_postmessage", "GET",
                                  detail="x")
        assert shim.coverage.touched == [
            ("http://t/", "L8_postmessage", "GET", "x")]


class _FilterSession:
    """Echoes q raw but rewrites literal callables -- the neg-filter-05 shape.

    The benchmark's m_filter_keywords: rewrite ``alert(``-style callables to
    ``blocked(``, strip script tags, strip on*= attribute tags.  A plain
    marked payload can never survive this filter; only the CONCAT stamp
    (``window['ale'+'rt']('TOK')``, no literal callable + paren) carries the
    marker through.
    """

    def __init__(self):
        import re as _re
        self._re = _re
        self.calls = []

    def request(self, method, url, params=None, data=None,
                headers=None, proxy=None):
        val = (params or {}).get("q", "") + (data or {}).get("q", "")
        safe = self._re.sub(
            r"(?i)(alert|prompt|confirm|eval|function|setTimeout|setinterval"
            r"|fetch|xmlhttprequest)\s*\(", "blocked(", val)
        safe = self._re.sub(r"(?i)</?script[^>]*>", "", safe)
        safe = self._re.sub(r"(?i)<[^>]*\bon\w+\s*=[^>]*>", "", safe)
        self.calls.append({"params": dict(params or {}),
                           "data": dict(data or {})})
        return _Resp(f"<html><body><div>{safe}</div></body></html>")


class TestAsyncConcatRetry:
    """Phase 166 in the async MAIN payload loop, not only under a WAF.

    The async concat retry used to live only inside the position-shift
    block, which requires a detected WAF *fingerprint*; a WAF-less keyword
    filter never reaches it, so async paid its whole payload budget and
    reported nothing where sync confirms via the concat stamp
    (benchmark neg-filter-05: async 106 requests / 0 findings, stable FN
    across both 192-case runs, while sync TP with 78).
    """

    def _collect_filtered(self, params):
        original = AsyncScanner._scan_advanced_param_layers

        async def _noop(self, *a, **k):
            if False:                 # pragma: no cover -- keeps it a gen
                yield None

        AsyncScanner._scan_advanced_param_layers = _noop
        try:
            async def run():
                asc = AsyncScanner(max_concurrent=4, per_host_delay=0,
                                   jitter=0)
                asc._semaphore = asyncio.Semaphore(4)
                session = _FilterSession()
                out = []
                async for f in asc._probe_param(session, "http://t/x", "GET",
                                                "q", params, {}, False, "x"):
                    out.append(f)
                return out, session

            return asyncio.run(run())
        finally:
            AsyncScanner._scan_advanced_param_layers = original

    def test_keyword_filter_confirms_via_concat_stamp(self):
        findings, session = self._collect_filtered({"q": "probe"})
        assert findings, ("a keyword-filtered but echo-raw target must "
                          "confirm via the concat stamp (neg-filter-05)")
        f = findings[0]
        assert f.data["type"] == "reflected"
        assert f.data["severity"] == "high"
        assert f.data["confidence"] == "high"
        # The winning variant must BE the concat-stamped one -- no literal
        # callable survives this filter, so anything else would mean the
        # fake verifier accepted a dead payload.
        assert "ale'+'rt" in f.data["payload"], (
            f"expected the concat-stamped winner, got {f.data['payload']!r}")
        # The bare concat variant rides the empty chain; only a transformed
        # one carries the concat_stamp tag (same shape as sync's retry list).
        assert f.data["transform"] == [] \
            or "concat_stamp" in f.data["transform"]
        # The filter really did have something to rewrite: at least one
        # literal-callable variant must have gone over the wire (the
        # REWRITE itself only shows in the response, not in what we sent).
        import re as _re2
        assert any(
            _re2.search(r"(?i)(alert|prompt|confirm|eval)\s*\(",
                        c["params"].get("q", "") + c["data"].get("q", ""))
            for c in session.calls), (
            "the fixture never exercised the filter -- a literal-callable "
            "variant must be sent first and rewritten")

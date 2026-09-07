"""Tests for the Phase 44 passive proxy scanner (xray/w13scan-style).

Pure-logic parts (endpoint signature, scope matching, body parsing) are
tested directly; the proxy itself is exercised against a REAL loopback
origin server so capture -> de-dup -> scan dispatch is verified end-to-end.
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

from xssentinel.core.passive_proxy import (
    PassiveProxy, _ProxyHandler, _parse_body, _run_capture,
    _verify_stored_hits, drain_captures, endpoint_signature, in_scope,
)
from xssentinel.core.requester import Requester

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

_pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")


class _Origin:
    """Minimal origin server reflecting ?q= verbatim (vulnerable)."""

    def __init__(self):
        self.server = None
        self.port = None

    def start(self):
        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                p = urlparse(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                body = f"<html><body><div>{q}</div></body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                body = f"<html><body><div>{raw}</div></body></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        for port in range(8942, 8954):
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


class TestEndpointSignature:
    def test_same_param_names_dedup(self):
        a = endpoint_signature("GET", "http://h/a?x=1&y=2", {"x": "1", "y": "2"}, {})
        b = endpoint_signature("GET", "http://h/a?y=9&x=7", {"y": "9", "x": "7"}, {})
        assert a == b

    def test_different_params_distinct(self):
        a = endpoint_signature("GET", "http://h/a?x=1", {"x": "1"}, {})
        b = endpoint_signature("GET", "http://h/a?x=1&y=2", {"x": "1", "y": "2"}, {})
        assert a != b

    def test_method_matters(self):
        a = endpoint_signature("GET", "http://h/a?x=1", {"x": "1"}, {})
        b = endpoint_signature("POST", "http://h/a?x=1", {"x": "1"}, {})
        assert a != b

    def test_body_params_included(self):
        a = endpoint_signature("POST", "http://h/a", {}, {"q": "x"})
        b = endpoint_signature("POST", "http://h/a", {}, {"q": "y"})
        assert a == b  # values ignored, names matter


class TestInScope:
    def test_none_captures_all(self):
        assert in_scope("http://any.com/x", None)

    def test_bare_host(self):
        assert in_scope("http://example.com/x", "example.com")
        assert in_scope("http://sub.example.com/x", "example.com")
        assert not in_scope("http://evil.com/x", "example.com")

    def test_url_prefix(self):
        assert in_scope("http://example.com/app/x", "http://example.com/app")
        assert not in_scope("http://example.com/other/x", "http://example.com/app")

    def test_host_port(self):
        assert in_scope("http://h:8080/x", "h:8080")
        assert not in_scope("http://h:9090/x", "h:8080")


class TestParseBody:
    def test_json(self):
        assert _parse_body("application/json", b'{"q":"1","n":2}') == {"q": "1", "n": 2}

    def test_form(self):
        assert _parse_body("application/x-www-form-urlencoded", b"a=1&b=2") == {"a": "1", "b": "2"}

    def test_empty(self):
        assert _parse_body(None, b"") == {}

    def test_json_non_dict_falls_back(self):
        # JSON array / scalar is not a param map -> form fallback gives {}.
        assert _parse_body("application/json", b'["a","b"]') == {}

    def test_invalid_body_no_crash(self):
        # Garbage body with a form content-type must not raise -- parse_qs
        # tolerates it (treats the whole string as a valueless key), which
        # is fine for a capture path that must never crash the proxy.
        out = _parse_body("application/x-www-form-urlencoded", b"\xff\xfe\x00garbage")
        assert isinstance(out, dict)
        out2 = _parse_body(None, b"\x00\x01\x02")
        assert isinstance(out2, dict)


class TestRunCapture:
    def test_get_dispatches_params(self):
        seen = {}

        class StubScanner:
            def scan_endpoint(self, url, method="GET", params=None, data=None):
                seen.update(url=url, method=method, params=params, data=data)

        _run_capture(StubScanner(), "GET", "http://h/vuln?q=1",
                     {"q": "1"}, {})
        # URL query is stripped (params already carry it) so the scanner
        # injects payloads as value-replacements, not appended dup params.
        assert seen == {"url": "http://h/vuln", "method": "GET",
                        "params": {"q": "1"}, "data": {}}

    def test_post_dispatches_body(self):
        seen = {}

        class StubScanner:
            def scan_endpoint(self, url, method="GET", params=None, data=None):
                seen.update(url=url, method=method, params=params, data=data)

        _run_capture(StubScanner(), "POST", "http://h/form?x=1",
                     {"x": "1"}, {"q": "posted"})
        assert seen["url"] == "http://h/form"  # query stripped
        assert seen["method"] == "POST"
        assert seen["data"] == {"q": "posted"}

    def test_callable_scanner(self):
        seen = []

        def fake(method, url, params, data):
            seen.append((method, url, params, data))

        _run_capture(fake, "GET", "http://h/x", {"a": "1"}, {})
        assert seen == [("GET", "http://h/x", {"a": "1"}, {})]


class TestProxyEndToEnd:
    def _raw_proxy_get(self, proxy_port: int, target_url: str) -> str:
        """Send an absolute-URI GET through the proxy via raw socket.

        This mimics a browser: the proxy receives 'GET http://host/... HTTP/1.1'
        and must relay + capture.  (requests would bypass the proxy for
        127.0.0.1 targets via its no_proxy logic, so raw sockets are used.)
        """
        import socket
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
        try:
            s.sendall(
                f"GET {target_url} HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
        return buf.decode("utf-8", "replace")

    def test_capture_and_dispatch(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        origin = _Origin()
        origin.start()
        try:
            proxy = PassiveProxy(
                port=0, host="127.0.0.1", scope=None,
                requester=Requester(timeout=10))
            proxy.start()
            try:
                # First request: captured.
                resp = self._raw_proxy_get(
                    proxy.port, f"{origin.base}/vuln?q=hello")
                assert "200" in resp.split("\r\n")[0]
                # Wait for the capture queue to drain.
                deadline = time.time() + 5
                while proxy.stats["captures"] < 1 and time.time() < deadline:
                    time.sleep(0.1)
                assert proxy.stats["captures"] >= 1
                # Second request with the same param NAMES must be de-duped.
                resp2 = self._raw_proxy_get(
                    proxy.port, f"{origin.base}/vuln?q=world")
                assert "200" in resp2.split("\r\n")[0]
                time.sleep(0.5)
                assert proxy.stats["captures"] == 1, proxy.stats
                assert proxy.stats["skipped_dup"] >= 1, proxy.stats
                # A different endpoint is captured again.
                self._raw_proxy_get(proxy.port, f"{origin.base}/other?id=5")
                deadline = time.time() + 5
                while proxy.stats["captures"] < 2 and time.time() < deadline:
                    time.sleep(0.1)
                assert proxy.stats["captures"] == 2, proxy.stats
                # POST form body is captured too.
                import socket
                s = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                try:
                    body = "q=posted"
                    s.sendall(
                        f"POST {origin.base}/form HTTP/1.1\r\n"
                        f"Host: 127.0.0.1\r\nContent-Type: "
                        f"application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n\r\n{body}".encode())
                    s.recv(65536)
                finally:
                    s.close()
                deadline = time.time() + 5
                while proxy.stats["captures"] < 3 and time.time() < deadline:
                    time.sleep(0.1)
                assert proxy.stats["captures"] == 3, proxy.stats
            finally:
                proxy.stop()
        finally:
            origin.stop()

    def test_real_scanner_finds_reflected_xss(self):
        """Regression: captured endpoints must reach the REAL Scanner with a
        query-stripped URL so payloads replace values instead of being
        appended as dup params (silent zero-finding bug)."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core.scanner import Scanner
        origin = _Origin()
        origin.start()
        try:
            proxy = PassiveProxy(
                port=0, host="127.0.0.1", scope="127.0.0.1",
                requester=Requester(timeout=10))
            scanner = Scanner(
                requester=proxy.requester, use_headless=False, crawl=False,
                max_transforms=3, max_payloads=6, threads=2,
                dom_engine="static", verbose=False)
            stop = threading.Event()
            threading.Thread(
                target=drain_captures, args=(proxy, scanner, 0.5, stop),
                daemon=True).start()
            proxy.start()
            try:
                resp = self._raw_proxy_get(
                    proxy.port, f"{origin.base}/vuln?q=hello")
                assert "200" in resp.split("\r\n")[0]
                deadline = time.time() + 90
                while time.time() < deadline:
                    if (proxy.stats["scans"] >= proxy.stats["captures"]
                            and proxy.captures.empty()
                            and len(scanner.findings) > 0):
                        break
                    time.sleep(1)
                xss = [f for f in scanner.findings
                       if f.data.get("type") == "reflected"]
                assert xss, (
                    f"expected reflected XSS via passive proxy, "
                    f"stats={proxy.stats} findings={len(scanner.findings)}")
            finally:
                proxy.stop()
                stop.set()
        finally:
            origin.stop()

    def test_connect_tunnel_pumps_bytes_both_ways(self):
        """Regression: the CONNECT tunnel (HTTPS pass-through, no MITM) must
        relay bytes in BOTH directions verbatim -- any silent corruption or
        one-way pump breaks every HTTPS site behind the proxy."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket

        # --- echo "origin" that the tunnel terminates at -------------------
        echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo_srv.bind(("127.0.0.1", 0))
        echo_srv.listen(2)
        echo_port = echo_srv.getsockname()[1]
        got = []

        def _echo_loop():
            conn, _ = echo_srv.accept()
            conn.settimeout(15)
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    got.append(data)
                    conn.sendall(data)      # echo back
            except (socket.timeout, ConnectionError, OSError):
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        threading.Thread(target=_echo_loop, daemon=True).start()

        proxy = PassiveProxy(
            port=0, host="127.0.0.1", scope=None,
            requester=Requester(timeout=10))
        proxy.start()
        try:
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            c.settimeout(15)
            try:
                # Client speaks CONNECT exactly like a browser would for HTTPS.
                c.sendall(
                    f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                assert b"200" in buf.split(b"\r\n")[0], buf
                # Now the tunnel is established: send a fake TLS ClientHello,
                # expect the echo server to return it verbatim.
                payload = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" \
                          b"client-hello-test-bytes"
                c.sendall(payload)
                echoed = b""
                deadline = time.time() + 10
                while len(echoed) < len(payload) and time.time() < deadline:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    echoed += chunk
                assert echoed == payload, \
                    f"tunnel echo mismatch: {echoed!r} != {payload!r}"
                # Downstream -> upstream direction must have delivered too.
                assert got and got[0] == payload, got
            finally:
                try:
                    c.close()
                except Exception:
                    pass
            deadline = time.time() + 5
            while proxy.stats["tunnels"] < 1 and time.time() < deadline:
                time.sleep(0.1)
            assert proxy.stats["tunnels"] >= 1, proxy.stats
        finally:
            proxy.stop()
            try:
                echo_srv.close()
            except Exception:
                pass

    def test_connect_tunnel_reclaims_after_full_idle(self):
        """A tunnel with NO activity for the full idle cap is reclaimed
        (dead half-open TCP conns must not leak proxy threads), while
        activity keeps it alive across gaps.

        The idle cap is configurable (default 600s) precisely so long-lived
        HTTPS multiplexing (WebSocket/SSE/slow downloads) is not killed by a
        short select timeout -- but a truly dead tunnel still gets cleaned.
        """
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket
        echo_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo_srv.bind(("127.0.0.1", 0))
        echo_srv.listen(2)
        echo_port = echo_srv.getsockname()[1]

        def _handle(conn):
            conn.settimeout(20)
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
            except (socket.timeout, ConnectionError, OSError):
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        def _echo_loop():
            while True:
                try:
                    conn, _ = echo_srv.accept()
                except OSError:
                    return
                threading.Thread(target=_handle, args=(conn,),
                                 daemon=True).start()

        threading.Thread(target=_echo_loop, daemon=True).start()

        proxy = PassiveProxy(
            port=0, host="127.0.0.1", scope=None,
            requester=Requester(timeout=10),
            tunnel_idle_timeout=1.0)   # tiny idle cap: 1 second
        proxy.start()
        try:
            # --- dead tunnel: silent past the cap -> proxy closes it ------
            c1 = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            c1.settimeout(10)
            try:
                c1.sendall(
                    f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = c1.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                assert b"200" in buf.split(b"\r\n")[0], buf
                # Stay silent for well over the 1s cap: the pump must give
                # up and close the tunnel (recv returns b"" / raises).
                time.sleep(3.5)
                try:
                    c1.sendall(b"should-fail-now")
                    closed = c1.recv(4096) == b""
                except (socket.timeout, ConnectionError, OSError):
                    closed = True
                assert closed, "dead tunnel was not reclaimed after idle cap"
            finally:
                try:
                    c1.close()
                except Exception:
                    pass
            # --- live tunnel: brief gaps (< cap) keep it up ----------------
            c2 = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            c2.settimeout(10)
            try:
                c2.sendall(
                    f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = c2.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                assert b"200" in buf.split(b"\r\n")[0], buf
                for i in range(3):
                    time.sleep(0.6)          # each gap < 1s cap
                    payload = f"ping-{i}-still-alive".encode()
                    c2.sendall(payload)
                    echoed = b""
                    deadline = time.time() + 5
                    while len(echoed) < len(payload) and time.time() < deadline:
                        chunk = c2.recv(4096)
                        if not chunk:
                            break
                        echoed += chunk
                    assert echoed == payload, \
                        f"live tunnel dropped at ping {i}: {echoed!r}"
            finally:
                try:
                    c2.close()
                except Exception:
                    pass
        finally:
            proxy.stop()
            try:
                echo_srv.close()
            except Exception:
                pass


class TestRelayEncoding:
    """Phase 44 relay must not corrupt compressed origin responses."""

    def _gzip_origin_and_proxy(self):
        import gzip
        import socket

        class _GzH(BaseHTTPRequestHandler):
            def do_GET(self):
                raw = b"<html><body>gzip test content</body></html>"
                gz = gzip.compress(raw)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(gz)))
                self.end_headers()
                self.wfile.write(gz)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _GzH)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        return srv, proxy

    def test_gzip_response_relayed_as_plaintext(self):
        """Regression: requests decodes resp.content but keeps the original
        Content-Encoding: gzip header.  Forwarding both makes the browser
        gunzip plaintext -> DecodeError 'incorrect header check'.  The proxy
        must strip the encoding header and send the decoded body."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket
        origin, proxy = self._gzip_origin_and_proxy()
        try:
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            s.settimeout(10)
            try:
                s.sendall(
                    f"GET http://127.0.0.1:{origin.server_address[1]}/ "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    f"Connection: close\r\n\r\n".encode())
                buf = b""
                while True:
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                head, _, body = buf.partition(b"\r\n\r\n")
                assert b"200" in head.split(b"\r\n")[0], head
                assert b"content-encoding" not in head.lower(), \
                    "Content-Encoding must be stripped from decoded body"
                assert b"gzip test content" in body, \
                    "decoded plaintext body must be relayed intact"
            finally:
                s.close()
        finally:
            proxy.stop()
            origin.shutdown()


class TestCapturedCookies:
    """Captured Cookie headers must reach the scan so login-gated pages are
    not silently re-scanned anonymously."""

    def test_cookie_carried_into_scan(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core.scanner import Scanner

        class _AuthH(BaseHTTPRequestHandler):
            def do_GET(self):
                # Requires session=auth; anonymous gets 401.
                if "session=auth" not in (self.headers.get("Cookie") or ""):
                    body = b"<html><body>401 login required</body></html>"
                    self.send_response(401)
                else:
                    p = urlparse(self.path)
                    q = parse_qs(p.query).get("q", [""])[0]
                    body = (f"<html><body><div>{q}</div></body></html>"
                            .encode())
                    self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _AuthH)
        op = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope="127.0.0.1",
                             requester=Requester(timeout=10))
        scanner = Scanner(requester=proxy.requester, use_headless=False,
                          crawl=False, max_transforms=3, max_payloads=6,
                          threads=2, dom_engine="static", verbose=False)
        stop = threading.Event()
        threading.Thread(target=drain_captures, args=(proxy, scanner, 0.5, stop),
                         daemon=True).start()
        proxy.start()
        try:
            import socket as _s
            c = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            c.settimeout(15)
            try:
                c.sendall(
                    f"GET http://127.0.0.1:{op}/authed?q=hello HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{op}\r\n"
                    f"Cookie: session=auth; pref=en\r\n"
                    f"Connection: close\r\n\r\n".encode())
                buf = b""
                while True:
                    try:
                        chunk = c.recv(65536)
                    except _s.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                assert b"200" in buf.split(b"\r\n")[0]
            finally:
                c.close()
            deadline = time.time() + 90
            xss = []
            while time.time() < deadline:
                xss = [f for f in scanner.findings
                       if f.data.get("type") == "reflected"]
                if xss:
                    break
                time.sleep(1)
            assert xss, (
                "captured cookie was NOT carried into the scan -- the "
                "auth-gated page was scanned anonymously (401) and the "
                f"reflected XSS was missed. stats={proxy.stats}")
        finally:
            proxy.stop()
            stop.set()
            srv.shutdown()


class TestConnectTargetParsing:
    def test_host_port(self):
        assert _ProxyHandler._parse_connect_target("example.com:443") == \
            ("example.com", 443)

    def test_host_default_port(self):
        assert _ProxyHandler._parse_connect_target("example.com") == \
            ("example.com", 443)

    def test_nondefault_port(self):
        assert _ProxyHandler._parse_connect_target("example.com:8443") == \
            ("example.com", 8443)

    def test_ipv6_literal(self):
        # Regression: naive partition(':') broke on IPv6 (ValueError -> 502).
        assert _ProxyHandler._parse_connect_target("[::1]:8443") == ("::1", 8443)

    def test_ipv6_literal_default_port(self):
        assert _ProxyHandler._parse_connect_target("[2001:db8::1]") == \
            ("2001:db8::1", 443)

    def test_bad_port_falls_back(self):
        assert _ProxyHandler._parse_connect_target("h:notaport") == ("h", 443)


class TestRelayMethods:
    """HEAD / OPTIONS must relay instead of returning 501."""

    def test_head_and_options_relayed(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket

        class _MH(BaseHTTPRequestHandler):
            def _ok(self, body=b""):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self):
                self._ok(b"<html>get</html>")

            def do_HEAD(self):
                self._ok()

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Allow", "GET, HEAD, OPTIONS")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _MH)
        op = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        try:
            for verb, expect in (("HEAD", b"200"), ("OPTIONS", b"204")):
                c = socket.create_connection(
                    ("127.0.0.1", proxy.port), timeout=10)
                c.settimeout(10)
                try:
                    c.sendall(
                        f"{verb} http://127.0.0.1:{op}/ HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{op}\r\n"
                        f"Connection: close\r\n\r\n".encode())
                    buf = b""
                    while True:
                        try:
                            chunk = c.recv(65536)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        buf += chunk
                    assert expect in buf.split(b"\r\n")[0], \
                        f"{verb} via proxy: {buf[:80]!r}"
                finally:
                    c.close()
        finally:
            proxy.stop()
            srv.shutdown()


class TestRequestBodyHandling:
    """Chunked request bodies must be de-framed and relayed; oversized
    bodies must be refused with 413 instead of truncated-and-forwarded."""

    @staticmethod
    def _post_raw(proxy_port, target, headers, body=b""):
        import socket
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
        s.settimeout(15)
        try:
            req = (f"POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   + headers + f"Content-Length: {len(body)}\r\n"
                   + "Connection: close\r\n\r\n").encode() + body
            s.sendall(req)
            buf = b""
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            return buf
        finally:
            s.close()

    def _origin(self, do_echo_body=True):
        class _BH(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                body = (f"<html><body>got:{raw}</body></html>".encode())
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _BH)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        return srv, proxy

    def test_chunked_body_relayed(self):
        """Transfer-Encoding: chunked bodies are de-framed then relayed as a
        normal body (was silently dropped -> origin saw empty body)."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket
        srv, proxy = self._origin()
        try:
            chunks = b"a=1&b=2"
            chunked_body = (f"{len(b'a=1'):x}\r\na=1\r\n"
                            f"{len(b'&b=2'):x}\r\n&b=2\r\n0\r\n\r\n").encode()
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            s.settimeout(15)
            try:
                s.sendall(
                    f"POST http://127.0.0.1:{srv.server_address[1]}/up "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: close\r\n\r\n".encode() + chunked_body)
                buf = b""
                while True:
                    try:
                        chunk = s.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                assert b"got:a=1&b=2" in buf, \
                    f"chunked body not relayed intact: {buf[-120:]!r}"
            finally:
                s.close()
        finally:
            proxy.stop()
            srv.shutdown()

    def test_oversized_body_refused_413(self):
        """Bodies over the cap must get 413 + connection close, never a
        truncated forward (smuggling)."""
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        srv, proxy = self._origin()
        try:
            big = b"x" * (2_100_000)          # > 2 MB cap
            buf = self._post_raw(
                proxy.port,
                f"http://127.0.0.1:{srv.server_address[1]}/up",
                "Content-Type: text/plain\r\n", big)
            status = buf.split(b"\r\n")[0]
            assert b"413" in status, f"expected 413, got {status!r}"
        finally:
            proxy.stop()
            srv.shutdown()


class TestMultipartCapture:
    """Phase 56: multipart uploads are captured -- non-file fields become
    body data, and the file field NAME is routed to the upload probe."""

    def _multipart_body(self, boundary="xssentinelb", filename="hello.txt"):
        return (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n"
            f"abc123\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; "
            f"filename=\"{filename}\"\r\n"
            f"Content-Type: text/plain\r\n\r\n"
            f"file-content\r\n"
            f"--{boundary}--\r\n").encode()

    def test_parse_multipart_splits_fields_and_file(self):
        from xssentinel.core.passive_proxy import _parse_multipart
        body = self._multipart_body()
        fields, files = _parse_multipart(
            "multipart/form-data; boundary=xssentinelb", body)
        assert fields == {"csrf_token": "abc123"}
        assert files == ["file"]          # filename parts reported by name

    def test_parse_body_multipart_returns_nonfile_fields(self):
        from xssentinel.core.passive_proxy import _parse_body
        body = self._multipart_body()
        assert _parse_body(
            "multipart/form-data; boundary=xssentinelb", body) == \
            {"csrf_token": "abc123"}

    def test_parse_multipart_non_multipart_is_empty(self):
        from xssentinel.core.passive_proxy import _parse_multipart
        assert _parse_multipart("application/json", b'{"a":1}') == ({}, [])

    def test_drain_routes_upload_field_to_scanner_transiently(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import socket as _s
        from xssentinel.core.passive_proxy import (PassiveProxy, drain_captures)
        origin = _Origin()
        origin.start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        seen = {}

        class _ScanStub:
            upload_fields = []

            def scan_endpoint(self, url, method="GET", params=None,
                              data=None, req=None):
                seen["upload_fields_during"] = list(self.upload_fields)
                seen["url"] = url

        stop = threading.Event()
        t = threading.Thread(target=drain_captures,
                             args=(proxy, _ScanStub(), 0.3, stop),
                             daemon=True)
        t.start()
        try:
            body = self._multipart_body()
            s = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(
                    f"POST {origin.base}/upload HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\nContent-Type: multipart/form-data; "
                    f"boundary=xssentinelb\r\nContent-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + body)
                s.recv(65536)
            finally:
                s.close()
            deadline = time.time() + 6
            while ("upload_fields_during" not in seen
                   and time.time() < deadline):
                time.sleep(0.1)
            # The file field was visible to the scan (upload probe target)
            # and the endpoint URL reached the scanner with query stripped.
            assert seen.get("upload_fields_during") == ["file"], seen
            assert seen.get("url", "").endswith("/upload"), seen
        finally:
            stop.set()
            proxy.stop()
            origin.stop()


class TestPutPatchCapture:
    """Phase 60: RESTful PUT/PATCH bodies are captured and dispatched with
    their real method (previously relayed but invisible)."""

    def test_run_capture_preserves_put_method_and_body(self):
        seen = {}

        class _S:
            def scan_endpoint(self, url, method="GET", params=None,
                              data=None, req=None):
                seen["method"] = method
                seen["data"] = dict(data or {})
                seen["params"] = dict(params or {})

        _run_capture(_S(), "PUT", "http://t/api", {},
                     {"name": "x", "role": "admin"})
        assert seen["method"] == "PUT"
        assert seen["data"] == {"name": "x", "role": "admin"}

    def test_run_capture_patch_without_body_keeps_method(self):
        seen = {}

        class _S:
            def scan_endpoint(self, url, method="GET", params=None,
                              data=None, req=None):
                seen["method"] = method
                seen["params"] = dict(params or {})

        _run_capture(_S(), "PATCH", "http://t/api", {"q": "1"}, {})
        assert seen["method"] == "PATCH"
        assert seen["params"] == {"q": "1"}

    def test_put_body_reaches_capture_through_proxy(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import http.server as _http
        import socket as _s
        from xssentinel.core.passive_proxy import (PassiveProxy, drain_captures)

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_PUT(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                out = b"<html><body>put-ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        origin = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        seen = {}

        class _ScanStub:
            def scan_endpoint(self, url, method="GET", params=None,
                              data=None, req=None):
                seen["method"] = method
                seen["data"] = dict(data or {})

        stop = threading.Event()
        t = threading.Thread(target=drain_captures,
                             args=(proxy, _ScanStub(), 0.3, stop), daemon=True)
        t.start()
        try:
            payload = b'{"name": "x", "role": "admin"}'
            s = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(
                    f"PUT http://127.0.0.1:{origin.server_address[1]}/api "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: "
                    f"application/json\r\nContent-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + payload)
                s.recv(65536)
            finally:
                s.close()
            deadline = time.time() + 6
            while "method" not in seen and time.time() < deadline:
                time.sleep(0.1)
            assert seen.get("method") == "PUT", seen
            assert seen.get("data") == {"name": "x", "role": "admin"}, seen
        finally:
            stop.set()
            proxy.stop()
            origin.shutdown()


class TestPassiveUploadDiscovery:
    """Phase 57/60 closure: an upload-filename XSS endpoint browsed through
    the passive proxy is actually DETECTED (capture -> field routing ->
    upload probe -> upload_xss finding), not just captured."""

    def test_passive_detects_upload_filename_xss(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import re as _re
        import http.server as _http
        import socket as _s
        from xssentinel.core.passive_proxy import (PassiveProxy, drain_captures)
        from xssentinel.core.scanner import Scanner

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(
                    int(self.headers.get("Content-Length") or 0))
                m = _re.search(rb'filename="([^"]*)"', body)
                name = m.group(1).decode("utf-8", "replace") if m else ""
                # Raw, unescaped echo: an <img onerror> filename becomes
                # executable markup (the app's upload summary page).
                out = ("<html><body><div>up:%s</div></body></html>"
                       % name).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        origin = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10, verify_ssl=False))
        # No --upload-field: the field must be discovered from the traffic.
        scanner = Scanner(requester=proxy.requester, use_headless=False,
                          crawl=False, max_transforms=2, max_payloads=4,
                          threads=1, dom_engine="static", verbose=False)
        stop = threading.Event()
        threading.Thread(target=drain_captures, args=(proxy, scanner, 0.4, stop),
                         daemon=True).start()
        proxy.start()
        try:
            dash = "--xssentinelb"
            body = (f"{dash}\r\n".encode()
                    + b'Content-Disposition: form-data; name="file"; '
                      b'filename="hi.txt"\r\n'
                    b"Content-Type: text/plain\r\n\r\ncontent\r\n"
                    + f"{dash}--\r\n".encode())
            s = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(
                    f"POST http://127.0.0.1:{origin.server_address[1]}/up "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: "
                    f"multipart/form-data; boundary=xssentinelb\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + body)
                s.recv(65536)
            finally:
                s.close()
            deadline = time.time() + 60
            while time.time() < deadline:
                if any(f.data.get("type") == "upload_xss"
                       for f in scanner.findings):
                    break
                time.sleep(1)
            hits = [f.data for f in scanner.findings
                    if f.data.get("type") == "upload_xss"]
            assert hits, [f.data.get("type") for f in scanner.findings]
            assert hits[0]["param"] == "file[filename]"
        finally:
            stop.set()
            proxy.stop()
            origin.shutdown()


class TestJsonCarrierPassive:
    """Phase 61: JSON-API endpoints captured by the proxy are re-probed as
    application/json (form-encoding would be ignored by a JSON API)."""

    def test_drain_sets_and_restores_json_body(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import http.server as _http
        import socket as _s
        from xssentinel.core.passive_proxy import (PassiveProxy, drain_captures)

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                out = b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        origin = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10))
        proxy.start()
        seen = {}

        class _S:
            json_body = None
            upload_fields = []

            def scan_endpoint(self, url, method="GET", params=None,
                              data=None, req=None):
                seen["json_body"] = self.json_body

        stop = threading.Event()
        t = threading.Thread(target=drain_captures,
                             args=(proxy, _S(), 0.3, stop), daemon=True)
        t.start()
        try:
            payload = b'{"q": "hi"}'
            s = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(
                    f"POST http://127.0.0.1:{origin.server_address[1]}/api "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: "
                    f"application/json\r\nContent-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + payload)
                s.recv(65536)
            finally:
                s.close()
            deadline = time.time() + 6
            while "json_body" not in seen and time.time() < deadline:
                time.sleep(0.1)
            assert seen.get("json_body") == {"q": "hi"}, seen
        finally:
            stop.set()
            proxy.stop()
            origin.shutdown()

    def test_passive_detects_json_reflection(self):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        import http.server as _http
        import json as _json
        import socket as _s
        from xssentinel.core.passive_proxy import (PassiveProxy, drain_captures)
        from xssentinel.core.scanner import Scanner
        seen_ct = []

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                raw = self.rfile.read(
                    int(self.headers.get("Content-Length") or 0))
                seen_ct.append((self.headers.get("Content-Type") or "")
                               .split(";")[0].strip())
                try:
                    obj = _json.loads(raw.decode("utf-8", "replace"))
                    val = obj.get("q", "")
                except Exception:
                    val = ""
                # JSON API that renders the value into a page (common: an
                # SPA shell or admin page reflecting saved input).
                out = ("<html><body><div>q:%s</div></body></html>"
                       % val).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        origin = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10, verify_ssl=False))
        scanner = Scanner(requester=proxy.requester, use_headless=False,
                          crawl=False, max_transforms=2, max_payloads=4,
                          threads=1, dom_engine="static", verbose=False)
        stop = threading.Event()
        threading.Thread(target=drain_captures, args=(proxy, scanner, 0.4, stop),
                         daemon=True).start()
        proxy.start()
        try:
            payload = b'{"q": "hi"}'
            s = _s.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                s.sendall(
                    f"POST http://127.0.0.1:{origin.server_address[1]}/api "
                    f"HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: "
                    f"application/json\r\nContent-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n".encode() + payload)
                s.recv(65536)
            finally:
                s.close()
            deadline = time.time() + 45
            while time.time() < deadline:
                if any(f.data.get("type") == "reflected"
                       for f in scanner.findings):
                    break
                time.sleep(1)
            hits = [f.data for f in scanner.findings
                    if f.data.get("type") == "reflected"]
            assert hits, [f.data.get("type") for f in scanner.findings]
            # At least one probe must have been sent as application/json.
            assert any("application/json" in ct for ct in seen_ct), seen_ct
        finally:
            stop.set()
            proxy.stop()
            origin.shutdown()


class TestStoredWatchUnit:
    """Phase 67 mechanism tests: passive stored/second-order watch.

    (The full browser-flow e2e lives behind RUN_STORED_LIVE=1 -- the
    degraded-loopback environment here cannot reliably keep the relay
    alive for the full capture->arm->browse->confirm sequence.)"""

    def test_arm_watch_fifo_cap(self):
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=5))
        for i in range(7):
            proxy.arm_stored_watch(f"tok{i}", {"n": i})
        assert list(proxy._stored_watch.keys()) == ["tok2", "tok3", "tok4",
                                                    "tok5", "tok6"]

    def test_check_stored_tokens_hits_and_forgets(self):
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=5))
        proxy.arm_stored_watch("xsso_a", {"inject_param": "q"})
        hits = proxy.check_stored_tokens("page with xsso_a inside")
        assert len(hits) == 1 and hits[0][0] == "xsso_a"
        assert proxy.check_stored_tokens("xsso_a again") == []  # forgotten

    def test_note_take_roundtrip(self):
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=5))
        proxy.note_stored_hit("xsso_b", {"inject_param": "q"},
                              "http://t/list", "html")
        assert len(proxy.take_stored_hits()) == 1
        assert proxy.take_stored_hits() == []

    def test_run_capture_arms_watch_on_write_endpoint(self):
        import http.server as _http
        import socket as _s

        entries: list[str] = []

        class _M(_http.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                raw = self.rfile.read(
                    int(self.headers.get("Content-Length") or 0)).decode(
                    "utf-8", "replace")
                import urllib.parse as _up
                entries.append((_up.parse_qs(raw).get("q") or [""])[0])
                out = b"<html><body>saved</body></html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        if not loopback_healthy():
            pytest.skip("loopback degraded")
        from xssentinel.core.scanner import Scanner
        origin = _http.ThreadingHTTPServer(("127.0.0.1", 0), _M)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=10, verify_ssl=False))
        proxy.start()
        scanner = Scanner(requester=proxy.requester, use_headless=False,
                          crawl=False, max_transforms=2, max_payloads=4,
                          threads=1, dom_engine="static", verbose=False)
        try:
            form = b"q=hello"
            s = _s.create_connection(("127.0.0.1", origin.server_address[1]),
                                     timeout=10)
            try:
                s.sendall(
                    b"POST /comment HTTP/1.1\r\nHost: t\r\n"
                    b"Content-Type: application/x-www-form-urlencoded\r\n"
                    + f"Content-Length: {len(form)}\r\n\r\n".encode()
                    + form)
                s.recv(65536)
            finally:
                s.close()
            # Direct dispatch (drain parity): scan + arm in one call.
            _run_capture(scanner, "POST",
                         f"http://127.0.0.1:{origin.server_address[1]}/comment",
                         {}, {"q": "hello"}, None, proxy=proxy)
            assert proxy._stored_watch, "watch never armed"
            tok, info = next(iter(proxy._stored_watch.items()))
            assert info["inject_param"] == "q"
            assert tok.startswith("xsso_")
            # The arm injection really reached the origin.
            assert any(tok in e for e in entries)
        finally:
            proxy.stop()
            origin.shutdown()

    def test_verify_stored_hits_confirms_and_reports(self):
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=5))

        class _S:
            def __init__(self):
                self.added = []

            def _add(self, finding):
                self.added.append(finding)

        sc = _S()
        token = "xsso_unit01"
        proxy.arm_stored_watch(token, {
            "inject_url": "http://t/comment", "inject_method": "POST",
            "inject_param": "q",
            "payload": "<img src=x onerror=alert('" + token + "')>",
        })
        # Operator's later browsed page renders the stored payload raw.
        proxy.note_stored_hit(
            token, proxy._stored_watch[token], "http://t/list",
            "<html><body><div>up:<img src=x onerror=alert('" + token
            + "')></div></body></html>")
        _verify_stored_hits(proxy, sc)
        assert len(sc.added) == 1
        f = sc.added[0].data
        assert f["type"] == "second_order" and f["param"] == "q"
        assert f["severity"] == "high" and f["confidence"] == "high"
        assert "/list" in f["proof"]["viewer_url"]

    def test_verify_drops_escaped_echo(self):
        proxy = PassiveProxy(port=0, host="127.0.0.1", scope=None,
                             requester=Requester(timeout=5))

        class _S:
            def __init__(self):
                self.added = []

            def _add(self, finding):
                self.added.append(finding)

        sc = _S()
        token = "xsso_unit02"
        proxy.arm_stored_watch(token, {
            "inject_url": "http://t/comment", "inject_method": "POST",
            "inject_param": "q", "payload": "<img src=x onerror=alert(1)>",
        })
        # Escaped echo: token present but NOT executable -> must NOT report.
        proxy.note_stored_hit(
            token, proxy._stored_watch[token], "http://t/list",
            "<html><body>q:&lt;img src=x onerror=alert('" + token
            + "')&gt;</body></html>")
        _verify_stored_hits(proxy, sc)
        assert sc.added == []

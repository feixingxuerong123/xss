"""Tests for Phase 50 -- passive proxy HTTPS interception (MITM).

The CA/leaf-certificate machinery is tested directly (deterministic
per-host leafs, SANs, CA-signed chain).  The interception itself is
verified end-to-end against a REAL self-signed TLS origin: a browser-style
client (requests) tunnels CONNECT through the proxy, trusts the generated
CA, and its HTTPS query params must come out the other side as captured
endpoints -- exactly like plain HTTP.  Blind-tunnel behaviour (no --mitm-ca,
or out-of-scope hosts) is asserted to stay byte-transparent.
"""
from __future__ import annotations
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Make xssentinel importable when run from the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from xssentinel.core.mitm_ca import MitmManager, available
from xssentinel.core.passive_proxy import PassiveProxy
from xssentinel.core.requester import Requester

from tests.conftest import SOCKETPAIR_OK, loopback_healthy

pytestmark = pytest.mark.skipif(
    not SOCKETPAIR_OK,
    reason="Windows loopback socketpair hangs (security software/TCP state)")

requires_crypto = pytest.mark.skipif(
    not available(),
    reason="cryptography package not installed")


# ---------------------------------------------------------------------------
# A self-signed TLS origin that reflects ?q= verbatim (vulnerable), the TLS
# counterpart of test_passive_proxy._Origin.
# ---------------------------------------------------------------------------
def _self_signed_cert(tmpdir, cn="127.0.0.1"):
    """Write a throwaway self-signed cert/key for the TLS origin; return
    the cert path (base)."""
    import datetime as _dt
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(
            ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256()))
    base = os.path.join(str(tmpdir), "origin")
    with open(base + ".key", "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(base + ".crt", "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return base


class _TlsServer(ThreadingHTTPServer):
    """ThreadingHTTPServer whose accepted sockets are TLS-wrapped."""

    def __init__(self, addr, handler, ctx):
        self._ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = super().get_request()
        return self._ctx.wrap_socket(sock, server_side=True), addr


class _TlsOrigin:
    def __init__(self, certbase):
        self.certbase = certbase
        self.server = None
        self.port = None

    def start(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.certbase + ".crt", self.certbase + ".key")

        class _H(BaseHTTPRequestHandler):
            def _send(self, body: bytes):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                p = urlparse(self.path)
                q = parse_qs(p.query).get("q", [""])[0]
                self._send(f"<html><body><div>{q}</div></body></html>".encode())

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                self._send(f"<html><body><div>{raw}</div></body></html>".encode())

            def log_message(self, *a):
                pass

        for port in range(8962, 8974):
            try:
                self.server = _TlsServer(("127.0.0.1", port), _H, ctx)
                break
            except OSError:
                continue
        if self.server is None:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                free = s.getsockname()[1]
            self.server = _TlsServer(("127.0.0.1", free), _H, ctx)
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
        return f"https://127.0.0.1:{self.port}"


def _tunneled_get(proxy_port: int, url: str,
                  ca_cert_path: str | None = None,
                  timeout: float = 15) -> tuple[int, str]:
    """Browser-style HTTPS request through the proxy.

    socket CONNECT -> TLS -> plaintext HTTP/1.1 inside.  With ``ca`` the
    client trusts the interception CA (MITM path); without it the client
    accepts whatever certificate the tunnel delivers (blind path, where the
    bytes pass through to the ORIGIN's own cert).  This is exactly what a
    real browser does behind a proxy and cannot be affected by NO_PROXY /
    proxy-pool quirks -- the same reason test_passive_proxy.py drives the
    proxy with raw sockets.  Returns (status_code, body_text).
    """
    from urllib.parse import urlparse
    p = urlparse(url)
    host, port = p.hostname, p.port
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        s.sendall(
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("proxy closed during CONNECT")
            buf += chunk
        status = int(buf.split(b"\r\n")[0].split()[1])
        if status != 200:
            return status, buf.decode("utf-8", "replace")
        if ca_cert_path:
            ctx = ssl.create_default_context(cafile=ca_cert_path)
        else:
            ctx = ssl._create_unverified_context()
        tls = ctx.wrap_socket(s, server_hostname=host)
        s = tls  # read from TLS from here on
        target = p.path or "/"
        if p.query:
            target += "?" + p.query
        s.sendall(
            f"GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Connection: close\r\n\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        head, _, body = resp.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n")[0].split()[1])
        return status, body.decode("utf-8", "replace")
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CA / leaf certificate unit tests
# ---------------------------------------------------------------------------
class TestMitmCa:
    @requires_crypto
    def test_manager_generates_ca_and_cert_sibling(self, tmp_path):
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        assert os.path.isfile(ca)
        cert_only = str(tmp_path / "ca-cert.pem")
        assert os.path.isfile(cert_only)
        # The cert-only file holds a CA certificate (basicConstraints CA).
        from cryptography import x509
        c = x509.load_pem_x509_certificate(open(cert_only, "rb").read())
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True

    @requires_crypto
    def test_existing_ca_is_reused(self, tmp_path):
        ca = str(tmp_path / "ca.pem")
        MitmManager(ca)
        before = os.path.getmtime(ca)
        time.sleep(0.01)
        MitmManager(ca)   # must NOT regenerate
        assert os.path.getmtime(ca) == before

    @requires_crypto
    def test_leaf_cached_and_keyed_by_host(self, tmp_path):
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        a1 = mgr.leaf_cert_path("example.com")
        a2 = mgr.leaf_cert_path("example.com")
        b = mgr.leaf_cert_path("other.test")
        assert a1 == a2 and os.path.isfile(a1)
        assert a1 != b

    @requires_crypto
    def test_leaf_signed_by_ca_with_serverauth_and_san(self, tmp_path):
        from cryptography import x509
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        leaf = mgr.leaf_cert_path("example.com")
        cert = x509.load_pem_x509_certificate(open(leaf, "rb").read())
        bc = cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value
        assert bc.ca is False
        # serverAuth extended key usage present.
        eku = [o.dotted_string for o in cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value]
        assert "1.3.6.1.5.5.7.3.1" in eku
        # SAN carries the host.
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        assert "example.com" in san.get_values_for_type(x509.DNSName)
        # Chain check: leaf is signed by the CA private key.
        ca_cert = x509.load_pem_x509_certificate(
            open(str(tmp_path / "ca-cert.pem"), "rb").read())
        from cryptography.hazmat.primitives.asymmetric import padding
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm)

    @requires_crypto
    def test_ip_literal_gets_ip_san(self, tmp_path):
        import ipaddress
        from cryptography import x509
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        leaf = mgr.leaf_cert_path("127.0.0.1")
        cert = x509.load_pem_x509_certificate(open(leaf, "rb").read())
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        assert ipaddress.ip_address("127.0.0.1") in \
            san.get_values_for_type(x509.IPAddress)


# ---------------------------------------------------------------------------
# End-to-end: HTTPS params captured through MITM; blind fallbacks intact
# ---------------------------------------------------------------------------
class TestHttpsMitm:
    @pytest.fixture()
    def origin(self, tmp_path):
        certbase = _self_signed_cert(tmp_path)
        o = _TlsOrigin(certbase)
        o.start()
        yield o
        o.stop()

    @pytest.fixture()
    def ca(self, tmp_path):
        return str(tmp_path / "mitm" / "ca.pem")

    def _proxy(self, ca=None, scope=None):
        requester = Requester(timeout=10, verify_ssl=False)
        return PassiveProxy(port=0, host="127.0.0.1", scope=scope,
                            requester=requester, mitm_ca=ca)

    def test_https_params_captured_through_mitm(self, origin, ca, tmp_path):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        proxy = self._proxy(ca=ca)
        proxy.start()
        try:
            # Browser-style HTTPS request; the client trusts our CA.
            status, body = _tunneled_get(
                proxy.port, f"{origin.base}/vuln?q=mitmworks",
                str(tmp_path / "mitm" / "ca-cert.pem"))
            assert status == 200 and "mitmworks" in body
            deadline = time.time() + 8
            while proxy.stats["captures"] < 1 and time.time() < deadline:
                time.sleep(0.1)
            assert proxy.stats["mitm"] >= 1, proxy.stats
            assert proxy.stats["captures"] >= 1, proxy.stats
            # The captured endpoint must be the HTTPS URL with its params --
            # the entire point of interception.
            method, url, params, data, _ = proxy.captures.get(timeout=1)
            assert method == "GET" and url.startswith("https://")
            assert params.get("q") == "mitmworks"
        finally:
            proxy.stop()

    def test_no_mitm_ca_keeps_blind_tunnel(self, origin, tmp_path):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        proxy = self._proxy(ca=None)
        proxy.start()
        try:
            # Blind tunnel: the client accepts the ORIGIN's own certificate
            # because the proxy relays the TLS bytes untouched.
            status, body = _tunneled_get(
                proxy.port, origin.base + "/vuln?q=blind")
            assert status == 200 and "blind" in body
            time.sleep(0.5)
            assert proxy.stats["tunnels"] >= 1, proxy.stats
            assert proxy.stats["mitm"] == 0, proxy.stats
            assert proxy.stats["captures"] == 0, proxy.stats  # nothing seen
        finally:
            proxy.stop()

    def test_out_of_scope_https_stays_blind(self, origin, ca, tmp_path):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        # Scope declares example.com; 127.0.0.1 is outside -> blind tunnel,
        # even though a CA is configured.
        proxy = self._proxy(ca=ca, scope="example.com")
        proxy.start()
        try:
            status, body = _tunneled_get(
                proxy.port, origin.base + "/vuln?q=ooscope")
            assert status == 200 and "ooscope" in body
            time.sleep(0.5)
            assert proxy.stats["tunnels"] >= 1, proxy.stats
            assert proxy.stats["mitm"] == 0, proxy.stats
            assert proxy.stats["captures"] == 0, proxy.stats
        finally:
            proxy.stop()

    def test_in_scope_https_is_intercepted(self, origin, ca, tmp_path):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        proxy = self._proxy(ca=ca, scope="127.0.0.1")
        proxy.start()
        try:
            status, body = _tunneled_get(
                proxy.port, f"{origin.base}/vuln?q=inscope",
                str(tmp_path / "mitm" / "ca-cert.pem"))
            assert status == 200 and "inscope" in body
            deadline = time.time() + 8
            while proxy.stats["captures"] < 1 and time.time() < deadline:
                time.sleep(0.1)
            assert proxy.stats["mitm"] >= 1, proxy.stats
            assert proxy.stats["captures"] >= 1, proxy.stats
        finally:
            proxy.stop()

    def test_post_body_captured_through_mitm(self, origin, ca, tmp_path):
        if not loopback_healthy():
            pytest.skip("loopback degraded")
        proxy = self._proxy(ca=ca)
        proxy.start()
        try:
            # The TLS origin only implements GET/POST; exercise the POST
            # relay so a body is captured too (form params), not just query.
            status, body = _tunneled_get(
                proxy.port, f"{origin.base}/vuln?q=postq",
                str(tmp_path / "mitm" / "ca-cert.pem"))
            assert status == 200
            # POST through the proxy with a form body.
            from urllib.parse import urlparse
            p = urlparse(origin.base + "/form")
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            try:
                s.sendall(
                    f"CONNECT 127.0.0.1:{p.port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{p.port}\r\n\r\n".encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    buf += s.recv(4096)
                assert b"200" in buf.split(b"\r\n")[0]
                ctx = ssl.create_default_context(
                    cafile=str(tmp_path / "mitm" / "ca-cert.pem"))
                tls = ctx.wrap_socket(s, server_hostname="127.0.0.1")
                payload = "q=posted&extra=1"
                tls.sendall(
                    f"POST /form HTTP/1.1\r\nHost: 127.0.0.1:{p.port}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n\r\n{payload}".encode())
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                tls.close()
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            deadline = time.time() + 8
            while proxy.stats["captures"] < 1 and time.time() < deadline:
                time.sleep(0.1)
            assert proxy.stats["captures"] >= 1, proxy.stats
            # POST body params reached the capture queue.
            items = []
            while not proxy.captures.empty():
                items.append(proxy.captures.get(timeout=1))
            assert any(it[1].endswith("/form") and it[3].get("q") == "posted"
                       for it in items), items
        finally:
            proxy.stop()


class TestMitmCaHardening:
    """Phase 72: CA key file permissions + concurrent leaf signing."""

    def test_key_files_restricted_posix(self, tmp_path):
        from xssentinel.core.mitm_ca import generate_ca
        if os.name != "posix":
            pytest.skip("POSIX permission bits only")
        ca = str(tmp_path / "ca.pem")
        generate_ca(ca)
        assert os.stat(ca).st_mode & 0o077 == 0

    def test_concurrent_leaf_signing_same_host(self, tmp_path):
        if not available():
            pytest.skip("cryptography not installed")
        import hashlib
        from xssentinel.core.mitm_ca import MitmManager
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        host = "race.test"
        results: list = []
        errs: list = []

        def worker():
            try:
                results.append(mgr.leaf_cert_path(host))
            except Exception as e:  # pragma: no cover
                errs.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errs, errs
        assert len(set(results)) == 1          # all agree on ONE file
        digest = hashlib.sha1(host.encode()).hexdigest()
        leaf = os.path.join(mgr._cache_dir, f"leaf-{digest}.pem")
        # The file is a complete, loadable key+cert pair (not interleaved).
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        pem = open(leaf, "rb").read()
        key = serialization.load_pem_private_key(pem, password=None)
        cert = x509.load_pem_x509_certificate(pem)
        assert key is not None and cert.subject is not None


class TestMitmCaHardening:
    """Phase 72: CA key file permissions + concurrent leaf signing."""

    def test_key_files_restricted_posix(self, tmp_path):
        from xssentinel.core.mitm_ca import generate_ca
        if os.name != "posix":
            pytest.skip("POSIX permission bits only")
        ca = str(tmp_path / "ca.pem")
        generate_ca(ca)
        assert os.stat(ca).st_mode & 0o077 == 0

    def test_concurrent_leaf_signing_same_host(self, tmp_path):
        if not available():
            pytest.skip("cryptography not installed")
        import hashlib
        from xssentinel.core.mitm_ca import MitmManager
        ca = str(tmp_path / "ca.pem")
        mgr = MitmManager(ca)
        host = "race.test"
        results: list = []
        errs: list = []

        def worker():
            try:
                results.append(mgr.leaf_cert_path(host))
            except Exception as e:  # pragma: no cover
                errs.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errs, errs
        assert len(set(results)) == 1          # all agree on ONE file
        digest = hashlib.sha1(host.encode()).hexdigest()
        leaf = os.path.join(mgr._cache_dir, f"leaf-{digest}.pem")
        # The file is a complete, loadable key+cert pair (not interleaved).
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        pem = open(leaf, "rb").read()
        key = serialization.load_pem_private_key(pem, password=None)
        cert = x509.load_pem_x509_certificate(pem)
        assert key is not None and cert.subject is not None

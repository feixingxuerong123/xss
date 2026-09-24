"""Passive proxy scanning mode (Phase 44) -- learned from xray / w13scan.

The operator points their browser (or any HTTP client) at XSSentinel's
built-in proxy; every request that flows through it is captured, its
parameters are extracted, de-duplicated by endpoint signature, and handed
to the normal detection pipeline.  This is how xray/w13scan's "被动扫描"
mode works: no URL list required, login-protected / JS-rendered pages get
covered automatically because the *real* traffic is observed.

Scope of this v1:
  * HTTP (GET/POST) requests are fully captured: URL, query params, body
    params, cookies.
  * HTTPS is CONNECT-tunneled.  By default the tunnel is blind (bytes are
    relayed untouched: low footprint, no cert installation, HTTPS params
    are NOT captured).  With ``--mitm-ca <ca>.pem`` the proxy instead
    terminates TLS itself with a per-host certificate signed by the local
    CA (see mitm_ca.py): HTTPS then behaves exactly like HTTP -- requests
    are relayed, params/cookies captured and scanned.  The CA certificate
    (<ca>-cert.pem) must be installed in the client's trust store.
  * Captured endpoints are de-duplicated by (method, host, path,
    sorted-param-names) signature so paginated / repeated requests don't
    cause re-scans.
  * Endpoints are scanned in a background worker thread so the proxy keeps
    serving traffic while scanning happens.

Usage (CLI)::

    xssentinel --passive --proxy-port 8080 --scope example.com
    xssentinel --passive --proxy-port 8080 --mitm-ca mitm/ca.pem

then configure the browser/system proxy to 127.0.0.1:8080 (for --mitm-ca,
install ``mitm/ca-cert.pem`` in the browser trust store first).
"""
from __future__ import annotations

import json
import logging
import queue
import re
import socket
import ssl
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, urlunparse

from .requester import Requester

_log = logging.getLogger("xssentinel.passive")

# Request headers that must NOT be forwarded to the origin (proxy-specific).
_SKIP_FORWARD_HEADERS = {
    "proxy-connection",
    "proxy-authorization",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",  # recomputed from body by requests
}


def endpoint_signature(method: str, url: str, params: dict, data: dict) -> str:
    """Return a de-dup signature for one captured endpoint.

    Two requests to the same (method, host, path) with the same *set* of
    parameter names are considered the same endpoint (values are ignored:
    pagination / token changes must not trigger re-scans).
    """
    p = urlparse(url)
    host = (p.hostname or "").lower()
    # Keep the port when it's non-default so http://h:8080/a != http://h/a.
    port = p.port
    if port is not None and not (
        (p.scheme == "http" and port == 80)
        or (p.scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    names = sorted(set(params.keys()) | set(data.keys()))
    return f"{method.upper()}|{host}|{p.path}|{','.join(names)}"


def in_scope(url: str, scope: str | None) -> bool:
    """Whether a captured URL is inside the operator-declared scope.

    scope may be a bare hostname ("example.com"), a host:port, or a URL
    prefix ("https://example.com/app").  None -> capture everything.
    """
    if not scope:
        return True
    s = scope.strip()
    if s.startswith(("http://", "https://")):
        return url.startswith(s)
    # Bare host / host:port
    p = urlparse(url)
    host = p.hostname or ""
    if ":" in s and not s.startswith("["):
        host_part, port_part = s.rsplit(":", 1)
        if port_part.isdigit():
            return host.lower() == host_part.lower() and p.port == int(port_part)
    return host.lower() == s.lower() or host.lower().endswith("." + s.lower())


def _parse_cookie_header(raw: str | None) -> dict | None:
    """Parse a request 'Cookie' header into {name: value} (None if absent).

    http.cookies.SimpleCookie handles quoted values, spaces and the '='
    inside values correctly (unlike a naive ';' / '=' split).
    """
    if not raw:
        return None
    try:
        from http.cookies import SimpleCookie
        c = SimpleCookie()
        c.load(raw)
        out = {k: v.value for k, v in c.items()}
        return out or None
    except Exception:
        return None


def _parse_multipart(content_type: str | None, body: bytes):
    """Parse a multipart/form-data body into (fields, file_field_names).

    ``fields`` holds the NON-file parts (CSRF tokens etc.) as strings; the
    file parts are reported by name in ``file_field_names`` so the caller
    can route them to the upload-filename XSS probe (their value is a
    filename, not something a form-encoding reflection probe should touch).
    Returns ({}, []) when the body is not multipart or is malformed.
    """
    import email
    ctype = (content_type or "").lower()
    if "multipart/form-data" not in ctype or not body:
        return {}, []
    boundary = None
    for part in ctype.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part.split("=", 1)[1].strip().strip('"')
            break
    if not boundary:
        return {}, []
    try:
        msg = email.message_from_bytes(
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/form-data; boundary="
            + boundary.encode("utf-8", "replace") + b"\r\n\r\n" + body)
    except Exception:
        return {}, []
    fields: dict = {}
    file_fields: list[str] = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_type() == "multipart/form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        if part.get_filename():
            file_fields.append(name)
            continue
        try:
            value = part.get_payload(decode=True)
            fields[name] = value.decode("utf-8", "replace") \
                if isinstance(value, bytes) else str(value)
        except Exception:
            fields[name] = ""
    return fields, file_fields


def _parse_body(content_type: str | None, body: bytes) -> dict:
    """Parse a request body into a dict of params (form-encoded / JSON /
    multipart non-file fields)."""
    if not body:
        return {}
    ctype = (content_type or "").lower()
    try:
        if "json" in ctype:
            obj = json.loads(body.decode("utf-8", "replace"))
            if isinstance(obj, dict):
                return {str(k): v for k, v in obj.items()}
            return {}
        if "x-www-form-urlencoded" in ctype:
            return {k: v[0] for k, v in parse_qs(
                body.decode("utf-8", "replace"), keep_blank_values=True).items()}
        if "multipart/form-data" in ctype:
            fields, _ = _parse_multipart(content_type, body)
            return fields
    except Exception:
        pass
    # Fallback: try form-encoding anyway (many clients omit the header).
    try:
        return {k: v[0] for k, v in parse_qs(
            body.decode("utf-8", "replace"), keep_blank_values=True).items()}
    except Exception:
        return {}


class _ProxyHandler(BaseHTTPRequestHandler):
    """Single HTTP proxy request handler.

    GET/POST/PUT/PATCH requests are relayed to the origin and the captured
    endpoint is pushed to the capture queue (unless the operator's scope
    excludes it) -- PUT/PATCH bodies (RESTful JSON/multipart mutations) are
    scanned the same way as POST.  CONNECT is tunneled untouched (or MITM'd
    when a CA is configured).  HEAD/OPTIONS/DELETE are relayed but not
    captured.
    """
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    @property
    def proxy(self) -> "PassiveProxy":
        return self.server  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # silence default stderr spam
        _log.debug("proxy %s", fmt % args)

    # -- helpers -----------------------------------------------------------
    _BODY_LIMIT = 2_000_000  # refuse + force-close above this (smuggling-safe)

    def _read_body(self) -> bytes:
        """Read a request body (Content-Length or chunked), capped safely.

        A body larger than _BODY_LIMIT is NOT truncated-and-forwarded: the
        unread remainder would be parsed as the next keep-alive request
        (classic request-smuggling shape).  Instead the connection is marked
        for close and an empty body is returned so the caller sends 413.
        """
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if te == "chunked":
            return self._read_chunked_body()
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > self._BODY_LIMIT:
            self._body_too_large = True
            self.close_connection = True
            return b""
        return self.rfile.read(length)

    def _read_chunked_body(self) -> bytes:
        """Read a Transfer-Encoding: chunked body (RFC 7230 framing)."""
        buf = b""
        while True:
            line = self.rfile.readline(4096)
            if not line:
                break
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                self._body_too_large = True   # malformed framing -> bail
                self.close_connection = True
                break
            if size == 0:
                while True:                    # consume trailers
                    t = self.rfile.readline(4096)
                    if t in (b"\r\n", b"\n", b""):
                        break
                break
            if len(buf) + size > self._BODY_LIMIT:
                self._body_too_large = True
                self.close_connection = True
                break
            chunk = self.rfile.read(size)
            if not chunk:
                break
            buf += chunk
            self.rfile.read(2)                 # trailing CRLF
        return buf

    def _forward_headers(self):
        """Yield (name, value) pairs safe to forward to the origin."""
        for name, value in self.headers.items():
            if name.lower() in _SKIP_FORWARD_HEADERS:
                continue
            yield name, value

    def _relay(self, method: str, capture: bool):
        """Relay one request to the origin; optionally capture the endpoint."""
        target = self.path
        if not target.startswith(("http://", "https://")):
            self.send_error(400, "Absolute-URI required for proxy requests")
            return
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else b""
        if getattr(self, "_body_too_large", False):
            # Phase 74: drain the unread request body BEFORE closing.
            # Closing a socket that still holds unread data sends RST,
            # which can destroy the 413 response before the client reads
            # it (intermittent "connection reset" instead of 413 -- the
            # test-suite flake and a real-client hazard alike).
            try:
                cap = self._BODY_LIMIT + 65536
                drained = 0
                while drained < cap:
                    chunk = self.rfile.read(min(cap - drained, 65536))
                    if not chunk:
                        break
                    drained += len(chunk)
            except Exception:
                pass  # client vanished mid-drain -- nothing to salvage
            self.send_error(413, "request body too large")
            return
        req = self.proxy.requester
        try:
            resp = req.session.request(
                method, target, data=body or None,
                headers=dict(self._forward_headers()) or None,
                allow_redirects=False, timeout=req.timeout,
            )
        except Exception as e:
            _log.debug("relay failed for %s %s: %s", method, target, e)
            self.send_error(502, f"relay failed: {e}")
            return

        if capture:
            try:
                self._capture(method, target,
                              self.headers.get("Content-Type"), body)
            except Exception as e:
                _log.debug("capture failed: %s", e)

        # Phase 67: a page the operator browses LATER may render data that a
        # previously scanned write endpoint stored -- zero-cost token check
        # on the relayed body, no extra requests.
        if method == "GET" and 200 <= resp.status_code < 300 \
                and self.proxy._stored_watch:
            try:
                for token, info in self.proxy.check_stored_tokens(
                        resp.text or ""):
                    self.proxy.note_stored_hit(token, info, target,
                                               resp.text or "")
            except Exception as e:
                _log.debug("stored token check failed: %s", e)

        self.send_response(resp.status_code)
        # Forward a safe subset of origin headers.
        skip_out = _SKIP_FORWARD_HEADERS | {"content-length"}
        # requests transparently DECODES resp.content (plaintext) but keeps
        # the original Content-Encoding header.  Re-forwarding that header
        # with the decoded body makes browsers try to gunzip plaintext ->
        # "incorrect header check" DecodeError on every compressed site.
        ce = resp.headers.get("Content-Encoding", "").lower()
        if ce in ("gzip", "deflate"):
            # requests always decodes these two -> body is plaintext.
            skip_out.add("content-encoding")
        elif ce == "br":
            # brotli is only decoded when the brotli lib is installed; when
            # it is not, resp.content is still raw br bytes and the header
            # MUST stay.  Heuristic: a plaintext body starts with markup.
            if resp.content[:1] in (b"<", b"{", b"["):
                skip_out.add("content-encoding")
        for name, value in resp.headers.items():
            if name.lower() in skip_out:
                continue
            self.send_header(name, value)
        payload = resp.content or b""
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-XSSentinel-Passive", "1")
        self.end_headers()
        self.wfile.write(payload)

    def _capture(self, method: str, url: str, content_type: str | None,
                 body: bytes):
        p = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        data = _parse_body(content_type, body)
        # Phase 56: multipart uploads -- the file part's NAME (not value) is
        # handed to the scanner so the upload-filename XSS probe can target
        # it; non-file parts (CSRF tokens) ride along as ordinary body data.
        file_fields: list[str] = []
        if content_type and "multipart/form-data" in content_type.lower():
            _, file_fields = _parse_multipart(content_type, body)
        if not params and not data and not file_fields:
            return  # nothing to scan
        if not in_scope(url, self.proxy.scope):
            return
        # Carry the request's cookies through to the scan: the scanner
        # re-fetches each endpoint with an independent session, and without
        # the browser's cookies every login-gated page is re-scanned
        # anonymously (silent coverage gap vs xray/w13scan, which replay the
        # authenticated request).
        cookies = _parse_cookie_header(self.headers.get("Cookie")) \
            if self.headers.get("Cookie") else None
        # Phase 61: remember JSON-body endpoints so the drained scan re-sends
        # probes as application/json (form-encoding would be ignored by a
        # JSON API -- the Phase 46 lesson, on the passive side).
        is_json = bool(content_type) and "json" in content_type.lower() \
            and isinstance(data, dict) and bool(data)
        self.proxy.capture(method, url, params, data, cookies,
                           upload_fields=file_fields or None,
                           is_json=is_json)

    # -- methods -----------------------------------------------------------
    def do_GET(self):
        self._relay("GET", capture=True)

    def do_POST(self):
        self._relay("POST", capture=True)

    def do_HEAD(self):
        # HEAD responses carry no body; nothing to capture or scan.
        self._relay("HEAD", capture=False)

    def do_OPTIONS(self):
        # CORS preflights / capability queries must not 501 behind the proxy.
        self._relay("OPTIONS", capture=False)

    def do_PUT(self):
        # RESTful uploads / JSON mutations: body params are worth scanning.
        self._relay("PUT", capture=True)

    def do_PATCH(self):
        self._relay("PATCH", capture=True)

    def do_DELETE(self):
        self._relay("DELETE", capture=False)

    @staticmethod
    def _parse_connect_target(hostport: str) -> tuple[str, int]:
        """Split a CONNECT authority into (host, port).

        Handles 'host:443', 'host' (default 443) and IPv6 literals like
        '[::1]:8443' -- the naive partition(':') breaks on IPv6 (P2 audit).
        """
        hostport = hostport.strip()
        if hostport.startswith("["):               # IPv6 literal
            host, _, rest = hostport[1:].partition("]")
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    pass
            return host, 443
        host, _, port_s = hostport.partition(":")
        try:
            return host, int(port_s or 443)
        except ValueError:
            return host, 443

    def do_CONNECT(self):
        """HTTPS proxy request.

        Blind by default: relay bytes both ways, no inspection.  When the
        proxy was started with --mitm-ca and the target is inside scope the
        connection is instead intercepted (TLS terminated with a per-host
        cert) so the inner HTTP stream flows through the normal relay +
        capture pipeline.
        """
        try:
            host, port = self._parse_connect_target(self.path)
        except Exception as e:
            _log.debug("CONNECT parse failed %s: %s", self.path, e)
            self.send_error(502, f"tunnel failed: {e}")
            return
        if self._should_mitm(host, port):
            self._serve_mitm(host, port)
        else:
            self._blind_tunnel(host, port)

    def _should_mitm(self, host: str, port: int) -> bool:
        """Whether this CONNECT target is intercepted (MITM) or tunneled."""
        mgr = getattr(self.proxy, "mitm", None)
        if mgr is None:
            return False
        # Out-of-scope hosts stay blind: the operator only wants their CA to
        # vouch for the sites they actually declared.
        if not in_scope(f"https://{host}:{port}/", self.proxy.scope):
            return False
        return True

    def _serve_mitm(self, host: str, port: int):
        """Terminate TLS with a per-host leaf cert and serve the inner
        HTTP/1.1 stream through the standard relay + capture pipeline.

        Any failure (missing toolchain, bad CA, handshake rejected) falls
        back to the blind tunnel so a misconfigured interception never
        breaks browsing outright.
        """
        try:
            leaf = self.proxy.mitm.leaf_cert_path(host)
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                sctx.set_alpn_protocols(["http/1.1"])  # inner is HTTP/1.1
            except Exception:
                pass
            sctx.load_cert_chain(leaf)
        except Exception as e:
            _log.debug("MITM setup for %s failed (%s) -> blind tunnel",
                       host, e)
            return self._blind_tunnel(host, port)

        # 200 first on the RAW socket; the client then starts the TLS
        # handshake (identical ordering to a real proxy CONNECT).
        self.send_response(200, "Connection established")
        self.end_headers()
        self.proxy.count_tunnel()
        self.proxy.count_mitm()
        raw = self.connection
        raw.settimeout(self.proxy.tunnel_idle_timeout)
        try:
            tls = sctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError, socket.timeout) as e:
            # Client rejected the cert / never handshook.  Do NOT fall back
            # to blind now: the 200 was already sent and the client is
            # waiting on TLS state.
            _log.debug("MITM handshake with %s failed: %s", host, e)
            self.close_connection = True
            return
        _log.debug("MITM handshake ok for %s", host)

        # Serve inner requests on the decrypted stream.  The browser sends
        # origin-form targets ('GET /x?q=1 HTTP/1.1'), which the relay path
        # requires as absolute URLs -- prefix the CONNECT authority.
        #
        # NOTE: parse_request() consumes self.raw_requestline, which
        # handle_one_request() pre-reads from self.rfile.  Calling
        # parse_request() directly would re-parse the OUTER CONNECT line
        # forever -- the inner loop must read each request line itself.
        self.connection = tls
        self.rfile = tls.makefile("rb", self.rbufsize)
        self.wfile = tls.makefile("wb", self.wbufsize)
        authority = host if port == 443 else f"{host}:{port}"
        self.close_connection = False
        try:
            while not self.close_connection:
                try:
                    self.raw_requestline = self.rfile.readline(65537)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not self.raw_requestline:
                    break                    # client closed the TLS session
                if len(self.raw_requestline) > 65536:
                    break                    # oversized line: give up cleanly
                if not self.parse_request():
                    break
                if self.path.startswith(("http://", "https://")):
                    pass  # nested absolute-form (rare) relays as-is
                else:
                    self.path = f"https://{authority}{self.path}"
                mname = "do_" + self.command
                if self.command == "CONNECT":
                    # A CONNECT *inside* an intercepted session means the
                    # client is chaining another proxy through us -- refuse
                    # instead of recursing into a second TLS termination.
                    self.send_error(502, "Nested CONNECT is not supported")
                    break
                if not hasattr(self, mname):
                    self.send_error(501, f"Unsupported method ({self.command})")
                    break
                try:
                    getattr(self, mname)()
                except (BrokenPipeError, ConnectionError, OSError) as e:
                    _log.debug("MITM inner request failed: %s", e)
                    break
                self.wfile.flush()
        finally:
            self.close_connection = True
            try:
                tls.close()
            except Exception:
                pass

    def _blind_tunnel(self, host: str, port: int):
        """Transparent HTTPS tunnel: relay bytes both ways, no inspection."""
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except Exception as e:
            _log.debug("CONNECT to %s failed: %s", self.path, e)
            self.send_error(502, f"tunnel failed: {e}")
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self.proxy.count_tunnel()
        idle = self.proxy.tunnel_idle_timeout
        try:
            # Bidirectional pump until either side closes.  Idle is NOT a
            # disconnect signal: HTTPS sites multiplex WebSockets / SSE /
            # slow large downloads over the tunnel, and killing it after
            # N seconds of silence breaks them all.  We only exit when
            # recv() returns b"" (peer closed) or raises -- or when the
            # tunnel has had ZERO activity for tunnel_idle_timeout (dead
            # half-open TCP conns are reclaimed so threads don't leak).
            downstream = self.connection
            downstream.settimeout(idle)
            upstream.settimeout(idle)
            last_active = time.time()
            while True:
                r, _, _ = select_pump([downstream, upstream],
                                      min(idle, 5.0))
                now = time.time()
                if not r:
                    if now - last_active > idle:
                        break  # dead tunnel: no activity for idle seconds
                    continue
                for sock in r:
                    data = sock.recv(65536)
                    if not data:
                        return
                    target = upstream if sock is downstream else downstream
                    target.sendall(data)
                last_active = now
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            # Bidirectional cleanup: close the upstream AND tell the handler
            # framework not to keep reading the client connection (a tunnel
            # that ended must not fall back into request parsing).
            self.close_connection = True
            try:
                upstream.close()
            except Exception:
                pass
            try:
                downstream.close()
            except Exception:
                pass


def select_pump(socks, timeout: float = 30.0):
    """select() wrapper so the CONNECT pump doesn't import select eagerly."""
    import select
    return select.select(socks, [], [], timeout)


class PassiveProxy(ThreadingHTTPServer):
    """Threaded HTTP proxy that captures endpoints and feeds the scanner.

    Attributes:
        captures: queue.Queue of (method, url, params, data) tuples.
        seen:     set of endpoint signatures already enqueued.
        scope:    operator-declared capture scope (host / prefix) or None.
        stats:    dict with counters (requests, captures, tunnels, scans).
    """
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int = 8080, host: str = "127.0.0.1",
                 scope: str | None = None,
                 requester: Requester | None = None,
                 tunnel_idle_timeout: float = 600.0,
                 mitm_ca: str | None = None):
        super().__init__((host, port), _ProxyHandler)
        self.scope = scope
        self.requester = requester or Requester(timeout=20)
        # Seconds a CONNECT tunnel may sit idle before its pump is treated
        # as dead.  Long on purpose (default 10 min): HTTPS sites multiplex
        # WebSockets / SSE / slow downloads whose gaps easily exceed 30 s.
        self.tunnel_idle_timeout = tunnel_idle_timeout
        # HTTPS interception (Phase 50): a MitmManager when the operator
        # passed --mitm-ca, else None (blind CONNECT tunnels, as before).
        self.mitm = None
        if mitm_ca:
            try:
                from .mitm_ca import MitmManager
                self.mitm = MitmManager(mitm_ca)
                _log.info("HTTPS interception enabled (CA: %s)", mitm_ca)
            except Exception as e:
                # Missing cryptography / unwritable CA dir, ... -- degrade to
                # blind tunneling instead of refusing to start.
                _log.warning("MITM disabled (%s); HTTPS stays blind-tunneled",
                             e)
                self.mitm = None
        self.captures: queue.Queue = queue.Queue()
        self._seen: set[str] = set()
        self._seen_lock = threading.Lock()
        # Phase 56: endpoint signature -> multipart file-field names, so the
        # drain worker can run the upload-filename probe on real uploads.
        self._file_fields: dict[str, list[str]] = {}
        # Phase 61: endpoint signatures that carried a JSON request body.
        self._json_sigs: set[str] = set()
        # Phase 67: passive stored/second-order watch -- tokens injected at
        # captured write endpoints, and hits seen in later browsed pages.
        self._stored_watch: dict[str, dict] = {}
        self._stored_hits: list[dict] = []
        self._stats_lock = threading.Lock()   # stats are shared across the
        # ThreadingHTTPServer handler threads + the drain worker; a plain
        # `+=` on a dict value is not atomic under the GIL release window.
        self.stats = {
            "requests": 0,
            "captures": 0,
            "tunnels": 0,
            "mitm": 0,
            "scans": 0,
            "skipped_dup": 0,
            "started": time.time(),
        }

    # -- capture API -------------------------------------------------------
    def capture(self, method: str, url: str, params: dict, data: dict,
                cookies: dict | None = None,
                upload_fields: list[str] | None = None,
                is_json: bool = False):
        with self._stats_lock:
            self.stats["requests"] += 1
        sig = endpoint_signature(method, url, params, data)
        with self._seen_lock:
            if sig in self._seen:
                with self._stats_lock:
                    self.stats["skipped_dup"] += 1
                return
            self._seen.add(sig)
            if upload_fields:
                # Phase 56: remember which multipart file fields this
                # endpoint carries so the drain worker can hand them to the
                # upload-filename XSS probe (the probe is multipart-specific
                # and needs the real file field name).
                self._file_fields[sig] = list(upload_fields)
            if is_json:
                # Phase 61: remember JSON-body endpoints for json-carrier
                # re-probing during the scan.
                self._json_sigs.add(sig)
        self.captures.put((method, url, params, data, cookies))
        with self._stats_lock:
            self.stats["captures"] += 1

    def take_upload_fields(self, method: str, url: str, params: dict,
                           data: dict) -> list[str]:
        """Return (and forget) the multipart file-field names captured for
        this endpoint signature.  Empty when the capture was not a file
        upload."""
        sig = endpoint_signature(method, url, params, data)
        with self._seen_lock:
            return self._file_fields.pop(sig, None) or []

    def take_json_flag(self, method: str, url: str, params: dict,
                       data: dict) -> bool:
        """Whether this captured endpoint carried a JSON body (and forget
        the marker)."""
        sig = endpoint_signature(method, url, params, data)
        with self._seen_lock:
            if sig in self._json_sigs:
                self._json_sigs.discard(sig)
                return True
            return False

    # -- Phase 67: passive stored/second-order watch -----------------------
    def arm_stored_watch(self, token: str, info: dict) -> None:
        """Record a second-order probe token injected at a captured write
        endpoint (bounded FIFO -- the newest write endpoints matter most)."""
        with self._seen_lock:
            if len(self._stored_watch) >= 5:
                oldest = next(iter(self._stored_watch))
                self._stored_watch.pop(oldest, None)
            self._stored_watch[token] = info

    def check_stored_tokens(self, text: str) -> list:
        """Return (and forget) every watched token present in ``text``."""
        with self._seen_lock:
            hits = [(tok, info) for tok, info in self._stored_watch.items()
                    if tok and tok in text]
            for tok, _ in hits:
                self._stored_watch.pop(tok, None)
        return hits

    def note_stored_hit(self, token: str, info: dict, viewer_url: str,
                        text: str) -> None:
        """Queue a token hit seen in a relayed page for drain-side
        verification (bounded)."""
        with self._stats_lock:
            if len(self._stored_hits) >= 10:
                self._stored_hits.pop(0)
            self._stored_hits.append({
                "token": token, "info": dict(info),
                "viewer_url": viewer_url,
                "text": text[:200000],
            })

    def take_stored_hits(self) -> list:
        with self._stats_lock:
            hits, self._stored_hits = self._stored_hits, []
        return hits

    def count_tunnel(self):
        with self._stats_lock:
            self.stats["tunnels"] += 1

    def count_mitm(self):
        """Increment the intercepted (MITM) connection counter."""
        with self._stats_lock:
            self.stats["mitm"] += 1

    def note_scan(self):
        """Increment the completed-scans counter (thread-safe)."""
        with self._stats_lock:
            self.stats["scans"] += 1

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "PassiveProxy":
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        mitm = "https-mitm" if self.mitm is not None else "https-blind"
        _log.info("passive proxy listening on %s:%s (scope=%s, %s)",
                  self.server_address[0], self.server_address[1],
                  self.scope or "*", mitm)
        return self

    def stop(self):
        self.shutdown()
        self.server_close()

    @property
    def port(self) -> int:
        return self.server_address[1]


# ---------------------------------------------------------------------------
# Background scan worker: drains captured endpoints and runs the pipeline.
# ---------------------------------------------------------------------------

def drain_captures(proxy: PassiveProxy, scanner, idle_flush: float = 1.0,
                   stop_event: threading.Event | None = None,
                   on_scan=None) -> None:
    """Consume captured endpoints and run them through ``scanner``.

    ``scanner`` may be a Scanner-like object exposing scan_endpoint(url,
    method, params, data) and .findings; or a plain callable
    scan(method, url, params, data) -- see _run_capture.  Keeps going until
    stop_event is set (poll every idle_flush seconds when the queue is
    empty, so a long-running proxy keeps draining as traffic arrives).
    """
    stop = stop_event or threading.Event()
    while not stop.is_set():
        try:
            item = proxy.captures.get(timeout=idle_flush)
        except queue.Empty:
            continue
        # Phase 67: verify queued stored-token hits from relayed pages.
        _verify_stored_hits(proxy, scanner)

        method, url, params, data, cookies = item
        # Phase 56: a captured multipart upload carries file-field names;
        # hand them to the scanner's upload probe for the lifetime of THIS
        # endpoint's scan, then take them back (the list is per-scan CLI
        # state, not per-endpoint).
        added_fields: list[str] = []
        if hasattr(scanner, "upload_fields") \
                and isinstance(getattr(scanner, "upload_fields", None), list):
            extra = proxy.take_upload_fields(method, url, params, data)
            for uf in extra:
                if uf not in scanner.upload_fields:
                    scanner.upload_fields.append(uf)
                    added_fields.append(uf)
        # Phase 61: JSON-body endpoints are re-probed as application/json
        # (the parsed body becomes the document); restore afterwards.
        saved_json = None
        had_json = False
        if hasattr(scanner, "json_body") and data \
                and proxy.take_json_flag(method, url, params, data):
            saved_json = scanner.json_body
            scanner.json_body = dict(data)
            had_json = True
        try:
            _run_capture(scanner, method, url, params, data, cookies,
                         proxy=proxy)
            proxy.note_scan()
            if on_scan:
                try:
                    on_scan(method, url, params, data)
                except Exception:
                    pass
        except Exception as e:
            _log.warning("scan failed for %s %s: %s", method, url, e)
        finally:
            if had_json:
                scanner.json_body = saved_json
            if added_fields:
                for uf in added_fields:
                    try:
                        scanner.upload_fields.remove(uf)
                    except ValueError:
                        pass


def _verify_stored_hits(proxy, scanner) -> None:
    """Phase 67: turn queued stored-token hits into confirmed findings.

    Only tokens that come back UNESCAPED in an executable context are
    reported (mirror of second_order.check_viewers semantics); everything
    else is dropped silently -- a stored probe that never executes must not
    become a finding.
    """
    for hit in proxy.take_stored_hits():
        try:
            from . import verifier as _vf
            from .second_order import _snippet
            info = hit["info"]
            v = _vf.verify_semantic(
                hit["text"], hit["token"],
                response_headers=hit.get("headers") or {})
            if not v.get("confirmed"):
                continue
            if hasattr(scanner, "_add"):
                from .findings import Finding, _grade_evidence
                # verify_semantic on the captured viewer response: the token
                # reached an executable context.  Nobody ran a browser over it,
                # so the old "executed at" wording claimed an observation the
                # passive path cannot make.
                _cls, _conf, _det = _grade_evidence(None, "high", (
                    f"payload injected at {info['inject_url']} "
                    f"({info['inject_method']} "
                    f"{info['inject_param']}) rendered in an executable "
                    f"context at {hit['viewer_url']} ({v.get('detail')})"))
                scanner._add(Finding(
                    url=info["inject_url"],
                    method=info["inject_method"],
                    param=info["inject_param"],
                    type="second_order", context=v.get("context"),
                    payload=info["payload"], transform=[],
                    severity="high", confidence=_conf,
                    detail=_det,
                    evidence_class=_cls,
                    headless=None,
                    proof={"viewer_url": hit["viewer_url"],
                           "token": hit["token"],
                           "snippet": _snippet(hit["text"], hit["token"])},
                ))
        except Exception as e:
            _log.debug("stored hit verification failed: %s", e)


def _run_capture(scanner, method: str, url: str, params: dict, data: dict,
                 cookies: dict | None = None, proxy=None):
    """Dispatch one captured endpoint to the scanner.

    The captured ``url`` may still carry its original query string; strip it
    before dispatch because the query params are already in ``params`` --
    otherwise the scanner injects payloads as *appended* same-name params
    (``?q=orig&q=payload``) and origins that read the first value never see
    the payload (silent zero-finding bug).

    ``cookies`` (captured from the browser request's Cookie header) are
    injected into a clone of the scanner's requester so login-gated pages
    are scanned WITH the authenticated session, not anonymously.  When
    cookies are absent the dispatch is byte-for-byte identical to before
    (no ``req`` kwarg -> scanner defaults to its own requester).
    """
    p = urlparse(url)
    clean_url = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    req_override = None
    if cookies:
        base = getattr(scanner, "req", None)
        if base is None:
            base = getattr(scanner, "requester", None)
        if base is not None and hasattr(base, "clone"):
            try:
                req_override = base.clone()
                for k, v in cookies.items():
                    req_override.session.cookies.set(k, v)
            except Exception:
                req_override = None
    scan = getattr(scanner, "scan_endpoint", None)
    if scan is None:
        # Plain callable: scan(method, url, params, data)
        scanner(method, clean_url, params, data)
        return
    kw = {"req": req_override} if req_override is not None else {}
    # Phase 57/60: dispatch on the METHOD, not on whether a body was seen.
    # A multipart upload with only a file part parses to EMPTY non-file
    # fields -- routing it through the GET branch would re-scan the upload
    # endpoint as a query GET and never reach the upload probe.
    if method in ("POST", "PUT", "PATCH"):
        scan(clean_url, method=method, params=params or {}, data=data or {},
             **kw)
    else:
        scan(clean_url, method="GET", params=params, data={}, **kw)

    # Phase 67: arm a second-order probe on body params of write endpoints.
    # The token is checked later, zero-cost, against every page the operator
    # browses; a hit is verified and reported by the drain loop.
    if proxy is not None and method in ("POST", "PUT", "PATCH") and data \
            and hasattr(scanner, "_add"):
        try:
            from .second_order import (_SECOND_ORDER_SHAPES, inject_payload)
            req2 = req_override or getattr(scanner, "req", None)
            if req2 is not None:
                for param in list(data)[:3]:
                    token = "xsso_" + secrets.token_hex(4)
                    for shape in _SECOND_ORDER_SHAPES:
                        payload = shape.format(t=token)
                        if inject_payload(req2, clean_url, method, param,
                                          payload):
                            proxy.arm_stored_watch(token, {
                                "inject_url": clean_url,
                                "inject_method": method,
                                "inject_param": param,
                                "payload": payload,
                            })
                            if hasattr(scanner, "requests_made"):
                                scanner.requests_made += 1
                            break
        except Exception as e:
            _log.debug("stored watch arm failed for %s: %s", clean_url, e)

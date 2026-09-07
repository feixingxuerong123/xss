"""Demo: XSSentinel passive proxy scanning (Phase 44) end-to-end.

Starts a tiny origin, points the built-in PassiveProxy at it, replays a few
browser-style requests through the proxy (raw-socket absolute-URI, exactly
like a browser would), and lets the background worker scan the captured
endpoints with the REAL Scanner pipeline.  Prints capture/scan/finding
stats and writes an HTML report.

Self-test only -- the target is the bundled in-process origin.

Run:  python tests/passive_demo.py
"""
from __future__ import annotations

import html
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.passive_proxy import PassiveProxy, drain_captures
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner


# ---------------------------------------------------------------------------
# In-process origin: one reflected-XSS endpoint + one safe (html.escape) one.
# ---------------------------------------------------------------------------
class _OriginHandler(BaseHTTPRequestHandler):
    def _render(self, body: str):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        if path == "/echo":          # reflected unsafely -> XSS
            self._render(f"<h1>hello {q}</h1>")
        elif path == "/safe":        # escaped -> must NOT be reported
            self._render(f"<h1>hello {html.escape(q)}</h1>")
        else:
            self._render("<h1>not found</h1>")

    def log_message(self, *a):       # silence
        pass


class _Origin:
    def __init__(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def raw_proxy_get(proxy_port: int, target_url: str) -> str:
    """Absolute-URI GET through the proxy (mimics a browser)."""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    s.settimeout(10)
    try:
        s.sendall(
            f"GET {target_url} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break  # headers+body already delivered; connection kept open
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                head, _, body = buf.partition(b"\r\n\r\n")
                clen = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        clen = int(line.split(b":", 1)[1].strip())
                        break
                if clen and len(body) >= clen:
                    break
    finally:
        s.close()
    return buf.decode("utf-8", "replace")


def main() -> int:
    origin = _Origin()
    proxy = PassiveProxy(port=0, host="127.0.0.1", scope="127.0.0.1",
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
    print(f"[*] origin     : {origin.base}")
    print(f"[*] proxy      : http://127.0.0.1:{proxy.port}")

    # --- replay browser traffic through the proxy -------------------------
    r1 = raw_proxy_get(proxy.port, f"{origin.base}/echo?q=hello")
    print(f"[*] GET /echo?q=hello        -> {r1.splitlines()[0]}")
    r2 = raw_proxy_get(proxy.port, f"{origin.base}/echo?q=world")   # dup sig
    print(f"[*] GET /echo?q=world (dup)  -> {r2.splitlines()[0]}")
    r3 = raw_proxy_get(proxy.port, f"{origin.base}/safe?q=<b>x</b>")
    print(f"[*] GET /safe?q=<b>x</b>      -> {r3.splitlines()[0]}")

    # --- wait for the background worker to finish scanning ----------------
    deadline = time.time() + 120
    while time.time() < deadline:
        if proxy.stats["scans"] >= proxy.stats["captures"] and \
                proxy.captures.empty():
            time.sleep(2)  # drain worker may still be finishing last scan
            break
        time.sleep(1)
    time.sleep(3)

    print("\n[+] capture stats:", {k: v for k, v in proxy.stats.items()
                                   if k != "started"})
    print(f"[+] endpoints captured : {proxy.stats['captures']} "
          f"(dup-skipped: {proxy.stats['skipped_dup']})")
    print(f"[+] scans run          : {proxy.stats['scans']}")
    print(f"[+] findings           : {len(scanner.findings)}")
    for f in scanner.findings:
        print(f"    - [{f.data.get('type')}] {f.data.get('url')} "
              f"param={f.data.get('param')} context={f.data.get('context')} "
              f"severity={f.data.get('severity')}")

    # --- write a report ----------------------------------------------------
    from xssentinel.cli_runner import _write_report
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "passive_demo_report.html")
    _write_report(scanner, f"passive://127.0.0.1:{origin.port}", out,
                  "html", meta={"passive": True, "stats": proxy.stats})
    print(f"[+] report: {out}")

    proxy.stop()
    stop.set()
    origin.stop()

    # --- self-check ---------------------------------------------------------
    ok = True
    if proxy.stats["captures"] < 2:      # /echo captured, /safe captured
        print("!! expected >=2 unique endpoints captured"); ok = False
    if proxy.stats["skipped_dup"] < 1:   # /echo?q=world de-duped
        print("!! expected dup-skip for /echo?q=world"); ok = False
    xss = [f for f in scanner.findings if f.data.get("type") == "reflected"
           and "echo" in f.data.get("url", "")]
    safe = [f for f in scanner.findings if "safe" in f.data.get("url", "")]
    if not xss:
        print("!! expected reflected XSS finding on /echo"); ok = False
    if safe:
        print(f"!! zero-误报 FAIL: {len(safe)} finding(s) on /safe"); ok = False
    print(f"\n[{'PASS' if ok else 'FAIL'}] passive demo self-check")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

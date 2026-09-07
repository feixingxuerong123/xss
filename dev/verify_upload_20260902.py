"""Phase 48 end-to-end: multipart filename XSS probe against a REAL HTTP
server (threaded http.server -- requests is sync, so no aiohttp needed).

The server parses the multipart body it receives, extracts the uploaded
filename, and reflects it RAW into HTML (a vulnerable upload summary page).
Also serves the "stored" file at /uploads/<name> with the name raw.

Exit 0 = probe confirmed upload_xss over the wire.
"""
from __future__ import annotations
import http.server
import os
import re
import sys
import threading
from urllib.parse import unquote, urlparse

sys.path.insert(0, r"D:\qoder\xssentinel")

# The dev sandbox exports HTTP_PROXY/HTTPS_PROXY for general egress; when a
# requests.Session honours it the proxy sends ABSOLUTE-form request-targets
# (POST http://127.0.0.1:<port>/up) and a naive self.path == "/up" check in
# the fixture breaks.  Loopback must never be proxied here -- keep the e2e
# hermetic (the Handler also tolerates absolute-form via urlparse anyway).
os.environ["NO_PROXY"] = "127.0.0.1,localhost"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def do_POST(self):
        body = self._read_body()
        ct = self.headers.get("Content-Type", "")
        m = re.search(r'name="[^"]*"\s*;\s*filename="([^"]*)"', body.decode("latin1"))
        name = m.group(1) if m else ""
        # urlparse: tolerate absolute-form request-targets (proxy egress).
        if urlparse(self.path).path == "/up":
            html = (f"<html><body>saved {name} "
                    f'<a href="/uploads/{name}">here</a></body></html>')
            data = html.encode("utf-8")
        else:
            data = b"<html><body>unknown</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/uploads/"):
            name = unquote(path[len("/uploads/"):])
            data = f"<html><body><div>{name}</div></body></html>".encode()
        else:
            data = b"<html><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    from xssentinel.core.requester import Requester
    from xssentinel.core import upload_probe

    try:
        req = Requester(timeout=8)
        # Raw multipart sanity: what does requests actually send?
        probe_req = req.request("POST", f"http://127.0.0.1:{port}/up",
                                files={"file": ("probeA.txt", b"hi", "text/plain")})
        assert "probeA.txt" in (probe_req.text or ""), \
            f"multipart filename lost on the wire: {probe_req.text[:120]!r}"
        print("[1] multipart filename round-trips through requests")

        found = upload_probe.probe_upload(
            req, f"http://127.0.0.1:{port}/up", "file")
        types = [f.data["type"] for f in found]
        print(f"[2] findings: {types}")
        ok = any(t == "upload_xss" for t in types)
        print(f"[{'PASS' if ok else 'FAIL'}] live filename reflection "
              f"confirmed as upload_xss")
        return 0 if ok else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())

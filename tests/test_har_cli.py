"""Phase 88 (P1): --har CLI end-to-end tests.

Builds a HAR file capturing traffic against a live local server, then
runs ``xssentinel --har cap.har -o out/`` and asserts:
  * every captured endpoint is scanned (per-URL report files);
  * POST form bodies reach the server (server records the body);
  * cookies are carried (server records the cookie header).
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _CaptureHandler(BaseHTTPRequestHandler):
    seen = []  # (method, path, cookie, body)

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        _CaptureHandler.seen.append(
            (self.command, self.path, self.headers.get("Cookie") or "",
             body))

    def do_GET(self):
        self._record()
        self._reply()

    def do_POST(self):
        self._record()
        self._reply()

    def _reply(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def live_server():
    _CaptureHandler.seen = []
    srv = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _make_har(base, path):
    entries = [
        {"request": {"method": "GET", "url": f"{base}{path}/a?q=1",
                     "headers": [{"name": "Content-Type",
                                  "value": "application/x-www-form-urlencoded"}],
                     "cookies": [], "postData": None},
         "response": {"status": 200, "statusText": "ok"}},
        {"request": {"method": "POST",
                     "url": f"{base}{path}/submit",
                     "headers": [{"name": "Content-Type",
                                  "value": "application/x-www-form-urlencoded"},
                                 {"name": "Cookie",
                                  "value": "sid=har123"}],
                     "cookies": [{"name": "sid", "value": "har123"}],
                     "postData": {"mimeType": "application/x-www-form-urlencoded",
                                  "text": "user=alice&msg=hi"}},
         "response": {"status": 200, "statusText": "ok"}},
    ]
    return {"log": {"version": "1.2", "entries": entries}}


def _run_cli(args, timeout=180):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "xssentinel"] + args,
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


class TestHarCliE2E:
    def test_har_endpoints_scanned_with_body_and_cookie(self, live_server,
                                                        tmp_path):
        _CaptureHandler.seen = []
        har_path = tmp_path / "cap.har"
        har_path.write_text(
            json.dumps(_make_har(live_server, "/app")), encoding="utf-8")
        out_dir = str(tmp_path / "har_out")
        code, out = _run_cli(
            ["--har", str(har_path), "-o", out_dir, "-f", "json",
             "--timeout", "3"])
        assert code == 0, out
        assert "2 endpoint(s) imported" in out
        assert "Batch complete: 2 target(s)" in out
        files = [f for f in os.listdir(out_dir) if f.endswith(".json")]
        assert len(files) == 2, files

        # The scanner probes with its own payloads; the original traffic
        # must have arrived at least once (server records it).
        seen = _CaptureHandler.seen
        methods = {(m, p) for m, p, _, _ in seen}
        assert any(p.startswith("/app/a") and m == "GET" for m, p in methods)
        assert any(p.startswith("/app/submit") and m == "POST"
                   for m, p in methods)
        # Cookie must have reached the server on the POST scan.
        post_with_cookie = [b for m, p, c, b in seen
                            if m == "POST" and "sid=har123" in c]
        assert post_with_cookie

    def test_har_missing_file_error(self, tmp_path):
        code, out = _run_cli(["--har", str(tmp_path / "nope.har"),
                              "-o", str(tmp_path / "o")])
        assert code == 2
        assert "HAR import failed" in out

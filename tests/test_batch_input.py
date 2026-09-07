"""Phase 88: batch-input pipeline tests.

Covers the P0 "scalable input" work:
  * cli_runner.load_target_urls() -- pure loader: --batch FILE, stdin
    pipe, comments/blank stripping, duplicate suppression, error paths.
  * End-to-end --batch-stdin via a live local HTTP server (fast, no
    refused-port retry stalls).
"""
import io
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# Unit tests for the pure loader
# --------------------------------------------------------------------------

def _load(batch_file=None, batch_stdin=False, url=None, stdin_text=None):
    from xssentinel.cli_runner import load_target_urls
    src = io.StringIO(stdin_text or "")
    # A StringIO is not a TTY, matching piped stdin.
    return load_target_urls(batch_file=batch_file, batch_stdin=batch_stdin,
                            url=url, stdin=src)


class TestLoadTargetUrls:
    def test_url_single(self):
        urls, err = _load(url="http://h/a")
        assert err is None and urls == ["http://h/a"]

    def test_stdin_basic(self):
        urls, err = _load(batch_stdin=True,
                          stdin_text="http://h/a\nhttp://h/b\n")
        assert err is None
        assert urls == ["http://h/a", "http://h/b"]

    def test_stdin_comments_and_blanks(self):
        urls, err = _load(
            batch_stdin=True,
            stdin_text="# c1\n\nhttp://h/a\n   \nhttp://h/b\n# c2\n")
        assert err is None and urls == ["http://h/a", "http://h/b"]

    def test_stdin_empty(self):
        urls, err = _load(batch_stdin=True, stdin_text="")
        assert urls == [] and err == "No URLs read from stdin"

    def test_stdin_dedup_exact(self):
        urls, err = _load(batch_stdin=True,
                          stdin_text="http://h/a\nhttp://h/a\nhttp://h/b\n")
        assert err is None and urls == ["http://h/a", "http://h/b"]

    def test_stdin_dedup_keeps_query_variants(self):
        urls, err = _load(
            batch_stdin=True,
            stdin_text="http://h/a?x=1\nhttp://h/a?x=2\nhttp://h/a\n")
        assert err is None
        assert urls == ["http://h/a?x=1", "http://h/a?x=2", "http://h/a"]

    def test_stdin_dedup_trailing_slash(self):
        # http://h/a and http://h/a/ are different paths -> both kept
        urls, err = _load(batch_stdin=True,
                          stdin_text="http://h/a\nhttp://h/a/\n")
        assert err is None and urls == ["http://h/a", "http://h/a/"]

    def test_batch_file_loading(self, tmp_path):
        f = tmp_path / "u.txt"
        f.write_text("# h\nhttp://h/x\nhttp://h/x\nhttp://h/y\n",
                     encoding="utf-8")
        urls, err = _load(batch_file=str(f))
        assert err is None and urls == ["http://h/x", "http://h/y"]

    def test_batch_file_missing(self):
        urls, err = _load(batch_file="Z:/no/such/file.txt")
        assert urls == [] and "not found" in err

    def test_mutual_exclusion(self):
        urls, err = _load(batch_file="x", batch_stdin=True)
        assert urls == [] and "mutually exclusive" in err

    def test_no_target(self):
        urls, err = _load()
        assert urls == [] and err is None


# --------------------------------------------------------------------------
# End-to-end: --batch-stdin with a live local server
# --------------------------------------------------------------------------

class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def live_server():
    srv = HTTPServer(("127.0.0.1", 0), _QuietHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def _run_cli(args, stdin_text=None, timeout=120):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "xssentinel"] + args,
        cwd=ROOT, env=env, input=stdin_text,
        capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


class TestBatchStdinE2E:
    def test_stdin_pipeline_scans_once_per_unique_url(self, live_server,
                                                     tmp_path):
        out_dir = str(tmp_path / "out")
        payload = (f"{live_server}/a\n{live_server}/a\n"
                   f"# comment\n{live_server}/b\n")
        code, out = _run_cli(
            ["--batch-stdin", "-o", out_dir, "-f", "json",
             "--timeout", "5"],
            stdin_text=payload)
        assert code == 0, out
        assert "Batch complete: 2 target(s)" in out
        files = [f for f in os.listdir(out_dir) if f.endswith(".json")]
        assert len(files) == 2, files

    def test_batch_file_e2e(self, live_server, tmp_path):
        urls_f = tmp_path / "urls.txt"
        urls_f.write_text(f"{live_server}/x\n{live_server}/y\n",
                          encoding="utf-8")
        out_dir = str(tmp_path / "out2")
        code, out = _run_cli(
            ["--batch", str(urls_f), "-o", out_dir, "-f", "json",
             "--timeout", "5"])
        assert code == 0, out
        assert "Batch complete: 2 target(s)" in out
        files = [f for f in os.listdir(out_dir) if f.endswith(".json")]
        assert len(files) == 2, files

    def test_single_url_unchanged(self, live_server, tmp_path):
        code, out = _run_cli(
            ["-u", f"{live_server}/single", "-f", "json", "-o",
             str(tmp_path / "single.json"), "--timeout", "5"])
        assert code == 0, out
        assert "finding(s)" in out

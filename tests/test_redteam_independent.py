"""Phase 176g: an independent target, kept as a standing regression.

Why this file exists.  The benchmark (benchmark/server.py + manifest.json +
runner.py) is a closed loop: the targets, the ground truth and the scorer are
all written by the same project, so it can only ever report on the shapes its
author thought of -- and it has no case whose whole point is "a scary keyword
is present and nothing is wrong".  A 50/50 layer matrix measures whether each
layer CAN fire, not whether the branches inside it ever ran.

So this lab is deliberately shaped unlike benchmark/server.py:

    benchmark uses          this lab uses
    ------------------      -----------------------------
    param `q`               params term / note / id
    paths /r/xxx01          paths /api/*
    always 200              mixed status + content type
    no auth surface         a Bearer-gated endpoint

and it carries DECOYS -- endpoints that must produce ZERO findings.  It found
its first real gap on the day it was written (no case had ever returned a real
`Content-Type: application/json`, so scanner.py's Phase 32 content-type branch
had never executed).  Keeping it as a test is what stops that from drifting
back.

The lab lives inside this file because that is the house convention for a test
target -- see test_param_miner_target.py and test_second_order_target.py.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PORT = 18991

HIGH_MED = ("high", "medium", "critical")

_STORE: list = []

SCARY = """<!doctype html><html><head><title>About</title></head><body>
<h1>About our stack</h1>
<p>MySQL 8.0, PostgreSQL 15 and SQLite in places. Log lines like
"syntax error near SELECT" and "Unclosed quotation mark after the character
string" do show up.</p>
<pre>&lt;script&gt;alert('documentation example')&lt;/script&gt;</pre>
<p>Example injection: ' OR 1=1 -- and &lt;img src=x onerror=alert(1)&gt;</p>
</body></html>"""

DOM_PAGE = """<!doctype html><html><body><div id="out"></div>
<script>
var h = decodeURIComponent((location.hash || '').slice(1));
document.getElementById('out').innerHTML = h;
</script></body></html>"""


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#x27;"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _send(self, status, ctype, body):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, body, status=200):
        self._send(status, "text/html; charset=utf-8", body)

    def _json(self, text):
        self._send(200, "application/json; charset=utf-8", text)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        path = u.path.rstrip("/") or "/"

        # ---- positives ------------------------------------------------
        if path == "/api/search":
            return self._html(f"<h2>Results</h2><div>Found: "
                              f"{q.get('term','none')}</div>")
        if path.startswith("/api/u/") and path.count("/") == 3:
            return self._html(f"<h2>Profile</h2><p>User "
                              f"{unquote(path.split('/')[3])}</p>")
        if path == "/api/reflect":
            return self._html(f"<p>Referrer was "
                              f"{self.headers.get('Referer') or 'none'}</p>")
        if path == "/api/cookie":
            return self._html(f"<p>Your preference: "
                              f"{self.headers.get('Cookie') or 'none'}</p>")
        if path == "/api/dom":
            return self._html(DOM_PAGE)
        if path == "/api/tpl":
            return self._html(f"<div id='app'>Hello "
                              f"{q.get('term','none')}</div>")
        if path == "/api/double":
            return self._html(f"<p>Decoded: "
                              f"{unquote(unquote(q.get('term','')))}</p>")
        if path == "/api/store/feed":
            return self._html("<ul>" + "".join(f"<li>{e}</li>"
                                               for e in _STORE) + "</ul>")

        # ---- decoys ---------------------------------------------------
        if path == "/static/about":
            return self._html(SCARY)
        if path == "/api/echo-json":
            msg = q.get("msg", "none").replace('"', '\\"')
            return self._json('{"ok": true, "echo": "%s"}' % msg)
        if path == "/api/safe":
            return self._html(f"<h2>Results</h2><div>Found: "
                              f"{_esc(q.get('term','none'))}</div>")
        if path == "/api/attr":
            # Inside a double-quoted attribute, quotes escaped, angle brackets
            # NOT -- which is still safe: brackets do not break the context out.
            v = q.get("term", "none").replace('"', "&quot;")
            return self._html(f'<input type="text" value="{v}">')
        if path == "/api/public/item":
            return self._html('{"ok": true, "item": {"id": 1, '
                              '"name": "widget"}}')
        if path.startswith("/api/private"):
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer "):
                return self._send(401, "application/json; charset=utf-8",
                                  '{"error": "unauthorized"}')
            return self._json('{"ok": true, "secret": "x"}')

        return self._html("<h1>Not Found</h1>", 404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""

        if path == "/api/post":
            f = {k: v[0] for k, v in parse_qs(raw).items()}
            return self._html(f"<p>Saved note: {f.get('body','none')}</p>")
        if path == "/api/store":
            try:
                f = json.loads(raw) if raw.strip().startswith("{") \
                    else {k: v[0] for k, v in parse_qs(raw).items()}
            except Exception:
                f = {}
            _STORE.append(unquote(str(f.get("note", ""))))
            return self._json('{"ok": true}')
        return self._html("<h1>Not Found</h1>", 404)

    def log_message(self, *a):
        pass


def _scan(base: str, path: str, extra: tuple = (),
          min_severity: tuple = HIGH_MED) -> list[dict]:
    """Run the real CLI against one endpoint and return its findings."""
    fd, out = tempfile.mkstemp(suffix=".json", prefix="redteam_")
    os.close(fd)
    try:
        subprocess.run(
            [sys.executable, "-m", "xssentinel", "-u", f"{base}{path}",
             "-f", "json", "-o", out, "--progress", "none",
             "--log-level", "error", *extra],
            cwd=str(ROOT), timeout=240,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            findings = json.load(open(out, encoding="utf-8")).get("findings", [])
            if min_severity is None:
                return findings
            return [f for f in findings
                    if f.get("severity") in min_severity]
        except Exception:
            return []
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


class TestIndependentTarget(unittest.TestCase):
    """Recall on shapes the benchmark never sees, and silence on decoys."""

    base = None

    @classmethod
    def setUpClass(cls):
        # This host's security software intermittently refuses specific
        # loopback ports (WinError 10013) -- probe candidates, trust a
        # port only after the fixture answers (Phase 176s lesson).
        last_err = None
        for port in (PORT, PORT + 1, PORT + 2, PORT + 7):
            try:
                srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            except OSError as e:
                last_err = e
                continue
            cls._srv = srv
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            time.sleep(0.8)
            cls.base = f"http://127.0.0.1:{port}"
            break
        else:
            raise last_err

    @classmethod
    def tearDownClass(cls):
        try:
            cls._srv.shutdown()
        except Exception:
            pass

    # -- positives: a scanner must find these ---------------------------
    #
    # Recall alone is not acceptance: `assertTrue(got)` once passed on a
    # run whose only finding was a low-confidence polyglot note.  Each
    # positive now also names the finding TYPE that legitimately confirms
    # that shape (sets, not single values: several layers may honestly
    # claim the same reflection) plus high severity + confidence -- the
    # signature of a confirmed finding rather than a noted one.

    _TYPES = {
        "query": {"reflected"},
        "path": {"path_xss"},
        "header": {"header_xss"},
        "cookie": {"header_xss", "cookie_xss"},
        "dom": {"dom_dynamic", "trusted_types_taint_flow"},
        "template": {"reflected"},
        "double": {"reflected"},
        "post": {"reflected"},
        "stored": {"stored", "second_order"},
    }

    def _confirmed(self, got, shape):
        types = self._TYPES[shape]
        hits = [f for f in got
                if f.get("type") in types
                and f.get("severity") == "high"
                and f.get("confidence") == "high"]
        self.assertTrue(
            hits,
            f"{shape}: no confirmed {sorted(types)} finding -- got "
            f"{[(f.get('type'), f.get('severity'), f.get('confidence')) for f in got]}")
        return hits

    def test_query_reflection(self):
        self._confirmed(_scan(self.base, "/api/search?term=probe"), "query")

    def test_path_segment_reflection(self):
        self._confirmed(_scan(self.base, "/api/u/alice"), "path")

    def test_header_reflection(self):
        self._confirmed(_scan(self.base, "/api/reflect"), "header")

    def test_cookie_reflection(self):
        self._confirmed(_scan(self.base, "/api/cookie"), "cookie")

    def test_dom_reflection(self):
        self._confirmed(_scan(self.base, "/api/dom"), "dom")

    def test_template_syntax(self):
        self._confirmed(_scan(self.base, "/api/tpl?term=probe"), "template")

    def test_double_url_encoding(self):
        self._confirmed(_scan(self.base, "/api/double?term=probe"), "double")

    def test_post_body_reflection(self):
        got = _scan(self.base, "/api/post", ("-m", "POST", "-d", "body=probe"))
        self._confirmed(got, "post")

    def test_stored(self):
        """Stored XSS needs the write and the render endpoint named.

        The scanner cannot discover which endpoint writes and which renders
        (that is a fact about the app, not a defect in the scanner), so the
        flags are the test's job.  --stored-param defaults to `q` and this
        target uses `note`, so leaving it out writes into the wrong field and
        nothing is ever persisted -- a false "miss" that looks like a bug in
        the engine.
        """
        got = _scan(self.base, "/api/store/feed", (
            "--stored-inject", f"{self.base}/api/store",
            "--stored-view", f"{self.base}/api/store/feed",
            "--stored-param", "note"))
        self._confirmed(got, "stored")

    # -- decoys: any finding here is a false positive -------------------

    def _silent(self, path, extra=()):
        got = _scan(self.base, path, extra)
        self.assertEqual(got, [], f"{path} produced {got}")

    def test_decoy_keyword_page(self):
        self._silent("/static/about")

    def test_decoy_correctly_escaped(self):
        self._silent("/api/safe?term=probe")

    def test_decoy_quoted_attribute(self):
        self._silent("/api/attr?term=probe")

    def test_decoy_public_resource(self):
        self._silent("/api/public/item?id=1")

    def test_decoy_requires_auth(self):
        self._silent("/api/private/item")

    def test_json_body_is_reported_at_LOW_confidence(self):
        """Not an FP and not a plain TP -- it locks the engine's own choice.

        Phase 32 (scanner.py) sees a non-HTML content type, keeps the finding
        and drops it to low confidence.  That decision used to live only in a
        comment; this asserts it, including that the detail line names the
        content type.  It does NOT assert exploitability.
        """
        # Phase 179: severity drops WITH confidence -- a severity-high
        # finding on a non-HTML response triaged like a live sink in every
        # severity-only consumer (benchmark FP gate, SARIF error level).
        got = _scan(self.base, "/api/echo-json?msg=probe", min_severity=None)
        self.assertTrue(got, "the reflection should still be recorded")
        for f in got:
            self.assertEqual(f.get("confidence"), "low")
            self.assertEqual(f.get("severity"), "low")
            self.assertIn("application/json", f.get("detail") or "")


if __name__ == "__main__":
    unittest.main()

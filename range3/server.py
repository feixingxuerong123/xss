# -*- coding: utf-8 -*-
"""Range #3 -- a third-opinion application range for XSSentinel.

Deliberately shaped unlike benchmark/server.py and unlike the red-team
fixture: a small "real app" with SQLite-backed state, a login flow with
server-side sessions, mixed content types, 401/404 semantics, and
carrier shapes (multi-reflection pages, RCDATA rendering, cookie and
header echoes, base64/JWT containers, stored and second-order flows)
that no other range in this repo serves.

Ground truth lives in range3/manifest.json; the scoring runner is
range3/runner.py.  Run:

    python range3/server.py [port]        # standalone
    python range3/runner.py               # scan + score
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import sqlite3
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

_DB_PATH = os.path.join(tempfile.gettempdir(), "xssentinel_range3.db")
_PORT = 8901

SESSION_COOKIE = "r3sid"
VALID_SESSION = "r3-session-token-24680"


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS comments "
        "(id INTEGER PRIMARY KEY, author TEXT, body TEXT, ts REAL)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS profiles "
        "(uid TEXT PRIMARY KEY, website TEXT, bio TEXT)")
    return conn


def _reset_db() -> None:
    if os.path.exists(_DB_PATH):
        os.unlink(_DB_PATH)
    conn = _db()
    # Second-order sink: the profile is written through the AUTHED update
    # endpoint; the PUBLIC profile page renders the stored website raw.
    conn.execute("INSERT INTO profiles VALUES ('u1337', ?, ?)",
                 ("https://benign.example", "hello"))
    conn.commit()
    conn.close()


def _page(body: str, status: int = 200, headers=None):
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    hdrs.update(headers or {})
    return status, hdrs, ("<!doctype html><html><head><title>Range3</title>"
                          "</head><body>" + body + "</body></html>").encode()


def _json(body: dict, status: int = 200):
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "Range3/1.0"

    # -- request plumbing ------------------------------------------------
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method: str):
        u = urlparse(self.path)
        path = u.path
        qs = {k: v[0] for k, v in
              parse_qs(u.query, keep_blank_values=True).items()}
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self._r3_body = raw.decode("utf-8", "replace")
        self._r3_filename = ""
        if "multipart/form-data" in (self.headers.get("Content-Type") or ""):
            for line in self._r3_body.split("\r\n"):
                if line.startswith("Content-Disposition") \
                        and "filename=" in line:
                    self._r3_filename = line.split("filename=", 1)[1] \
                        .strip().strip('"')
                    break
        form = {k: v[0] for k, v in
                parse_qs(self._r3_body, keep_blank_values=True).items()}

        # "/" maps to _h_get; hyphens normalize to underscores (Python
        # method names cannot carry them: /redirect-preview -> _h_get_...).
        seg = path.replace("/", "_") if path != "/" else ""
        key = "_h_" + method.lower() + seg.replace("-", "_")
        handler = getattr(self, key, None)
        if handler is None:
            # Segmented routes: /page/<seg>, /public/profile/<uid>.
            if path.startswith("/page/"):
                handler = self._h_get_page
            elif path.startswith("/public/profile/"):
                handler = self._h_get_public_profile
        if handler is None:
            return self._send(*_page("<h1>404</h1>", status=404))

        # Auth gates on the handlers that declare one.
        if getattr(handler, "requires_auth", False) and not self._authed():
            return self._send(*_page("<h1>login required</h1>", status=401))
        self._send(*handler(qs, form))

    def _send(self, status: int, headers: dict, body):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        return f"{SESSION_COOKIE}={VALID_SESSION}" in cookie

    def log_message(self, *a):
        pass

    # -- handlers ----------------------------------------------------------
    def _h_get(self, qs, form):
        return _page("<h1>Range3 home</h1><p>index</p>")

    # VULN q: raw echo into element body.
    def _h_get_search(self, qs, form):
        return _page(f"<p>results for <b>{qs.get('q', '')}</b>:</p><ul></ul>")

    # -- DVWA-style graduated defenses (honest ground truth) -----------
    # MEDIUM: strip <script> ONCE, non-recursively -> <sscriptcript>
    # reassembles after the strip.
    def _h_get_xss_medium(self, qs, form):
        import re as _re
        # One pass over opening tags only -- the classic non-recursive strip.
        term = _re.sub(r"(?i)<script>", "", qs.get("q", ""))
        return _page(f"<p>medium: {term}</p>")

    # HIGH: strip ANY tag carrying s-c-r-i-p-t interleaved (DVWA high
    # shape), leave every other tag raw -> <svg/onload> survives.
    def _h_get_xss_high(self, qs, form):
        import re as _re
        term = _re.sub(r"(?i)<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t", "",
                       qs.get("q", ""))
        return _page(f"<p>high: {term}</p>")

    # IMPOSSIBLE: context-aware output encoding -- safe by construction.
    def _h_get_xss_impossible(self, qs, form):
        import html as _html
        term = _html.escape(qs.get("q", ""), quote=True)
        return _page(f"<p>impossible: {term}</p>")

    # VULN (legacy charset): the page declares UTF-7 and reflects RAW --
    # a browser decodes the reflected +ADw-script+AD4- back to markup.
    # Semantic-only verification sees inert text; only a real browser
    # (headless) can confirm, so the manifest marks it headless-only.
    def _h_get_legacy(self, qs, form):
        # parse_qs decodes '+' as a SPACE, which would destroy the UTF-7
        # escape sequences (+ADw-...).  Take the raw query with unquote
        # (NOT unquote_plus): a UTF-7 payload must survive byte-exact.
        from urllib.parse import unquote as _unquote
        raw_q = _unquote(urlparse(self.path).query)
        term = raw_q[2:] if raw_q.startswith("q=") else raw_q
        return 200, {"Content-Type": "text/html; charset=UTF-7"}, (
            "<html><head><title>Range3 legacy</title></head><body>"
            f"<p>legacy archive: {term}</p>"
            "</body></html>").encode("utf-8")

    # VULN: MULTI-REFLECTION -- the marker lands in a nav comment first
    # and in a live script string second.
    def _h_get_find(self, qs, form):
        term = qs.get("q", "")
        return _page(f"<!-- breadcrumb: {term} -->"
                     f"<nav>home &gt; results</nav>"
                     f"<script>var lastQuery = '{term}';</script>")

    # VULN: raw echo inside RCDATA; only the </textarea> breakout fires.
    def _h_get_article(self, qs, form):
        return _page(f"<textarea name='draft'>{qs.get('draft', '')}"
                     f"</textarea>")

    # VULN: raw into a double-quoted attribute.
    def _h_get_redirect_preview(self, qs, form):
        return _page(f'<a id="goto" href="{qs.get("url", "")}">continue</a>')

    # VULN: raw URL path segment into the body.
    def _h_get_page(self, qs, form):
        seg = unquote(self.path[len("/page/"):].rsplit("/", 1)[-1])
        return _page(f"<h2>page: {seg}</h2>")

    # VULN: raw header echo into the body.
    def _h_get_track(self, qs, form):
        ip = self.headers.get("X-Client-IP", "") \
            or self.headers.get("True-Client-IP", "")
        return _page(f"<p>last seen from {ip}</p>")

    # VULN: raw cookie value into a script string.
    def _h_get_mypage(self, qs, form):
        theme = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("theme="):
                theme = part.split("=", 1)[1]
        return _page(f"<script>var theme = '{theme}';</script>")

    # Contact page: the scenario DSL's entry point (message param).
    def _h_get_contact(self, qs, form):
        msg = qs.get("message", "")
        return _page(f"<h2>contact</h2><p>draft: {msg}</p>"
                     '<form method="POST" action="/comment">'
                     '<input name="author"><textarea name="message">'
                     "</textarea><button>send</button></form>")

    # SAFE: JSON content type -- the reflection is real but inert.
    def _h_post_api_echo(self, qs, form):
        try:
            data = json.loads(self._r3_body or "{}")
        except Exception:
            data = {}
        return _json({"echo": data.get("msg", ""), "ok": True})

    # VULN: base64 container decoded then reflected raw.
    def _h_get_gob64(self, qs, form):
        raw = qs.get("next", "")
        try:
            decoded = base64.b64decode(
                raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
        except Exception:
            decoded = ""
        return _page(f"<p>continuing to {decoded}</p>")

    # VULN: JWT claim value reflected raw.
    def _h_get_jwtview(self, qs, form):
        token = qs.get("token", "")
        name = ""
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            name = claims.get("name", "")
        except Exception:
            name = ""
        return _page(f"<p>hello, {name}</p>")

    # VULN: location.hash -> innerHTML, no server-side reflection.
    def _h_get_domsearch(self, qs, form):
        return _page(
            "<div id=\"out\"></div>"
            "<script>"
            "document.getElementById('out').innerHTML = "
            "  '<p>results for ' + location.hash.slice(1) + '</p>';"
            "</script>")

    # SAFE: the same shape as /search but with context-aware output
    # encoding -- the probe reflects, escaped, and nothing executes.
    def _h_get_safe(self, qs, form):
        term = html.escape(qs.get("q", ""), quote=True)
        return _page(f"<p>results for <b>{term}</b>:</p><ul></ul>")

    # SAFE: keyword-scare page -- dangerous-LOOKING words, all escaped.
    def _h_get_archive(self, qs, form):
        blob = html.escape(qs.get("blob", ""), quote=True)
        return _page(f"<p>archive note: SELECT * FROM users; onerror=1 "
                     f"<script>alert(1)</script> {blob}</p>")

    # SAFE: strict CSP -- the raw echo cannot execute.
    def _h_get_cspstrict(self, qs, form):
        csp = "default-src 'none'; script-src 'none'"
        return _page(f"<p>{qs.get('q', '')}</p>",
                     headers={"Content-Security-Policy": csp})

    # VULN: strict-ish CSP whose nonce is STABLE per path (server-side
    # cache/hardcoded shape) -- a nonce read from one response stays
    # valid on the injected request.  Hashing the FULL path-with-query
    # instead rotates the nonce every probe, which is exactly the shape
    # the verifier must refuse (Phase 36) -- Range3 measured that refusal
    # before the fix.
    def _h_get_cspnonce(self, qs, form):
        nonce = hashlib.sha256(
            ("r3-nonce-seed"
             + urlparse(self.path).path).encode()).hexdigest()[:16]
        csp = f"default-src 'self'; script-src 'nonce-{nonce}'"
        term = qs.get("q", "")
        body = (f"<p data-reflected=\"{term}\">{term}</p>"
                f"<script nonce=\"{nonce}\">var ok = 1;</script>")
        return _page(body, headers={"Content-Security-Policy": csp})

    # VULN: uploaded filename echoed raw into the page.
    def _h_post_upload(self, qs, form):
        return _page(f"<p>Saved: {self._r3_filename}</p>")

    # VULN (stored, SQLite): comment bodies render raw on the feed page.
    def _h_post_comment(self, qs, form):
        conn = _db()
        conn.execute("INSERT INTO comments (author, body, ts) VALUES (?,?,?)",
                     (form.get("author", "anon"), form.get("body", ""),
                      time.time()))
        conn.commit()
        conn.close()
        return _json({"stored": True})

    def _h_get_comments(self, qs, form):
        conn = _db()
        rows = conn.execute(
            "SELECT author, body FROM comments ORDER BY id DESC LIMIT 20"
        ).fetchall()
        conn.close()
        items = "".join(f"<li><b>{a}</b>: {b}</li>" for a, b in rows)
        return _page(f"<ul id=\"feed\">{items}</ul>")

    # VULN (second-order, SQLite, auth-gated write): the public profile
    # page renders the stored website value raw.
    def _h_post_profile_update(self, qs, form):
        uid = form.get("uid", "u1337")
        conn = _db()
        conn.execute("UPDATE profiles SET website=? WHERE uid=?",
                     (form.get("website", ""), uid))
        conn.commit()
        conn.close()
        return _json({"updated": uid})
    _h_post_profile_update.requires_auth = True

    def _h_get_public_profile(self, qs, form):
        uid = self.path.rstrip("/").rsplit("/", 1)[-1]
        conn = _db()
        row = conn.execute("SELECT website FROM profiles WHERE uid=?",
                           (uid,)).fetchone()
        conn.close()
        if not row:
            return _page("<h1>no such profile</h1>", status=404)
        return _page(f'<p>website: <a href="{row[0]}">{row[0]}</a></p>')

    # VULN behind auth: raw echo of an admin-only parameter.
    def _h_get_admin_report(self, qs, form):
        return _page(f"<h3>report: {qs.get('name', '')}</h3>")
    _h_get_admin_report.requires_auth = True

    def _h_post_login(self, qs, form):
        if form.get("user") == "admin" and form.get("pass") == "r3-pass":
            return 200, {
                "Content-Type": "application/json",
                "Set-Cookie": f"{SESSION_COOKIE}={VALID_SESSION}; Path=/",
            }, json.dumps({"ok": True}).encode()
        return _json({"ok": False}, status=401)


def run_server(port: int = _PORT, ready_callback=None):
    _reset_db()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if ready_callback:
        ready_callback(srv)
    srv.serve_forever()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else _PORT
    print(f"[*] Range3 on http://127.0.0.1:{port} (db: {_DB_PATH})")
    run_server(port)

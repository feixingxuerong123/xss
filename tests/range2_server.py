"""Attack Range #2 — real-world-style XSS fixtures (benchmark coverage gaps).

 Unlike benchmark/server.py (context-matrix fixtures), this range models
 messy real-world apps: half-broken filters, odd reflection contexts,
 two-step stored flows, CSP nonce leaks and DOM sinks beyond the basics.

 Each fixture has a ground truth (vuln/safe) judged against a REAL
 browser's semantics, not our scanner's opinion.

 Run:  python tests/run_range2.py        (starts the range on a free port)
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# In-memory store for the two-step stored-XSS fixtures.
# ---------------------------------------------------------------------------
_STORE: dict[str, str] = {}

_PAGE = "<!DOCTYPE html><html><head><title>R2</title></head><body>{}</body></html>"

_NEXT_ID = 0


def _next_id() -> str:
    global _NEXT_ID
    _NEXT_ID += 1
    return str(_NEXT_ID)


# ---------------------------------------------------------------------------
# Vuln fixtures — each is exploitable in a real browser.
# ---------------------------------------------------------------------------

def v_strip_script_recursive(v: str) -> tuple:
    """Single-pass removal of 'script' -> <sscriptcript> re-forms <script>."""
    safe = re.sub(r"script", "", v, flags=re.I)
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


def v_strip_script_open(v: str) -> tuple:
    """Removes only '<script' openers; event-handler tags sail through."""
    safe = v.replace("<script", "").replace("<SCRIPT", "")
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


def v_attr_sq_encode_dq(v: str) -> tuple:
    """Encodes double quotes only; reflection sits in a SINGLE-quote attr."""
    safe = v.replace('"', "&quot;")
    return _PAGE.format(f"<img alt='{safe}' src=ok.png>"), "text/html"


def v_blacklist_onload(v: str) -> tuple:
    """Blacklists 'onload' only -> onerror/ontoggle/etc still work."""
    safe = v.replace("onload", "").replace("OnLoad", "")
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


def v_space_filter(v: str) -> tuple:
    """Strips spaces -> slash-separated attributes still inject."""
    safe = v.replace(" ", "")
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


def v_mxss_svg_style(v: str) -> tuple:
    """'script' filtered; page re-parses node text via innerHTML (mXSS)."""
    safe = v.replace("script", "")
    body = (
        f"<div id=out>{safe}</div>"
        "<script>"
        "var out=document.getElementById('out');"
        "out.innerHTML=out.textContent;"  # mutating sink: round-trip reparse
        "</script>"
    )
    return _PAGE.format(body), "text/html"


def v_unclosed_quote_attr(v: str) -> tuple:
    """Value never closed: '<img src="' + v (rest of tag swallowed)."""
    return _PAGE.format(f'<img src="{v}<br>rest'), "text/html"


def v_comment_dashbang(v: str) -> tuple:
    """Reflection inside a comment; '--!>' is a valid HTML5 comment close."""
    return _PAGE.format(f"<!-- note: {v} --><p>after</p>"), "text/html"


def v_regex_context(v: str) -> tuple:
    """Reflection inside a JS regex literal: /../ must be closed first."""
    body = (
        f"<div>query echoed</div>"
        "<script>var re = /" + v + "/; if(re.test('x'))console.log(1);</script>"
    )
    return _PAGE.format(body), "text/html"


def v_stored_two_step_store(v: str) -> tuple:
    """POST: stores raw value (re-encoded only for transport)."""
    _STORE[_next_id()] = v
    return _PAGE.format("<p>saved</p>"), "text/html"


def v_stored_two_step_view(_: str) -> tuple:
    """GET: renders the stored value RAW (classic store-encode-view-raw)."""
    items = "".join(f"<li>{v}</li>" for v in _STORE.values()) or "<li>(empty)</li>"
    return _PAGE.format(f"<ul>{items}</ul>"), "text/html"


def v_csp_nonce_leak(v: str) -> tuple:
    """Nonce-based CSP, but the nonce leaks into attacker-reflected text."""
    nonce = "R2nonce0123456789abcdef"
    csp = f"script-src 'nonce-{nonce}'; object-src 'none'"
    body = (
        f"<p>echo: {v}</p>"
        f"<p>debug-nonce: {nonce}</p>"  # nonce exposed near reflection
        f"<script nonce='{nonce}'>var ok=1;</script>"
    )
    html = ("<!DOCTYPE html><html><head>"
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            f"<title>R2</title></head><body>{body}</body></html>")
    return html, "text/html"


def v_dom_hash_iframe_srcdoc(v: str) -> tuple:
    """location.hash flows into iframe.srcdoc (property assignment)."""
    body = (
        '<iframe id=f></iframe>'
        "<script>"
        "document.getElementById('f').srcdoc = decodeURIComponent("
        "location.hash.slice(1));"
        "</script>"
    )
    return _PAGE.format(body), "text/html"


def v_dom_cookie_innerhtml(v: str) -> tuple:
    """document.cookie -> innerHTML (attacker sets cookie via param echo)."""
    body = (
        f'<meta http-equiv="Set-Cookie" content="dummy=1">'  # no-op; cookie
        # is set by the scanner/JS below so the flow stays deterministic:
        "<div id=o>safe</div>"
        "<script>"
        f"document.cookie='r2c={urllib.parse.quote(v)}';"
        "document.getElementById('o').innerHTML=document.cookie;"
        "</script>"
    )
    return _PAGE.format(body), "text/html"


def v_dom_name_innerhtml(v: str) -> tuple:
    """window.name -> innerHTML (name persists across navigation)."""
    body = (
        "<div id=o>safe</div>"
        "<script>window.name=window.name||'';"
        "if(location.search.indexOf('seed=')>=0){window.name="
        "decodeURIComponent(location.search.split('seed=')[1].split('&')[0]);}"
        "document.getElementById('o').innerHTML=window.name;"
        "</script>"
    )
    return _PAGE.format(body), "text/html"


def v_dom_search_nested(v: str) -> tuple:
    """URLSearchParams -> template string -> innerHTML (multi-hop)."""
    body = (
        "<div id=o></div>"
        "<script>"
        "var p=new URLSearchParams(location.search);"
        "var t=`<b>${p.get('v')}</b>`;"
        "document.getElementById('o').innerHTML=t;"
        "</script>"
    )
    return _PAGE.format(body), "text/html"


# ---------------------------------------------------------------------------
# Safe fixtures — must NOT be reported.
# ---------------------------------------------------------------------------

def s_js_json_encode(v: str) -> tuple:
    # Correct JSON-in-HTML encoding: < > & must be \u-escaped, otherwise
    # a literal </script> would terminate the script early (a real bug).
    body = ("<script>var q="
            + json.dumps(v).replace("<", "\\u003c")
                            .replace(">", "\\u003e")
                            .replace("&", "\\u0026")
            + ";console.log(q.length);</script>")
    return _PAGE.format("<div>ok</div>" + body), "text/html"


def s_full_entity_attr(v: str) -> tuple:
    import html as _h
    safe = _h.escape(v, quote=True)
    return _PAGE.format(f"<img alt='{safe}' src=ok.png>"), "text/html"


def s_strict_csp_self(v: str) -> tuple:
    import html as _h
    safe = _h.escape(v, quote=True)
    html = ("<!DOCTYPE html><html><head>"
            '<meta http-equiv="Content-Security-Policy" '
            "content=\"script-src 'self'; object-src 'none'\">"
            f"<title>R2</title></head><body><div>{safe}</div></body></html>")
    return html, "text/html"


def s_upper_entity(v: str) -> tuple:
    """html.escape then uppercased: &LT;/&QUOT; are NOT decoded by browsers."""
    import html as _h
    safe = _h.escape(v, quote=True).upper()
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


def s_percent_literal(v: str) -> tuple:
    """Outputs the URL-encoded form literally without decoding."""
    safe = urllib.parse.quote(v, safe="")
    return _PAGE.format(f"<div>{safe}</div>"), "text/html"


# ---------------------------------------------------------------------------
# Case table: (path, param, kind)
#   kind: 'query' | 'stored' (POST store -> separate view)
# ---------------------------------------------------------------------------
VULN_CASES = [
    ("/r2/strip-script-recursive", "q", "query"),
    ("/r2/strip-script-open", "q", "query"),
    ("/r2/attr-sq-encode-dq", "q", "query"),
    ("/r2/blacklist-onload", "q", "query"),
    ("/r2/space-filter", "q", "query"),
    ("/r2/mxss-svg-style", "q", "query"),
    ("/r2/unclosed-quote", "q", "query"),
    ("/r2/comment-dashbang", "q", "query"),
    ("/r2/regex-context", "q", "query"),
    ("/r2/stored/store", "q", "stored"),   # view = /r2/stored/view
    ("/r2/stored/store", "q", "second_order"),  # same pair, so_module path
    ("/r2/csp-nonce-leak", "q", "query"),
    ("/r2/dom-hash-srcdoc", "v", "query"),
    ("/r2/dom-cookie", "v", "query"),
    ("/r2/dom-name", "v", "query"),
    ("/r2/dom-search-nested", "v", "query"),
    # --- Phase 63: today's newer capabilities under real-world drill ---
    ("/r2/json-api", "q", "json_post"),        # JSON body echoed raw
    ("/r2/upload-put", "file", "put_upload"),  # RESTful PUT multipart upload
    ("/r2/cors-open", "", "cors"),             # Origin reflection + creds
    ("/r2/xsleak-open", "", "xsleak"),         # no isolation headers at all
]

SAFE_CASES = [
    ("/r2/safe/js-json-encode", "q"),
    ("/r2/safe/full-entity-attr", "q"),
    ("/r2/safe/strict-csp-self", "q"),
    ("/r2/safe/upper-entity", "q"),
    ("/r2/safe/percent-literal", "q"),
    ("/r2/safe/isolated", ""),                 # COOP/CORP/COEP set: no leak
]

_ROUTES = {
    "/r2/strip-script-recursive": v_strip_script_recursive,
    "/r2/strip-script-open": v_strip_script_open,
    "/r2/attr-sq-encode-dq": v_attr_sq_encode_dq,
    "/r2/blacklist-onload": v_blacklist_onload,
    "/r2/space-filter": v_space_filter,
    "/r2/mxss-svg-style": v_mxss_svg_style,
    "/r2/unclosed-quote": v_unclosed_quote_attr,
    "/r2/comment-dashbang": v_comment_dashbang,
    "/r2/regex-context": v_regex_context,
    "/r2/stored/store": v_stored_two_step_store,
    "/r2/stored/view": v_stored_two_step_view,
    "/r2/csp-nonce-leak": v_csp_nonce_leak,
    "/r2/dom-hash-srcdoc": v_dom_hash_iframe_srcdoc,
    "/r2/dom-cookie": v_dom_cookie_innerhtml,
    "/r2/dom-name": v_dom_name_innerhtml,
    "/r2/dom-search-nested": v_dom_search_nested,
    "/r2/safe/js-json-encode": s_js_json_encode,
    "/r2/safe/full-entity-attr": s_full_entity_attr,
    "/r2/safe/strict-csp-self": s_strict_csp_self,
    "/r2/safe/upper-entity": s_upper_entity,
    "/r2/safe/percent-literal": s_percent_literal,
}


class Range2Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, ctype: str, status: int = 200,
              extra_headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _render(self, method: str):
        path = urllib.parse.urlparse(self.path).path
        fn = _ROUTES.get(path)
        if fn is None:
            self._send(_PAGE.format("<h1>R2 range</h1>"), "text/html", 404)
            return
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            form = urllib.parse.parse_qs(raw, keep_blank_values=True)
            v = (form.get("q") or form.get("v") or [""])[0]
        else:
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query,
                keep_blank_values=True)
            v = (qs.get("q") or qs.get("v") or [""])[0]
        body, ctype = fn(v)
        extra = {}
        if path == "/r2/csp-nonce-leak":
            extra["Content-Security-Policy"] = (
                "script-src 'nonce-R2nonce0123456789abcdef'; object-src 'none'")
        self._send(body, ctype, extra_headers=extra)

    def do_GET(self):  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        # --- Phase 63: carrier/audit routes (bypass the q/v pipeline) ---
        if path == "/r2/cors-open":
            origin = self.headers.get("Origin") or "null"
            self._send(
                "<html><body><div>cors-open</div></body></html>",
                "text/html",
                extra_headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                })
            return
        if path == "/r2/xsleak-open":
            # No COOP/CORP/COEP, no frame guard: full XS-Leak surface.
            self._send("<html><body><div>leak me</div></body></html>",
                       "text/html")
            return
        if path == "/r2/safe/isolated":
            self._send("<html><body><div>isolated</div></body></html>",
                       "text/html",
                       extra_headers={
                           "Cross-Origin-Opener-Policy": "same-origin",
                           "Cross-Origin-Resource-Policy": "same-origin",
                           "Cross-Origin-Embedder-Policy": "require-corp",
                       })
            return
        self._render("GET")

    def do_POST(self):  # noqa: N802
        if urllib.parse.urlparse(self.path).path == "/r2/json-api":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            try:
                obj = json.loads(raw)
                val = str(obj.get("q", ""))
            except Exception:
                val = ""
            # JSON API that renders the value into a page unescaped.
            self._send("<html><body><div>q:%s</div></body></html>" % val,
                       "text/html")
            return
        self._render("POST")

    def do_PUT(self):  # noqa: N802
        if urllib.parse.urlparse(self.path).path == "/r2/upload-put":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            m = re.search(rb'filename="([^"]*)"', body)
            name = m.group(1).decode("utf-8", "replace") if m else ""
            self._send("<html><body><div>up:%s</div></body></html>" % name,
                       "text/html")
            return
        self._send(_PAGE.format("<h1>R2 range</h1>"), "text/html", 404)

    def log_message(self, *args):  # silence
        pass


def start_range2(port: int = 8896, ready_callback=None) -> ThreadingHTTPServer:
    """Bind `port`, walking upward; fall back to an OS-assigned port
    (large parts of the low range are reserved on this Windows host)."""
    import socket

    server = None
    last_err = None
    for p in range(port, port + 12):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), Range2Handler)
            break
        except OSError as e:
            last_err = e
    if server is None:
        # OS-assigned free port (never collides with reserved ranges).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            free = probe.getsockname()[1]
        try:
            server = ThreadingHTTPServer(("127.0.0.1", free), Range2Handler)
        except OSError as e:
            raise RuntimeError(f"range2 cannot bind: {last_err or e}")
    # ALWAYS start the serving thread: 'start_' must imply serving.  A bare
    # bind() leaves connects queued in the backlog forever (observed as a
    # pytest fixture hang when ready_callback was omitted).
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    if ready_callback is not None:
        ready_callback(server)
    return server


if __name__ == "__main__":
    s = start_range2(8896, ready_callback=lambda srv: print(
        f"[+] range2 ready on http://127.0.0.1:{srv.server_port}"))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        s.shutdown()

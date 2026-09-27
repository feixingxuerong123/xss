# -*- coding: utf-8 -*-
"""Range #4 -- a REAL-framework SPA range (React 18 / Vue 3, vendored).

The three existing ranges hand-roll their markup.  This one renders its
reflections through ACTUAL framework code paths -- React's
dangerouslySetInnerHTML and Vue's v-html -- because a sink that only
exists in a hand-rolled fixture says nothing about whether the engine
finds it inside a real bundle.  The vendor files are pinned upstream
releases served locally (no CDN dependency at scan time).

Shapes:
  * /react?search=   -- server reflects the param into a JS config line
    (window.__INITIAL__), the React app renders it via
    dangerouslySetInnerHTML: config-injection -> framework sink.
  * /react-safe      -- identical page, React renders a TEXT node (its
    default, auto-escaping behavior).  Safe by construction.
  * /vue?msg=        -- same two-step shape, Vue 3 v-html.
  * /vue-safe        -- v-text.  Safe by construction.

Every sink is CLIENT-side: only a real browser can confirm, so the
manifest marks all cases headless.  Ground truth is authored from the
framework semantics (dangerouslySetInnerHTML/v-html DO NOT escape;
text nodes/v-text DO).
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_PORT = 19702
_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")

_SHELL = """<!doctype html><html><head><title>Range4</title></head><body>
<div id="app"></div>
<script src="/vendor/react.production.min.js"></script>
<script src="/vendor/react-dom.production.min.js"></script>
<script>window.__INITIAL__ = {q: '{value}'};</script>
<script src="/app_react.js"></script>
</body></html>"""

_SHELL_VUE = """<!doctype html><html><head><title>Range4</title></head><body>
<div id="app"></div>
<script src="/vendor/vue.global.prod.js"></script>
<script>window.__INITIAL__ = {q: '{value}'};</script>
<script src="/app_vue.js"></script>
</body></html>"""

_APP_REACT_VULN = """
const e = React.createElement;
ReactDOM.createRoot(document.getElementById('app')).render(
  e('div', {dangerouslySetInnerHTML: {__html:
    '<p>results for ' + window.__INITIAL__.q + '</p>'}}));
"""

# SAFE: no server reflection anywhere -- the param is read CLIENT-SIDE
# from location.search, and React renders it as a TEXT node (auto-escaped
# by construction).  The first Range4 draft reflected the param into a
# server-side JS config line, which is itself a script-string injection
# sink: every variant confirmed there and the "safe" twin measured FP.
_APP_REACT_SAFE = """
const e = React.createElement;
const q = new URLSearchParams(location.search).get('search') || '';
ReactDOM.createRoot(document.getElementById('app')).render(
  e('div', null, e('p', null, 'results for ' + q)));
"""

_APP_VUE_VULN = """
Vue.createApp({
  data() { return {q: window.__INITIAL__.q}; },
  template: '<p v-html="q2"></p>',
  computed: {q2() { return 'results for ' + this.q; }},
}).mount('#app');
"""

_APP_VUE_SAFE = """
const q = new URLSearchParams(location.search).get('msg') || '';
Vue.createApp({
  data() { return {q: q}; },
  template: '<p v-text="q2"></p>',
  computed: {q2() { return 'results for ' + this.q; }},
}).mount('#app');
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: no TIME_WAIT churn
    server_version = "Range4/1.0"

    def _send(self, status, headers, body):
        # Content-Length is REQUIRED under HTTP/1.1 keep-alive: without it
        # the client waits for a body that never terminates (read timeout).
        headers = dict(headers or {})
        headers["Content-Length"] = str(len(body))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _page(self, body, status=200):
        return self._send(status, {"Content-Type": "text/html; charset=utf-8"},
                          body.encode("utf-8"))

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        qs = {k: v[0] for k, v in
              parse_qs(u.query, keep_blank_values=True).items()}

        if path.startswith("/vendor/"):
            name = os.path.basename(path)   # no traversal
            fp = os.path.join(_VENDOR, name)
            if not os.path.isfile(fp):
                return self._send(404, {"Content-Type": "text/plain"}, b"no")
            ctype = ("application/javascript" if name.endswith(".js")
                     else "application/octet-stream")
            return self._send(200, {"Content-Type": ctype},
                              open(fp, "rb").read())
        if path.startswith("/app_"):
            name = os.path.basename(path)
            apps = {"app_react.js": _APP_REACT_VULN,
                    "app_react_safe.js": _APP_REACT_SAFE,
                    "app_vue.js": _APP_VUE_VULN,
                    "app_vue_safe.js": _APP_VUE_SAFE}
            body = apps.get(name)
            if body is None:
                return self._send(404, {"Content-Type": "text/plain"}, b"no")
            return self._send(200, {"Content-Type": "application/javascript"},
                              body.encode("utf-8"))

        # NOTE: parse_qs decodes '+' as a space; the config line must carry
        # the value byte-exact, so take the raw query with unquote.
        from urllib.parse import unquote
        raw_q = unquote(u.query)
        value = raw_q.split("=", 1)[1] if "=" in raw_q else ""

        if path == "/react":
            return self._page(_SHELL.replace("{value}", value))
        if path == "/react-safe":
            return self._page(_SHELL.replace("{value}", "")
                              .replace("app_react.js", "app_react_safe.js"))
        if path == "/vue":
            return self._page(_SHELL_VUE.replace("{value}", value))
        if path == "/vue-safe":
            return self._page(_SHELL_VUE.replace("{value}", "")
                              .replace("app_vue.js", "app_vue_safe.js"))
        if path == "/":
            return self._page("<h1>Range4 home</h1>")
        return self._send(404, {"Content-Type": "text/plain"}, b"no")

    def log_message(self, *a):
        pass


def run_server(port: int = _PORT, ready_callback=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if ready_callback:
        ready_callback(srv)
    srv.serve_forever()
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else _PORT
    print(f"[*] Range4 on http://127.0.0.1:{port}")
    run_server(port)

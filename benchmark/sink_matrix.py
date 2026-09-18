"""Sink coverage matrix: which sinks can the real-browser engine confirm?

The engine's injected script hooks a list of sinks; the static analyzer has
its own list (`trusted_types._DANGER_SINKS`).  The two are maintained
separately, so "the engine covers it" is an assumption.  Phase 161 already
found one such assumption to be false (the Function hook does NOT cover a
direct eval).  This probe builds one page per sink shape -- all driven from
`location.hash` so the engine's hash probe reaches them, exactly like
benchmark pos-dom-01..06 -- and reports whether a hit is observed.

Usage: python -m benchmark.sink_matrix [port]
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")

_PAGE = """<!DOCTYPE html><html><body>
<div id="o">safe</div><iframe id="f"></iframe>
<script>
try { %s } catch (e) { document.title = 'ERR ' + e; }
</script>
</body></html>"""

# name -> JS body.  Each one feeds location.hash (the marker) into one sink.
SINKS = {
    "innerHTML (control)":
        "document.getElementById('o').innerHTML = location.hash.slice(1);",
    "outerHTML":
        "document.getElementById('o').outerHTML = location.hash.slice(1);",
    "insertAdjacentHTML":
        "document.getElementById('o').insertAdjacentHTML("
        "'beforeend', location.hash.slice(1));",
    "iframe.srcdoc":
        "document.getElementById('f').srcdoc = location.hash.slice(1);",
    "document.write":
        "document.write(location.hash.slice(1));",
    "eval":
        "eval(location.hash.slice(1));",
    "new Function":
        "new Function(location.hash.slice(1));",
    "setTimeout(string)":
        "setTimeout(location.hash.slice(1), 0);",
    "Range.createContextualFragment":
        "var r = document.createRange(); r.selectNodeContents(document.body);"
        " document.body.appendChild("
        "r.createContextualFragment(location.hash.slice(1)));",
    "a.href = 'javascript:' + x":
        "var a = document.createElement('a');"
        " a.href = 'javascript:' + location.hash.slice(1);"
        " document.body.appendChild(a);",
    "el.setAttribute('onclick', x)":
        "document.getElementById('o').setAttribute("
        "'onclick', location.hash.slice(1));",
    "el.onerror = x (string)":
        "var i = document.createElement('img');"
        " i.onerror = location.hash.slice(1) || null;"
        " i.src = 'x-bad://nope'; document.body.appendChild(i);",
    "window.name -> innerHTML":
        "document.getElementById('o').innerHTML = window.name;",
    "document.cookie -> innerHTML":
        "document.getElementById('o').innerHTML = document.cookie;",
}

_ROUTES = {f"/s/{i}": body for i, body in enumerate(SINKS.values())}
_NAMES = {f"/s/{i}": name for i, name in enumerate(SINKS.keys())}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = _ROUTES.get(self.path.split("?")[0].split("#")[0])
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        html = (_PAGE % body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, *a):  # silence
        pass


def sink_urls(port: int) -> dict:
    """name -> URL, so callers (and tests) share ONE definition of the pages."""
    return {name: f"http://127.0.0.1:{port}{path}"
            for path, name in _NAMES.items()}


def start_server(port: int = 0) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return srv


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18898
    srv = start_server(port)
    port = srv.server_port

    from xssentinel.core.dom_engine import DynamicDomAnalyzer
    engine = DynamicDomAnalyzer(timeout=10)

    rows = []
    hit_count = 0
    for path, name in _NAMES.items():
        url = f"http://127.0.0.1:{port}{path}"
        t0 = time.perf_counter()
        try:
            found = engine.analyze(url)
        except Exception as e:                       # pragma: no cover
            found = []
            print(f"  !! {name}: {e}", flush=True)
        el = time.perf_counter() - t0
        sinks = sorted({str(f.get("sink", "")) for f in (found or [])})
        ok = bool(found)
        hit_count += 1 if ok else 0
        rows.append({"sink": name, "confirmed": ok, "hit_sinks": sinks,
                     "elapsed": round(el, 1)})
        print(f"  {'HIT ' if ok else 'MISS'} {name:<32} {el:5.1f}s {sinks}",
              flush=True)

    print(f"\n=== summary ===\nshapes probed: {len(rows)}   "
          f"confirmed: {hit_count}   missed: {len(rows) - hit_count}")
    missed = [r["sink"] for r in rows if not r["confirmed"]]
    print("missed:", json.dumps(missed, ensure_ascii=False))
    out = os.path.join("benchmark", "results", "sink_matrix.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

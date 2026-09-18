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

# name -> (JS body, expectation).  Each body feeds location.hash (the marker)
# into one sink.  expectation is a CONTRACT, not a description:
#   "confirm" -- the browser must report this shape (it executes, or the
#                marker reaches a sink the browser acts on);
#   "no-exec" -- must NOT be reported, because it was MEASURED not to
#                execute.  Pinning these stops someone "fixing" a non-gap.
SINKS = {
    "innerHTML (control)": (
        "document.getElementById('o').innerHTML = location.hash.slice(1);",
        "confirm"),
    "outerHTML": (
        "document.getElementById('o').outerHTML = location.hash.slice(1);",
        "confirm"),
    "insertAdjacentHTML": (
        "document.getElementById('o').insertAdjacentHTML("
        "'beforeend', location.hash.slice(1));", "confirm"),
    "iframe.srcdoc": (
        "document.getElementById('f').srcdoc = location.hash.slice(1);",
        "confirm"),
    "document.write": (
        "document.write(location.hash.slice(1));", "confirm"),
    "eval": (
        "eval(location.hash.slice(1));", "confirm"),
    "new Function": (
        "new Function(location.hash.slice(1));", "confirm"),
    "setTimeout(string)": (
        "setTimeout(location.hash.slice(1), 0);", "confirm"),
    "Range.createContextualFragment": (
        "var r = document.createRange(); r.selectNodeContents(document.body);"
        " document.body.appendChild("
        "r.createContextualFragment(location.hash.slice(1)));", "confirm"),
    "iframe.src = 'javascript:' + x": (
        "var f = document.createElement('iframe');"
        " f.src = 'javascript:' + location.hash.slice(1);"
        " document.body.appendChild(f);", "confirm"),
    # --- measured NOT to execute (Phase 167): the engine must stay silent ----
    # marker reaching these attributes is a FLOW observation, not execution:
    # benchmark/sink_execution.py measured embed.src / object.data (both
    # javascript: and data:text/html) as non-executing in Chromium, while
    # iframe.src=javascript: does execute.
    "embed.src = 'javascript:' + x": (
        "var e = document.createElement('embed');"
        " e.src = 'javascript:' + location.hash.slice(1);"
        " document.body.appendChild(e);", "no-exec"),
    "object.data = 'data:text/html,...'": (
        "var o = document.createElement('object');"
        " o.data = 'data:text/html,' + location.hash.slice(1);"
        " document.body.appendChild(o);", "no-exec"),
    "el.setAttribute('onclick', x)": (
        "document.getElementById('o').setAttribute("
        "'onclick', location.hash.slice(1));", "confirm"),
    "window.name -> innerHTML": (
        "document.getElementById('o').innerHTML = window.name;", "confirm"),
    "document.cookie -> innerHTML": (
        "document.getElementById('o').innerHTML = document.cookie;",
        "confirm"),
    # --- measured NOT to execute: recorded so nobody re-opens them ---------
    "a.href = 'javascript:' + x": (
        "var a = document.createElement('a');"
        " a.href = 'javascript:' + location.hash.slice(1);"
        " document.body.appendChild(a);", "no-exec"),
    "el.onerror = x (string)": (
        "var i = document.createElement('img');"
        " i.onerror = location.hash.slice(1) || null;"
        " i.src = 'x-bad://nope'; document.body.appendChild(i);", "no-exec"),
}
# Why the two no-exec shapes are recorded rather than hooked (measured in
# Chromium via Playwright, headless, 2026-09-18):
#   * a.href = 'javascript:...'  did not execute -- not on page load, and not
#     even on a TRUSTED click in this harness.  Activation-dependent, so
#     reporting it as "confirmed" would be over-claiming.
#   * el.onerror = 'code' (string) did not execute at all: the event-handler
#     PROPERTY path is not a sink.  The content attribute is a sink, and
#     setAttribute (incl. on* names) is already hooked.
# The self-executing URL property sinks (iframe.src / embed.src / object.data
# with javascript: or data:text/html) ARE hooked -- Phase 163.

_ROUTES = {f"/s/{i}": body for i, (body, _exp) in enumerate(SINKS.values())}
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
        expect = SINKS[name][1]
        # expectation is a CONTRACT: "confirm" shapes must hit, "no-exec"
        # shapes (measured non-sinks) must stay silent.
        verdict = "ok" if (ok if expect == "confirm" else not ok) else "MISMATCH"
        if expect == "confirm":
            hit_count += 1 if ok else 0
        rows.append({"sink": name, "expect": expect, "confirmed": ok,
                     "verdict": verdict, "hit_sinks": sinks,
                     "elapsed": round(el, 1)})
        flag = "" if verdict == "ok" else "   << CONTRACT MISMATCH"
        print(f"  {'HIT ' if ok else 'MISS'} {name:<34} {el:5.1f}s "
              f"expect={expect:<8}{flag} {sinks}", flush=True)

    must = [r for r in rows if r["expect"] == "confirm"]
    confirmed = [r for r in must if r["confirmed"]]
    bad = [r for r in rows if r["verdict"] == "MISMATCH"]
    print(f"\n=== summary ===\nshapes probed: {len(rows)}")
    print(f"must confirm: {len(must)}   confirmed: {len(confirmed)}")
    print("not-confirmed:", json.dumps(
        [r["sink"] for r in must if not r["confirmed"]], ensure_ascii=False))
    print("measured-not-a-sink (must stay silent):", json.dumps(
        [r["sink"] for r in rows if r["expect"] == "no-exec"],
        ensure_ascii=False))
    print("CONTRACT MISMATCHES:", json.dumps([r["sink"] for r in bad],
                                             ensure_ascii=False))
    out = os.path.join("benchmark", "results", "sink_matrix.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

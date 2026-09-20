"""Phase 168: does a STATIC ``<frame src=javascript:>`` run, or is it dropped?

`tests/test_url_sink_elements.py::test_executing_shapes_confirm` asserts that
``<frame src="javascript:...">`` confirms, and the working tree no longer does --
`sandbox.py` vetoes it with "no executable node carries the token".  Two
statements are in conflict and only a measurement settles it:

  * ``benchmark/results/sink_execution.json`` reports ``frame.src =
    javascript:CODE`` as EXECUTES  --  but that shape builds the element with
    ``document.createElement('frame')`` and appends it, i.e. it never goes
    through the HTML parser.
  * ``sandbox.py`` records ``frame`` as "measured dropped in all four contexts"
    (``FRAMESET_ONLY_STARTS``), which would make a *static* ``<frame>`` tag
    inert no matter what its ``src`` says.

The sentinel is ``parent.document.title=1`` because a frame/iframe runs its
javascript: URL in its own nested context; the parent is same-origin here.

Usage: python -m benchmark.probe_frame_parse
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")
os.environ["NO_PROXY"] = "127.0.0.1,localhost"

PORT = 18942
JS = "javascript:parent.document.title=1"

_DOC = "<!DOCTYPE html><html><head><title>page</title></head>{tail}</html>"

PAGES: dict[str, str] = {
    # sentinel control: a plain script in the top document
    "/c/script": _DOC.format(tail="<body><script>document.title=1</script></body>"),
    # control: the nested-context sentinel itself works
    "/c/iframe-js": _DOC.format(
        tail=f'<body><iframe src="{JS}"></iframe></body>'),
    # the disputed shape: a static <frame> where the parser may drop it
    "/c/frame-bare": _DOC.format(
        tail=f'<body><frame src="{JS}"></body>'),
    # ... and the same tag inside the container that owns it
    "/c/frame-frameset": _DOC.format(
        tail=f'<frameset><frame src="{JS}"></frameset>'),
    # the dynamic path sink_execution.json measured
    "/c/frame-dynamic": _DOC.format(
        tail='<body><script>var e=document.createElement("frame");'
             f'e.src="{JS}";'
             "(document.body||document.documentElement).appendChild(e);"
             "</script></body>"),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):                                   # noqa: N802
        body = PAGES.get(self.path, "<html><body>x</body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def main() -> int:
    from playwright.sync_api import sync_playwright

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{PORT}"

    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for path in PAGES:
            page = browser.new_page()
            page.goto(f"{base}{path}", wait_until="commit")
            page.wait_for_timeout(1200)
            ran = page.title() == "1"
            # what the parser actually built, so "dropped" is observable
            built = page.evaluate(
                "() => [...document.querySelectorAll('frame,iframe,frameset')]"
                ".map(e => e.tagName.toLowerCase()).join(',')")
            rows.append({"case": path, "executed": ran, "built": built})
            page.close()
        browser.close()
    srv.shutdown()

    for r in rows:
        print(f"  {'EXEC ' if r['executed'] else 'no   '} {r['case']:22s} "
              f"built=[{r['built']}]", flush=True)

    by = {r["case"]: r for r in rows}
    print("\n=== read-out ===")
    print("  sentinel (plain script)      :", by["/c/script"]["executed"])
    print("  nested-sentinel (iframe)     :", by["/c/iframe-js"]["executed"])
    print("  static <frame> bare          :", by["/c/frame-bare"]["executed"],
          " built:", by["/c/frame-bare"]["built"] or "(none)")
    print("  static <frame> in <frameset> :", by["/c/frame-frameset"]["executed"],
          " built:", by["/c/frame-frameset"]["built"] or "(none)")
    print("  dynamic createElement(frame) :", by["/c/frame-dynamic"]["executed"],
          " built:", by["/c/frame-dynamic"]["built"] or "(none)")

    out = "benchmark/results/probe_frame_parse.json"
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\nwritten:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

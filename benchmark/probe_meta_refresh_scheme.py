"""Phase 168 premise check: does a `javascript:` URL in a meta refresh RUN?

The two red tests (`test_phase35.py::test_meta_refresh_javascript_still_confirms`,
`test_verifier_uri_csp.py::test_real_meta_refresh_confirms`) assert that a page
reflecting

    <meta http-equiv="refresh" content="0;url=javascript:CODE">

-executes nothing, and they are red because the working tree now says it does.
Before touching either side, measure the thing they disagree about.

The existing measurement (`benchmark/sink_execution.py`) builds the meta with
`document.createElement` + `appendChild`.  The tests feed the markup through a
real HTML parse.  Those are not the same shape, so this probe serves the pages
over a real HTTP origin and parses the markup.

Four controls, so a "did not execute" can be told apart from "this harness
cannot see execution":

  A  inline <script>document.title=1</script>          the sentinel works
  B  iframe.src = javascript:CODE                      javascript: URLs are observable
  C  meta refresh -> http://.../child                  the refresh actually navigates
  D  meta refresh -> invalid scheme (about:)           refresh rejects bad URLs

If A-C are all positive and the javascript: cases are negative, "does not run"
is a measurement rather than an artefact.

Usage: python -m benchmark.probe_meta_refresh_scheme
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")
os.environ["NO_PROXY"] = "127.0.0.1,localhost"

PORT = 18941
SENT = "document.title=1"          # read back as page.title() == "1"

HITS: list[str] = []

_SHELL = "<html><head>{head}</head><body>{body}</body></html>"

PAGES: dict[str, str] = {
    "/case/script": _SHELL.format(
        head="", body=f"<script>{SENT}</script>"),
    "/case/iframe-js": _SHELL.format(
        head="",
        body="<script>var e=document.createElement('iframe');"
             f"e.src='javascript:parent.{SENT}';"
             "document.body.appendChild(e);</script>"),
    "/case/meta-http": _SHELL.format(
        head='<meta http-equiv="refresh" content="0;url=/child">', body="p"),
    "/case/meta-badscheme": _SHELL.format(
        head='<meta http-equiv="refresh" content="0;url=about:blank">', body="p"),
    "/case/meta-js-inline": _SHELL.format(
        head=f'<meta http-equiv="refresh" content="0;url=javascript:{SENT}">',
        body="p"),
    "/case/meta-js-created": _SHELL.format(
        head="",
        body="<script>var e=document.createElement('meta');"
             "e.httpEquiv='refresh';"
             f"e.content='0;url=javascript:{SENT}';"
             "document.head.appendChild(e);</script>"),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):                                   # noqa: N802
        HITS.append(self.path)
        body = PAGES.get(self.path, "<html><body>child</body></html>")
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):                          # keep the output clean
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
            HITS.clear()
            page.goto(f"{base}{path}", wait_until="commit")
            page.wait_for_timeout(1500)
            ran = page.title() == "1"
            navigated = page.url != f"{base}{path}"
            rows.append({
                "case": path,
                "executed": ran,
                "url_after": page.url,
                "navigated": navigated,
                "nav_requests": list(HITS),
            })
            page.close()
        browser.close()

    srv.shutdown()

    for r in rows:
        print(f"  {'EXEC ' if r['executed'] else 'no   '} {r['case']:26s} "
              f"nav={str(r['navigated']):5s} reqs={r['nav_requests']}",
              flush=True)

    by = {r["case"]: r for r in rows}
    print("\n=== controls ===")
    print("  A sentinel works            :", by["/case/script"]["executed"])
    print("  B javascript: observable    :", by["/case/iframe-js"]["executed"])
    print("  C refresh navigates to http :",
          "/child" in by["/case/meta-http"]["nav_requests"])
    print("  D refresh rejects about:    :",
          not any("/case/meta-badscheme" != u for u in [])
          and by["/case/meta-badscheme"]["navigated"])

    out = "benchmark/results/probe_meta_refresh_scheme.json"
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\nwritten:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

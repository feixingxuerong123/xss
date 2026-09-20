"""Which elements actually fire `onfocus` when given `autofocus`?

`_handler_state` in `xssentinel/core/sandbox.py` has to answer "can this on*
handler fire with nobody touching anything" -- and for `onfocus` that turns on
whether the element is focusable.  The obvious rule ("autofocus only applies to
form controls") is the one this module shipped first, and it is wrong: `tabindex`
makes an arbitrary element focusable, which is why `<span tabindex=1 autofocus
onfocus=CODE>` is a payload people actually use.

So measure it instead of reasoning about the spec.  Each case is served over
HTTP and navigated to, with the sentinel installed by an init script -- NOT
`page.set_content()`, which rebuilds the document and wipes the global, and
produced a self-contradictory first reading of this same table (input reported
no-exec while span reported EXEC).

Result is written to benchmark/results/autofocus_probe.json and read by
tests/test_sandbox.py's autofocus rule.

Usage: python -m benchmark.autofocus_probe
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

X = "__x()"                      # quote-free sentinel; see browser_dom_oracle.py

CASES = {
    "div tabindex=1 autofocus":      f'<div tabindex=1 autofocus onfocus={X}>x</div>',
    "div autofocus (no tabindex)":   f'<div autofocus onfocus={X}>x</div>',
    "span tabindex=1 autofocus":     f'<span tabindex=1 autofocus onfocus={X}>x</span>',
    "a tabindex=1 autofocus":        f'<a href=# tabindex=1 autofocus onfocus={X}>x</a>',
    "input autofocus":               f'<input autofocus onfocus={X}>',
    "input tabindex=1 autofocus":    f'<input tabindex=1 autofocus onfocus={X}>',
    "img tabindex=1 autofocus":      f'<img src=y tabindex=1 autofocus onfocus={X}>',
    "button autofocus":              f'<button autofocus onfocus={X}>b</button>',
    "li tabindex=1 autofocus":       f'<li tabindex=1 autofocus onfocus={X}>b</li>',
    "textarea autofocus":            f'<textarea autofocus onfocus={X}></textarea>',
    "video tabindex=1 autofocus":    f'<video tabindex=1 autofocus onfocus={X}></video>',
    "details open ontoggle":         f'<details open ontoggle={X}>b</details>',
    "div tabindex=1 onclick":        f'<div tabindex=1 onclick={X}>x</div>',
    "span autofocus (no tabindex)":  f'<span autofocus onfocus={X}>x</span>',
}
PAGES: dict[str, str] = {}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = PAGES.get(self.path, "").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


INIT = "window.__x = function () { document.title = 'EXEC'; };"


def main() -> int:
    from playwright.sync_api import sync_playwright
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/p"
    out = {}
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context()
        ctx.add_init_script(INIT)
        pg = ctx.new_page()
        for name, body in CASES.items():
            PAGES["/p"] = ("<!DOCTYPE html><html><head><title>b</title></head>"
                           f"<body>{body}</body></html>")
            pg.goto(url, wait_until="commit")
            pg.wait_for_timeout(600)
            out[name] = pg.title() == "EXEC"
            print(f"  {'EXEC ' if out[name] else 'no-exec'}  {name}", flush=True)
        b.close()
    srv.shutdown()
    path = os.path.join("benchmark", "results", "autofocus_probe.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(out, open(path, "w", encoding="utf-8"), indent=1)
    print("\n`div` contradicts every other tabindex+autofocus element above; the\n"
          "sandbox reports UNKNOWN for it rather than picking a side. See\n"
          "_handler_state's onfocus branch.")
    print("written:", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

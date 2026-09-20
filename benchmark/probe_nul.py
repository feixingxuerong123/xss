"""Where does a U+0000 in reflected markup actually go?

`xssentinel/core/sandbox.py` replaces NUL with U+FFFD in text and in attribute
*names* and did nothing to attribute *values* -- so `alt="a\x00b"` serialised
with the NUL still in it while Chromium's own innerHTML shows `a\ufffdb`.  That
is not cosmetic: `javascript:` URI detection has to match the value the DOM
actually holds, and a value that differs from the browser's is a rule reading
the wrong bytes.

Each shape below is served, then read back three ways, because the three can
disagree and only the pair-wise comparison shows which one a rule must use:

    innerHTML   what the parser serialises (what a round-trip re-parses)
    attr        the code points the DOM attribute really holds
    href        how an <a> resolved it, i.e. whether the browser sees a URL

Usage: python -m benchmark.probe_nul [--json out.json]
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from xssentinel.core import sandbox  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "nul_probe.json"
N = "\x00"

CASES: list[tuple[str, str]] = [
    ("attr-dq", f'<img alt="a{N}b" src=x>'),
    ("attr-sq", f"<img alt='a{N}b' src=x>"),
    ("attr-uq", f"<img alt=a{N}b src=x>"),
    ("attr-name", f"<img {N}alt=x src=y>"),
    ("text-p", f"<p>a{N}b</p>"),
    ("text-div", f"<div>a{N}b</div>"),
    ("textarea-nul", f"<textarea>a{N}b</textarea>"),
    ("script-nul", f"<script>var a='x{N}y'</script>"),
    ("jsuri-in-scheme", f'<a href="javascript{N}:__x()">c</a>'),
    ("jsuri-mid", f'<a href="java{N}script:__x()">c</a>'),
    ("jsuri-entity", '<a href="jav&#x00;ascript:__x()">c</a>'),
    ("jsuri-leading-ws", '<a href=" javascript:__x()">c</a>'),
    ("src-trailing", f'<img src="x{N}" onerror="__x()">'),
    ("handler-nul", f'<img src=x onerror="ale{N}rt(1)">'),
    ("srcdoc-nul", f'<iframe srcdoc=\'<img src=x onerror="top.a{N}b">\'></iframe>'),
    ("title-nul", f"<title>a{N}b</title>"),
    ("comment-nul", f"<p><!--a{N}b--></p>"),
    ("rawtext-nul", f"<style>a{N}{{color:red}}</style><img src=x onerror=__x()>"),
    # Tag names: `bypass.py` ships `<scr\x00ipt>alert(1)</scr\x00ipt>` as a
    # null-byte-insertion payload, and `payloads.json` carries it too.  Whether
    # the NUL is *dropped* (making a real <script>) or *replaced* (making an
    # unknown inert element) is the difference between that payload being a
    # finding and being noise, so it is measured, not assumed.
    ("tagname-script-nul", f"<scr{N}ipt>alert(1)</scr{N}ipt>"),
    ("tagname-unknown-nul", f"<div{N}x>a</div{N}x>"),
    ("endtag-nul", f"<p>a</p{N}>"),
    ("svg-handler-leading-nul", f'<svg onload={N}top.__x()></svg>'),
]

_PROBE = """
(o) => {
  const c = document.createElement('div');
  c.innerHTML = o.html;
  const hex = (s) => Array.from(s).map(ch => ch.codePointAt(0).toString(16)).join(' ');
  const attrs = [];
  for (const el of c.querySelectorAll('*')) {
    const n = el.tagName.toLowerCase();
    const list = [];
    for (const a of el.attributes) list.push(a.name + '=' + hex(a.value));
    // textContent as CODE POINTS, because the serialisation alone cannot tell a
    // dropped NUL from a U+FFFD that simply does not print here
    // tag name hexed too: `scr<NUL>ipt` may become `SCR\ufffdIPT`, and a
    // printable tag name cannot tell that apart from `SCRIPT`
    const row = {tag: n, taghex: hex(n), attrs: list, text: hex(el.textContent)};
    if (n === 'a') { try { row.href = el.href; } catch (e) { row.href = null; } }
    attrs.push(row);
  }
  return {ser: c.innerHTML, dom: attrs};
}
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        raw = b"<html><body></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context().new_page()
            for attempt in range(3):
                try:
                    page.goto(base + "/", wait_until="load")
                    break
                except Exception:
                    page.wait_for_timeout(150 * (attempt + 1))
            for name, html in CASES:
                try:
                    got = page.evaluate(_PROBE, {"html": html})
                except Exception as e:
                    rows.append({"case": name, "err": str(e)[:120]})
                    continue
                sb = sandbox.serialize(sandbox.parse(html).root)
                rows.append({"case": name, "input": html, "browser": got["ser"],
                             "dom": got["dom"], "sandbox": sb})
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def report(rows: list[dict]) -> int:
    bad = 0
    for r in rows:
        if r.get("err"):
            print(f"{r['case']:<18} ERR {r['err']}")
            bad += 1
            continue
        agree = r["browser"] == r["sandbox"]
        if not agree:
            bad += 1
        print(f"{r['case']:<18} {'ok' if agree else 'DIFF'}")
        print(f"    browser : {r['browser']!r}")
        if not agree:
            print(f"    sandbox : {r['sandbox']!r}")
        for row in r["dom"]:
            print(f"    dom[{row['tag']}|{row.get('taghex')}] {row['attrs']}"
                  + (f" text={row.get('text')!r}" if row.get("text") else "")
                  + (f" href={row.get('href')!r}" if "href" in row else ""))
    print(f"\n{len(rows) - bad}/{len(rows)} shapes serialise identically to Chromium")
    return bad


if __name__ == "__main__":
    rows = run()
    dest = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else str(OUT)
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    raise SystemExit(1 if report(rows) else 0)

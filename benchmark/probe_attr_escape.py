"""Which characters does Chromium escape in an attribute value?

`_serialize_attr_value` escapes `& " < >` and the control characters, a rule
written from a mix of the serialisation spec and one early measurement.  The
random differential fuzzer (`benchmark/fuzz_dom_diff.py`) immediately disagreed
on TAB: `<table attributename="\t">` comes back from Chromium with the tab
*inside* the quotes, while the sandbox writes `&#9;`.

That is not cosmetic.  Attribute values are re-parsed on a round-trip, so a
serialiser that invents character references changes the bytes a mutation
verdict is judged on, and a serialiser that fails to emit them where Chromium
does would do the same in the other direction.

So: ask the browser about each character once, for all three quoting styles,
rather than patching one character at a time.

Usage: python -m benchmark.probe_attr_escape
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

OUT = pathlib.Path(__file__).resolve().parent / "results" / "attr_escape.json"

# name -> the literal text placed inside the attribute value.  Values are chosen
# so a character reference in the output is distinguishable from the raw byte.
CHARS = {
    "tab": "\t",
    "newline": "\n",
    "carriage": "\r",
    "formfeed": "\f",
    "nul": "\x00",
    "ctrl01": "\x01",
    "ctrl1f": "\x1f",
    "nbsp": "\xa0",
    "amp": "&",
    "amp-entity": "&amp;",
    "lt": "<",
    "gt": ">",
    "dquote": '"',
    "squote": "'",
    "fffd": "\ufffd",
    "space": " ",
    "slash": "/",
    "backslash": "\\",
}


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


_PROBE = """
(o) => {
  const out = {};
  for (const [k, v] of Object.entries(o.cases)) {
    const d = document.createElement('div');
    d.innerHTML = v;
    out[k] = d.innerHTML;
  }
  return out;
}
"""


def _cases(quote: str) -> dict[str, str]:
    out = {}
    for name, ch in CHARS.items():
        if quote == "dq":
            out[f"{name}-dq"] = f'<table x="{ch}y"></table>'
        elif quote == "sq":
            out[f"{name}-sq"] = f"<table x='{ch}y'></table>"
        else:
            # unquoted: a value terminates at whitespace, so skip the ones that
            # would split the tag -- those are covered by the quoted arms
            if ch in " \t\n\r\f\"'`<>=":
                continue
            out[f"{name}-uq"] = f"<table x={ch}y></table>"
    return out


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
            page.goto(base + "/", wait_until="load")
            for quote in ("dq", "sq", "uq"):
                cases = _cases(quote)
                br = page.evaluate(_PROBE, {"cases": cases})
                for key, html in cases.items():
                    mine = sandbox.serialize(
                        sandbox.parse(html, fragment=True).root)
                    rows.append({"case": key, "input": html,
                                 "chromium": br.get(key), "sandbox": mine})
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def report(rows: list[dict]) -> int:
    bad = 0
    for r in rows:
        ok = r["chromium"] == r["sandbox"]
        if not ok:
            bad += 1
            print(f"  {r['case']:<16} in={r['input']!r}")
            print(f"      chromium: {r['chromium']!r}")
            print(f"      sandbox : {r['sandbox']!r}")
    print(f"\n{len(rows) - bad}/{len(rows)} attribute-value serialisations "
          f"match Chromium byte for byte")
    return bad


if __name__ == "__main__":
    rows = run()
    dest = (sys.argv[sys.argv.index("--json") + 1]
            if "--json" in sys.argv else str(OUT))
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    raise SystemExit(1 if report(rows) else 0)

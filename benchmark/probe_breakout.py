"""Measure which start tags actually break out of foreign content.

The HTML spec's "break out of foreign content" list is easy to mis-remember, and
guessing it in `sandbox.py` was measurably wrong in both directions: `<select>`
does not break out where the list says it should, `<template>` does not break
out at all, and each mistake moves an XSS verdict.

The experiment is direct: put `<svg><CAND><img src=x onerror=SENT>` in the page
and look at where the img landed.  If it is a child of the svg, the candidate
stayed foreign; if it is a sibling of the svg, the candidate broke out.  The
img's own liveness is read too, because that is the only thing the sandbox needs
to get right.

Usage: python -m benchmark.probe_breakout
Writes benchmark/results/foreign_breakout.json
"""
from __future__ import annotations

import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, ".")

# Candidate tag names, unioned from the spec list, the elements a pentest
# payload reaches for, and every name currently in sandbox.FOREIGN_BREAK.
CANDIDATES = sorted(set("""
a abbr address area article aside audio b base basefont bgsound big blockquote
body br button caption center col colgroup data datalist dd details dfn dialog
dir div dl dt em embed fieldset figcaption figure font footer form h1 h2 h3 h4
h5 h6 head header hgroup hr html i iframe img input ins kbd keygen label legend
li link listing main map mark menu menuitem meta meter nav noembed noframes
noscript object ol optgroup option output p param picture plaintext pre progress
q rp rt ruby s samp script search section select small source span strike
strong style sub summary sup table tbody td template textarea tfoot th thead
time title tr tt u ul var video wbr xmp
""".split()))

JS = """
(o) => {
  const c = document.createElement('div');
  c.innerHTML = o.frag;
  document.body.appendChild(c);
  // The root selector has to be the container actually under test.  The first
  // revision hardcoded 'svg' and probed <math> with it, so `svg` was null,
  // `svg.contains(img)` was null, and every MathML name came back as
  // "broke out" -- 120 out of 120, which is not a result, it is a broken probe.
  const host = c.querySelector(o.root);
  // Look the candidate up in the whole container, not inside `root *`: an
  // element that broke out is by definition not under the foreign root, and
  // scoping the query there reports "no such element" for exactly the cases
  // the measurement exists to find.
  const cand = c.querySelector(o.cand);
  const img = c.querySelector('img');
  const candKids = host ? Array.from(host.querySelectorAll('*'))
    .map(e => e.tagName.toLowerCase()) : null;
  return {
    // The question is where the CANDIDATE element ended up: inside the foreign
    // subtree, or in the HTML tree alongside it.  Asking about the img instead
    // answers "does img break out", which is the same for every candidate.
    cand_created: !!cand,
    cand_stayed_foreign: cand ? !!(host && host.contains(cand)) : null,
    cand_ns: cand ? (cand.namespaceURI || '').split('/').pop() : null,
    img_stayed_foreign: img ? !!(host && host.contains(img)) : null,
    host_children: candKids,
    ser: c.innerHTML,
  };
}
"""


def main() -> int:
    from playwright.sync_api import sync_playwright
    results = {}
    math_results = {}
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.goto("about:blank")
        page.evaluate("() => { window.__x = () => { window.__hit = true; }; }")
        for root, store, opener in (("svg", results, "<svg>"),
                                    ("math", math_results, "<math>")):
            for cand in CANDIDATES:
                frag = f"{opener}<{cand}><img src=x onerror=__x()>"
                store[cand] = page.evaluate(
                    JS, {"frag": frag, "root": root, "cand": cand})
                page.evaluate("() => { document.body.innerHTML = ''; }")
        b.close()

    out = os.path.join("benchmark", "results", "foreign_breakout.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"svg": results, "mathml": math_results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    def names(store, want):
        return sorted(k for k, v in store.items()
                      if v["cand_stayed_foreign"] is want)

    svg_stays = names(results, True)
    svg_break = names(results, False)
    svg_und = sorted(k for k, v in results.items()
                     if v["cand_stayed_foreign"] is None)
    math_stays = names(math_results, True)
    math_break = names(math_results, False)

    print(f"probed {len(CANDIDATES)} tag names inside <svg> and inside <math>\n")
    print(f"SVG: stays foreign ({len(svg_stays)}) -- and img still breaks out:")
    print("   " + " ".join(svg_stays))
    print(f"\nSVG: breaks out ({len(svg_break)}):")
    print("   " + " ".join(svg_break))
    if svg_und:
        print(f"\nSVG: no such element created ({len(svg_und)}):")
        print("   " + " ".join(svg_und))
    print(f"\nMathML: stays foreign ({len(math_stays)}):")
    print("   " + " ".join(math_stays))
    print(f"\nMathML: breaks out ({len(math_break)}):")
    print("   " + " ".join(math_break))
    print("\nSandbox tables to write from this measurement:")
    print("SVG_BREAK_OUT = {" + ", ".join(f'"{n}"' for n in svg_break) + "}")
    print("MATHML_BREAK_OUT = {" + ", ".join(f'"{n}"' for n in math_break) + "}")
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

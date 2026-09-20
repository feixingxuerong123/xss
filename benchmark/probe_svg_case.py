"""Does Chromium case-adjust SVG/MathML attribute names the way the sandbox does?

`benchmark/sandbox_fidelity.py` spends most of its remaining divergence budget on
one payload family, `svg-animate`: the sandbox printed `attributename` where the
browser printed `attributeName`.  Serialisation is not cosmetic here -- the
round-trip *is* the mXSS model, so a name the sandbox rewrites differently from
the DOM produces a second parse that never happened.

The fix is a lookup table, and a lookup table written from memory of the spec is
exactly the kind of citation this project has caught me inventing twice.  So this
file checks every entry: one page per name, `div.innerHTML = <payload>`, read the
serialised DOM back, and compare it byte for byte with `sandbox.serialize()`.

Also covered, because each is a different rule that could independently be wrong:
the already-correct spelling, an all-caps spelling, a *prefixed* name (`xlink:`,
`xmlns:`, which must survive untouched), an attribute on the `<svg>` element
itself, the MathML side, an HTML attribute inside an integration point (must NOT
be adjusted), and the foreign element names.

Usage: python -m benchmark.probe_svg_case [--json out.json]
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.browser_dom_oracle import (  # noqa: E402
    _Handler, _goto, _serve)
from xssentinel.core import sandbox  # noqa: E402
from xssentinel.core.sandbox import _SVG_ATTR_CASE, _MATHML_ATTR_CASE  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "svg_case.json"

#: How the round-trip is read: a div sink, because that is the sink the scanner
#: models, and the same one `BROWSER_SERIALISATION` in tests/test_sandbox.py used.
_READ = """(h) => {
  const d = document.createElement('div');
  d.innerHTML = h;
  return d.innerHTML;
}"""


def _attr_cases() -> list[tuple[str, str]]:
    """(label, payload) -- one per table entry, keyed on what the table claims."""
    out: list[tuple[str, str]] = []
    for low, want in sorted(_SVG_ATTR_CASE.items()):
        out.append((f"svg:{low}->{want}",
                    f'<svg><animate {low}="v"></animate></svg>'))
    for low, want in sorted(_MATHML_ATTR_CASE.items()):
        out.append((f"math:{low}->{want}",
                    f'<math><annotation-xml {low}="v"></annotation-xml></math>'))
    # the spellings a payload author actually sends
    out.append(("svg:ATTRIBUTENAME-upper",
                '<svg><animate ATTRIBUTENAME="v"></animate></svg>'))
    out.append(("svg:attributeName-as-is",
                '<svg><animate attributeName="v"></animate></svg>'))
    out.append(("svg:viewbox-on-root",
                '<svg viewbox="0 0 1 1"><rect/></svg>'))
    # prefixed names are not in the table and must come back unchanged
    out.append(("svg:xlink-href-prefix",
                '<svg><use xlink:href="#a"></use></svg>'))
    out.append(("svg:xmlns-xlink-decl",
                '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><use/></svg>'))
    out.append(("svg:xml-space-prefix", '<svg><text xml:space="preserve">t</text></svg>'))
    # an attribute that is NOT on the list, on a foreign element
    out.append(("svg:href-untouched", '<svg><a href="/x">t</a></svg>'))
    out.append(("svg:onerror-untouched",
                '<svg><img onerror="__x()" src=x></svg>'))
    # integration point: HTML content, so no adjustment may happen
    out.append(("svg-integration-html-attr",
                '<svg><foreignObject><div attributename="v">t</div>'
                '</foreignObject></svg>'))
    out.append(("math-integration-html-attr",
                '<math><mtext><span attributename="v">t</span></mtext></math>'))
    # foreign ELEMENT names, the sibling rule.  Every SVG element with a capital
    # in its spec name is on this list, because the sandbox table that reads them
    # was written from three samples and a three-sample table is how the
    # `<option>` rule went wrong.
    for el in SVG_ELEMENTS:
        out.append((f"elem:{el}", f'<svg><{el} id="x"></{el}></svg>'))
    return out


#: Lowercase as the tokenizer delivers it; only the round-trip decides the case.
SVG_ELEMENTS = [
    "a", "animate", "animatecolor", "animatemotion", "animatetransform",
    "circle", "clippath", "defs", "desc", "discard", "ellipse", "feblend",
    "fecolormatrix", "fecomponenttransfer", "fecomposite", "feconvolvematrix",
    "fediffuselighting", "fedisplacementmap", "fedistantlight", "fedropshadow",
    "feflood", "fefunca", "fefuncb", "fefuncg", "fefuncr", "fegaussianblur",
    "feimage", "femerge", "femergenode", "femorphology", "feoffset",
    "fepointlight", "fespecularlighting", "fespotlight", "fetile",
    "feturbulence", "filter", "foreignobject", "g", "hatch", "hatchpath",
    "image", "line", "lineargradient", "marker", "mask", "metadata", "mpath",
    "path", "pattern", "polygon", "polyline", "radialgradient", "rect", "set",
    "stop", "svg", "switch", "symbol", "text", "textpath", "tspan", "use",
    "view",
    # The last four are spelled with capitals on purpose.  A foreign tag name is
    # lowercased first and *then* looked up, so `<viewBox>` becomes `viewbox` (an
    # unknown element, left alone) while `<FEgaussianBlur>` still finds
    # `feGaussianBlur`.  Those four rows are what says the table is keyed on the
    # lowercased name and not on the bytes.
    "animateAttributeSet", "viewBox", "FEgaussianBlur", "ForeignObject",
]


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    cases = _attr_cases()
    srv, base = _serve()
    _Handler.PAGES = {"/blank": "<html><body></body></html>"}
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            page = ctx.new_page()
            for label, payload in cases:
                row: dict[str, object] = {"case": label, "input": payload}
                if not _goto(page, base + "/blank"):
                    row.update({"chromium": None, "harness_error": "reset"})
                    rows.append(row)
                    continue
                try:
                    row["chromium"] = page.evaluate(_READ, payload)
                except Exception as e:
                    row["chromium"] = None
                    row["err"] = str(e)[:120]
                rows.append(row)
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def report(rows: list[dict]) -> int:
    bad = 0
    for r in rows:
        ch = r.get("chromium")
        if ch is None:
            print(f"{r['case']:<34} INCONCLUSIVE {r.get('harness_error') or r.get('err')}")
            bad += 1
            continue
        mine = sandbox.serialize(sandbox.parse(r["input"], fragment=True).root)
        if mine != ch:
            bad += 1
            print(f"DIFF {r['case']}")
            print(f"     in : {r['input']!r}")
            print(f"     chr: {ch!r}")
            print(f"     mine:{mine!r}")
    print(f"\n{len(rows) - bad}/{len(rows)} foreign-name round-trips byte-identical")
    return bad


if __name__ == "__main__":
    rows = run()
    dest = (sys.argv[sys.argv.index("--json") + 1]
            if "--json" in sys.argv else str(OUT))
    pathlib.Path(dest).parent.mkdir(parents=True, exist_ok=True)
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\nwritten:", dest)
    raise SystemExit(1 if report(rows) else 0)

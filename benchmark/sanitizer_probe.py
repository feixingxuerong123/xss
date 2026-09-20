"""Does an allow-list re-serialisation actually create mutation XSS?

Phase 169 measured 820 (payload x context x sink) cases and found
**zero** mutation vectors in a bare `parse -> innerHTML -> parse` round trip:
whatever is live on the first parse is live on the second, and nothing becomes
live that was not.  So the mechanism the field calls "mXSS" is not the round
trip -- it is the step where something *between* the two parses writes the DOM
back out under an allow-list, and that serialisation differs from the browser's.

`xssentinel/core/sanitizer_bypass.py` (layer L7) only pattern-matches that
situation: version ranges, weak configs, `sanitize(x) -> innerHTML`.  It says so
in its own docstring -- "heuristic, flags for human review rather than proving
exploitation".  `mxss_verify.py` tried to prove it with a browser but round
trips `innerHTML`, which this measurement now knows proves nothing.

So this script asks the one question that decides whether an mXSS model is
worth building:

    parse(payload)  ->  ALLOW-LIST WALK  ->  serialise  ->  re-parse
                                                    ^
                                          does the marker get LIVE here
                                          when it was INERT before?

with a control that runs the same payload through parse -> serialise -> re-parse
with **no** allow-list in the middle.  If the control fires, the payload is
ordinary XSS and should not be called mutation.  If only the allow-list arm
fires, the sanitizer's own serialisation created the vector -- that is real mXSS,
and it is worth modelling.

The allow-list walk is written in JS and runs on the browser's real DOM, so its
output is the browser's serialisation of a filtered tree -- not a Python model
of one.  That is the point: the ground truth has to come from the thing we are
trying to predict.  It is deliberately NOT DOMPurify's exact config; this
measures whether the *mechanism* exists, not DOMPurify's CVE list.

Usage: python -m benchmark.sanitizer_probe
Writes benchmark/results/sanitizer_probe.json
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, ".")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

#: Quote-free sentinel, for the reason written in the first version's docstring
#: and then violated by it: `S = 'document.title="EXEC"'` inside
#: `onerror="…"` closes the attribute at the second `"`, the handler compiles as
#: `document.title=`, and a vector that really fires reports "inert".  Only the
#: *unquoted* attribute spellings survived, so the first run's per-vector column
#: was a quoting artefact rather than a result.  Same discipline as
#: benchmark/browser_dom_oracle.py: the sentinel must never be able to break the
#: syntax it is being tested in.
SENTINEL = "__x()"

# The classic mutation families -- each one is a payload whose fate is decided by
# *how the serialiser writes the tree back out*, not by what the parser saw.
VECTORS: list[tuple[str, str]] = [
    ("svg-style-img", f'<svg><style><img src=x onerror="{SENTINEL}"></style></svg>'),
    ("svg-p-style",
     f'<svg></p><style><a id="</style><img src=x onerror={SENTINEL}>">'),
    ("math-mtext-table-mglyph",
     f'<math><mtext><table><mglyph><style>'
     f'<img src=x onerror="{SENTINEL}"></style>'),
    ("form-math-mtext",
     f'<form><math><mtext></form><form><mglyph><style>'
     f'</style><img src=x onerror={SENTINEL}>'),
    ("noscript-p-title",
     f'<noscript><p title="</noscript><img src=x onerror={SENTINEL}>">'),
    ("annotation-xml-html",
     f'<math><annotation-xml encoding="text/html">'
     f'<img src=x onerror="{SENTINEL}"></annotation-xml></math>'),
    ("table-caption-td-svg",
     f'<table><caption></caption><td><svg><style>'
     f'<img src=x onerror="{SENTINEL}"></style></svg></td></table>'),
    ("template-svg", f'<template><svg onload="{SENTINEL}"></svg></template>'),
    ("xmp-noscript", f'<xmp><noscript></xmp><img src=x onerror={SENTINEL}>'),
    ("select-style-option",
     f'<select><option><style></option></select>'
     f'<img src=x onerror={SENTINEL}></style></select>'),
    ("dloption-svg", f'</select><option><svg><style>'
                     f'<img src=x onerror="{SENTINEL}">'),
    ("comment-svg-style", f'<!--<svg><style></style></svg>-->'
                          f'<img src=x onerror={SENTINEL}>'),
    ("listing-script", f'<listing><script>{SENTINEL}</script>'),
    ("textarea-close", f'<textarea></textarea><img src=x onerror={SENTINEL}>'),
    ("title-close", f'<title></title><img src=x onerror={SENTINEL}>'),
    ("svg-foreignobject",
     f'<svg><foreignObject><div onclick="{SENTINEL}">y</div></foreignObject></svg>'),
    ("cdata-svg", f'<svg><![CDATA[<img src=x onerror="{SENTINEL}>"]]></svg>'),
    ("style-attr-break", f'<style>a{{}}</style><img src=x onerror={SENTINEL}>'),
]

# An allow-list with the shape real sanitizers have: common HTML, SVG allowed
# (as DOMPurify allows it by default), event handlers and javascript: URIs
# stripped, KEEP_CONTENT semantics (a dropped element keeps its children).
PROBE_JS = """
async (o) => {
  // Each arm gets a clean slate AND a cleared title.  `onerror` fires on its own
  // schedule, so a node left in the body by arm A can report into arm B's read
  // -- the exact contamination that made the first browser_dom_oracle run print
  // the parser's answer for every sink.  The old comment here said "fresh
  // document" while only resetting document.title.
  const reset = () => { document.title = ''; document.body.innerHTML = ''; };
  const arm = async (html) => {
    reset();
    const c = document.createElement('div');
    c.innerHTML = html;
    document.body.appendChild(c);
    await new Promise(res => setTimeout(res, o.settle));
    return document.title === 'EXEC';
  };
  const r = {raw: null, sanitized: null, mutated: false, err: null};
  try {
    reset();
    const a = document.createElement('div');
    a.innerHTML = o.payload;
    r.raw = a.innerHTML;
    r.ctrl_fires = await arm(o.payload);                 // parse once, as served
    r.ctrl_roundtrip_fires = await arm(r.raw);           // + browser serialise
    const s = document.createElement('div');
    s.innerHTML = o.payload;
    r.sanitized = await window.__sanitize(s);            // allow-list serialise
    r.mutated = r.sanitized !== r.raw;
    r.san_fires = await arm(r.sanitized);                // re-parse that output
  } catch (e) { r.err = String(e).slice(0, 200); }
  return r;
}
"""

ALLOW = ("a|abbr|b|blockquote|br|caption|center|cite|code|col|colgroup|dd|del|"
         "details|div|dl|dt|em|figcaption|figure|footer|h1|h2|h3|h4|h5|h6|"
         "header|hr|html|i|img|ins|kbd|li|main|map|mark|nav|ol|optgroup|"
         "option|p|pre|q|rb|rp|rt|rtc|ruby|s|samp|section|select|small|span|"
         "strike|strong|sub|summary|sup|table|tbody|td|tfoot|th|thead|"
         "time|tr|tt|u|ul|var|wbr|svg|path|circle|rect|line|polyline|polygon|"
         "text|tspan|g|defs|use|animate|set|foreignObject|desc|title|style|"
         "math|mi|mn|mo|ms|mtext|mglyph|malignmark|annotation-xml|noscript|"
         "listing|xmp|plaintext|iframe|form|button|input|textarea|body")
ATTRS = ("class|id|style|title|href|src|alt|width|height|align|valign|border|"
         "colspan|rowspan|start|type|value|name|placeholder|disabled|checked|"
         "open|contenteditable|dir|lang|tabindex|encoding|xlink:href|d|cx|cy|r|"
         "x|y|width|http-equiv|content|srcdoc|action|formaction|attributeName|"
         "values|begin|dur|fill|span|size|face|color|bgcolor")


def main() -> int:
    from playwright.sync_api import sync_playwright
    settle = 320
    rows = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        page.goto("about:blank")
        # The sentinel.  No navigations happen after this, so a plain evaluate
        # is enough -- and it must survive the whole run, because every arm
        # compares against the same observable.
        page.evaluate("() => { window.__x = function () "
                      "{ document.title = 'EXEC'; }; }")
        page.evaluate("""(a) => {
          window.__allow = a.allow; window.__attrs = a.attrs;
        }""", {"allow": ALLOW, "attrs": ATTRS})
        for name, payload in VECTORS:
            page.evaluate("() => { document.title=''; document.body.innerHTML=''; }")
            # The sanitize helper is defined per page so it can read the DOM.
            page.evaluate("""(a) => {
              window.__sanitize = async (root) => {
                return await new Promise(res => {
                  const ALLOW = new Set(a.allow.split('|'));
                  const ATTR = new Set(a.attrs.split('|'));
                  const URI = new Set(['href','src','xlink:href','action','formaction']);
                  const out = document.createDocumentFragment();
                  const walk = (node, parentDst) => {
                    for (const child of Array.from(node.childNodes)) {
                      if (child.nodeType === 3) { parentDst.appendChild(child.cloneNode()); continue; }
                      if (child.nodeType === 8) continue;
                      if (child.nodeType !== 1) continue;
                      const tag = child.tagName.toLowerCase();
                      let target = parentDst;
                      if (ALLOW.has(tag)) {
                        const el = document.createElementNS(child.namespaceURI, child.tagName);
                        for (const at of Array.from(child.attributes)) {
                          const nm = at.name.toLowerCase();
                          if (/^on/.test(nm)) continue;
                          if (!ATTR.has(nm)) continue;
                          if (URI.has(nm) && /^\\s*(java|)script:/i.test(at.value.replace(/[\\u0000-\\u001f]/g,''))) continue;
                          try { el.setAttribute(at.name, at.value); } catch (e) {}
                        }
                        parentDst.appendChild(el);
                        target = el;
                      }
                      walk(child, target);
                    }
                  };
                  walk(root, out);
                  const holder = document.createElement('div');
                  holder.appendChild(out);
                  res(holder.innerHTML);
                });
              };
            }""", {"allow": ALLOW, "attrs": ATTRS})
            r = page.evaluate(PROBE_JS, {"payload": payload, "settle": settle})
            r["name"] = name
            r["payload"] = payload
            # mXSS, defined honestly: inert before the allow-list, live after it.
            r["mxss"] = bool(r.get("san_fires") and not r.get("ctrl_fires"))
            rows.append(r)
            print(f"  {'MXSS ' if r['mxss'] else '     '}"
                  f"raw={'fire' if r.get('ctrl_fires') else 'inert '}"
                  f" rt={'fire' if r.get('ctrl_roundtrip_fires') else 'inert '}"
                  f" san={'fire' if r.get('san_fires') else 'inert '}"
                  f" mutated={'Y' if r.get('mutated') else 'n'}  {name}",
                  flush=True)
        b.close()

    out = os.path.join("benchmark", "results", "sanitizer_probe.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump({"vectors": len(rows), "allow_list": ALLOW, "attrs": ATTRS,
               "rows": rows}, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    fire_raw = [r for r in rows if r.get("ctrl_fires")]
    mxss = [r for r in rows if r["mxss"]]
    # The finding that matters came from THIS arm, not the sanitizer arm: the
    # browser's own serialise-and-reparse turned an inert payload live.  The
    # first version of this summary printed only the allow-list number and
    # reported "mutation vectors: 0" while the column beside it said `rt=fire`
    # for a payload that was `raw=inert`.  Report both, or the script's own
    # output contradicts its own data.
    rt_mxss = [r for r in rows
               if r.get("ctrl_roundtrip_fires") and not r.get("ctrl_fires")]
    lost = [r for r in rows if r.get("ctrl_fires") and not r.get("san_fires")]
    print("\n=== summary ===")
    print(f"vectors: {len(rows)}   live as-served (ordinary XSS): {len(fire_raw)}")
    print(f"BARE round-trip vectors (no sanitizer, inert->live): "
          f"{len(rt_mxss)}")
    for r in rt_mxss:
        print(f"    RT-MXSS  {r['name']}")
        print(f"      payload: {r['payload'][:110]}")
        print(f"      raw ser: {r['raw'][:110]}")
    print(f"allow-list round-trip vectors (sanitizer needed)   : {len(mxss)}")
    for r in mxss:
        print(f"    SAN-MXSS  {r['name']}")
        print(f"      raw : {r['raw'][:110]}")
        print(f"      san : {str(r['sanitized'])[:110]}")
    print(f"allow-list removed a live vector: {len(lost)} "
          f"({', '.join(r['name'] for r in lost[:6])})")
    print(f"errors: {[r['name'] for r in rows if r.get('err')]}")
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

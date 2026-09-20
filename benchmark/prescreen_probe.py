"""Measure before touching the browser pre-screen: could the HTML sandbox
replace or sharpen `dom_engine.page_can_run_sink`?

Phase 159 built that pre-screen as a *prove-inert* filter (regex over the raw
page: any paren, any DOM global, any member assignment -> keep the browser).
It costs ~5.6 s per skipped-eligible session, and 41 of the 57 slow benchmark
cases paid it unnecessarily, so making it sharper is worth real wall clock.

The tempting answer is "use the sandbox -- it knows markup properly".  This
script exists to find out whether that is true, and it is deliberately written
to be able to say NO:

  * the markup-level question (`<img onerror>`, `javascript:` URI, srcdoc, live
    <script>) is exactly what `sandbox` answers well;
  * but a DOM-XSS finding's execution surface is a **JS data-flow**
    (`location.hash` -> `innerHTML`), which lives in the inline script body and
    in no markup at all.  A markup-only predicate does not merely miss the
    optimisation there -- it skips the page, and every DOM finding with it.

So the measurement reports, per benchmark case, three verdicts side by side and
the two numbers that decide the question: how much would be newly skipped, and
how many `dom_xss` / stored-DOM cases would be newly skipped.  A non-zero second
number ends the idea.

Usage: python -m benchmark.prescreen_probe
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, ".")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from xssentinel.core import sandbox                      # noqa: E402
from xssentinel.core.dom_engine import page_can_run_sink  # noqa: E402
from benchmark import server                              # noqa: E402

# The pre-screen is evaluated on the page the server returns BEFORE any payload
# is reflected into it -- that is what "is this page worth a browser session"
# means.  So the placeholder must carry no markup at all.  Using a real payload
# here was the first version's mistake: it made the answer depend on which
# payload was being tried, and a predicate that varies with the payload is not a
# page property and cannot pre-screen anything.
PROBE = "Pz"

# Cases whose whole point is a sink that exists only inside JS.
DOM_CONTEXTS = {"dom_xss"}


def _modes() -> dict:
    out = dict(getattr(server, "MODES", {}))
    out.update(getattr(server, "MODES_CTX", {}))
    out.update(getattr(server, "PAGE_MODES", {}))
    return out


def _page_for(mode: str) -> str:
    """Render one lab page for `mode`, tolerant of the two call signatures.

    Modes that need state this script does not drive (stored/write-then-read,
    upload, response-header, mutation) return nothing here; they are counted and
    reported as uncovered rather than silently dropped from the denominator.
    """
    fn = _modes().get(mode)
    if fn is None:
        return ""
    try:
        try:
            res = fn(PROBE, {})
        except TypeError:
            res = fn(PROBE)
    except Exception:
        return ""
    if isinstance(res, tuple):
        res = res[-1]
    return res or ""


def _markup_executable(html: str) -> bool:
    """The sandbox's honest answer to 'does this page carry markup-level
    execution surface?'  -- deliberately payload-free (token="")."""
    if not html:
        return False
    state, detail = sandbox.find_live_nodes(sandbox.parse(html).root, "",
                                            sink="parser")
    return state == "live"


def main() -> int:
    manifest = json.load(open("benchmark/manifest.json", encoding="utf-8"))
    cases = manifest["cases"] if isinstance(manifest, dict) else manifest
    rows = []
    for c in cases:
        page = _page_for(c.get("mode", ""))
        if not page:
            continue
        rows.append({
            "id": c.get("id"), "context": c.get("context"),
            "ground_truth": c.get("ground_truth"),
            "regex_keeps": page_can_run_sink(page),
            "markup_keeps": _markup_executable(page),
        })

    total = len(rows)
    regex_skips = [r for r in rows if not r["regex_keeps"]]
    markup_skips = [r for r in rows if not r["markup_keeps"]]
    newly = [r for r in markup_skips if r["regex_keeps"]]
    dom_losers = [r for r in newly
                  if r["context"] in DOM_CONTEXTS or "dom" in str(r["id"])]
    stored_losers = [r for r in newly
                     if r["context"] in {"stored_xss", "second_order"}]

    print(f"pages rendered from the manifest : {total}/{len(cases)}")
    print(f"skipped today (Phase 159 regex)  : {len(regex_skips)}"
          f"  ({len(regex_skips) / max(1, total):.0%})")
    print(f"skipped by a markup-only sandbox : {len(markup_skips)}"
          f"  ({len(markup_skips) / max(1, total):.0%})")
    print(f"NEWLY skipped (the claimed gain) : {len(newly)}")
    print(f"NEWLY skipped DOM cases (the cost): {len(dom_losers)}")
    for r in dom_losers[:12]:
        print(f"    would silently drop  {r['id']:14s} {r['context']}"
              f"  ground_truth={r['ground_truth']}")
    print(f"NEWLY skipped stored/2nd-order   : {len(stored_losers)}")
    for r in stored_losers[:6]:
        print(f"    would silently drop  {r['id']:14s} {r['context']}")

    print("\n--- verdict ---")
    if dom_losers or stored_losers:
        print("A markup-only sandbox pre-screen is UNSAFE: it skips pages whose")
        print("execution surface is a JS data-flow (location.hash -> innerHTML),")
        print("which is the entire point of a DOM probe. The regex over-approximates")
        print("on purpose -- Phase 159 inverted it to 'prove inert' after Phase 154's")
        print("sink whitelist proved too narrow, and markup-only is narrower still.")
    else:
        print(f"Safe on this corpus: {len(newly)} pages newly skipped, no DOM case")
        print("lost. Worth wiring in, but weigh the gain against 41 sessions of")
        print("~5.6 s in the full run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

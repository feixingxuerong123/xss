"""The SVG/MathML namespace: what actually executes, and what only waits for a click.

`benchmark/corpus_gap.py` still lists ~40 shipped payloads whose tokens no
measured corpus has ever judged, and they fall into three families:

    xlink:href / href carrying a `javascript:` URI
        `<svg><a xlink:href>`, `<svg><image href>`, `<svg><use xlink:href>`,
        `<svg><feImage href>`, `<math><maction xlink:href>`.  The sandbox
        currently *declines* all of them ("not measured"), which is honest but
        costs a browser round-trip per candidate and blocks the gate's promotion
        arm.

    `onload` on an inner SVG element
        `<svg><desc onload>`, `<clipPath onload>`, `<ellipse onload>`,
        `<filter onload>`, `<use onload>`...  `AUTO_FIRING_EVENTS` says `onload`
        is auto-firing on `svg`, `body`, `img`, `script` and friends; an inner
        SVG element has no resource to load, so the same table would be an OVER
        if it applied there.

    the click-only shapes
        `<svg><a href=javascript:>` is `live(+act)`, `<button onclick>` is
        `live(+act)`.  A False from the auto arm is *not* evidence of inert for
        these -- that is the bounded-False rule this project keeps having to
        relearn -- so the harness asks a second, trusted question: click it.

Three arms per case, then: `auto` (the page as served, no interaction), `ihn`
(the same bytes through a `div.innerHTML` sink), and `click` (a real mouse click
at the element's own box, only for cases that declare a selector).  A case with no
selector cannot referee an inert verdict, and says so.

Usage: python -m benchmark.probe_svg_ns [--json out.json]
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.browser_dom_oracle import (  # noqa: E402
    _INIT, _Handler, _clear, _goto, _read_hit, _serve, _wait_load)
from xssentinel.core import sandbox  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "svg_ns.json"

X = "__x()"

# (payload, id, css selector to click or "")
# -- payload first, because these rows are read as "shape, then what it is".
_RAW: list[tuple[str, str, str]] = [
    # -- javascript: URIs in foreign content -----------------------------------
    # Each anchor carries a `<text>` child inside a sized `<svg>`: an SVG `<a>`
    # with no laid-out content has no box to click, and a click that cannot land
    # is not evidence that the URI does not run.  `probe_svg_ns` learned that the
    # hard way -- its first revision reported "click did not execute" for every
    # one of these rows while the box was 0x0.
    ('<svg width=60 height=30><a xlink:href="javascript:%s"><text y="12">g</text>'
     '</a></svg>' % X, "svg-a-xlink-js", "a"),
    ('<svg xmlns:xlink="http://www.w3.org/1999/xlink" width=60 height=30>'
     '<a xlink:href="javascript:%s"><text y="12">g</text></a></svg>' % X,
     "svg-a-xlink-js-declared", "a"),
    ('<svg width=60 height=30><a href="javascript:%s"><text y="12">g</text>'
     '</a></svg>' % X, "svg-a-href-js", "a"),
    ('<svg width=40 height=40><image href="javascript:%s"></image></svg>' % X,
     "svg-image-href-js", ""),
    ('<svg width=40 height=40><image xlink:href="javascript:%s"></image></svg>' % X,
     "svg-image-xlink-js", ""),
    ('<svg><use xlink:href="javascript:%s"></use></svg>' % X,
     "svg-use-xlink-js", ""),
    ('<svg><feImage href="javascript:%s"></feImage></svg>' % X,
     "svg-feimage-href-js", ""),
    ('<math><maction xlink:href="javascript:%s">g</maction></math>' % X,
     "math-maction-xlink-js", ""),
    ('<math><a href="javascript:%s"><semantics>g</semantics></a></math>' % X,
     "math-a-href-js", "a"),
    ('<svg width=60 height=30><a xlink:href="#x" target="_top"><text y="12">g</text>'
     '</a></svg>', "svg-a-xlink-fragment", "a"),
    # -- onload on inner SVG elements -----------------------------------------
    ('<svg onload="%s"></svg>' % X, "svg-root-onload", ""),
    ('<svg><foreignObject onload="%s"></foreignObject></svg>' % X,
     "svg-foreignobject-onload", ""),
    ('<svg><desc onload="%s"></desc></svg>' % X, "svg-desc-onload", ""),
    ('<svg><clipPath onload="%s"></clipPath></svg>' % X, "svg-clippath-onload",
     ""),
    ('<svg><ellipse onload="%s"></ellipse></svg>' % X, "svg-ellipse-onload", ""),
    ('<svg><filter onload="%s"></filter></svg>' % X, "svg-filter-onload", ""),
    ('<svg><linearGradient onload="%s"></linearGradient></svg>' % X,
     "svg-lineargradient-onload", ""),
    ('<svg><path d="M0 0" onload="%s"></path></svg>' % X, "svg-path-onload", ""),
    ('<svg><use xlink:href="#nope" onload="%s"></use></svg>' % X,
     "svg-use-onload", ""),
    ('<svg><image href="/nope" onload="%s"></image></svg>' % X,
     "svg-image-onload", ""),
    ('<svg><style>.x{}</style><g onload="%s"></g></svg>' % X, "svg-g-onload", ""),
    ('<svg width=40 height=40 onload="%s"><rect width=4 height=4></svg>' % X,
     "svg-root-onload-sized", ""),
    # -- other events the svg namespace might invent ---------------------------
    ('<svg onmouseover="%s">t</svg>' % X, "svg-onmouseover", ""),
    ('<svg width=40 height=40><rect width=40 height=40 onmouseover="%s">'
     '</rect></svg>' % X, "svg-rect-onmouseover", "rect"),
    ('<svg><animate onbegin="%s" attributeName="x" dur="1s"></animate></svg>' % X,
     "svg-animate-onbegin", ""),
    # -- the click-only shapes, as controls on the activation model ------------
    ('<button onclick="%s">x</button>' % X, "button-onclick", "button"),
    ('<div onclick="%s">x</div>' % X, "div-onclick", "div"),
    ('<a href="javascript:%s">g</a>' % X, "html-a-js", "a"),
    ('<dialog open onclose="%s"></dialog>' % X, "dialog-onclose", ""),
    ('<canvas onload="%s"></canvas>' % X, "canvas-onload", ""),
    ('<details open><summary>x</summary><p>y</p></details ontoggle="%s">' % X,
     "details-after-ontoggle", ""),
    ('<keygen onfocus="%s" autofocus>' % X, "keygen-autofocus", ""),
    ('<isindex action="javascript:%s" type=submit>' % X, "isindex-action-js",
     ""),
    ('<body background="http://127.0.0.1:9/nope">b</body>', "body-background",
     ""),
    ('<dom-module id="x-foo"><script>%s</script></dom-module>' % X,
     "dom-module-script", ""),
]
# fix the tuple order (id was written second for readability above)
CASES: list[tuple[str, str, str]] = [
    (cid, pay, sel) for pay, cid, sel in _RAW]


def _page_body(payload: str) -> str:
    """Every row is served inside a body, the way a reflected page is.

    The one row that needs an `xmlns:xlink` declaration carries it in its own
    payload; wrapping it here would have put a second, unclosed `<svg>` around the
    shape being measured, which measures that wrapper instead.
    """
    return f"<html><body>{payload}</body></html>"


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    _Handler.PAGES = {
        "/blank": "<html><body></body></html>",
        **{f"/p{i}": _page_body(p) for i, (_, p, _) in enumerate(CASES)},
    }
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT)
            page = ctx.new_page()
            _park(page)          # the default cursor sits at (0,0), over content
            for i, (cid, payload, sel) in enumerate(CASES):
                row: dict[str, object] = {"case": cid, "payload": payload,
                                          "click": sel}
                if not _goto(page, base + "/blank"):
                    row.update({"auto": None, "ihn": None,
                                "harness_error": "loopback reset"})
                    rows.append(row)
                    continue
                _clear(page)
                if not _goto(page, f"{base}/p{i}"):
                    row.update({"auto": None, "ihn": None,
                                "harness_error": "reset on payload page"})
                    rows.append(row)
                    continue
                row["complete"] = _wait_load(page)
                page.wait_for_timeout(400)
                row["auto"] = _read_hit(page)
                row["ready"] = _ready(page)
                # -- the trusted-click arm: only where something has a box ------
                row["clicked"] = None
                if sel:
                    box = None
                    try:
                        box = page.locator(sel).first.bounding_box(timeout=1500)
                    except Exception:
                        box = None
                    row["box"] = box
                    if not box or box["width"] < 4 or box["height"] < 4:
                        # A 0x0 box cannot be clicked: reading that as "did not
                        # execute" would turn a harness limit into an inert
                        # verdict, which is the bounded-False mistake in its most
                        # expensive form.  Say instead that nothing was asked.
                        row["click_note"] = f"no clickable box: {box}"
                    else:
                        cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                        # ...and confirm the click will land on the element the
                        # payload cares about, not on whatever paints on top.
                        hit = page.evaluate(
                            "([x, y, s]) => { const e = "
                            "document.elementFromPoint(x, y); if (!e) return '';"
                            " const want = document.querySelector(s);"
                            " return (e === want || e.contains(want) || "
                            "want.contains(e)) ? 'hit' : e.tagName; }",
                            [cx, cy, sel])
                        row["click_hit"] = hit
                        if hit != "hit":
                            row["click_note"] = f"point hit {hit!r} instead"
                        else:
                            page.mouse.click(cx, cy)
                            page.wait_for_timeout(400)
                            row["clicked"] = _read_hit(page)
                # park the cursor where nothing lives: the mouse stays where the
                # last click landed, and a payload two rows later inherits a
                # mouseover from it (this harness measured `<svg onmouseover>` as
                # "fires without interaction" until the cursor was parked).
                _park(page)
                # -- the innerHTML arm -----------------------------------------
                row["ihn"] = None
                if _goto(page, base + "/blank"):
                    _clear(page)
                    try:
                        page.evaluate(
                            "(h) => { const d = document.createElement('div');"
                            " d.innerHTML = h; document.body.appendChild(d); }",
                            payload)
                        page.wait_for_timeout(400)
                        row["ihn"] = _read_hit(page)
                    except Exception as e:
                        row["ihn_err"] = str(e)[:120]
                rows.append(row)
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def _ready(page):
    try:
        return page.evaluate("() => document.readyState")
    except Exception:
        return None


def _park(page) -> None:
    """Put the cursor where nothing lives: bottom-right of a 1280x720 viewport.

    Every payload here keeps its content in the top-left, so a cursor parked at
    (1270, 710) hovers an empty strip.  This matters because `mouse.click()`
    leaves the cursor where it landed and a later page load under that cursor
    hands a real `mouseover` to whatever is there -- the row two after would
    otherwise report "fired without any interaction", which is what this harness
    measured before the park was added.  The `except` is only for the window
    closing under us; a lost park cannot invent a hit, it can only fail to
    prevent one, and the affected rows say so in their own click arm.
    """
    try:
        page.mouse.move(1270, 710)
    except Exception:
        pass


def report(rows: list[dict]) -> int:
    """A confident sandbox claim may disagree; a decline may not be punished.

    The click arm changes what counts as a miss for `live(+act)`: that verdict
    *predicts* the click arm, so a hit after the click is agreement, not error.
    """
    bad = 0
    declined = 0
    print(f"{'case':<28}{'auto':<7}{'click':<7}{'ihn':<7}"
          f"{'sandbox(parser)':<20}{'sandbox(ihn)':<18}")
    for r in rows:
        if r.get("harness_error") or r.get("auto") is None:
            print(f"{r['case']:<28}INCONCLUSIVE "
                  f"{r.get('harness_error') or r.get('ihn_err') or ''}")
            bad += 1
            continue
        auto, ihn = bool(r["auto"]), bool(r["ihn"])
        clicked = r.get("clicked")
        vp = sandbox.judge(r["payload"], X, sink="parser")
        vi = sandbox.judge(r["payload"], X, sink="innerhtml")

        def fmt(v: sandbox.Verdict) -> str:
            return v.state + ("(+act)" if v.activation else "")

        notes = []
        for v, executes, arm in ((vp, auto, "parser"), (vi, ihn, "ihn")):
            if v.state == "unknown":
                declined += 1
                continue
            if v.state == "live":
                if v.activation:
                    # the claim is "it runs, once clicked": only the click arm
                    # can refute it, and only if there was one
                    if r["click"] and clicked is False:
                        notes.append(f"{arm}:ACT-CLAIM-DENIED")
                elif not executes and not clicked:
                    notes.append(f"{arm}:OVER")
            elif executes:
                notes.append(f"{arm}:MISSED")
        if notes:
            bad += 1
        print(f"{r['case']:<28}{str(auto):<7}{str(clicked):<7}{str(ihn):<7}"
              f"{fmt(vp):<20}{fmt(vi):<18}"
              f"{'  <-- ' + ' '.join(notes) if notes else ''}")
    print(f"\n{len(rows) - bad}/{len(rows)} foreign-namespace shapes free of "
          f"OVER, MISSED and denied activation ({declined} declined to the browser)")
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

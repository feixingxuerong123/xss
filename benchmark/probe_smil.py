"""Does a SMIL timing handler need user interaction, or does it just fire?

`payloads.json` ships `<svg><animate onbegin=...>` and friends 29 times; the
oracle has never carried one, so no verdict about them has ever been refereed.
The sandbox currently claims `onbegin`/`onrepeat` auto-fire on *any* element
(`AUTO_FIRING_EVENTS[...] = {'*'}`) while `judge` reports them as
live-**with-activation** -- which cannot both be right, and each half fails a
different way:

    `<div onbegin=CODE>`    no SMIL timeline exists on an HTML element, so if
                            this "fires" it is an OVER, the class that costs a
                            pentest credibility.
    `<animate onbegin=CODE>` default `begin` is 0s: the timeline starts when the
                            document starts.  If that needs no interaction but
                            the sandbox demands activation, the gate's
                            promotion arm refuses to rescue it -> a false
                            negative in the other direction.

`onend`/`onrepeat` add a timing question the oracle's 300 ms settle was never
sized for, so the settle here is derived from the animation's own `dur`.

Methodology is imported, not re-implemented: served pages + `add_init_script`
sentinel + real navigation + per-arm clearing, exactly as
`benchmark/browser_dom_oracle.py` does it, because a re-typed copy of the
sentinel handling is how that oracle once produced 820 identical columns.

Usage: python -m benchmark.probe_smil [--json out.json] [--settle-scale N]
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

OUT = pathlib.Path(__file__).resolve().parent / "results" / "smil_probe.json"

# (id, payload, seconds the animation needs before the event can fire)
CASES: list[tuple[str, str, float]] = [
    ("animate-begin-default",
     '<svg><animate onbegin="__x()" attributeName="x" dur="1s"></animate></svg>',
     0.2),                      # begin=0s: should be firing during load itself
    ("animate-begin-0s",
     '<svg width=40 height=40><rect width=4 height=4><animate onbegin="__x()"'
     ' attributeName="width" to="40" begin="0s" dur="1s"></animate></rect></svg>',
     0.2),
    ("animate-begin-indefinite",
     '<svg width=40 height=40><rect width=4 height=4><animate onbegin="__x()"'
     ' attributeName="width" to="40" begin="indefinite" dur="1s"></animate>'
     '</rect></svg>',
     0.2),
    ("animate-end",
     '<svg width=40 height=40><rect width=4 height=4><animate onend="__x()"'
     ' attributeName="width" to="40" dur="1s"></animate></rect></svg>',
     1.6),
    ("animate-repeat",
     '<svg width=40 height=40><rect width=4 height=4><animate onrepeat="__x()"'
     ' attributeName="width" to="40" dur="1s" repeatCount="3"></animate>'
     '</rect></svg>',
     1.6),
    ("set-begin",
     '<svg width=40 height=40><rect width=4 height=4><set onbegin="__x()"'
     ' attributeName="width" to="40"></set></rect></svg>',
     0.2),
    ("animate-on-svg",
     '<svg width=40 height=40 onbegin="__x()"><rect width=4 height=4></svg>',
     0.2),
    # the HTML side of the `{'*'}` claim: no SMIL timeline can exist here
    ("div-onbegin", '<div onbegin="__x()">t</div>', 0.2),
    ("p-onbegin", '<p onbegin="__x()">t</p>', 0.2),
    ("input-onbegin", '<input onbegin="__x()">', 0.2),
    ("div-onanimationstart", '<div onanimationstart="__x()">t</div>', 0.2),
    ("div-onanimationstart-running",
     '<style>@keyframes k{from{opacity:0}to{opacity:1}}</style>'
     '<div onanimationstart="__x()" style="animation:k 1s">t</div>', 0.4),
    ("circle-onbegin",
     '<svg width=40 height=40><circle cx=2 cy=2 r=2 onbegin="__x()"></circle></svg>',
     0.2),
    ("animate-begin-mouseover",
     '<svg width=40 height=40 style="height:200px;width:200px">'
     '<rect width=100 height=100><animate onbegin="__x()" attributeName="width"'
     ' to="120" begin="mouseover" dur="1s"></animate></rect></svg>',
     0.4),
    # -- the rest of what `payloads.json` actually ships ----------------------
    # 27 SMIL-ish payloads live in the corpus; these are the element and
    # attribute-animation forms none of them has ever been refereed against.
    ("animatetransform-onbegin",
     '<svg><animateTransform onbegin="__x()" attributeName="transform"'
     ' dur="1s"></animateTransform></svg>', 0.3),
    ("animatemotion-onbegin",
     '<svg><animateMotion onbegin="__x()" path="M0,0 L10,10" dur="1s">'
     '</animateMotion></svg>', 0.3),
    ("discard-onbegin",
     '<svg><rect width=40 height=40><discard onbegin="__x()" begin="0s">'
     '</discard></rect></svg>', 0.3),
    ("animate-begin-delay-2s",
     '<svg width=40 height=40><rect width=4 height=4><animate onbegin="__x()"'
     ' attributeName="width" to="40" begin="2s" dur="1s"></animate></rect></svg>',
     3.2),                      # needs TIME, not a gesture: the distinction that
                                # decides whether the gate may promote it
    ("set-begin-indefinite",
     '<svg><set onbegin="__x()" attributeName="x" to="1" begin="indefinite">'
     '</set></svg>', 0.3),
    ("animate-href-jscript",
     '<svg width=40 height=40><a><text>x</text><animate attributeName="href"'
     ' values="javascript:__x()" dur="1s" fill="freeze"></animate></a></svg>',
     1.6),
    ("animate-xlinkhref-jscript",
     '<svg width=40 height=40 xmlns:xlink="http://www.w3.org/1999/xlink"><a>'
     '<text>x</text><animate attributeName="xlink:href"'
     ' values="javascript:__x()" dur="1s" fill="freeze"></animate></a></svg>',
     1.6),
    ("animate-no-target",
     '<svg><animate attributeName="href" values="javascript:__x()"'
     ' dur="1s"></animate></svg>', 1.6),
    ("set-onload-to-handler",
     '<svg width=40 height=40><rect width=4 height=4><set attributeName="onload"'
     ' to="__x()" begin="0s" dur="1s"></set></rect></svg>', 1.6),
    # -- separating two explanations for "SMIL inside srcdoc never fires" ------
    # The oracle's iframe_src host is `<iframe srcdoc="__P__">`, so a payload
    # carrying its own `"` truncates the attribute: "does not fire" could mean
    # "nested timelines do not run" OR "the nested document is a mangled
    # fragment".  Single-quoting the attribute delivers the same payload intact,
    # which tells the two apart.  And neither reading means anything without the
    # control below: if no handler inside a nested document can ever write the
    # sentinel here, every `False` above is the harness, not the browser.
    ("srcdoc-control-img-error",
     "<iframe srcdoc='<img src=x onerror=\"__x()\">'></iframe>", 0.4),
    ("srcdoc-smil-intact",
     "<iframe srcdoc='<svg><animate onbegin=\"__x()\" attributeName=\"x\""
     " dur=\"1s\"></animate></svg>'></iframe>", 1.0),
    ("srcdoc-smil-truncated",
     '<iframe srcdoc="<svg><animate onbegin="__x()" attributeName="x"'
     ' dur="1s"></animate></svg>"></iframe>', 1.0),
    # The oracle's iframe_src rows truncate to `... attributeName=` -- an EMPTY
    # attributeName -- and do not fire, while the intact `attributeName="x"` form
    # above does.  So the question is whether an animation with no attribute to
    # drive ever starts a timeline, which is a rule about the element, not about
    # srcdoc.  Measured directly, in a complete document:
    ("animate-empty-attributename",
     '<svg><animate onbegin="__x()" attributeName="" dur="1s"></animate></svg>',
     1.0),
    ("animate-valueless-attributename",
     '<svg><animate onbegin="__x()" attributeName dur="1s"></animate></svg>',
     1.0),
    ("animate-no-attributename",
     '<svg><animate onbegin="__x()" dur="1s"></animate></svg>', 1.0),
    ("set-no-attributename",
     '<svg><set onbegin="__x()" to="1"></set></svg>', 1.0),
]


def run(settle_scale: float = 1.0) -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    _Handler.PAGES = {
        "/blank": "<html><body></body></html>",
        **{f"/p{i}": f"<html><body>{body}</body></html>"
           for i, (_, body, _) in enumerate(CASES)},
    }
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT)
            page = ctx.new_page()
            for i, (name, body, needs) in enumerate(CASES):
                settle = max(0.3, needs) * settle_scale
                row = {"case": name, "payload": body, "settle_s": round(settle, 2)}
                # -- arm 1: what the server sent ------------------------------
                if not _goto(page, base + "/blank"):
                    row.update({"exec_parser": None, "exec_ihn1": None,
                                "harness_error": "loopback reset"})
                    rows.append(row)
                    continue
                _clear(page)
                if not _goto(page, f"{base}/p{i}"):
                    row.update({"exec_parser": None, "exec_ihn1": None,
                                "harness_error": "reset on payload page"})
                    rows.append(row)
                    continue
                _wait_load(page)
                page.wait_for_timeout(int(settle * 1000))
                row["exec_parser"] = _read_hit(page)
                row["ready"] = _ready(page)
                # -- arm 2: a DOM sink re-parses the same bytes ---------------
                if not _goto(page, base + "/blank"):
                    row["exec_ihn1"] = None
                    rows.append(row)
                    continue
                _clear(page)
                try:
                    page.evaluate(
                        "(h) => { const d = document.createElement('div');"
                        " d.innerHTML = h; document.body.appendChild(d); }", body)
                    page.wait_for_timeout(int(settle * 1000))
                    row["exec_ihn1"] = _read_hit(page)
                except Exception as e:
                    row["exec_ihn1"] = None
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


def report(rows: list[dict]) -> int:
    """Same three-way contract as `sandbox_fidelity.py`: only a *confident*
    sandbox claim can disagree.  `unknown` and `live(+act)` are declines -- the
    first sends the case to the browser, the second keeps the gate from
    promoting it -- and counting either as a miss would make this harness
    punish the sandbox for the very hedging that keeps OVER at zero."""
    bad = 0
    declined = 0
    print(f"{'case':<30}{'settle':<8}{'browser(parser)':<16}"
          f"{'browser(ihn)':<14}{'sandbox(parser)':<22}{'sandbox(ihn)':<20}")
    for r in rows:
        if r.get("harness_error") or r.get("exec_parser") is None:
            print(f"{r['case']:<30}INCONCLUSIVE "
                  f"{r.get('harness_error') or r.get('ihn_err') or ''}")
            bad += 1
            continue
        bp, bi = bool(r["exec_parser"]), bool(r.get("exec_ihn1"))
        v = [sandbox.judge(r["payload"], "__x()", sink=s)
             for s in ("parser", "innerhtml")]

        def claim(x: sandbox.Verdict):
            """(asserts-executes, asserts-inert) -- or (None, None) if it abstains."""
            if x.state == "unknown":
                return None, None
            if x.state == "live":
                return (not x.activation), False
            return False, True

        def fmt(x: sandbox.Verdict) -> str:
            return f"{x.state}{'(+act)' if x.activation else ''}"

        notes = []
        for got, executes, sink in ((v[0], bp, "parser"), (v[1], bi, "innerhtml")):
            says_yes, says_no = claim(got)
            if says_yes is None:
                declined += 1
                continue
            if says_yes and not executes:
                notes.append(f"{sink}:OVER")
            if says_no and executes:
                notes.append(f"{sink}:MISSED")
        if notes:
            bad += 1
        print(f"{r['case']:<30}{r['settle_s']:<8}{str(bp):<16}{str(bi):<14}"
              f"{fmt(v[0]):<22}{fmt(v[1]):<20}{'  <-- ' + ' '.join(notes) if notes else ''}")
    print(f"\n{len(rows) - bad}/{len(rows)} SMIL shapes free of OVER and MISSED "
          f"({declined} arm-verdicts declined to the browser)")
    return bad


if __name__ == "__main__":
    scale = 1.0
    if "--settle-scale" in sys.argv:
        scale = float(sys.argv[sys.argv.index("--settle-scale") + 1])
    rows = run(scale)
    dest = (sys.argv[sys.argv.index("--json") + 1]
            if "--json" in sys.argv else str(OUT))
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    raise SystemExit(1 if report(rows) else 0)

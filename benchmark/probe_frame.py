"""Does a `<frame>` need a real `<frameset>` around it before it can execute?

`test_sandbox.py` asserted `<frame src='javascript:…'></frame>` was live on the
strength of a table lookup that never distinguished *where* the `<frame>` lived.
That distinction is not cosmetic: `<frame>` is only allowed as a child of
`<frameset>`, so in a normal reflected page (`<html><body>…`) the token is
dropped and the payload is dead, while in a genuine frameset document the same
bytes open a browsing context and run the URI.  One verdict for both shapes is
either a false negative or an OVER, depending on which one you happen to test.

The other half of the question is the page itself.  A frameset is only honoured
while the parser is in "before html"/"frameset-ok" state, so the payload has to
be the *whole document*: served inside `<body>` it is a parse error and ignored,
and a harness that wrapped it the way every other probe does would report a
False that the browser never chose.  So each case here carries its own document
plus the fragment used for the innerHTML arm, and the frames-that-actually-run
control sits next to the claim it is supposed to referee.

Methodology is imported, not re-implemented: served pages + `add_init_script`
sentinel + real navigation + per-arm clearing, as `benchmark/browser_dom_oracle.py`
does it.  The sentinel writes `localStorage`, which is shared across same-origin
frames, so a handler inside a child frame is visible from the parent.

Usage: python -m benchmark.probe_frame [--json out.json]
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

OUT = pathlib.Path(__file__).resolve().parent / "results" / "frame_probe.json"

#: Rows that referee the *harness*, not the sandbox.  `<frame src="/child">`
#: executes a handler that lives in the served child document, so the token is
#: absent from the string handed to `judge` -- an inert verdict there is correct
#: about that string, and comparing it to a browser hit would invent a MISSED.
HARNESS_ONLY = frozenset({"frameset-frame-child-doc"})

# (id, whole document served for the parser arm, fragment for the innerHTML arm)
CASES: list[tuple[str, str, str]] = [
    # -- the claim under test --------------------------------------------------
    ("frameset-frame-jsuri",
     '<html><frameset><frame src="javascript:__x()"></frameset>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    ("frameset-rows0-jsuri",
     '<html><frameset rows="0"><frame src="javascript:__x()"></frameset>',
     '<frameset rows="0"><frame src="javascript:__x()"></frameset>'),
    ("frameset-cols0-jsuri",
     '<html><frameset cols="0"><frame src="javascript:__x()"></frameset>',
     '<frameset cols="0"><frame src="javascript:__x()"></frameset>'),
    ("frameset-nested-jsuri",
     '<html><frameset rows="100"><frameset><frame src="javascript:__x()">'
     '</frameset></frameset>',
     '<frameset rows="100"><frameset><frame src="javascript:__x()"></frameset>'
     '</frameset>'),
    ("frameset-two-jsuri",
     '<html><frameset cols="50,50"><frame src="javascript:__x()">'
     '<frame src="javascript:__x()"></frameset>',
     '<frameset cols="50,50"><frame src="javascript:__x()"></frameset>'),
    ("frameset-onload-js",
     '<html><frameset onload="__x()"></frameset>',
     '<frameset onload="__x()"></frameset>'),
    # -- the same bytes in a body document: is the frame still a frame? -------
    ("body-frame-jsuri",
     '<html><body><frame src="javascript:__x()"></body></html>',
     '<frame src="javascript:__x()">'),
    ("head-frame-jsuri",
     '<html><head><frame src="javascript:__x()"></head><body></body></html>',
     '<frame src="javascript:__x()">'),
    ("body-frameset-frame-jsuri",
     '<html><body><frameset><frame src="javascript:__x()"></frameset></body></html>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    # -- where exactly does the frameset stop being honoured? ------------------
    # `frameset-frame-jsuri` has no body and works, `body-frameset-frame-jsuri`
    # has one and does not, so the boundary is the body element -- but "where the
    # body comes from" is three different shapes, and only measuring says which.
    ("head-frameset-frame-jsuri",
     '<html><head><frameset><frame src="javascript:__x()"></frameset></head>',
     '<head><frameset><frame src="javascript:__x()"></frameset></head>'),
    ("text-then-frameset-jsuri",
     '<html>x<frameset><frame src="javascript:__x()"></frameset>',
     'x<frameset><frame src="javascript:__x()"></frameset>'),
    ("comment-then-frameset-jsuri",
     '<html><!--c--><frameset><frame src="javascript:__x()"></frameset>',
     '<!--c--><frameset><frame src="javascript:__x()"></frameset>'),
    ("ws-then-frameset-jsuri",
     '<html>\n  <frameset><frame src="javascript:__x()"></frameset>',
     '\n  <frameset><frame src="javascript:__x()"></frameset>'),
    ("closed-body-then-frameset-jsuri",
     '<html><body>b</body><frameset><frame src="javascript:__x()"></frameset>',
     '<body>b</body><frameset><frame src="javascript:__x()"></frameset>'),
    ("noscript-frameset-jsuri",
     '<html><noscript><frameset><frame src="javascript:__x()"></frameset>'
     '</noscript>',
     '<noscript><frameset><frame src="javascript:__x()"></frameset></noscript>'),
    # -- what may stand *before* the frameset without killing it? -------------
    # `head-frameset-frame-jsuri` says head is fine and `text-then-...` says text
    # is not, which is the spec's `frameset-ok` flag.  The flag's exact boundary
    # is what an allow-list has to encode, and a list inferred from one sample is
    # how the `<option>` rule got written wrong once already -- so each kind of
    # head content and each kind of body content gets its own row.
    ("head-script-then-frameset-jsuri",
     '<html><head><script>var a=1</script></head>'
     '<frameset><frame src="javascript:__x()"></frameset>',
     '<head><script>var a=1</script></head><frameset>'
     '<frame src="javascript:__x()"></frameset>'),
    ("head-link-then-frameset-jsuri",
     '<html><head><link rel=stylesheet href=/nope></head>'
     '<frameset><frame src="javascript:__x()"></frameset>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    ("head-style-then-frameset-jsuri",
     '<html><head><style>p{}</style></head>'
     '<frameset><frame src="javascript:__x()"></frameset>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    ("head-title-then-frameset-jsuri",
     '<html><head><title>t</title></head>'
     '<frameset><frame src="javascript:__x()"></frameset>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    ("div-then-frameset-jsuri",
     '<html><div>d</div><frameset><frame src="javascript:__x()"></frameset>',
     '<div>d</div><frameset><frame src="javascript:__x()"></frameset>'),
    ("frameset-then-frameset-jsuri",
     '<html><frameset><frame src="/blank"><frameset>'
     '<frame src="javascript:__x()"></frameset></frameset>',
     '<frameset><frame src="/blank"><frameset>'
     '<frame src="javascript:__x()"></frameset></frameset>'),
    ("doctype-frameset-jsuri",
     '<!doctype html><html><frameset><frame src="javascript:__x()"></frameset>',
     '<frameset><frame src="javascript:__x()"></frameset>'),
    # The head has a fixed set of tags it accepts without opening a body, and
    # only those keep a following `<frameset>` alive.  Every name in that list
    # gets a row: a four-name sample is what the `<option>` rule was written
    # from, and it took 152 names to show the sample was lying.
    ("head-base-then-frameset-jsuri",
     '<html><head><base href="/"><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<base href="/"><frameset><frame src="javascript:__x()"></frameset>'),
    ("head-basefont-then-frameset-jsuri",
     '<html><head><basefont size=1><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<basefont size=1><frameset><frame src="javascript:__x()"></frameset>'),
    ("head-bgsound-then-frameset-jsuri",
     '<html><head><bgsound src=/nope><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<bgsound src=/nope><frameset><frame src="javascript:__x()"></frameset>'),
    ("head-meta-then-frameset-jsuri",
     '<html><head><meta charset=utf-8><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<meta charset=utf-8><frameset><frame src="javascript:__x()"></frameset>'),
    ("head-noframes-then-frameset-jsuri",
     '<html><head><noframes></noframes><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<noframes></noframes><frameset><frame src="javascript:__x()"></frameset>'),
    ("head-template-then-frameset-jsuri",
     '<html><head><template><p>x</p></template><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<template><p>x</p></template><frameset>'
     '<frame src="javascript:__x()"></frameset>'),
    ("svg-then-frameset-jsuri",
     '<html><svg></svg><frameset><frame src="javascript:__x()"></frameset>',
     '<svg></svg><frameset><frame src="javascript:__x()"></frameset>'),
    # `div-then-frameset` measured False, but that div *contained the text `d`*,
    # and text is a separate clearing cause.  Until an element is measured with
    # no character data in it, nothing here says whether the flag is cleared by
    # "a body got built" or by "a character token was seen" -- and the two rules
    # disagree about `<html><div></div><frameset>`, which is a shape a reflected
    # payload really can produce.
    ("empty-div-then-frameset-jsuri",
     '<html><div></div><frameset><frame src="javascript:__x()"></frameset>',
     '<div></div><frameset><frame src="javascript:__x()"></frameset>'),
    ("empty-p-then-frameset-jsuri",
     '<html><p><frameset><frame src="javascript:__x()"></frameset>',
     '<p><frameset><frame src="javascript:__x()"></frameset>'),
    ("empty-span-then-frameset-jsuri",
     '<html><span><frameset><frame src="javascript:__x()"></frameset>',
     '<span><frameset><frame src="javascript:__x()"></frameset>'),
    ("img-then-frameset-jsuri",
     '<html><img src=x><frameset><frame src="javascript:__x()"></frameset>',
     '<img src=x><frameset><frame src="javascript:__x()"></frameset>'),
    ("table-then-frameset-jsuri",
     '<html><table></table><frameset><frame src="javascript:__x()"></frameset>',
     '<table></table><frameset><frame src="javascript:__x()"></frameset>'),
    ("empty-body-then-frameset-jsuri",
     '<html><body><frameset><frame src="javascript:__x()"></frameset></body>',
     '<body><frameset><frame src="javascript:__x()"></frameset></body>'),
    ("open-div-text-frameset-jsuri",
     '<html><div>d<frameset><frame src="javascript:__x()"></frameset>',
     '<div>d<frameset><frame src="javascript:__x()"></frameset>'),
    ("math-then-frameset-jsuri",
     '<html><math><mi></mi></math><frameset>'
     '<frame src="javascript:__x()"></frameset>',
     '<math><mi></mi></math><frameset><frame src="javascript:__x()"></frameset>'),
    # Text is a clearing cause, so the question is which *kind* of text.  The
    # sandbox exempts raw-text contents (`<style>p{}</style>`) and foreign
    # contents (`<svg>text</svg>`), because those character tokens never reach
    # body content -- an assumption about the parser, so it gets measured.
    ("svg-text-then-frameset-jsuri",
     '<html><svg>text</svg><frameset><frame src="javascript:__x()"></frameset>',
     '<svg>text</svg><frameset><frame src="javascript:__x()"></frameset>'),
    ("style-inbody-text-then-frameset-jsuri",
     '<html><style>p{}</style><frameset><frame src="javascript:__x()">'
     '</frameset>',
     '<style>p{}</style><frameset><frame src="javascript:__x()"></frameset>'),
    ("title-inbody-text-then-frameset-jsuri",
     '<html><title>t</title><frameset><frame src="javascript:__x()"></frameset>',
     '<title>t</title><frameset><frame src="javascript:__x()"></frameset>'),
    ("template-text-then-frameset-jsuri",
     '<html><template>t</template><frameset><frame src="javascript:__x()">'
     '</frameset>',
     '<template>t</template><frameset><frame src="javascript:__x()"></frameset>'),
    ("textarea-text-then-frameset-jsuri",
     '<html><textarea>t</textarea><frameset><frame src="javascript:__x()">'
     '</frameset>',
     '<textarea>t</textarea><frameset><frame src="javascript:__x()"></frameset>'),
    # -- controls --------------------------------------------------------------
    # A frame that loads a real child document and runs a handler *there* is the
    # control that says the harness reaches into child browsing contexts.  The
    # first revision of this file used `<frame srcdoc=...>` for it, measured
    # False, and would have "proved" every frame row below undetectable --
    # `srcdoc` is an `<iframe>` attribute; a `<frame>` with no `src` goes to
    # about:blank and runs nothing.  So srcdoc is a case, not a control.
    ("frameset-frame-child-doc",
     '<html><frameset><frame src="/child"></frameset>',
     '<frameset><frame src="/child"></frameset>'),
    ("frameset-frame-srcdoc",
     '<html><frameset><frame srcdoc="&lt;img src=x onerror=__x()&gt;">'
     '</frameset>',
     '<frameset><frame srcdoc="&lt;img src=x onerror=__x()&gt;"></frameset>'),
    ("body-frame-child-doc",
     '<html><body><frame src="/child"></body></html>',
     '<frame src="/child">'),
    ("iframe-jsuri",
     '<html><body><iframe src="javascript:__x()"></iframe></body></html>',
     '<iframe src="javascript:__x()"></iframe>'),
    ("iframe-srcdoc-jsuri",
     '<html><body><iframe srcdoc="&lt;script&gt;__x()&lt;/script&gt;"></iframe>'
     '</body></html>',
     '<iframe srcdoc="&lt;script&gt;__x()&lt;/script&gt;"></iframe>'),
]


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    _Handler.PAGES = {
        "/blank": "<html><body></body></html>",
        # the positive control's payload: a handler that exists only in the
        # child document, so a hit can only come from the frame having loaded it
        "/child": "<html><body><img src=x onerror=__x()></body></html>",
        **{f"/p{i}": doc for i, (_, doc, _) in enumerate(CASES)},
    }
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT)
            page = ctx.new_page()
            for i, (name, doc, frag) in enumerate(CASES):
                row: dict[str, object] = {"case": name, "document": doc,
                                          "fragment": frag}
                # -- arm 1: the browser parses the served document ------------
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
                row["load_complete"] = _wait_load(page)
                page.wait_for_timeout(400)
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
                        " d.innerHTML = h; document.body.appendChild(d); }", frag)
                    page.wait_for_timeout(400)
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
    """Same three-way contract as `probe_smil.py`: only a *confident* sandbox
    claim can disagree.  `unknown` is a decline -- it sends the case to the
    browser -- and counting a decline as a miss would punish the very hedging
    that keeps OVER at zero."""
    bad = 0
    declined = 0
    print(f"{'case':<28}{'browser(doc)':<14}{'browser(ihn)':<14}"
          f"{'sandbox(doc)':<20}{'sandbox(fragment)':<20}")
    for r in rows:
        if r.get("harness_error") or r.get("exec_parser") is None:
            print(f"{r['case']:<28}INCONCLUSIVE "
                  f"{r.get('harness_error') or r.get('ihn_err') or ''}")
            bad += 1
            continue
        bp, bi = bool(r["exec_parser"]), bool(r.get("exec_ihn1"))
        if not r.get("load_complete"):
            print(f"{r['case']:<28}INCONCLUSIVE parent never reached 'complete'"
                  " -- a frameset page can hold load open")
            bad += 1
            continue
        doc = sandbox.judge(r["document"], "__x()", sink="parser")
        frag = sandbox.judge(r["fragment"], "__x()", sink="innerhtml")

        def claim(x: sandbox.Verdict):
            """(asserts-executes, asserts-inert) -- or (None, None) if it abstains."""
            if x.state == "unknown":
                return None, None
            if x.state == "live":
                return (not x.activation), False
            return False, True

        def fmt(x: sandbox.Verdict) -> str:
            return f"{x.state}{'(+act)' if x.activation else ''}"

        if r["case"] in HARNESS_ONLY:
            print(f"{r['case']:<28}{str(bp):<14}{str(bi):<14}"
                  f"{'-harness control-':<20}")
            if not bp:
                print("   ^ the child document did NOT run: every other True "
                      "here needs re-reading")
                bad += 1
            continue

        notes = []
        for got, executes, arm in ((doc, bp, "doc"), (frag, bi, "ihn")):
            says_yes, says_no = claim(got)
            if says_yes is None:
                declined += 1
                continue
            if says_yes and not executes:
                notes.append(f"{arm}:OVER")
            if says_no and executes:
                notes.append(f"{arm}:MISSED")
        if notes:
            bad += 1
        print(f"{r['case']:<28}{str(bp):<14}{str(bi):<14}"
              f"{fmt(doc):<20}{fmt(frag):<20}"
              f"{'  <-- ' + ' '.join(notes) if notes else ''}")
    print(f"\n{len(rows) - bad}/{len(rows)} frame shapes free of OVER and MISSED "
          f"({declined} arm-verdicts declined to the browser)")
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

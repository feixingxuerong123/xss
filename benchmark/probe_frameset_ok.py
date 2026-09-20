"""Which start tags clear the `frameset-ok` flag?  Every name, not a sample.

`benchmark/probe_frame.py` measured that a `<frameset>` survives to build a
browsing context after an empty `<div>`, `<p>`, `<span>`, `<svg>` or `<math>`,
but is ignored after `<img src=x>`, `<table>`, a `<body>` tag or a single
non-whitespace character.  That is the HTML `frameset-ok` flag, and a sandbox
that models `<frameset>` at all has to know when to switch it off -- honouring it
where the browser dropped it is an OVER, the exact class of error that makes a
scanner's output untrustworthy.

The measured set is only trustworthy if it covers the names instead of a sample
of them, so this sweeps one page per element name: `<html><NAME>` then a
frameset holding `<frame src="javascript:__x()">`.  A hit means the frameset was
honoured.  `probe_frame.py` says the payload's own *text* is what most of these
names trip over, so a second pass runs the same page for a handful of names with
the element closed (`<NAME></NAME>`) to separate "this tag clears" from "the
characters it swallowed clear".

Usage: python -m benchmark.probe_frameset_ok [--json out.json]
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.browser_dom_oracle import (  # noqa: E402
    _Handler, _clear, _goto, _serve, _wait_load)

OUT = pathlib.Path(__file__).resolve().parent / "results" / "frameset_ok.json"

#: The name that follows `<frameset>` is always a `<frame src=javascript:>`; only
#: the thing in front of it changes.
TAIL = '<frameset><frame src="javascript:__x()"></frameset>'

#: Every hit records WHICH page produced it.  `localStorage` is shared by the
#: whole origin, and a `javascript:` frame can finish navigating after the harness
#: has moved on -- so a plain flag turns one row's late write into the next row's
#: false True.  The first pass of this file caught exactly that: `<html><style>`
#: unclosed reports "honoured", which is impossible, because the raw-text state
#: eats the whole tail and no `<frame>` exists to run.  A nonce makes a late write
#: from an earlier page read as a miss instead of a hit, which is the safe
#: direction: this sweep is looking for names that KILL the frameset.
_INIT_NONCE = """
window.__x = function () {
  try {
    var n = window.__nonce;
    if (n === undefined && window.parent && window.parent !== window)
      n = window.parent.__nonce;          // the frame's own realm has no stamp
    localStorage.setItem('__exec', String(n === undefined ? '?' : n));
  } catch (e) {}
};
"""


def _doc(tag: str, nonce: str) -> str:
    """A page whose own name is stamped into the hit.

    The `<script>` sits in head, which `probe_frame.py` measured as harmless to
    the flag, so it does not change what is being tested.
    """
    return (f"<html><script>window.__nonce={json.dumps(nonce)}</script>"
            f"<{tag}>")

# Every HTML element name the sandbox has a table entry for, plus the legacy and
# foreign names a response can contain.  Grouped, not deduplicated by intent:
# `<img>` and `<table>` are the two surprises in the first group.
NAMES: list[str] = [
    # structural / sectioning
    "html", "head", "body", "frameset", "frame", "div", "span", "p", "br", "hr",
    "article", "section", "nav", "aside", "header", "footer", "main", "h1",
    "h6", "hgroup", "address", "pre", "listing", "xmp", "plaintext", "menu",
    "ul", "ol", "li", "dl", "dt", "dd",
    # inline
    "a", "em", "strong", "small", "s", "cite", "q", "dfn", "abbr", "code",
    "var", "samp", "kbd", "sub", "sup", "i", "b", "u", "mark", "ruby", "rt",
    "rp", "bdi", "bdo", "wbr", "nobr", "font", "big", "strike", "tt",
    # replaced / media
    "img", "image", "iframe", "embed", "object", "param", "video", "audio",
    "source", "track", "canvas", "map", "area", "svg", "math", "picture",
    # form
    "form", "label", "input", "button", "select", "datalist", "optgroup",
    "option", "textarea", "output", "progress", "meter", "fieldset",
    "legend", "search",
    # table
    "table", "caption", "colgroup", "col", "tbody", "tfoot", "thead", "tr",
    "td", "th",
    # metadata / scripting
    "title", "link", "meta", "base", "script", "noscript", "style",
    "template", "slot", "dialog", "details", "summary", "marquee",
    "basefont", "bgsound", "isindex", "noembed", "noframes", "keygen",
    "portal", "fencedframe", "custom-element",
]

#: The raw-text / escapable-raw-text names, measured closed as well as open: for
#: these two the swallowing of the tail is the whole question.
CLOSED = ["style", "script", "title", "textarea", "xmp", "plaintext", "iframe",
          "noembed", "noframes", "noscript", "template", "table", "select",
          "object", "svg", "math", "frameset", "div"]


def _pages() -> dict[str, str]:
    pages = {"/blank": "<html><body></body></html>"}
    for i, name in enumerate(NAMES):
        pages[f"/o{i}"] = _doc(name, f"o{i}") + TAIL
    for k, name in enumerate(CLOSED):
        pages[f"/c{k}"] = _doc(name, f"c{k}") + f"</{name}>" + TAIL
    return pages


def _ids() -> list[tuple[str, str]]:
    return ([(f"open:{n}", f"/o{i}") for i, n in enumerate(NAMES)]
            + [(f"closed:{n}", f"/c{k}") for k, n in enumerate(CLOSED)])


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    srv, base = _serve()
    pages = _pages()
    _Handler.PAGES = pages
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            # `_INIT_NONCE` replaces the imported `_INIT` on purpose: same
            # sentinel, but every hit says which page wrote it.
            ctx.add_init_script(_INIT_NONCE)
            page = ctx.new_page()
            for name, path in _ids():
                nonce = path[1:]
                row: dict[str, object] = {"case": name, "path": path,
                                          "expect": nonce,
                                          "document": pages[path]}
                if not _goto(page, base + "/blank"):
                    row.update({"exec": None, "harness_error": "loopback reset"})
                    rows.append(row)
                    continue
                _clear(page)
                if not _goto(page, base + path):
                    row.update({"exec": None, "harness_error": "reset on page"})
                    rows.append(row)
                    continue
                row["complete"] = _wait_load(page)
                page.wait_for_timeout(300)
                got = _read_raw(page)
                row["raw"] = got
                # a hit only counts if THIS page wrote it
                row["exec"] = (got == nonce)
                rows.append(row)
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def _read_raw(page):
    """Whatever the sentinel recorded, including another page's stamp."""
    try:
        v = page.evaluate("() => { try { return localStorage.getItem('__exec')"
                          " } catch (e) { return null } }")
    except Exception:
        return None
    return v


def report(rows: list[dict]) -> int:
    """The browser's answer is the whole point here, so this prints the two
    lists the sandbox needs -- per pass, because the open and closed passes mean
    different things: an *open* raw-text element eats the tail, so its row says
    nothing about the flag, while a *closed* one leaves the frameset as the next
    token and says exactly whether that start tag cleared it."""
    keeps: list[str] = []
    kills: list[str] = []
    unknown: list[str] = []
    stale: list[str] = []
    for r in rows:
        if r.get("exec") is None or not r.get("complete"):
            unknown.append(r["case"])
            continue
        (keeps if r["exec"] else kills).append(r["case"])
        if r.get("raw") not in (None, r["expect"]):
            stale.append(f"{r['case']}<-{r['raw']}")
    for pass_name, label in (("open:", "OPEN  "), ("closed:", "CLOSED")):
        k = [x.split(":", 1)[1] for x in keeps if x.startswith(pass_name)]
        d = [x.split(":", 1)[1] for x in kills if x.startswith(pass_name)]
        print(f"{label} honoured ({len(k):3}): {' '.join(k) or '(none)'}")
        print(f"{label} ignored ({len(d):3}): {' '.join(d) or '(none)'}\n")
    if stale:
        print("rows whose localStorage slot held ANOTHER page's stamp (proof the "
              "nonce was needed):", " ".join(stale[:12]))
    if unknown:
        print("inconclusive   :", " ".join(unknown))
    return len(unknown)


if __name__ == "__main__":
    rows = run()
    dest = (sys.argv[sys.argv.index("--json") + 1]
            if "--json" in sys.argv else str(OUT))
    pathlib.Path(dest).parent.mkdir(parents=True, exist_ok=True)
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\nwritten:", dest)
    raise SystemExit(1 if report(rows) else 0)

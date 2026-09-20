"""Sink execution matrix: which sink shapes ACTUALLY run code in Chromium?

`benchmark/sink_matrix.py` answers "does the ENGINE report this shape".  That is
a different question from "does the browser RUN it", and conflating the two is
how a claim gets over-stated: Phase 163 hooked embed.src / object.data as URL
sinks and labelled them "executes with no activation", having measured only
iframe.src.

Measurement notes, both learned the hard way here:

  * The sentinel is ``document.title = 'EXEC'`` (parent-scoped for nested
    browsing contexts).  A local HTTP probe server was tried first -- fetch AND
    a plain ``new Image().src`` never reached it from this browser session, so
    every shape read as "did not execute", including the ``script.text``
    control.  A control that fails is the tell.
  * A ``data:`` URL iframe is OPAQUE-ORIGIN, so it cannot write the parent's
    title.  Those shapes are reported INCONCLUSIVE, not "no-exec": the sentinel
    cannot report, which is not evidence of non-execution.

Usage: python -m benchmark.sink_execution
Writes benchmark/results/sink_execution.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, ".")

_SELF = 'document.title="EXEC"'                 # same-document sentinel
_FRAME = 'parent.document.title="EXEC"'         # nested browsing context

# name -> (JS, needs trusted click, sentinel-usable?)
SHAPES: list[tuple[str, str, bool, bool]] = [
    ("iframe.src = javascript:CODE",
     "var e=document.createElement('iframe');"
     f" e.src='javascript:{_FRAME}'; document.body.appendChild(e);", False, True),
    ("iframe.srcdoc = <script>CODE",
     "var e=document.createElement('iframe');"
     f" e.srcdoc='<script>{_FRAME}<\\/script>';"
     " document.body.appendChild(e);", False, True),
    ("embed.src = javascript:CODE",
     "var e=document.createElement('embed');"
     f" e.src='javascript:{_SELF}'; document.body.appendChild(e);", False, True),
    ("object.data = javascript:CODE",
     "var e=document.createElement('object');"
     f" e.data='javascript:{_SELF}'; document.body.appendChild(e);", False, True),
    ("embed.src = data:text/html,<script>CODE",
     "var e=document.createElement('embed');"
     f" e.src='data:text/html,<script>{_SELF}<\\/script>';"
     " document.body.appendChild(e);", False, True),
    ("object.data = data:text/html,<script>CODE",
     "var e=document.createElement('object');"
     f" e.data='data:text/html,<script>{_SELF}<\\/script>';"
     " document.body.appendChild(e);", False, True),
    ("iframe.src = data:text/html,<script>CODE",
     "var e=document.createElement('iframe');"
     f" e.src='data:text/html,<script>{_FRAME}<\\/script>';"
     " document.body.appendChild(e);", False, False),
    ("a.href = javascript:CODE (no activation)",
     "var e=document.createElement('a');"
     f" e.href='javascript:{_SELF}'; document.body.appendChild(e);", False, True),
    ("a.href = javascript:CODE (trusted click)",
     "var e=document.createElement('a'); e.id='exec'; e.textContent='go';"
     " e.style='display:block;width:120px;height:30px;background:#ccc';"
     f" e.href='javascript:{_SELF}'; document.body.appendChild(e);", True, True),
    ("a.href = javascript:CODE (synthetic click)",
     "var e=document.createElement('a');"
     f" e.href='javascript:{_SELF}'; document.body.appendChild(e); e.click();",
     False, True),
    ("script.text = SENT (control)",
     "var e=document.createElement('script');"
     f" e.text='{_SELF}'; document.body.appendChild(e);", False, True),
    ("div.innerHTML = <img onerror=SENT (control)",
     "var e=document.createElement('div');"
     " e.innerHTML='<img src=x onerror=\\'document.title=\"EXEC\"\\'>';"
     " document.body.appendChild(e);", False, True),
    ("img.src = javascript:CODE",
     "var e=document.createElement('img');"
     f" e.src='javascript:{_SELF}'; document.body.appendChild(e);", False, True),
    ("link.href = javascript:CODE",
     "var e=document.createElement('link');"
     f" e.href='javascript:{_SELF}'; document.head.appendChild(e);",
     False, True),
    ("script.src = javascript:CODE",
     "var e=document.createElement('script');"
     f" e.src='javascript:{_SELF}'; document.body.appendChild(e);",
     False, True),
    ("base.href = javascript:CODE",
     "var e=document.createElement('base');"
     f" e.href='javascript:{_SELF}'; document.head.appendChild(e);",
     False, True),
    ("frame.src = javascript:CODE",
     "var e=document.createElement('frame');"
     f" e.src='javascript:{_FRAME}';"
     " (document.body || document.documentElement).appendChild(e);",
     False, True),
    ("meta refresh url=javascript:CODE",
     "var e=document.createElement('meta');"
     " e.httpEquiv='refresh';"
     f" e.content='0;url=javascript:{_SELF}'; document.head.appendChild(e);",
     False, True),
    ("img.src = data:text/html,<script>CODE",
     "var e=document.createElement('img');"
     f" e.src='data:text/html,<script>{_SELF}<\/script>';"
     " document.body.appendChild(e);", False, True),
    ("script.src = data:text/html,<script>CODE",
     "var e=document.createElement('script');"
     f" e.src='data:text/html,<script>{_SELF}<\/script>';"
     " document.body.appendChild(e);", False, True),
    ("div.innerHTML = <script>CODE (control)",
     "var e=document.createElement('div');"
     f" e.innerHTML='<script>{_SELF}<\/script>';"
     " document.body.appendChild(e);", False, True),
]


def main() -> int:
    from playwright.sync_api import sync_playwright
    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("about:blank")
        for name, js, needs_click, sentinel_ok in SHAPES:
            page.evaluate("document.title=''")
            try:
                page.evaluate(f"() => {{ {js} }}")
            except Exception as e:
                rows.append({"shape": name, "executes": None,
                             "note": f"injection error: {str(e)[:60]}"})
                print(f"  ERR  {name}  ({str(e)[:44]})", flush=True)
                continue
            if needs_click:
                try:
                    page.click("#exec")
                except Exception:
                    pass
            page.wait_for_timeout(450)
            ran = page.title() == "EXEC"
            if not sentinel_ok:
                rows.append({"shape": name, "executes": None,
                             "note": "opaque origin: the sentinel cannot "
                                     "report from a data: document"})
                print(f"  ????  {name}   (inconclusive)", flush=True)
                continue
            rows.append({"shape": name, "executes": ran, "note": ""})
            print(f"  {'EXECUTES' if ran else 'no-exec '} {name}", flush=True)
        browser.close()

    ok = [r for r in rows if r["executes"] is True]
    no = [r for r in rows if r["executes"] is False]
    inc = [r for r in rows if r["executes"] is None]
    print(f"\n=== summary ===\nshapes probed: {len(rows)}   "
          f"execute: {len(ok)}   no-exec: {len(no)}   inconclusive: {len(inc)}")
    print("no-exec (reporting one of these as 'marker executed' over-claims):")
    for r in no:
        print("   -", r["shape"])
    if inc:
        print("inconclusive (sentinel cannot report; NOT evidence either way):")
        for r in inc:
            print("   -", r["shape"])
    out = os.path.join("benchmark", "results", "sink_execution.json")
    json.dump(rows, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("written:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

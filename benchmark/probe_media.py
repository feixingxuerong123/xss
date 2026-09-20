"""Media events and SVG/Math URL sinks: does anything fire without a gesture?

`benchmark/corpus_gap.py` names these as the payloads the referee has never
seen: `<audio oncanplay=...>` / `onloadeddata` / `onloadstart` (11 uses),
`<svg><image href="javascript:">` (9), `<math><maction xlink:href=...>` (18),
`<svg><foreignObject onload>` (7), `<isindex action="javascript:">` (4).  None of
those event names is in `AUTO_FIRING_EVENTS`, so today every one of them falls to
the generic "requires user interaction" tail of `_handler_state` -- which is a
*claim*, not an absence of one: it keeps the gate from vetoing a payload that can
never fire, and keeps it from promoting one that fires on load.

Two rules learned the hard way this session, both built in here:

  * A single-host measurement is not a rule.  The SMIL family measured clean on
    23 shapes and then produced 12 over-claims once reflected into 20 hosts (an
    unquoted `class=` swallows `src=`; `<option>` changes rendering).  So every
    shape below is measured in **six** reflection contexts.
  * Media needs a source that exists.  Chromium refuses to *play* audible media
    without a gesture, but `loadstart`/`loadedmetadata`/`canplay` are about
    loading.  A data: URI keeps the question about the event, not about the
    network -- and if autoplay policy is what suppresses it, "no" is still the
    honest answer, just for a reason worth naming.

Sentinel handling is imported from `benchmark/browser_dom_oracle.py` rather than
re-typed, because a re-typed copy once produced 820 identical columns.

Usage: python -m benchmark.probe_media [--json out.json]
"""
from __future__ import annotations

import base64
import io
import json
import pathlib
import sys
import wave
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.browser_dom_oracle import (  # noqa: E402
    _INIT, _Handler, _clear, _goto, _read_hit, _serve, _wait_load)
from xssentinel.core import sandbox  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "results" / "media_probe.json"
X = "__x()"


def _tiny_wav() -> str:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setframerate(8000)
        w.setsampwidth(1)
        w.writeframes(bytes(8))
    return "data:audio/wav;base64," + base64.b64encode(buf.getvalue()).decode()


WAV = _tiny_wav()

# The six reflection contexts.  `__P__` is where the payload lands.
CONTEXTS = [
    ("text", '<html><body><div>__P__</div></body></html>'),
    ("attr_unq", '<html><body><div class=__P__>t</div></body></html>'),
    ("select", '<html><body><select><option>__P__</option></select></body></html>'),
    ("template", "<html><body><template>__P__</template></body></html>"),
    ("table_td", "<html><body><table><tr><td>__P__</td></tr></table></body></html>"),
    ("svg_fo", "<html><body><svg><foreignObject>__P__</foreignObject></svg></body></html>"),
]

# (id, payload, seconds the event needs, does the shape need a gesture by design)
SHAPES: list[tuple[str, str, float]] = [
    ("audio-loadstart", f'<audio onloadstart="{X}" src="{WAV}"></audio>', 1.0),
    ("audio-canplay", f'<audio oncanplay="{X}" src="{WAV}"></audio>', 1.5),
    ("audio-loadedmetadata",
     f'<audio onloadedmetadata="{X}" src="{WAV}"></audio>', 1.5),
    ("audio-loadeddata", f'<audio onloadeddata="{X}" src="{WAV}"></audio>', 1.5),
    ("audio-canplaythrough",
     f'<audio oncanplaythrough="{X}" src="{WAV}"></audio>', 1.5),
    ("audio-durationchange",
     f'<audio ondurationchange="{X}" src="{WAV}"></audio>', 1.5),
    ("audio-error-missing",
     f'<audio onerror="{X}" src="/no-such-file.wav"></audio>', 1.0),
    ("audio-canplay-nosrc", f'<audio oncanplay="{X}"></audio>', 1.0),
    ("audio-canplay-broken-src",
     f'<audio oncanplay="{X}" src="/no-such-file.wav"></audio>', 1.5),
    ("audio-canplay-empty-src", f'<audio oncanplay="{X}" src=""></audio>', 1.0),
    ("audio-canplay-invalid-data",
     f'<audio oncanplay="{X}" src="data:audio/wav;base64,###notb64"></audio>',
     1.5),
    ("audio-loadstart-broken-src",
     f'<audio onloadstart="{X}" src="/no-such-file.wav"></audio>', 1.0),
    ("audio-onplaying-valid",
     f'<audio onplaying="{X}" src="{WAV}"></audio>', 2.0),
    ("video-timeupdate", f'<video ontimeupdate="{X}" src="{WAV}"></video>', 1.5),
    ("track-error",
     f'<video><track onerror="{X}" src="/nope.vtt" kind="captions" '
     f'default></video>', 1.0),
    # URL sinks the sandbox has no measured answer for
    ("svg-image-href", f'<svg><image href="javascript:{X}"></image></svg>', 0.5),
    ("svg-image-xlink",
     f'<svg xmlns:xlink="http://www.w3.org/1999/xlink">'
     f'<image xlink:href="javascript:{X}"></image></svg>', 0.5),
    ("math-maction-xlink",
     f'<math><maction actiontype="statusline#" xlink:href="javascript:{X}">'
     f'x</maction></math>', 0.5),
    ("feimage-href",
     f'<svg><filter id="f"><feImage href="javascript:{X}"></feImage></filter>'
     f'<rect filter="url(#f)"></rect></svg>', 0.5),
    ("isindex-action", f'<isindex action="javascript:{X}" type="submit">', 0.5),
    ("foreignobject-onload",
     f'<svg><foreignObject onload="{X}"><div xmlns="http://www.w3.org/'
     f'1999/xhtml">t</div></foreignObject></svg>', 0.5),
    ("svg-desc-onload", f'<svg><desc onload="{X}">d</desc></svg>', 0.5),
    ("canvas-onload", f'<canvas onload="{X}"></canvas>', 0.5),
    # 1.5 s, not 0.5: the first run showed parser=True / innerHTML=False for this
    # one shape while the same markup fired True/True inside table_td, which is
    # the signature of a settle that is too short, not of a sink difference.
    ("body-background", f'<img background="/nope.png" src=x onerror="{X}">', 1.5),
]


def run() -> list[dict]:
    from playwright.sync_api import sync_playwright

    pages = {f"/{ci}.{si}": tpl.replace("__P__", body)
             for ci, (_, tpl) in enumerate(CONTEXTS)
             for si, (_, body, _) in enumerate(SHAPES)}
    srv, base = _serve()
    _Handler.PAGES = {"/blank": "<html><body></body></html>", **pages}
    rows: list[dict[str, Any]] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT)
            page = ctx.new_page()
            for ci, (cname, tpl) in enumerate(CONTEXTS):
                for si, (sname, body, needs) in enumerate(SHAPES):
                    doc = tpl.replace("__P__", body)
                    row: dict[str, Any] = {"case": f"{cname}:{sname}",
                                            "context": cname,
                                            "shape": sname, "document": doc}
                    if not _goto(page, base + "/blank"):
                        row.update({"exec_parser": None, "exec_ihn1": None,
                                    "harness_error": "loopback reset"})
                        rows.append(row)
                        continue
                    _clear(page)
                    if not _goto(page, f"{base}/{ci}.{si}"):
                        row.update({"exec_parser": None, "exec_ihn1": None,
                                    "harness_error": "reset on payload page"})
                        rows.append(row)
                        continue
                    _wait_load(page)
                    page.wait_for_timeout(int(max(300, needs * 1000)))
                    row["exec_parser"] = _read_hit(page)
                    # ---- the DOM sink arm, same bytes ----
                    if not _goto(page, base + "/blank"):
                        row["exec_ihn1"] = None
                        rows.append(row)
                        continue
                    _clear(page)
                    try:
                        inner = doc[len("<html><body>"):-len("</body></html>")]
                        page.evaluate(
                            "(h) => { const d = document.createElement('div');"
                            " d.innerHTML = h; document.body.appendChild(d); }",
                            inner)
                        page.wait_for_timeout(int(max(300, needs * 1000)))
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


def report(rows: list[dict]) -> int:
    """Three-way contract as in probe_smil / sandbox_fidelity: only a confident
    claim can be wrong.  `unknown` and `live(+act)` are declines."""
    bad = declined = answered_ok = 0
    fired = []
    for r in rows:
        if r.get("harness_error") or r.get("exec_parser") is None:
            bad += 1
            continue
        bp, bi = bool(r["exec_parser"]), bool(r.get("exec_ihn1"))
        if bp or bi:
            fired.append((r["case"], bp, bi))
        doc = r["document"]
        v = [sandbox.judge(doc, X, sink=s) for s in ("parser", "innerhtml")]
        notes = []
        for got, executes in ((v[0], bp), (v[1], bi)):
            if got.state == "unknown":
                declined += 1
                continue
            says_yes = got.state == "live" and not got.activation
            says_no = got.state == "inert"
            if says_yes and not executes:
                notes.append("OVER")
            if says_no and executes:
                notes.append("MISSED")
        if notes:
            bad += 1
            print(f"  {r['case']:<44} parser={bp} ihn={bi} "
                  f"sandbox={v[0].state}{'(+act)' if v[0].activation else ''} "
                  f"{' '.join(notes)}")
            print(f"      {doc[:112]}")
        else:
            answered_ok += 1
    print(f"\nfired somewhere: {len(fired)} shapes")
    for case, bp, bi in fired[:24]:
        print(f"   {case:<44} parser={bp} ihn={bi}")
    print(f"\n{answered_ok}/{len(rows)} shapes agree; {declined} arm-verdicts "
          f"declined; {bad} disagree/inconclusive")
    return bad


if __name__ == "__main__":
    rows = run()
    dest = (sys.argv[sys.argv.index("--json") + 1]
            if "--json" in sys.argv else str(OUT))
    json.dump(rows, open(dest, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    raise SystemExit(1 if report(rows) else 0)

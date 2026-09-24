"""Is the browser-truth oracle reproducible?  Re-measure rows and find out.

`benchmark/results/browser_dom_oracle.json` is the ground truth everything else is
scored against -- `sandbox_fidelity.py`, `corpus_gap.py`, the `MISSED 0 / OVER 0`
headline.  Nothing in the repo asked whether it can be reproduced.  This does, and
it had to: two full 1200-row runs of the same 60-payload x 20-host matrix (one
committed as of Phase 176i, one in this working tree) disagree on 7 rows, e.g.
`img-onerror x text`, the most ordinary shape in the corpus.

Why a hit has to carry a fingerprint.  The oracle's sentinel writes
`localStorage['__exec']='1'`, and localStorage is shared by every same-origin
document -- including a frame that a *previous* row left navigating.  So a plain
flag lets one row's late write land on the next row's read, which reads as
"executes" where nothing executed.  Here every navigation goes to its own URL
(`/p3a2`), and the sentinel records the URL it ran under; a hit counts only if the
stamp is this attempt's own URL.  A contaminated row therefore reads as a MISS,
never as a false True -- the safe direction for a tool whose job is to catch drift.

Three verdicts per (payload, host, arm): STABLE-yes, STABLE-no, FLAKY.  FLAKY rows
are the ones no sandbox verdict may be scored against until the cause is found.

Usage:
  python -m benchmark.oracle_reproduce                      # the known 7
  python -m benchmark.oracle_reproduce img-onerror/text ... # named rows
  python -m benchmark.oracle_reproduce --tries 5
"""
from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from benchmark.browser_dom_oracle import (  # noqa: E402
    HOSTS, HOST_SETTLE_OVERRIDES, PAYLOADS, SETTLE_OVERRIDES, _Handler, _clear,
    _goto, _serve, _wait_load)

OUT = pathlib.Path(__file__).resolve().parent / "results" / "oracle_reproduce.json"

#: The rows where the committed oracle and this working tree's oracle disagree on
#: browser truth, as `payload/host`.
DISAGREEING = [
    "mxss-svg-p-style/select", "title-close-break/text", "iframe-srcdoc/table_td",
    "script-close-break/table_td", "img-onerror/text", "mxss-body-br/svg_style",
    "iframe-srcdoc/select",
]

#: The sentinel records WHERE it ran, not just that it ran.  `window.top` because a
#: `srcdoc` frame and a `javascript:` frame are separate realms whose own
#: `location` is not the row's URL; same-origin here, so the read is allowed, and
#: if it ever is not, the fallback still stamps something rather than nothing.
_INIT_STAMP = """
window.__x = function () {
  var stamp = '?';
  try { stamp = window.top.location.pathname; }
  catch (e) { try { stamp = location.pathname; } catch (e2) {} }
  try { localStorage.setItem('__exec', stamp); } catch (e3) {}
};
"""

_SINK = """(h) => { const d = document.createElement('div');
  d.innerHTML = h; document.body.appendChild(d); }"""


def _lookup(name: str) -> tuple[str, str, str]:
    """`payload/host` -> (payload id, its bytes, host template)."""
    pid, hid = name.split("/", 1)
    payload = dict((p, b) for p, b, _t in PAYLOADS)[pid]
    host = dict((hid, tpl) for hid, tpl, _ok in HOSTS)[hid]
    return pid, payload, host


def _settle(pid: str, hid: str) -> int:
    return max(300, SETTLE_OVERRIDES.get(pid, 0), HOST_SETTLE_OVERRIDES.get(hid, 0))


def _read_stamp(page):
    try:
        return page.evaluate("() => { try { return localStorage.getItem('__exec')"
                             " } catch (e) { return null } }")
    except Exception:
        return None


def measure(names: list[str], tries: int) -> list[dict]:
    from playwright.sync_api import sync_playwright

    spec = [(n,) + _lookup(n) for n in names]
    srv, base = _serve()
    pages: dict[str, str] = {}
    for i, (_n, _pid, payload, host) in enumerate(spec):
        doc = host.replace("__P__", payload)
        for j in range(tries):
            pages[f"/p{i}a{j}"] = doc          # the parser arm: server reflects it
            pages[f"/s{i}a{j}"] = "<html><body></body></html>"   # the sink arm
    _Handler.PAGES = pages
    rows: list[dict] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context()
            ctx.add_init_script(_INIT_STAMP)
            page = ctx.new_page()
            for i, (name, pid, _payload, host) in enumerate(spec):
                doc = host.replace("__P__", _payload)
                settle = _settle(pid, name.split("/", 1)[1])
                parser: list[bool] = []
                sink: list[bool] = []
                for j in range(tries):
                    # ---- arm 1: reflected by the server, parsed on load ------
                    _goto(page, base + "/blank")
                    _clear(page)
                    _goto(page, f"{base}/p{i}a{j}")
                    _wait_load(page)
                    page.wait_for_timeout(settle)
                    parser.append(_read_stamp(page) == f"/p{i}a{j}")
                    # ---- arm 2: a DOM sink re-parses the same bytes ----------
                    _goto(page, base + "/blank")
                    _clear(page)
                    _goto(page, f"{base}/s{i}a{j}")
                    _wait_load(page)
                    page.evaluate(_SINK, doc)
                    page.wait_for_timeout(settle)
                    sink.append(_read_stamp(page) == f"/s{i}a{j}")
                    print(f"  {name:34} try {j + 1}  parser={parser[-1]!s:5}"
                          f" sink={sink[-1]!s:5}", flush=True)
                rows.append({"row": name, "document": doc, "settle": settle,
                             "parser": parser, "sink": sink,
                             "parser_stable": len(set(parser)) == 1,
                             "sink_stable": len(set(sink)) == 1})
            browser.close()
    finally:
        srv.shutdown()
        srv.server_close()
    return rows


def report(rows: list[dict], tries: int) -> int:
    """Count the rows that cannot be trusted, and say which artifact each one
    contradicts -- a disagreement between two runs is only interesting once it is
    pointed at a specific stored answer."""
    stored = {}
    for dest in (str(pathlib.Path("benchmark/results/browser_dom_oracle.json")),
                 str(pathlib.Path(__file__).resolve().parent
                     / "results" / "_oracle_head.json")):
        if not pathlib.Path(dest).exists():
            continue
        d = json.load(open(dest, encoding="utf-8"))
        for r in d["rows"]:
            stored.setdefault(f"{r['payload']}/{r['host']}", {})[
                pathlib.Path(dest).name] = (r.get("exec_parser"),
                                            r.get("exec_ihn1"))
    unstable = 0
    print()
    print(f"{'row':<34}{'parser (n=%d)' % tries:<22}{'sink (n=%d)' % tries:<22}"
          "stored answers")
    for r in rows:
        unstable += not (r["parser_stable"] and r["sink_stable"])
        flags = "  ".join("FLAKY" if not k else ("yes" if v[0] else "no")
                          for k, v in ((r["parser_stable"], r["parser"]),
                                       (r["sink_stable"], r["sink"])))
        who = " | ".join(f"{name}:{parser!s}/{sink!s}" for name, (parser, sink)
                         in sorted(stored.get(r["row"], {}).items()))
        print(f"{r['row']:<34}{str(r['parser']):<22}{str(r['sink']):<22}"
              f"{flags}   {who}")
    print(f"\n{len(rows) - unstable}/{len(rows)} rows reproduced "
          f"{tries}x in both arms; {unstable} did not")
    if unstable:
        print("Those rows are not evidence. Until they reproduce, no MISSED/OVER "
              "number that depends on them may be quoted as a correctness claim.")
    return unstable


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Re-measure oracle rows for "
                                 "reproducibility")
    ap.add_argument("rows", nargs="*",
                    help="payload/host names (default: the known disagreements)")
    ap.add_argument("--tries", type=int, default=3,
                    help="measurements per row per arm (default: 3)")
    ap.add_argument("--json", default=str(OUT), help="where to write the artifact")
    a = ap.parse_args()
    names = a.rows or DISAGREEING
    for n in names:
        if "/" not in n:
            raise SystemExit(f"row names must look like payload/host, got {n!r}")
    rows = measure(names, a.tries)
    pathlib.Path(a.json).parent.mkdir(parents=True, exist_ok=True)
    json.dump({"tries": a.tries, "rows": rows},
              open(a.json, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\nwritten:", a.json)
    raise SystemExit(1 if report(rows, a.tries) else 0)

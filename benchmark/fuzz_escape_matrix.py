# -*- coding: utf-8 -*-
"""Phase 129: generated escape-consistency matrix (property fuzz).

Why this exists
---------------
Every escaping-blind false positive this project has hit (Phases 123, 126,
128) was found by hand, and each one lived in the same blind spot: a payload
shape / context combination that NOBODY had written a manifest pair for.
`/fuzz/render` lets the harness generate the combinations instead of us.

The invariant
-------------
When the application HTML-escapes the reflected value (``esc=html``: ``< > &
" '`` all become entities), a finding may only be reported if the payload's
executability does not depend on any escaped character.  For the contexts
below, escaping provably kills the break-out, so ANY high/medium finding is
a false positive:

    text       -- needs "<" to start a tag
    attr_dq    -- needs a quote to leave the value
    attr_sq    -- ditto
    script_dq  -- needs a quote or "</script>" (both escaped)
    script_sq  -- ditto
    svg        -- needs "<" to open foreign content
    comment    -- needs ">" to close the comment

Documented EXCEPTIONS (escaping does NOT neutralise them -- a finding there
is legitimate, so the harness reports it instead of failing):

    attr_bare  -- an unquoted attribute needs no quote at all; a bare
                  "autofocus onfocus=... x=" breaks out with only spaces
    href       -- "javascript:" needs neither "<" nor a quote

Non-vacuity anchors
-------------------
A harness that only ever asserts "no findings" passes trivially when the
target or the scanner is broken.  So the run aborts unless
``text + raw`` confirms -- proof that the pipeline actually fires.

Usage::

    python benchmark/fuzz_escape_matrix.py [port]
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark.server as srv
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

SAFE_CONTEXTS = ["text", "attr_dq", "attr_sq", "script_dq", "script_sq",
                 "svg", "comment"]
EXCEPTION_CONTEXTS = ["attr_bare", "href"]
ANCHOR = ("text", "raw")
HIGH_MED = ("high", "medium", "critical")


def _scan(base: str, ctx: str, esc: str, sink: str = "none",
          budget=(14, 6)):
    url = f"{base}/fuzz/render?ctx={ctx}&esc={esc}&sink={sink}"
    sc = Scanner(requester=Requester(timeout=10), max_payloads=budget[0],
                 max_transforms=budget[1], dom_engine="static",
                 verbose=False)
    sc.scan_target(url, method="GET", params={"q": "xssentinel_bench_probe"},
                   data={}, oob_collect=False)
    sc.dedup()
    hits = [f.data for f in sc.findings
            if f.data.get("param") == "q"
            and f.data.get("severity") in HIGH_MED]
    return hits


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8962
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.run_server, kwargs={"port": port},
                     daemon=True).start()
    for _ in range(60):
        try:
            urllib.request.urlopen(base + "/fuzz/render?q=up", timeout=2)
            break
        except Exception:
            time.sleep(0.25)
    else:
        print("server did not come up")
        return 2

    print("=" * 74)
    print("[anchor] the pipeline must FIRE on raw text, else this run is "
          "vacuous")
    anchor = _scan(base, *ANCHOR)
    print("  %-9s %-5s -> %d high/medium finding(s)  %s"
          % (ANCHOR[0], ANCHOR[1], len(anchor),
             sorted({h.get("type") for h in anchor})))
    if not anchor:
        print("  ABORT: no confirmation on raw text -- target or scanner is "
              "not exercising the path, every later assertion would be "
              "meaningless")
        return 2

    violations = []
    print("=" * 74)
    print("[invariant] escaped rendering must NOT confirm")
    for ctx in SAFE_CONTEXTS:
        row = {}
        for esc in ("raw", "html"):
            hits = _scan(base, ctx, esc)
            row[esc] = hits
            if esc == "html" and hits:
                violations.append((ctx, esc, "none", hits))
        print("  %-9s raw: %-3d html: %-3d %s"
              % (ctx, len(row["raw"]), len(row["html"]),
                 "<-- VIOLATION" if row["html"] else ""))

    print("=" * 74)
    print("[invariant] escaped + a page-level sink must STILL not confirm")
    print("            (the exact combination behind the Phase 123 clobber "
          "and Phase 128 mXSS false positives)")
    for ctx in SAFE_CONTEXTS:
        hits = _scan(base, ctx, "html", sink="dom")
        if hits:
            violations.append((ctx, "html", "dom", hits))
        print("  %-9s html+dom sink: %-3d %s"
              % (ctx, len(hits), "<-- VIOLATION" if hits else ""))

    print("=" * 74)
    print("[documented exceptions] escaping cannot neutralise these "
          "(reported, not failed)")
    for ctx in EXCEPTION_CONTEXTS:
        row = {}
        for esc in ("raw", "html"):
            row[esc] = _scan(base, ctx, esc)
        print("  %-9s raw: %-3d html: %-3d  types(html)=%s"
              % (ctx, len(row["raw"]), len(row["html"]),
                 sorted({h.get("type") for h in row["html"]})))

    print("=" * 74)
    if violations:
        print(f"FAIL: {len(violations)} escape-consistency violation(s)")
        for ctx, esc, sink, hits in violations:
            for h in hits[:3]:
                print("  ctx=%s esc=%s sink=%s  type=%s sev=%s payload=%r"
                      % (ctx, esc, sink, h.get("type"), h.get("severity"),
                         str(h.get("payload"))[:90]))
        return 1
    print("PASS: no escaped context produced a high/medium finding")
    return 0


if __name__ == "__main__":
    sys.exit(main())

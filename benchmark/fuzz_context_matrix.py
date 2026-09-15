# -*- coding: utf-8 -*-
"""Phase 130: context-consistency matrix (the FN side of the net).

`fuzz_escape_matrix.py` asks "does the engine stay silent when it must?"
(the false-positive side).  This is the mirror image: "does the engine
SPEAK when a payload it owns is reflected raw into the context that
payload was written for?"  A silent engine there is a false negative.

Design notes that keep this from being a self-defeating test
-----------------------------------------------------------
Asserting "raw must confirm" is only meaningful if the target really is
vulnerable for the payloads the engine sends.  So a zero-confirmation
context is NOT reported as a failure immediately -- it is DIAGNOSED:

    take the corpus entries written for that context, mark them the way
    the scanner does (``verifier.mark``) and run the SAME verifier the
    scanner uses (``verify_semantic``) on the rendered page.

    * verifier confirms  -> the shape IS executable here, yet the scan
      produced nothing  => a real FALSE NEGATIVE (fail).
    * verifier silent   -> this template/corpus pair does not reproduce
      the context        => informational, not a failure.

That split is what separates "the engine missed it" from "our toy page
did not model it" -- the same discipline as checking the escape twins by
hand instead of trusting a green bench.

Usage::

    python benchmark/fuzz_context_matrix.py [port]
"""
from __future__ import annotations

import os
import secrets
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import benchmark.server as srv
from xssentinel.core import payloads as corpus
from xssentinel.core import verifier
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

HIGH_MED = ("high", "medium", "critical")

# fuzz target context -> the corpus written for that context
CTX_TO_CORPUS = {
    "text": "html_element",
    "attr_dq": "html_attribute_dq",
    "attr_sq": "html_attribute_sq",
    "attr_bare": "html_attribute_noquote",
    "script_dq": "script_string_dq",
    "script_sq": "script_string_sq",
    "href": "url_javascript",
    "svg": "svg_context",
    "comment": "html_comment",
}

DIAGNOSE_N = 6      # corpus entries checked by hand when a context is silent


# Escaping/filter modes exercised on the FN side.  `raw` is the baseline;
# the two filters are where bypass failures (real FNs) hide.  Full HTML
# escaping is the FP net's job (fuzz_escape_matrix.py), not this one.
FN_ESCAPES = ["raw", "strip_script", "encode_angles"]


def _scan(base: str, ctx: str, esc: str = "raw", sink: str = "none"):
    url = f"{base}/fuzz/render?ctx={ctx}&esc={esc}&sink={sink}"
    sc = Scanner(requester=Requester(timeout=10), max_payloads=14,
                 max_transforms=6, dom_engine="static", verbose=False)
    sc.scan_target(url, method="GET",
                   params={"q": "xssentinel_bench_probe"}, data={},
                   oob_collect=False)
    sc.dedup()
    return [f.data for f in sc.findings
            if f.data.get("param") == "q"
            and f.data.get("severity") in HIGH_MED]


def _stride(items: list, n: int) -> list:
    if n <= 0 or not items:
        return []
    if len(items) <= n:
        return items
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def _render(base: str, ctx: str, value: str, esc: str = "raw"):
    url = (f"{base}/fuzz/render?ctx={ctx}&esc={esc}"
           f"&q={urllib.parse.quote(value, safe='')}")
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace"), dict(r.headers)


def _diagnose(base: str, ctx: str, esc: str) -> tuple[bool, str]:
    """True when the verifier confirms a corpus payload the scan missed."""
    entries = corpus.by_context(CTX_TO_CORPUS[ctx])
    for entry in _stride(entries, DIAGNOSE_N):
        payload = entry.get("payload") or ""
        if not payload:
            continue
        token = "xssv_" + secrets.token_hex(4)
        marked = verifier.mark(payload, token)
        try:
            text, headers = _render(base, ctx, marked, esc)
        except Exception:
            continue
        v = verifier.verify_semantic(text, token, response_headers=headers)
        if v.get("confirmed"):
            return True, (f"{CTX_TO_CORPUS[ctx]}/{esc}: verifier confirms "
                          f"{payload[:52]!r} but the scan reported nothing")
    return False, (f"{CTX_TO_CORPUS[ctx]}/{esc}: not reproducible "
                   f"({len(entries)} corpus entries)")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8965
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

    fn: list[tuple[str, str]] = []
    inert: list[str] = []
    print("=" * 78)
    print("[context consistency] the context's OWN corpus, reflected raw or "
          "through a filter,")
    print("                     must be confirmed whenever the verifier says "
          "the shape is live")
    for ctx in CTX_TO_CORPUS:
        for esc in FN_ESCAPES:
            hits = _scan(base, ctx, esc)
            if hits:
                print("  %-9s %-14s confirmed: %-3d %s"
                      % (ctx, esc, len(hits),
                         sorted({h.get("type") for h in hits})))
                continue
            is_fn, why = _diagnose(base, ctx, esc)
            if is_fn:
                fn.append((ctx, why))
                print("  %-9s %-14s confirmed: 0   <-- FALSE NEGATIVE: %s"
                      % (ctx, esc, why))
            else:
                inert.append(f"{ctx}/{esc}")
                print("  %-9s %-14s confirmed: 0   (informational) %s"
                      % (ctx, esc, why))

    print("=" * 74)
    if fn:
        print(f"FAIL: {len(fn)} false negative(s)")
        for ctx, why in fn:
            print(f"  {ctx}: {why}")
        return 1
    print("PASS: every context the target can reproduce is confirmed"
          + (f"; not reproducible: {', '.join(inert)}" if inert else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
